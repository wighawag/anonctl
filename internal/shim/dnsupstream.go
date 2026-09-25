package shim

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// The upstream half of the DNS forwarder: ONE persistent, pipelined DNS-over-TCP
// stream to the resolver, held open across queries and re-dialled on error or
// idle.
//
// WHY. The version this replaces dialed a FRESH SOCKS stream per query and closed
// it, so every name paid a stream open THROUGH THE CIRCUIT (and the exit's own TCP
// connect to the resolver) before its exchange, plus a teardown after, and a
// getaddrinfo asking A and AAAA paid that twice. That is exactly what RFC 7766 says
// not to do: DNS-over-TCP connections are meant to be persistent and pipelined. What
// it costs in wall time is whatever the circuit costs at that moment, which is the
// real defect: a slow or cold circuit was paid once per NAME. (On the reporting host,
// telemaque, a forced lookup measured inside the account's session had a ~2.2s
// median; how much of that was this per-query open is NOT established, since the
// forwarder's own port answered in ~0.3s the same day. See
// work/notes/observations/dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance.md.)
//
// WHY IT CHANGES NO ANONYMITY PROPERTY. The stream is already per-account: the
// dial carries the `<account>@` isolation username (Tor IsolateSOCKSAuth), which
// pins its circuit class, and the shim process itself is per-account under its own
// uid. Holding that one stream open therefore links nothing that re-opening it
// repeatedly did not already link, and it produces FEWER stream events for the
// endpoint to observe rather than more. The fail-closed property is untouched and
// is the reason the dial function is the ONLY way out of this file: if the
// endpoint is down there is no answer, never an answer from somewhere else.
//
// WHY IDS ARE REWRITTEN. Pipelining means several queries are outstanding on one
// connection at once, and their answers may come back in ANY order (RFC 7766
// section 6.2.1.1), so a response is matched to its waiter by DNS message ID. The
// clients' own IDs cannot be used for that: two clients (or two resolver
// instances) can legitimately have the same ID in flight at the same time, and
// with one shared connection that collision would deliver one client's answer to
// the other. So each query is assigned an ID unique among the IDs OUTSTANDING ON
// THIS STREAM, and the client's original ID is restored on the way back out.

// THE IDLE TRADEOFF (DefaultDNSUpstreamIdle) has one honest term on each side:
// longer keeps more lookups off a cold circuit (a page load, a `git fetch`, a
// package update are all bursts of names with gaps of seconds), shorter holds a Tor
// stream open for less wall time. The idle teardown only ever takes a stream with
// NOTHING in flight (checked and marked in one step, failIfIdle), so a stream is
// never reaped from under a query still waiting; with queries in flight, their own
// deadlines govern. An earlier version killed the stream on any read timeout with a
// waiter present, and restarted the idle clock only when a frame arrived, so a query
// written just before the timer fired died with it. The clock now also restarts on
// every query written, so idleness means no traffic in either direction.

// errUpstreamBroken marks a STREAM-level failure that is not this query's own fault
// (EOF, a write error, a short or unreadable frame, a stream abandoned because it
// stopped answering, an idle teardown that raced this query): the stream is unusable
// and the query is retried once on a fresh one, within its OWN deadline. It is
// deliberately distinct from errUpstreamTimeout, which is never retried: the client
// asked for an answer within a bounded window, and quietly spending a second window
// is how a bounded wait becomes an unbounded one.
var errUpstreamBroken = errors.New("dns upstream: stream broken")

// errUpstreamTimeout means THIS query's own deadline expired. It is returned only to
// the query whose deadline it was: an earlier version handed it to every query in
// flight on the stream when any one of them timed out, so a query with most of its
// budget left was reported as "deadline expired" when its deadline never had.
var errUpstreamTimeout = errors.New("dns upstream: exchange deadline expired")

// errStreamAbandoned: a query's deadline expired with NOTHING received on the stream
// since that query was written, so the stream has stopped answering and is torn
// down. Every other query in flight on it is retried on a fresh stream.
var errStreamAbandoned = fmt.Errorf("%w: abandoned, it stopped answering", errUpstreamBroken)

// errUpstreamIdle marks the idle teardown, a normal end of life for a stream. It is
// retryable (it wraps errUpstreamBroken) because a query can be handed a stream in
// the instant the teardown claims it; retried, it reaches a client only if the retry
// fails as well, and then as that failure's own reason.
var errUpstreamIdle = fmt.Errorf("%w: closed after idle", errUpstreamBroken)

// errUpstreamClosed: the forwarder is shutting down. Not retried.
var errUpstreamClosed = errors.New("dns upstream: forwarder closed")

// dnsUpstream owns at most one live stream and re-dials as needed. Its dial func
// is the SOCKS dial, so the isolation username is carried on every dial including
// every re-dial.
type dnsUpstream struct {
	dial func(ctx context.Context) (net.Conn, error)
	// exchangeTimeout bounds one attempt (dial included); idle is how long a stream
	// with nothing in flight is kept. Both are per-upstream values, set once before the
	// reader goroutines exist.
	exchangeTimeout time.Duration
	idle            time.Duration

	mu     sync.Mutex
	cur    *dnsStream
	closed bool
}

// exchange sends one DNS message upstream and returns the response, reusing the
// live stream when there is one. It bounds the WHOLE attempt, dial included: the
// dial used to be unbounded (proxy.SOCKS5 over proxy.Direct has no timeout), which
// meant an endpoint that accepted a connection and then said nothing parked the
// query forever, with no deadline to fire and nothing to report.
func (u *dnsUpstream) exchange(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("dns upstream: refusing to forward a %d-byte query (shorter than a DNS header)", len(query))
	}
	if len(query) > 65535 {
		return nil, fmt.Errorf("dns upstream: refusing to forward a %d-byte query (longer than DNS-over-TCP framing allows)", len(query))
	}
	deadline := time.Now().Add(u.exchangeTimeout)
	for attempt := 0; ; attempt++ {
		if !time.Now().Before(deadline) {
			// Out of budget before (re)trying, e.g. after queueing behind a slow dial: this
			// query's own deadline, reported as such, and no write into a shared stream.
			return nil, errUpstreamTimeout
		}
		s, err := u.stream(deadline)
		if err != nil {
			return nil, err
		}
		resp, rerr := s.roundTrip(query, deadline)
		if rerr == nil {
			return resp, nil
		}
		if !s.live() {
			// Only a DEAD stream is retired. A query whose own answer was slow leaves a
			// stream that is still answering others, and dropping it would make the next query
			// dial a second stream while the first lingers until its idle timeout.
			u.retire(s)
		}
		// RETRY ONCE on a fresh stream when the failure was the STREAM's and not this
		// query's: the peer closed it (RFC 7766 lets either end, and a Tor exit will),
		// another query found it had stopped answering, or the idle teardown claimed it as
		// this query arrived. Without this, each of those costs a client a SERVFAIL for a
		// failure that says nothing about the path. Bounded by the SAME deadline, and never
		// for errUpstreamTimeout, so a retry can never extend a client's wait.
		if attempt == 0 && errors.Is(rerr, errUpstreamBroken) {
			continue
		}
		return nil, rerr
	}
}

// stream returns the live stream, or dials a new one.
//
// The dial happens under the mutex on purpose: a burst of queries (getaddrinfo's
// A and AAAA, a page load's worth of names) then pays for ONE circuit connect and
// pipelines the rest onto it, instead of racing N connects. A query queued behind a
// slow dial keeps its own deadline, which exchange checks before it writes.
func (u *dnsUpstream) stream(deadline time.Time) (*dnsStream, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, errUpstreamClosed
	}
	if u.cur != nil && u.cur.live() {
		return u.cur, nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	conn, err := u.dial(ctx)
	if err != nil {
		u.cur = nil
		return nil, err
	}
	s := newDNSStream(conn, u.idle)
	u.cur = s
	return s, nil
}

// retire drops a stream if it is still the current one, so the next query dials.
func (u *dnsUpstream) retire(s *dnsStream) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cur == s {
		u.cur = nil
	}
}

// close tears down the live stream and refuses any further dial (forwarder
// shutdown). Without the refusal, a query still in flight at shutdown would dial a
// fresh stream that nothing ever closes.
func (u *dnsUpstream) close() {
	u.mu.Lock()
	s := u.cur
	u.cur = nil
	u.closed = true
	u.mu.Unlock()
	if s != nil {
		s.fail(errUpstreamClosed)
	}
}

// dnsStream is one pipelined DNS-over-TCP connection: many outstanding queries,
// answers matched back to their waiters by the ID this stream assigned.
type dnsStream struct {
	conn net.Conn
	idle time.Duration

	// wmu serialises writes so two pipelined queries cannot interleave their bytes
	// inside one length-prefixed frame.
	wmu sync.Mutex

	mu      sync.Mutex
	waiters map[uint16]chan []byte
	nextID  uint16
	dead    error
	done    chan struct{}
	// lastRecv is when the last frame arrived (or the stream was opened). A query whose
	// deadline expires with nothing received since it was written proves the stream has
	// stopped answering; one that expires while other answers keep arriving proves only
	// that ITS answer was slow.
	lastRecv time.Time
}

func newDNSStream(conn net.Conn, idle time.Duration) *dnsStream {
	s := &dnsStream{
		conn:     conn,
		idle:     idle,
		waiters:  make(map[uint16]chan []byte),
		done:     make(chan struct{}),
		lastRecv: time.Now(),
	}
	go s.read()
	return s
}

func (s *dnsStream) live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dead == nil
}

// roundTrip writes one query and waits for the answer with that query's ID.
func (s *dnsStream) roundTrip(query []byte, deadline time.Time) ([]byte, error) {
	ch := make(chan []byte, 1)
	id, err := s.register(ch)
	if err != nil {
		return nil, err
	}
	defer s.unregister(id)

	// One copy, because the ID is rewritten for the wire and the caller's buffer is
	// not ours to touch.
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	binary.BigEndian.PutUint16(frame[2:4], id)

	s.wmu.Lock()
	_ = s.conn.SetWriteDeadline(deadline)
	_, werr := s.conn.Write(frame)
	writtenAt := time.Now()
	if werr == nil {
		// A written query restarts the idle clock, so the teardown can never claim a
		// stream with a query on it that was written moments before the timer fired.
		_ = s.conn.SetReadDeadline(writtenAt.Add(s.idle))
	}
	s.wmu.Unlock()
	if werr != nil {
		// A failed or partial write corrupts the framing for everyone, so the stream goes
		// either way. What THIS query is told depends on why: its own deadline, or a
		// broken stream it may retry.
		s.fail(fmt.Errorf("%w: write: %v", errUpstreamBroken, werr))
		if isTimeout(werr) {
			return nil, errUpstreamTimeout
		}
		return nil, s.reason()
	}

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case resp := <-ch:
		return withClientID(resp, query), nil
	case <-s.done:
		// The answer may have landed in ch in the same instant the stream died (the peer
		// answered and closed at once): select picks at random between two ready cases, so
		// look before discarding an answer that has already arrived.
		select {
		case resp := <-ch:
			return withClientID(resp, query), nil
		default:
		}
		return nil, s.reason()
	case <-timer.C:
		if s.silentSince(writtenAt) {
			// Nothing at all has arrived since this query was written: the stream has stopped
			// answering, so tear it down and let every other query in flight retry on a fresh
			// one, each within its own deadline.
			s.fail(errStreamAbandoned)
		}
		// Otherwise answers are still arriving and only THIS one was slow: the stream stays,
		// and a late answer for this ID is dropped by the reader as unmatched.
		return nil, errUpstreamTimeout
	}
}

// withClientID hands the client back its OWN message ID: the one on the wire was
// this stream's.
func withClientID(resp, query []byte) []byte {
	copy(resp[:2], query[:2])
	return resp
}

// silentSince reports that no frame has arrived since t.
func (s *dnsStream) silentSince(t time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastRecv.After(t)
}

// register allocates an ID unique among the queries CURRENTLY OUTSTANDING on this
// stream and records the waiter under it.
func (s *dnsStream) register(ch chan []byte) (uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead != nil {
		return 0, s.dead
	}
	if len(s.waiters) >= 65535 {
		return 0, fmt.Errorf("dns upstream: 65535 queries already outstanding")
	}
	for {
		s.nextID++
		if _, taken := s.waiters[s.nextID]; !taken {
			s.waiters[s.nextID] = ch
			return s.nextID, nil
		}
	}
}

func (s *dnsStream) unregister(id uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.waiters, id)
}

func (s *dnsStream) reason() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead != nil {
		return s.dead
	}
	return errUpstreamBroken
}

// fail marks the stream dead, closes the connection and releases every waiter.
// The first reason wins, because it is the one that explains the rest.
func (s *dnsStream) fail(err error) {
	s.mu.Lock()
	if s.dead != nil {
		s.mu.Unlock()
		return
	}
	s.dead = err
	close(s.done)
	s.mu.Unlock()
	_ = s.conn.Close()
}

// read is the stream's single reader: it pulls length-prefixed responses and
// delivers each to the waiter registered under its ID. An unmatched ID is dropped
// (a late answer whose waiter has already given up), never guessed at.
func (s *dnsStream) read() {
	for {
		// The read deadline doubles as the idle timer: nothing has arrived for a whole
		// idle period, so the stream is torn down and the next query dials a new one.
		_ = s.conn.SetReadDeadline(time.Now().Add(s.idle))
		var lenBuf [2]byte
		if n, err := readFull(s.conn, lenBuf[:]); err != nil {
			if isTimeout(err) && n == 0 {
				if s.failIfIdle() {
					return
				}
				// Queries are in flight, so this is not idleness and the idle clock has no
				// business killing the stream: their own deadlines govern, and a query that
				// times out with nothing received since it was written abandons the stream.
				continue
			}
			s.fail(fmt.Errorf("%w: read length: %v", errUpstreamBroken, err))
			return
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := readFull(s.conn, resp); err != nil {
			s.fail(fmt.Errorf("%w: read body: %v", errUpstreamBroken, err))
			return
		}
		if len(resp) < 12 {
			s.fail(fmt.Errorf("%w: %d-byte response (shorter than a DNS header)", errUpstreamBroken, len(resp)))
			return
		}
		s.deliver(binary.BigEndian.Uint16(resp[:2]), resp)
	}
}

// failIfIdle tears the stream down as idle if, and only if, nothing is in flight,
// checking and marking under one lock so a query cannot register in between. A query
// that was handed this stream just before still loses the race at register, and gets
// errUpstreamIdle, which is retryable.
func (s *dnsStream) failIfIdle() bool {
	s.mu.Lock()
	if s.dead != nil || len(s.waiters) != 0 {
		s.mu.Unlock()
		return s.dead != nil
	}
	s.dead = errUpstreamIdle
	close(s.done)
	s.mu.Unlock()
	_ = s.conn.Close()
	return true
}

func (s *dnsStream) deliver(id uint16, resp []byte) {
	s.mu.Lock()
	s.lastRecv = time.Now()
	ch, ok := s.waiters[id]
	if ok {
		delete(s.waiters, id)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- resp:
	default:
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readFull is io.ReadFull with the error wrapped as-is; it exists so the read loop
// above reads the same way for both halves of a frame.
func readFull(conn net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
