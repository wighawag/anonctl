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
// stream open for less wall time. The default is comfortably longer than one
// exchange deadline, so a stream is never reaped from under a query still waiting.

// errUpstreamBroken marks a CONNECTION-level failure (write error, EOF, a short or
// unreadable frame): the stream is unusable and the query may be retried once on a
// fresh one. It is deliberately distinct from a deadline expiry, which says
// nothing is wrong with the connection and must NOT be retried behind the client's
// back: the client asked for an answer within a bounded window, and quietly
// spending a second window is how a bounded wait becomes an unbounded one.
var errUpstreamBroken = errors.New("dns upstream: stream broken")

// errUpstreamTimeout marks the exchange deadline firing: the query was written and
// no answer arrived in time. It is kept distinct from errUpstreamBroken because the
// two mean different things to an operator (a slow circuit, not a dead stream), and
// because it is never retried here.
var errUpstreamTimeout = errors.New("dns upstream: exchange deadline expired")

// errUpstreamIdle marks the idle teardown, which is a normal, healthy end of life
// for a stream and never reaches a client: any waiter has long since been answered
// or timed out.
var errUpstreamIdle = errors.New("dns upstream: closed after idle")

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

	mu  sync.Mutex
	cur *dnsStream
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
		s, fresh, err := u.stream(deadline)
		if err != nil {
			return nil, err
		}
		resp, rerr := s.roundTrip(query, deadline)
		if rerr == nil {
			return resp, nil
		}
		u.retire(s)
		// RE-DIAL ONCE, and only for the case that actually needs it: a stream we found
		// already open turned out to be dead. An idle DNS-over-TCP connection is closed by
		// the peer routinely (RFC 7766 lets either end do it, and a Tor exit will), and the
		// close is often only observable when we write into it, so without this retry every
		// such close would cost one client a dropped query.
		if attempt == 0 && !fresh && errors.Is(rerr, errUpstreamBroken) && time.Now().Before(deadline) {
			continue
		}
		return nil, rerr
	}
}

// stream returns the live stream, or dials a new one. It reports whether the
// stream is FRESH (dialled by this call), which is what makes the re-dial above
// safe: retrying on a stream we just created would retry a real failure.
//
// The dial happens under the mutex on purpose: a burst of queries (getaddrinfo's
// A and AAAA, a page load's worth of names) then pays for ONE circuit connect and
// pipelines the rest onto it, instead of racing N connects.
func (u *dnsUpstream) stream(deadline time.Time) (*dnsStream, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cur != nil && u.cur.live() {
		return u.cur, false, nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	conn, err := u.dial(ctx)
	if err != nil {
		u.cur = nil
		return nil, false, err
	}
	s := newDNSStream(conn, u.idle)
	u.cur = s
	return s, true, nil
}

// retire drops a stream if it is still the current one, so the next query dials.
func (u *dnsUpstream) retire(s *dnsStream) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cur == s {
		u.cur = nil
	}
}

// close tears down the live stream (shim shutdown).
func (u *dnsUpstream) close() {
	u.mu.Lock()
	s := u.cur
	u.cur = nil
	u.mu.Unlock()
	if s != nil {
		s.fail(errUpstreamIdle)
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
}

func newDNSStream(conn net.Conn, idle time.Duration) *dnsStream {
	s := &dnsStream{
		conn:    conn,
		idle:    idle,
		waiters: make(map[uint16]chan []byte),
		done:    make(chan struct{}),
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
	s.wmu.Unlock()
	if werr != nil {
		s.fail(fmt.Errorf("%w: write: %v", errUpstreamBroken, werr))
		return nil, s.reason()
	}

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case resp := <-ch:
		// Hand the client back its OWN message ID: the one on the wire was this stream's.
		copy(resp[:2], query[:2])
		return resp, nil
	case <-s.done:
		return nil, s.reason()
	case <-timer.C:
		// An upstream that accepted a query and did not answer it inside the window is
		// not a connection worth keeping: tear it down so the next query starts clean
		// rather than pipelining onto a stream that has stopped answering.
		s.fail(fmt.Errorf("%w", errUpstreamTimeout))
		return nil, errUpstreamTimeout
	}
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
		if _, err := readFull(s.conn, lenBuf[:]); err != nil {
			if isTimeout(err) && s.idleOnly() {
				s.fail(errUpstreamIdle)
				return
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

// idleOnly reports that nothing is in flight, which is what makes a read timeout
// an idle teardown rather than an upstream that stopped answering.
func (s *dnsStream) idleOnly() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.waiters) == 0
}

func (s *dnsStream) deliver(id uint16, resp []byte) {
	s.mu.Lock()
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
