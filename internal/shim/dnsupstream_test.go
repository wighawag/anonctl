package shim

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/socks5hfixture"
	"golang.org/x/net/proxy"
)

// The upstream stream's tests: one persistent, pipelined DNS-over-TCP connection per
// account (dnsupstream.go). The properties asserted are the ones connection reuse
// could plausibly break: answers delivered to the wrong waiter, a dead stream costing
// a client its query, a stream held forever, and a re-dial that forgets the account's
// isolation username.

// TestForwarder_ReusesOneStreamForManyQueriesWithInterleavedIDs is the hardest
// property of connection reuse, so it is asserted directly rather than inferred
// from a faster median: several queries are outstanding on ONE pipelined
// DNS-over-TCP connection, the upstream answers them OUT OF ORDER (RFC 7766 allows
// exactly that), and BOTH clients use the SAME DNS message ID, which is legal and
// which a shared connection would otherwise confuse.
//
// If IDs were not rewritten per stream, this test is how you would find out: the
// two answers would be interchangeable and each client could be handed the other's.
func TestForwarder_ReusesOneStreamForManyQueriesWithInterleavedIDs(t *testing.T) {
	const nameA, nameB = "a.anonctl.test", "b.anonctl.test"
	res := startPipelinedResolver(t, resolverOptions{
		answers:     map[string]string{nameA: "203.0.113.11", nameB: "203.0.113.22"},
		batch:       2, // hold two queries, then answer the SECOND one first
		answerFirst: false,
	})
	fwd := startForwarderVia(t, res, ForwarderConfig{})

	type got struct {
		name string
		ip   string
	}
	results := make(chan got, 2)
	for _, name := range []string{nameA, nameB} {
		go func(name string) {
			// buildAQuery uses a FIXED id (0x1234) for every query, so both of these carry the
			// same client-side ID: the collision is the point.
			results <- got{name, queryAWithTimeout(t, fwd.Addr(), name, 5*time.Second)}
		}(name)
	}
	want := map[string]string{nameA: "203.0.113.11", nameB: "203.0.113.22"}
	for i := 0; i < 2; i++ {
		g := <-results
		if g.ip != want[g.name] {
			t.Fatalf("%s resolved to %q, want %q: an answer was delivered to the wrong waiter", g.name, g.ip, want[g.name])
		}
	}
	if n := res.connCount(); n != 1 {
		t.Fatalf("upstream saw %d connections for 2 queries; want 1 reused stream (RFC 7766 pipelining)", n)
	}

	// And a later query still rides the SAME stream rather than paying another circuit
	// connect, which is the whole point of the change.
	if ip := queryAWithTimeout(t, fwd.Addr(), nameA, 5*time.Second); ip != want[nameA] {
		t.Fatalf("third query resolved %s to %q, want %q", nameA, ip, want[nameA])
	}
	if n := res.connCount(); n != 1 {
		t.Fatalf("upstream saw %d connections for 3 queries; want 1 reused stream", n)
	}
}

// TestForwarder_RedialsAfterThePeerClosesTheStream covers the cost of holding a
// connection open: the peer can close it at any time (RFC 7766 lets either end,
// and an idle Tor stream will), and the close is frequently only observable when we
// write into it. A client must not lose a query to that, so the forwarder re-dials
// once and the second query is answered on the new stream.
func TestForwarder_RedialsAfterThePeerClosesTheStream(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{
		answers:         map[string]string{uniqueName: answerIP},
		closeAfterFirst: true,
	})
	fwd := startForwarderVia(t, res, ForwarderConfig{})

	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("first query resolved to %q, want %q", ip, answerIP)
	}
	// Let the peer's close land, so the next query finds a stream that looks live and
	// is not: the exact case the re-dial exists for.
	time.Sleep(150 * time.Millisecond)
	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("query after the peer closed the stream resolved to %q, want %q (the re-dial did not happen)", ip, answerIP)
	}
	if n := res.connCount(); n != 2 {
		t.Fatalf("upstream saw %d connections; want 2 (one, then one re-dial)", n)
	}
}

// TestForwarder_ClosesAnIdleStreamAndDialsAgain asserts the other half of holding a
// connection open: it is not held forever. After an idle period the stream is torn
// down, and the next query dials a fresh one and is answered.
func TestForwarder_ClosesAnIdleStreamAndDialsAgain(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{answers: map[string]string{uniqueName: answerIP}})
	const idle = 200 * time.Millisecond
	fwd := startForwarderVia(t, res, ForwarderConfig{IdleTimeout: idle})

	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("first query resolved to %q, want %q", ip, answerIP)
	}
	deadline := time.Now().Add(3 * time.Second)
	for res.openConns() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if res.openConns() != 0 {
		t.Fatalf("the idle stream was still open well past the %s idle timeout; it must not be held forever", idle)
	}
	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("query after the idle close resolved to %q, want %q", ip, answerIP)
	}
	if n := res.connCount(); n != 2 {
		t.Fatalf("upstream saw %d connections; want 2 (one, then one after the idle close)", n)
	}
}

// TestForwarder_ReusedStreamStillCarriesTheIsolationUsername keeps the property the
// reuse could quietly have broken: the account's DNS shares ITS OWN circuit class,
// which is what the `<account>@` isolation username buys (Tor IsolateSOCKSAuth).
// Fewer dials must not mean an unauthenticated one, and the RE-DIAL is the dial
// most likely to lose it, so both are checked.
func TestForwarder_ReusedStreamStillCarriesTheIsolationUsername(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{
		answers:         map[string]string{uniqueName: answerIP},
		closeAfterFirst: true,
	})
	fx := socks5hfixture.New(socks5hfixture.Options{
		RequireAuth:    true,
		KnownHosts:     map[string]string{upstreamName: hostOf(res.addr())},
		RedirectTarget: res.addr(),
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	t.Cleanup(func() { fx.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    "127.0.0.1:0",
		ProxyAddr: fx.Addr(),
		ProxyAuth: &proxy.Auth{User: "anon-01"},
		Upstream:  upstreamName + ":53",
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second)
	time.Sleep(150 * time.Millisecond) // let the peer's close land, forcing the re-dial
	queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second)

	users := fx.AuthUsernames()
	if len(users) < 2 {
		t.Fatalf("expected the re-dial to authenticate too; usernames seen: %v", users)
	}
	for i, u := range users {
		if u != "anon-01" {
			t.Fatalf("dial %d carried username %q, want the per-account isolation username %q", i, u, "anon-01")
		}
	}
}

// ---- in-test PIPELINED DNS-over-TCP resolver (RFC 7766), for reuse assertions ----

// resolverOptions configures pipelinedResolver.
type resolverOptions struct {
	// answers maps a queried name to the A record to return. An unknown name gets
	// NXDOMAIN, which is a perfectly good answer.
	answers map[string]string
	// batch holds the FIRST this-many queries on a connection before answering any of
	// them, which is how a test puts several queries in flight at once. Later queries
	// on the same connection are answered one at a time.
	batch int
	// answerFirst answers a held batch in arrival order; false answers it in REVERSE
	// order, so a correct forwarder must match answers to waiters by ID and not by
	// arrival.
	answerFirst bool
	// closeAfterFirst makes the resolver hang up after answering one query on a
	// connection, the way an upstream or a Tor exit reaps a stream.
	closeAfterFirst bool
}

type pipelinedResolver struct {
	opts resolverOptions
	ln   net.Listener

	mu     sync.Mutex
	conns  int
	open   int
	seened []string
}

func startPipelinedResolver(t *testing.T, opts resolverOptions) *pipelinedResolver {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pipelined resolver listen: %v", err)
	}
	r := &pipelinedResolver{opts: opts, ln: ln}
	t.Cleanup(func() { ln.Close() })
	go r.accept()
	return r
}

func (r *pipelinedResolver) addr() string { return r.ln.Addr().String() }

func (r *pipelinedResolver) connCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns
}

func (r *pipelinedResolver) openConns() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.open
}

func (r *pipelinedResolver) accept() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.conns++
		r.open++
		r.mu.Unlock()
		go r.serve(c)
	}
}

func (r *pipelinedResolver) serve(c net.Conn) {
	defer func() {
		c.Close()
		r.mu.Lock()
		r.open--
		r.mu.Unlock()
	}()
	var held [][]byte
	batch := r.opts.batch
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		name := decodeName(msg[12:])
		r.mu.Lock()
		r.seened = append(r.seened, name)
		r.mu.Unlock()
		held = append(held, msg)
		if batch > 1 && len(held) < batch {
			continue // keep it in flight: the point is several outstanding at once
		}
		batch = 1 // the batch is served; later queries are answered as they arrive
		if !r.opts.answerFirst {
			for i, j := 0, len(held)-1; i < j; i, j = i+1, j-1 {
				held[i], held[j] = held[j], held[i]
			}
		}
		for _, q := range held {
			resp := r.answer(q)
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
			copy(out[2:], resp)
			if _, err := c.Write(out); err != nil {
				return
			}
		}
		held = nil
		if r.opts.closeAfterFirst {
			return
		}
	}
}

// answer renders a response for one query: the A record configured for that name,
// or NXDOMAIN. The query's ID is echoed, which is what the forwarder matches on.
func (r *pipelinedResolver) answer(query []byte) []byte {
	name := decodeName(query[12:])
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x80
	ip, ok := r.opts.answers[strings.ToLower(strings.TrimSuffix(name, "."))]
	if !ok {
		resp[3] = 0x83 // NXDOMAIN
		return resp
	}
	resp[6], resp[7] = 0, 1
	ans := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ans = append(ans, net.ParseIP(ip).To4()...)
	return append(resp, ans...)
}

// startForwarderVia starts a forwarder whose endpoint is a fixture pointed at the
// given resolver, the shape every reuse test needs.
func startForwarderVia(t *testing.T, res *pipelinedResolver, cfg ForwarderConfig) *Forwarder {
	t.Helper()
	fx := socks5hfixture.New(socks5hfixture.Options{
		KnownHosts:     map[string]string{upstreamName: hostOf(res.addr())},
		RedirectTarget: res.addr(),
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	t.Cleanup(func() { fx.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg.Listen = "127.0.0.1:0"
	cfg.ProxyAddr = fx.Addr()
	cfg.ProxyAuth = &proxy.Auth{User: "anon"}
	cfg.Upstream = upstreamName + ":53"
	fwd, err := StartForwarder(ctx, cfg)
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	t.Cleanup(func() { fwd.Close() })
	return fwd
}

func queryAWithTimeout(t *testing.T, forwarder, name string, timeout time.Duration) string {
	t.Helper()
	conn, err := net.Dial("udp", forwarder)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildAQuery(name)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read answer (DNS did not resolve through the proxy): %v", err)
	}
	return parseFirstA(buf[:n])
}
