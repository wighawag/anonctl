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

const uniqueName = "unique.anonctl.test"
const upstreamName = "dns.anonctl.test"
const answerIP = "203.0.113.55"

// TestForwarder_ResolvesThroughProxyWithIsolationUsername proves the leak-proof
// DNS half: a UDP query to the forwarder is resolved over the SOCKS proxy via
// TCP (socks5h, upstream addressed by NAME so the proxy resolves it), the
// proxy-side resolver answers, and the dial carried the per-account isolation
// username. No host resolver is consulted.
func TestForwarder_ResolvesThroughProxyWithIsolationUsername(t *testing.T) {
	resolver := startDNSOverTCP(t)

	fx := socks5hfixture.New(socks5hfixture.Options{
		RequireAuth:    true,
		KnownHosts:     map[string]string{upstreamName: hostOf(resolver.addr)},
		RedirectTarget: resolver.addr,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    "127.0.0.1:0",
		ProxyAddr: fx.Addr(),
		ProxyAuth: &proxy.Auth{User: "anon"},
		Upstream:  upstreamName + ":53", // resolved proxy-side (socks5h)
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	ip := queryA(t, fwd.Addr(), uniqueName)
	if ip != answerIP {
		t.Fatalf("resolved %s to %q, want %q (proxy-side answer)", uniqueName, ip, answerIP)
	}
	if !resolver.saw(uniqueName) {
		t.Fatalf("proxy-side resolver never saw %q; it did not resolve through the proxy", uniqueName)
	}
	// The upstream resolver name was resolved PROXY-SIDE (socks5h), not locally.
	if !containsFold(fx.ResolvedHosts(), upstreamName) {
		t.Fatalf("proxy never resolved %q; upstream was not addressed by name (socks5h broken): %v", upstreamName, fx.ResolvedHosts())
	}
	// The dial carried the isolation username on the DNS path too.
	if u := fx.AuthUsernames(); len(u) == 0 || u[0] != "anon" {
		t.Fatalf("DNS dial usernames %v, want the isolation username %q", u, "anon")
	}
}

// TestForwarder_ResolvesOverTCP proves the TCP listener (RFC 7766 DNS-over-TCP),
// the path a truncation retry and a `use-vc` client take (see the forwarder's WHY
// BOTH LISTENERS).
func TestForwarder_ResolvesOverTCP(t *testing.T) {
	resolver := startDNSOverTCP(t)
	fx := socks5hfixture.New(socks5hfixture.Options{
		KnownHosts:     map[string]string{upstreamName: hostOf(resolver.addr)},
		RedirectTarget: resolver.addr,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    "127.0.0.1:0",
		ProxyAddr: fx.Addr(),
		Upstream:  upstreamName + ":53",
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	conn, err := net.Dial("tcp", fwd.TCPAddr())
	if err != nil {
		t.Fatalf("dial forwarder tcp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	q := buildAQuery(uniqueName)
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("write tcp query: %v", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read tcp resp length: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read tcp resp: %v", err)
	}
	if ip := parseFirstA(resp); ip != answerIP {
		t.Fatalf("TCP resolved %s to %q, want %q", uniqueName, ip, answerIP)
	}
	if !resolver.saw(uniqueName) {
		t.Fatalf("proxy-side resolver never saw %q over the TCP path", uniqueName)
	}
}

// TestForwarder_FailsClosedWhenProxyDown asserts the load-bearing property: with the
// endpoint unreachable, NOTHING RESOLVES. The query is not answered from the host
// resolver, from /etc/hosts, or from anywhere else, for any reason.
//
// What it no longer asserts is SILENCE, and the difference is deliberate: a failure
// the client can see (SERVFAIL, carrying no records) is not a fallback and discloses
// nothing, while silence was indistinguishable from a kernel-level drop and cost a
// real operator an hour in `nft`. So the assertion is about CONTENT: whatever comes
// back must carry no address and must not be a successful answer. The name asked for
// is one the HOST could resolve trivially, so a leak would be visible as an address
// rather than having to be inferred.
func TestForwarder_FailsClosedWhenProxyDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    "127.0.0.1:0",
		ProxyAddr: "127.0.0.1:1", // nothing listening
		Upstream:  upstreamName + ":53",
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	conn, err := net.Dial("udp", fwd.Addr())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buildAQuery("localhost")); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return // nothing at all is also fail-closed
	}
	resp := buf[:n]
	if ip := parseFirstA(resp); ip != "" {
		t.Fatalf("the endpoint was down and the forwarder answered with %q: that address can only have come from a local resolver, which is the leak this whole design exists to prevent", ip)
	}
	if rcode := resp[3] & 0x0F; rcode != 2 {
		t.Fatalf("rcode %d with the endpoint down; want 2 (SERVFAIL): anything else claims a result nobody produced", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Fatalf("the failure carried %d answer records; it must carry none", ancount)
	}

	// And an EDNS client is told WHY, in the words that tell the operator what to do:
	// the endpoint is down, not slow.
	edns, ok := rawMsg(t, fwd.Addr(), withEDNS(buildAQuery("localhost"), false), 2*time.Second)
	if !ok {
		t.Fatal("an EDNS client got nothing with the endpoint down")
	}
	if _, text, ok := ExtendedDNSError(edns); !ok || text != dnsFailEndpointUnreachable.token() {
		t.Fatalf("EDE %q (present=%v), want %q: a dead endpoint must be named as unreachable, not as slow", text, ok, dnsFailEndpointUnreachable.token())
	}
}

// TestForwarder_ExchangeDeadlineExpiryIsVisible pins the fix for the defect this work
// started from. When the upstream exchange outruns the deadline, the forwarder now
// answers SERVFAIL, immediately, carrying no records.
//
// WHAT IT USED TO DO, MEASURED. It emitted NOTHING: the query was dropped and the
// client waited out its own timeout with no signal, and the shim logged nothing
// either (confirmed against the released 0.9.0 binary through an endpoint that
// accepts a connection and then goes quiet). On the reporting host that produced
// `dns-forced-path-answers` red with "the shim ANSWERED and the answer never
// arrived", a message that asserts a conntrack un-NAT drop and sends the operator to
// `nft`, for an event inside anonctl's own forwarder. The upstream here is
// deliberately SILENT rather than slow, because what is under test is what the
// forwarder does when the deadline wins, not how long it waited.
func TestForwarder_ExchangeDeadlineExpiryIsVisible(t *testing.T) {
	silent := startSilentDNSOverTCP(t)
	fx := socks5hfixture.New(socks5hfixture.Options{
		KnownHosts:     map[string]string{upstreamName: hostOf(silent)},
		RedirectTarget: silent,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    "127.0.0.1:0",
		ProxyAddr: fx.Addr(),
		Upstream:  upstreamName + ":53",
		// The shape under test is deadline-INDEPENDENT (what the forwarder emits when the
		// deadline wins), so shrinking it encodes no production timing.
		ExchangeTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	conn, err := net.Dial("udp", fwd.Addr())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	// The client's window is far longer than the exchange deadline, so anything the
	// forwarder wanted to say about the expiry would have arrived by now.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buildAQuery(uniqueName)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	start := time.Now()
	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	if rerr != nil {
		t.Fatalf("the deadline expiry produced nothing (%v): an operator can only discover that by timing out, which is the defect this fixes", rerr)
	}
	resp := buf[:n]
	if rcode := resp[3] & 0x0F; rcode != 2 {
		t.Fatalf("rcode %d after a deadline expiry; want 2 (SERVFAIL)", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Fatalf("the failure carried %d answer records; it must carry none", ancount)
	}
	if id := binary.BigEndian.Uint16(resp[:2]); id != 0x1234 {
		t.Fatalf("the failure carried id %#04x, want the asker's own %#04x (a client discards anything else)", id, 0x1234)
	}
	// It must arrive when the deadline fires, not when the client gives up: the whole
	// point is that the client stops waiting.
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("the failure took %s to arrive on a 300ms deadline; a client cannot fail fast on that", waited)
	}

	edns, ok := rawMsg(t, fwd.Addr(), withEDNS(buildAQuery(uniqueName), false), 2*time.Second)
	if !ok {
		t.Fatal("an EDNS client got nothing after a deadline expiry")
	}
	if _, text, ok := ExtendedDNSError(edns); !ok || text != dnsFailDeadline.token() {
		t.Fatalf("EDE %q (present=%v), want %q: a slow circuit must be named as slow, not as a dead endpoint", text, ok, dnsFailDeadline.token())
	}
}

// TestForwarder_ItsOwnServfailIsNeverCached is the other direction of "never cache
// SERVFAIL": the forwarder's OWN failure (here a deadline expiry) must not be
// remembered, so the first query after the upstream recovers is answered for real.
// A cached "could not resolve" would outlive the outage that produced it.
func TestForwarder_ItsOwnServfailIsNeverCached(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{answers: map[string]string{uniqueName: answerIP}, ttl: 600, dropFirst: 1})
	fwd := startForwarderVia(t, res, ForwarderConfig{ExchangeTimeout: 300 * time.Millisecond})

	first, ok := rawQuery(t, fwd.Addr(), uniqueName, 3*time.Second)
	if !ok || first[3]&0x0F != 2 {
		t.Fatalf("the first query (upstream silent) should have produced SERVFAIL; got ok=%v", ok)
	}
	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("after the upstream recovered the name resolved to %q, want %q: the forwarder's own SERVFAIL was served from the cache", ip, answerIP)
	}
	if n := res.queryCount(); n != 2 {
		t.Fatalf("the upstream saw %d queries; want 2 (the failure must not have been cached)", n)
	}
}

// rawMsg sends an arbitrary pre-built message and returns whatever comes back.
func rawMsg(t *testing.T, forwarder string, msg []byte, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	conn, err := net.Dial("udp", forwarder)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// TestForwarder_TCPClientAlsoGetsAVisibleFailure covers the leg the forwarder's header
// explains is not optional (a truncation retry, or glibc under `use-vc`). That client
// used to get a bare connection close when the upstream exchange failed, which
// reaches getaddrinfo as a generic try-again with no reason attached. It must get the
// same SERVFAIL the UDP client gets, correctly length-prefixed.
func TestForwarder_TCPClientAlsoGetsAVisibleFailure(t *testing.T) {
	silent := startSilentDNSOverTCP(t)
	fx := socks5hfixture.New(socks5hfixture.Options{
		KnownHosts:     map[string]string{upstreamName: hostOf(silent)},
		RedirectTarget: silent,
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:          "127.0.0.1:0",
		ProxyAddr:       fx.Addr(),
		Upstream:        upstreamName + ":53",
		ExchangeTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	conn, err := net.Dial("tcp", fwd.TCPAddr())
	if err != nil {
		t.Fatalf("dial forwarder tcp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := buildAQuery(uniqueName)
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("write tcp query: %v", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("the TCP client got no answer at all (%v): a use-vc client must see the failure", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read tcp failure body: %v", err)
	}
	if rcode := resp[3] & 0x0F; rcode != 2 {
		t.Fatalf("TCP rcode %d, want 2 (SERVFAIL)", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Fatalf("the TCP failure carried %d answer records; it must carry none", ancount)
	}
}

// startSilentDNSOverTCP accepts DNS-over-TCP connections, reads the query and never
// answers: a stand-in for an upstream (or a circuit) slower than the deadline.
func startSilentDNSOverTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("silent resolver listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c) // held open, deliberately unanswered
		}
	}()
	return ln.Addr().String()
}

// ---- in-test DNS-over-TCP resolver + wire helpers (A only) ----

type dnsResolver struct {
	addr   string
	mu     sync.Mutex
	seened []string
}

func (r *dnsResolver) record(n string) { r.mu.Lock(); r.seened = append(r.seened, n); r.mu.Unlock() }
func (r *dnsResolver) saw(n string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seened {
		if strings.EqualFold(s, n) {
			return true
		}
	}
	return false
}

func startDNSOverTCP(t *testing.T) *dnsResolver {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns resolver listen: %v", err)
	}
	r := &dnsResolver{addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				name := decodeName(msg[12:])
				r.record(name)
				resp := buildAResponse(msg, name)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}(c)
		}
	}()
	return r
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func buildAQuery(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	msg = append(msg, encodeName(name)...)
	return append(msg, 0, 1, 0, 1)
}

func buildAResponse(query []byte, name string) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x80
	if !strings.EqualFold(name, uniqueName) {
		resp[3] = 0x83
		return resp
	}
	resp[6], resp[7] = 0, 1
	ans := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
	ans = append(ans, net.ParseIP(answerIP).To4()...)
	return append(resp, ans...)
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0)
}

func decodeName(b []byte) string {
	var parts []string
	for len(b) > 0 {
		l := int(b[0])
		if l == 0 || 1+l > len(b) {
			break
		}
		parts = append(parts, string(b[1:1+l]))
		b = b[1+l:]
	}
	return strings.Join(parts, ".")
}

func queryA(t *testing.T, forwarder, name string) string {
	t.Helper()
	conn, err := net.Dial("udp", forwarder)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
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

func parseFirstA(resp []byte) string {
	for i := 12; i+16 <= len(resp); i++ {
		if resp[i] == 0xc0 && resp[i+1] == 0x0c &&
			resp[i+2] == 0 && resp[i+3] == 1 &&
			resp[i+4] == 0 && resp[i+5] == 1 &&
			resp[i+10] == 0 && resp[i+11] == 4 {
			return net.IP(resp[i+12 : i+16]).String()
		}
	}
	return ""
}
