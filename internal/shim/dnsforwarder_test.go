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
// the path glibc's `use-vc` clients take (egress UDP is dropped by the ruleset).
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

// TestForwarder_FailsClosedWhenProxyDown asserts fail-closed: proxy unreachable
// means NO answer (never a local/plaintext fallback).
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
	if _, err := conn.Write(buildAQuery(uniqueName)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("got a DNS answer with the proxy down; want fail-closed (no answer)")
	}
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
