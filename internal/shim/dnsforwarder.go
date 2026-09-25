package shim

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// The DNS half of the shim: a DNS-to-SOCKS-TCP bridge, mirrored from netcage's
// internal/dnsforwarder (same leak-proof seam). DNS through a SOCKS proxy is a
// CLIENT-SIDE UDP->TCP conversion, NEVER a UDP datagram to the proxy (Tor and
// most socks5h endpoints accept no UDP). So the forwarder accepts the account's
// ordinary DNS query and resolves it over the endpoint via TCP: a SOCKS CONNECT
// to an upstream resolver addressed BY HOSTNAME (resolved proxy-side, i.e.
// socks5h), carrying DNS-over-TCP framing. The query never leaves the box in
// plaintext, the host resolver never sees the name, and if the endpoint cannot
// answer, the client gets a SERVFAIL naming why (fail-closed, no host fallback,
// and never silence: see answer below).
//
// WHY BOTH LISTENERS. UDP is what every stub resolver sends by default, glibc as
// much as musl (the reporting host's glibc queries over UDP; its resolv.conf has no
// `use-vc`), and the account's nft redirect carries `udp dport 53` here. TCP is not
// optional either, for two reasons that do not depend on the host: RFC 7766 makes TCP
// support mandatory for DNS servers because a client RETRIES OVER TCP when a UDP
// answer comes back truncated, and a host configured with `options use-vc` (the
// netcage recipe this is mirrored from, where UDP egress was dropped) sends
// everything over TCP. A UDP-only forwarder would leave either client with EAI_AGAIN.
//
// WHY THE ISOLATION USERNAME ON EVERY DIAL. The per-account `<account>@` username
// (Tor IsolateSOCKSAuth) is what puts this account's DNS in the SAME circuit class
// as its own TCP (the relay dials with the same username) and in a DIFFERENT one from
// every other account's. Without it, two accounts' lookups could share a circuit, and
// a shared circuit is a link between them that no amount of per-account forcing
// undoes.

// DefaultDNSExchangeTimeout bounds ONE attempt at an upstream DNS exchange, dial
// included, and its EXPIRY IS REPORTED rather than dropped (dnsfailure.go).
//
// WHY IT WAS 5s AND WHY THAT WAS WRONG (telemaque, 0.9.0, work/notes/observations/dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance.md).
// A forced lookup there, measured inside the account's session, had a ~2.2s median
// and a 3.6s warm-path maximum. How much of that the forwarder's own exchange accounts
// for is not established, but a deadline of 5s within sight of a 3.6s WARM sample
// leaves a cold circuit build little room. Worse, it fired SILENTLY, which produced
// exactly the shape that sent an operator to nft and conntrack (`dns-forced-path-answers`
// red with "the shim ANSWERED and the answer never arrived"), for an event inside
// anonctl's own forwarder. Measured against the 0.9.0 binary through an endpoint that
// accepts a connection and then goes quiet: the client got nothing at all and the
// shim logged nothing either.
//
// WHY 10s NOW. The per-query cost this deadline used to govern was a circuit connect
// PLUS an exchange, paid for every name; with the stream held open (dnsupstream.go)
// the connect is paid once per idle period, so the deadline can afford room for the
// one legitimately slow case left, a cold circuit build, without that room being
// spent per name. It stays well inside DNSProbeTimeout, which verify sizes from it.
// Note what a client does meanwhile: glibc's own per-query timeout is 5s, so a client
// may retry before this fires, and that retry rides the SAME stream rather than
// starting another circuit connect.
const DefaultDNSExchangeTimeout = 10 * time.Second

// DefaultDNSUpstreamIdle is how long a stream with nothing in flight is held open
// before the forwarder tears it down. See dnsupstream.go for the tradeoff.
const DefaultDNSUpstreamIdle = 30 * time.Second

// dnsTCPClientIdle is how long a CLIENT's DNS-over-TCP connection is held with
// nothing asked on it. It is about this loopback connection only, not about the
// endpoint, and it is short because a TCP client (a truncation retry, or glibc under
// `use-vc`) opens a connection per lookup:
// a held-open idle client connection costs a goroutine and buys nothing.
const dnsTCPClientIdle = 10 * time.Second

// ForwarderConfig configures the DNS-over-SOCKS-TCP forwarder.
type ForwarderConfig struct {
	// Listen is the loopback address to serve DNS on (the account's per-account
	// DNS port the nft redirect points at), e.g. "127.0.0.1:19053".
	Listen string
	// ProxyAddr is the SOCKS5 endpoint host:port queries are tunnelled through
	// (e.g. the Tor SocksPort).
	ProxyAddr string
	// ProxyAuth carries the per-account isolation username (`<account>@`, empty
	// password) so the endpoint isolates this account (Tor IsolateSOCKSAuth). Nil
	// for a plain socks-peruser endpoint that needs no username.
	ProxyAuth *proxy.Auth
	// Upstream is the DNS resolver addressed BY HOSTNAME so the proxy resolves it
	// (socks5h), reached as DNS-over-TCP. Defaults to a public resolver name.
	Upstream string
	// ExchangeTimeout bounds one upstream attempt (the dial plus the exchange); zero
	// means DefaultDNSExchangeTimeout. IdleTimeout is how long an idle upstream stream
	// is held open; zero means DefaultDNSUpstreamIdle. The shim leaves both at their
	// defaults: they are settable so the unit suite can drive the expiry and idle paths
	// in milliseconds, PER FORWARDER rather than through a package var, because a
	// forwarder's goroutines outlive the test that started it and a shared knob is a
	// data race (found by `go test -race`).
	ExchangeTimeout time.Duration
	IdleTimeout     time.Duration
	// NoCache disables the per-account answer cache (dnscache.go). The shim leaves it
	// off (so the cache is ON); it exists so a test can assert what happens on a path
	// with no cache in the way, and so an operator-facing switch has somewhere to land
	// if the cache's timing side channel ever matters more than the latency.
	NoCache bool
}

// Forwarder is a running DNS-to-SOCKS-TCP bridge, serving UDP and TCP.
type Forwarder struct {
	cfg    ForwarderConfig
	pc     net.PacketConn
	ln     net.Listener
	dialer proxy.Dialer
	up     *dnsUpstream
	cache  *dnsCache
}

// StartForwarder binds the UDP and TCP listeners and serves in the background
// until ctx is done. Both listeners are required (see WHY BOTH LISTENERS above).
func StartForwarder(ctx context.Context, cfg ForwarderConfig) (*Forwarder, error) {
	if cfg.Upstream == "" {
		cfg.Upstream = "1.1.1.1:53"
	}
	if cfg.ExchangeTimeout <= 0 {
		cfg.ExchangeTimeout = DefaultDNSExchangeTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultDNSUpstreamIdle
	}
	// The forward dialer is proxy.Direct in all but one respect: a failure to reach the
	// endpoint's own address is TAGGED, so a dead anonymizer can be reported as such and
	// not as a slow one (dnsfailure.go).
	dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, cfg.ProxyAuth, reachabilityDialer{})
	if err != nil {
		return nil, fmt.Errorf("dns forwarder: build SOCKS5 dialer: %w", err)
	}
	pc, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("dns forwarder: listen udp %s: %w", cfg.Listen, err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("dns forwarder: listen tcp %s: %w", cfg.Listen, err)
	}
	f := &Forwarder{cfg: cfg, pc: pc, ln: ln, dialer: dialer}
	// The upstream stream is per-FORWARDER, and the shim is per-account, so it is
	// per-account by construction: nothing here is shared between accounts, and the
	// dial below carries this account's isolation username on every dial and re-dial.
	f.up = &dnsUpstream{dial: f.dialUpstream, exchangeTimeout: cfg.ExchangeTimeout, idle: cfg.IdleTimeout}
	if !cfg.NoCache {
		// Per-account by construction: a field of this forwarder, in this account's own
		// shim process, never written to disk and gone when the process ends. See
		// dnscache.go for what it holds and for the timing side channel it creates.
		f.cache = newDNSCache()
	}
	go f.serveUDP()
	go f.serveTCP()
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		_ = ln.Close()
		f.up.close()
	}()
	return f, nil
}

// dialUpstream opens ONE SOCKS stream to the upstream resolver. It is the only way
// out of this file, which is what makes fail-closed structural: there is no code
// path from a query to any resolver other than this dial, so a dead endpoint can
// only ever produce a failure, never a plaintext lookup.
//
// The context bound is load-bearing and it was missing: proxy.SOCKS5 is built over
// proxy.Direct, which has NO timeout, so an endpoint that accepted the TCP
// connection and then went quiet parked the query with no deadline to fire.
func (f *Forwarder) dialUpstream(ctx context.Context) (net.Conn, error) {
	if cd, ok := f.dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", f.cfg.Upstream)
	}
	return f.dialer.Dial("tcp", f.cfg.Upstream)
}

// Addr returns the bound UDP address.
func (f *Forwarder) Addr() string { return f.pc.LocalAddr().String() }

// TCPAddr returns the bound TCP address.
func (f *Forwarder) TCPAddr() string { return f.ln.Addr().String() }

// Close stops the forwarder, including its upstream stream: without that, the
// stream and its reader outlived Close until their idle timeout.
func (f *Forwarder) Close() error {
	err := f.pc.Close()
	if e := f.ln.Close(); e != nil && err == nil {
		err = e
	}
	f.up.close()
	return err
}

func (f *Forwarder) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			resp, ok := f.answer(query)
			if !ok {
				return
			}
			_, _ = f.pc.WriteTo(resp, addr)
		}()
	}
}

// serveTCP accepts DNS-over-TCP connections (RFC 7766), each carrying one or more
// 2-byte-length-prefixed queries: truncation retries and `use-vc` clients.
func (f *Forwarder) serveTCP() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handleTCPConn(conn)
	}
}

func (f *Forwarder) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	for {
		// TWO DIFFERENT DEADLINES, and conflating them was a bug worth naming. This one is
		// how long an IDLE client connection is held while nothing is asked on it (RFC 7766
		// leaves it to the server, and glibc opens a connection per lookup anyway). The
		// per-query one below is how long the ANSWER may take. They used to be one 5s
		// deadline covering both, which meant an upstream attempt allowed to run longer than
		// 5s would have its answer written to a connection whose deadline had already
		// expired: the client got a bare close instead of the answer or the SERVFAIL.
		_ = conn.SetDeadline(time.Now().Add(dnsTCPClientIdle))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return // EOF or timeout: done with this connection
		}
		query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(f.cfg.ExchangeTimeout + 2*time.Second))
		resp, ok := f.answer(query)
		if !ok {
			return
		}
		framed := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(resp)))
		copy(framed[2:], resp)
		if _, err := conn.Write(framed); err != nil {
			return
		}
	}
}

// answer is the one place a query becomes a reply, for BOTH listeners, so the UDP leg
// and the TCP leg (truncation retries, `use-vc` clients) cannot drift apart on the
// rule that matters: an upstream failure is a SERVFAIL with a logged, classified
// reason, and never an answer from anywhere else.
//
// FAIL-CLOSED, AND SAID OUT LOUD. There is no host-resolver fallback here and never
// may be. What changed is that the client is TOLD, instead of discovering the failure
// by waiting out its own timeout on a query nobody will ever answer (the UDP leg used
// to emit nothing; the TCP leg used to close the connection, which reaches glibc as a
// reasonless try-again). ok=false only for a message too short to answer at all.
func (f *Forwarder) answer(query []byte) ([]byte, bool) {
	resp, err := f.resolveViaSOCKS(query)
	if err == nil {
		return resp, true
	}
	kind := classifyDNSFailure(err)
	log.Printf("dns: %s (SERVFAIL, fail-closed)", kind.logReason(f.cfg.ProxyAddr, f.cfg.Upstream, err))
	return servfail(query, kind)
}

// resolveViaSOCKS answers a DNS message from this account's cache, or forwards it to
// the upstream resolver over the account's persistent, pipelined DNS-over-TCP stream
// (dnsupstream.go), dialling one when there is none.
//
// FAIL-CLOSED, INCLUDING ON A CACHE MISS. The only route to an answer other than the
// cache is the SOCKS dial, and the cache is only ever filled from an answer that
// came back through it. So a miss with a dead endpoint yields a failure, never a
// lookup that leaves the box in the clear, and there is no host-resolver path in
// this file to fall back to even if something wanted one.
func (f *Forwarder) resolveViaSOCKS(query []byte) ([]byte, error) {
	if f.cache != nil {
		if resp, ok := f.cache.get(query); ok {
			return resp, nil
		}
	}
	resp, err := f.up.exchange(query)
	if err != nil {
		return nil, err
	}
	if f.cache != nil {
		f.cache.put(query, resp)
	}
	return resp, nil
}
