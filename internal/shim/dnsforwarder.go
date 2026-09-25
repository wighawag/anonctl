package shim

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
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
// plaintext, the host resolver never sees the name, and if the endpoint is down
// the query is dropped (fail-closed, no host fallback).
//
// It serves on BOTH UDP and TCP. TCP is load-bearing: with egress UDP dropped by
// the nft ruleset, resolv.conf carries `options use-vc` and glibc's getaddrinfo
// then queries over TCP (RFC 7766); a UDP-only forwarder would leave glibc
// clients with EAI_AGAIN. The per-account `<account>@` isolation username is
// carried on the dial via ProxyAuth (the Tor IsolateSOCKSAuth knob), the same
// username the relay uses, so the account's DNS shares its circuit class.

// DefaultDNSExchangeTimeout bounds ONE attempt at an upstream DNS exchange, dial
// included (the dial used to have no bound at all; see dialUpstream).
//
// MEASURED SHAPE OF ITS EXPIRY (telemaque, 0.9.0, work/notes/observations/dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance.md):
// the expiry is SILENT. resolveViaSOCKS returns an error, both serve loops drop the
// query fail-closed, and the client is left waiting out its own timeout with nothing
// to tell it why; the shim logs nothing either. Confirmed against the released 0.9.0
// binary through an endpoint that accepts a connection and then goes quiet. That is
// the same observable a verify probe reports as "the shim answered and the answer
// never arrived", for an event inside this forwarder. On that host a forced lookup,
// measured inside the account's session, had a ~2.2s median and a 3.6s warm-path
// maximum, so this deadline sits within sight of a warm sample and leaves a cold
// circuit build little room. TestForwarder_ExchangeDeadlineExpiryIsSilent pins the
// shape before anything changes it.
const DefaultDNSExchangeTimeout = 5 * time.Second

// DefaultDNSUpstreamIdle is how long a stream with nothing in flight is held open
// before the forwarder tears it down. See dnsupstream.go for the tradeoff.
const DefaultDNSUpstreamIdle = 30 * time.Second

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
// until ctx is done. Both listeners are required (UDP for musl clients, TCP for
// glibc `use-vc` clients).
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
	dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, cfg.ProxyAuth, proxy.Direct)
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

// Close stops the forwarder.
func (f *Forwarder) Close() error {
	err := f.pc.Close()
	if e := f.ln.Close(); e != nil && err == nil {
		err = e
	}
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
			resp, err := f.resolveViaSOCKS(query)
			if err != nil {
				return // fail-closed: drop, never fall back to a host resolver
			}
			_, _ = f.pc.WriteTo(resp, addr)
		}()
	}
}

// serveTCP accepts DNS-over-TCP connections (RFC 7766), each carrying one or more
// 2-byte-length-prefixed queries. Required for glibc `use-vc` clients.
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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return // EOF or timeout: done with this connection
		}
		query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp, err := f.resolveViaSOCKS(query)
		if err != nil {
			return // fail-closed: drop, never fall back
		}
		framed := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(resp)))
		copy(framed[2:], resp)
		if _, err := conn.Write(framed); err != nil {
			return
		}
	}
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
