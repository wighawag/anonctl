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
}

// Forwarder is a running DNS-to-SOCKS-TCP bridge, serving UDP and TCP.
type Forwarder struct {
	cfg    ForwarderConfig
	pc     net.PacketConn
	ln     net.Listener
	dialer proxy.Dialer
}

// StartForwarder binds the UDP and TCP listeners and serves in the background
// until ctx is done. Both listeners are required (UDP for musl clients, TCP for
// glibc `use-vc` clients).
func StartForwarder(ctx context.Context, cfg ForwarderConfig) (*Forwarder, error) {
	if cfg.Upstream == "" {
		cfg.Upstream = "1.1.1.1:53"
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
	go f.serveUDP()
	go f.serveTCP()
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		_ = ln.Close()
	}()
	return f, nil
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

// resolveViaSOCKS forwards a DNS message to the upstream resolver over a SOCKS5
// TCP connection using DNS-over-TCP framing (RFC 1035 2-byte length prefix). The
// dial carries the isolation username; if the endpoint is unreachable it returns
// an error and the caller drops the query (fail-closed).
func (f *Forwarder) resolveViaSOCKS(query []byte) ([]byte, error) {
	conn, err := f.dialer.Dial("tcp", f.cfg.Upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
