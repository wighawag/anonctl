// Package socks5hfixture is a controllable, in-process SOCKS5h proxy used as the
// deterministic test harness for anonctl's shim leak assertions. It is NOT a
// production proxy: it exists so the shim's tests can assert the leak-proof
// properties (a CONNECT reaches the proxy, the per-account isolation username
// arrives proxy-side, a killed proxy fails closed, a hostname is resolved
// proxy-side) WITHOUT depending on real Tor.
//
// It mirrors netcage's internal/socks5hfixture (same SOCKS5/RFC 1928 shape) but
// adds the two things anonctl's shim needs that netcage's did not:
//
//   - Username/password auth (RFC 1929), RECORDING every SOCKS username it was
//     offered (AuthUsernames). This is how a test proves the shim injects the
//     per-account `<account>@` isolation username (the Tor IsolateSOCKSAuth knob)
//     on BOTH the relay dial and the DNS-forwarder dial.
//   - IP-literal CONNECTs are accepted by default (AllowIPConnect defaults true),
//     because the transparent relay dials the ORIGINAL DESTINATION, which is an
//     IP (the kernel already redirected it), NOT a hostname. netcage's fixture
//     rejected IP CONNECTs to catch a local-resolution leak; the shim relay's
//     job is precisely to CONNECT by the recovered IP, so that rejection does
//     not apply to it.
//
// "socks5h" means remote (proxy-side) name resolution: a client may send the
// proxy a HOSTNAME (SOCKS5 ATYP=domain) which the proxy resolves. The DNS
// forwarder uses this path (it CONNECTs to an upstream resolver by NAME); the
// fixture records every resolved hostname (ResolvedHosts) so a test can prove a
// lookup arrived proxy-side and never at a host resolver.
package socks5hfixture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Options configures a Fixture.
type Options struct {
	// ExitIP is the source address the proxy dials its outbound connections
	// from, i.e. the exit IP a destination observes. Must be a locally bindable
	// address (e.g. a 127.x loopback alias in tests). Empty means the OS default
	// source.
	ExitIP string

	// KnownHosts is the proxy-side DNS view: hostname -> resolved IP. A CONNECT
	// to a HOSTNAME not in this table is refused (so tests control exactly what
	// the proxy can resolve). IP-literal CONNECTs do not consult this table.
	KnownHosts map[string]string

	// RequireAuth, when true, makes the fixture OFFER username/password auth (RFC
	// 1929) in method negotiation and require the client to complete it. The
	// offered username is recorded either way (see AuthUsernames); RequireAuth
	// controls only whether the no-auth method is refused.
	RequireAuth bool

	// DisallowIPConnect flips the default: when true the fixture REJECTS
	// ATYP=ipv4/ipv6 CONNECTs (as netcage's fixture does, to catch a
	// local-resolution leak). The shim relay legitimately CONNECTs by the
	// recovered original-destination IP, so it leaves this false (IP CONNECTs
	// allowed). The DNS-forwarder path uses a hostname regardless.
	DisallowIPConnect bool

	// RedirectTarget, when set, makes every CONNECT (any host/IP/port) dial THIS
	// host:port instead, from ExitIP. It lets a test point the relay at a routable
	// placeholder original-destination IP while the fixture actually connects to a
	// real local echo server. The exit IP the destination observes is still ExitIP.
	RedirectTarget string
}

// Fixture is a controllable SOCKS5h proxy. The zero value is not usable; build
// one with New.
type Fixture struct {
	opts Options

	mu       sync.Mutex
	ln       net.Listener
	closed   bool
	resolved []string
	authUser []string
}

// New builds a Fixture. Call Start to bind and serve.
func New(opts Options) *Fixture {
	return &Fixture{opts: opts}
}

// Start binds the proxy on bindAddr (e.g. "127.0.0.1:0" for an ephemeral port)
// and begins serving in the background. Use Addr to learn the bound address.
func (f *Fixture) Start(bindAddr string) error {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("socks5h fixture bind %s: %w", bindAddr, err)
	}
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()

	go f.serve(ln)
	return nil
}

// Addr returns the bound address ("host:port"), or "" if not started.
func (f *Fixture) Addr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln == nil {
		return ""
	}
	return f.ln.Addr().String()
}

// ResolvedHosts returns, in order, the hostnames the proxy was asked to resolve
// proxy-side. The DNS-through-proxy assertion binds to this.
func (f *Fixture) ResolvedHosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.resolved...)
}

// AuthUsernames returns, in order, the SOCKS usernames the proxy was offered in
// RFC 1929 auth. The per-account isolation-username assertion binds to this: it
// proves the shim dialled with the `<account>@` username Tor's IsolateSOCKSAuth
// keys on.
func (f *Fixture) AuthUsernames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.authUser...)
}

// Close stops the proxy (the kill switch): the listener closes and subsequent
// dials to it fail. Idempotent.
func (f *Fixture) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.ln != nil {
		return f.ln.Close()
	}
	return nil
}

func (f *Fixture) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go f.handle(c)
	}
}

func (f *Fixture) recordResolved(host string) {
	f.mu.Lock()
	f.resolved = append(f.resolved, host)
	f.mu.Unlock()
}

func (f *Fixture) recordAuth(user string) {
	f.mu.Lock()
	f.authUser = append(f.authUser, user)
	f.mu.Unlock()
}

// SOCKS5 constants (RFC 1928 / RFC 1929).
const (
	socksVer   = 0x05
	authVer    = 0x01 // RFC 1929 username/password subnegotiation version
	methodNone = 0x00
	methodAuth = 0x02 // username/password

	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded         = 0x00
	repHostUnreachable   = 0x04
	repCommandNotSupport = 0x07
	repAtypNotSupported  = 0x08
)

func (f *Fixture) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	if err := f.handshake(c); err != nil {
		return
	}
	host, port, err := f.readConnectRequest(c)
	if err != nil {
		return
	}

	// socks5h: a hostname target is resolved PROXY-SIDE from the controlled view;
	// an IP-literal target is dialed directly (the relay's original-destination
	// path). Only a hostname counts as a proxy-side resolution.
	var ip string
	if parsed := net.ParseIP(host); parsed != nil {
		ip = host
	} else {
		f.recordResolved(host)
		var ok bool
		ip, ok = f.opts.KnownHosts[host]
		if !ok {
			writeReply(c, repHostUnreachable)
			return
		}
	}

	dialTarget := net.JoinHostPort(ip, port)
	if f.opts.RedirectTarget != "" {
		dialTarget = f.opts.RedirectTarget
	}
	var localAddr net.Addr
	if f.opts.ExitIP != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(f.opts.ExitIP)}
	}
	dialer := net.Dialer{LocalAddr: localAddr, Timeout: 5 * time.Second}
	upstream, err := dialer.Dial("tcp", dialTarget)
	if err != nil {
		writeReply(c, repHostUnreachable)
		return
	}
	defer upstream.Close()

	if err := writeReply(c, repSucceeded); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

// handshake does SOCKS5 method negotiation. It always ACCEPTS username/password
// auth (recording the offered username), and additionally accepts no-auth unless
// RequireAuth is set. Recording the username on the auth path is the observability
// hook the isolation-username assertion binds to.
func (f *Fixture) handshake(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != socksVer {
		return errors.New("bad socks version")
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	offersAuth, offersNone := false, false
	for _, m := range methods {
		switch m {
		case methodAuth:
			offersAuth = true
		case methodNone:
			offersNone = true
		}
	}

	// Prefer username/password auth so the offered username is recorded. Fall back
	// to no-auth only when the client did not offer auth and RequireAuth is off.
	switch {
	case offersAuth:
		if _, err := c.Write([]byte{socksVer, methodAuth}); err != nil {
			return err
		}
		return f.readAuth(c)
	case offersNone && !f.opts.RequireAuth:
		_, err := c.Write([]byte{socksVer, methodNone})
		return err
	default:
		// No acceptable method (0xFF).
		_, _ = c.Write([]byte{socksVer, 0xFF})
		return errors.New("no acceptable auth method")
	}
}

// readAuth reads an RFC 1929 username/password subnegotiation, records the
// username, and always accepts (the fixture authenticates no credentials; it
// exists to OBSERVE the username, which is the isolation knob).
func (f *Fixture) readAuth(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != authVer {
		return errors.New("bad auth version")
	}
	uname := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, uname); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, passwd); err != nil {
		return err
	}
	f.recordAuth(string(uname))
	// Auth status 0x00 == success.
	_, err := c.Write([]byte{authVer, 0x00})
	return err
}

// readConnectRequest parses a CONNECT request and returns the requested host and
// port. A hostname (ATYP=domain) is the DNS-forwarder path; an IP literal is the
// relay's original-destination path (accepted unless DisallowIPConnect).
func (f *Fixture) readConnectRequest(c net.Conn) (host, port string, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return "", "", err
	}
	if hdr[0] != socksVer {
		return "", "", errors.New("bad socks version in request")
	}
	if hdr[1] != cmdConnect {
		writeReply(c, repCommandNotSupport)
		return "", "", errors.New("only CONNECT supported")
	}
	switch hdr[3] {
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(c, lenByte); err != nil {
			return "", "", err
		}
		name := make([]byte, int(lenByte[0]))
		if _, err = io.ReadFull(c, name); err != nil {
			return "", "", err
		}
		host = string(name)
	case atypIPv4:
		if f.opts.DisallowIPConnect {
			writeReply(c, repAtypNotSupported)
			return "", "", errors.New("IP address type rejected (DisallowIPConnect)")
		}
		ip := make([]byte, 4)
		if _, err = io.ReadFull(c, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	case atypIPv6:
		if f.opts.DisallowIPConnect {
			writeReply(c, repAtypNotSupported)
			return "", "", errors.New("IP address type rejected (DisallowIPConnect)")
		}
		ip := make([]byte, 16)
		if _, err = io.ReadFull(c, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	default:
		writeReply(c, repAtypNotSupported)
		return "", "", errors.New("unsupported address type")
	}

	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(c, portBytes); err != nil {
		return "", "", err
	}
	p := int(portBytes[0])<<8 | int(portBytes[1])
	return host, fmt.Sprintf("%d", p), nil
}

// writeReply writes a minimal SOCKS5 reply with a zero BND.ADDR/BND.PORT.
func writeReply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{socksVer, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
