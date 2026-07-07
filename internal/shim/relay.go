package shim

import (
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/net/proxy"
)

// The TCP half of the shim: a transparent TCP-to-SOCKS relay. The nft ruleset
// REDIRECTs the account's TCP to this loopback port, rewriting the destination to
// the relay; the original destination survives in the kernel and is recovered
// via the SO_ORIGINAL_DST socket option (IPv4) and its IP6T_SO_ORIGINAL_DST
// analogue (IPv6). The relay then opens a socks5h CONNECT to that original
// destination through the endpoint, carrying the per-account `<account>@`
// isolation username (the Tor IsolateSOCKSAuth knob). There is NO plaintext
// fallback: if the endpoint is unreachable the dial errors and the connection is
// dropped (fail-closed at the relay level too).
//
// This half is anonctl-specific (netcage forces egress via a TUN sidecar rather
// than SO_ORIGINAL_DST); the manual recipe validated the nft redirect that makes
// SO_ORIGINAL_DST meaningful (work/notes/findings/manual-per-uid-tor-recipe.md).

// SO_ORIGINAL_DST is the getsockopt option (linux/netfilter_ipv4.h) that returns
// a REDIRECTed socket's pre-rewrite destination. IP6T_SO_ORIGINAL_DST
// (linux/netfilter_ipv6/ip6_tables.h) is the IPv6 analogue; both are numerically
// 80 but read at different socket levels (IPPROTO_IP vs IPPROTO_IPV6).
const (
	soOriginalDst   = 80
	ip6tOriginalDst = 80
)

// Relay is a transparent TCP-to-SOCKS relay. The zero value needs at least
// ProxyAddr set; SocksUser/SocksPass carry the isolation username.
type Relay struct {
	// ProxyAddr is the SOCKS5 endpoint host:port (e.g. the Tor SocksPort).
	ProxyAddr string
	// SocksUser is the per-account isolation username (`<account>`); SocksPass is
	// normally empty (the username alone drives Tor IsolateSOCKSAuth). Both empty
	// means an unauthenticated dial (a plain socks-peruser endpoint).
	SocksUser string
	SocksPass string

	// originalDst recovers a redirected connection's pre-rewrite destination. It
	// defaults to the SO_ORIGINAL_DST/IP6T_SO_ORIGINAL_DST syscall lookup; tests
	// inject a known destination (a unit test cannot set SO_ORIGINAL_DST without
	// the nft redirect, which needs root + netns).
	originalDst func(*net.TCPConn) (string, error)
}

// dialer builds the socks5h dialer with the isolation auth. A non-empty user (or
// pass) is sent as RFC 1929 auth; both empty means no auth.
func (r *Relay) dialer() (proxy.Dialer, error) {
	var auth *proxy.Auth
	if r.SocksUser != "" || r.SocksPass != "" {
		auth = &proxy.Auth{User: r.SocksUser, Password: r.SocksPass}
	}
	return proxy.SOCKS5("tcp", r.ProxyAddr, auth, proxy.Direct)
}

// Serve accepts redirected connections on ln and relays each through the endpoint
// to its original destination. It blocks until ln is closed. Each connection is
// handled independently; a per-connection failure (unresolvable original dst,
// endpoint down) drops that connection, never the listener.
func (r *Relay) Serve(ln net.Listener) error {
	if r.originalDst == nil {
		r.originalDst = originalDstSyscall
	}
	dialer, err := r.dialer()
	if err != nil {
		return fmt.Errorf("relay: build SOCKS5 dialer: %w", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err // listener closed
		}
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			continue
		}
		go r.handle(tc, dialer)
	}
}

func (r *Relay) handle(c *net.TCPConn, dialer proxy.Dialer) {
	defer c.Close()
	orig, err := r.originalDst(c)
	if err != nil {
		log.Printf("relay: SO_ORIGINAL_DST: %v", err)
		return
	}
	up, err := dialer.Dial("tcp", orig)
	if err != nil {
		// Fail-closed: no direct fallback to orig. Drop the connection.
		log.Printf("relay: socks dial %s: %v (drop, fail-closed)", orig, err)
		return
	}
	defer up.Close()
	splice(c, up)
}

// splice copies bytes in both directions until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) { _, _ = io.Copy(dst, src); done <- struct{}{} }
	go cp(a, b)
	go cp(b, a)
	<-done
}

// originalDstSyscall recovers a redirected connection's pre-rewrite destination
// via getsockopt. It tries the IPv4 option first, then the IPv6 analogue, so a
// dual-stack relay recovers either family. The socket is duplicated (File) so the
// raw fd is stable for the syscall.
func originalDstSyscall(c *net.TCPConn) (string, error) {
	f, err := c.File()
	if err != nil {
		return "", err
	}
	defer f.Close()
	fd := int(f.Fd())

	if addr, err := getOriginalDst4(fd); err == nil {
		return parseOriginalDst4(addr)
	}
	addr, err := getOriginalDst6(fd)
	if err != nil {
		return "", err
	}
	return parseOriginalDst6(addr)
}

// getOriginalDst4 reads SO_ORIGINAL_DST (IPv4) off the fd.
func getOriginalDst4(fd int) (*syscall.RawSockaddrInet4, error) {
	var addr syscall.RawSockaddrInet4
	sz := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_IP), uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&sz)), 0)
	if errno != 0 {
		return nil, errno
	}
	return &addr, nil
}

// getOriginalDst6 reads IP6T_SO_ORIGINAL_DST (IPv6) off the fd.
func getOriginalDst6(fd int) (*syscall.RawSockaddrInet6, error) {
	var addr syscall.RawSockaddrInet6
	sz := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_IPV6), uintptr(ip6tOriginalDst),
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&sz)), 0)
	if errno != 0 {
		return nil, errno
	}
	return &addr, nil
}

// parseOriginalDst4 decodes an IPv4 SO_ORIGINAL_DST sockaddr into "ip:port". The
// port is in network (big-endian) byte order in the sockaddr; ntohs it.
func parseOriginalDst4(sa *syscall.RawSockaddrInet4) (string, error) {
	ip := net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
	port := ntohs(sa.Port)
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
}

// parseOriginalDst6 decodes an IPv6 IP6T_SO_ORIGINAL_DST sockaddr into
// "[ip]:port" (net.JoinHostPort brackets the v6 literal).
func parseOriginalDst6(sa *syscall.RawSockaddrInet6) (string, error) {
	ip := make(net.IP, net.IPv6len)
	copy(ip, sa.Addr[:])
	port := ntohs(sa.Port)
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
}

// ntohs converts a network-byte-order 16-bit value (as stored in a RawSockaddr's
// Port field) to host order.
func ntohs(n uint16) uint16 { return n>>8 | n<<8 }
