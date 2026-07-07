package shim

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/socks5hfixture"
)

// TestParseOriginalDst4 proves the IPv4 SO_ORIGINAL_DST decode: a
// RawSockaddrInet4 (as the kernel fills it, port in network byte order) becomes
// the "ip:port" the relay must CONNECT to via the proxy.
func TestParseOriginalDst4(t *testing.T) {
	var sa syscall.RawSockaddrInet4
	sa.Family = syscall.AF_INET
	sa.Addr = [4]byte{93, 184, 216, 34} // example.com
	// Port 443 in network (big-endian) byte order, as the kernel returns it.
	sa.Port = htons(443)

	got, err := parseOriginalDst4(&sa)
	if err != nil {
		t.Fatalf("parseOriginalDst4: %v", err)
	}
	if got != "93.184.216.34:443" {
		t.Fatalf("parseOriginalDst4 = %q, want 93.184.216.34:443", got)
	}
}

// TestParseOriginalDst6 proves the IPv6 analogue (IP6T_SO_ORIGINAL_DST): a
// RawSockaddrInet6 decodes to a bracketed "[ip]:port". Even though v6 egress is
// dropped by the nft ruleset, the shim must handle the v6 original-destination
// shape (story 11: v6 handled explicitly, never a silent bypass).
func TestParseOriginalDst6(t *testing.T) {
	var sa syscall.RawSockaddrInet6
	sa.Family = syscall.AF_INET6
	// 2606:4700:4700::1111
	sa.Addr = [16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}
	sa.Port = htons(443)

	got, err := parseOriginalDst6(&sa)
	if err != nil {
		t.Fatalf("parseOriginalDst6: %v", err)
	}
	if got != "[2606:4700:4700::1111]:443" {
		t.Fatalf("parseOriginalDst6 = %q, want [2606:4700:4700::1111]:443", got)
	}
}

// TestRelay_ForwardsToProxyWithIsolationUsername proves the relay's whole job:
// it takes the ORIGINAL DESTINATION (recovered here via the injectable seam,
// since a unit test cannot set SO_ORIGINAL_DST without the nft redirect), opens
// a socks5h CONNECT to it through the proxy carrying the per-account `<account>@`
// isolation username, and splices bytes end to end. The fixture records the
// username so we prove the isolation knob was sent.
func TestRelay_ForwardsToProxyWithIsolationUsername(t *testing.T) {
	// A real destination server the proxy will reach (via RedirectTarget) and echo.
	echo := startEcho(t)

	fx := socks5hfixture.New(socks5hfixture.Options{
		RequireAuth:    true,
		RedirectTarget: echo, // every CONNECT is dialed to the echo server
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()

	r := &Relay{
		ProxyAddr: fx.Addr(),
		SocksUser: "anon",
		SocksPass: "",
		// Inject a known original destination (an IP literal, as the kernel would
		// hand back): the fixture's RedirectTarget then steers it to the echo.
		originalDst: func(*net.TCPConn) (string, error) { return "203.0.113.7:443", nil },
	}
	ln := startRelay(t, r)

	c, err := net.Dial("tcp", ln)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write through relay: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo through relay: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("relayed echo = %q, want ping", buf)
	}

	users := fx.AuthUsernames()
	if len(users) == 0 || users[0] != "anon" {
		t.Fatalf("relay dialed with usernames %v, want the isolation username %q first", users, "anon")
	}
}

// TestRelay_FailsClosedWhenProxyDown asserts the relay-level fail-closed: with
// the endpoint unreachable, the relayed connection gets NOTHING (no direct
// fallback to the original destination). The client's read must fail/EOF.
func TestRelay_FailsClosedWhenProxyDown(t *testing.T) {
	r := &Relay{
		ProxyAddr:   "127.0.0.1:1", // nothing listening
		SocksUser:   "anon",
		originalDst: func(*net.TCPConn) (string, error) { return "203.0.113.7:443", nil },
	}
	ln := startRelay(t, r)

	c, err := net.Dial("tcp", ln)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		// A write may or may not error depending on timing; the read is the proof.
		_ = err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err == nil {
		t.Fatal("relay returned data with the proxy down; want fail-closed (no fallback)")
	}
}

// htons converts a host-order 16-bit value to network byte order, matching how
// the kernel stores the port in a SO_ORIGINAL_DST sockaddr.
func htons(n uint16) uint16 { return n>>8 | n<<8 }

// ---- test helpers ----

// startRelay starts r on an ephemeral loopback port and returns its address.
func startRelay(t *testing.T, r *Relay) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go r.Serve(ln)
	return ln.Addr().String()
}

// startEcho starts a trivial TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String()
}
