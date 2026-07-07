---
kind: finding
title: Manual per-UID Tor recipe (nft skuid redirect into a shim) - VALIDATED end-to-end
slug: manual-per-uid-tor-recipe
source: |
  Hand-validated end-to-end by the anonctl maintainer (wighawag, at the root
  keyboard) with the agent driving, on a real host: Debian GNU/Linux 13 "trixie",
  kernel 6.12.90+deb13.1-amd64, Tor 0.4.9.9, nftables v1.1.3, on 2026-07-07.
  Every confirmation below is a command that was actually run and an output that
  was actually observed; the DNS-leak check was re-run with a discriminating
  black-hole probe to remove ambiguity (see "The DNS subtlety"). The stream-
  isolation ground-truth is in the sibling finding tor-isolatesocksauth-default.md.
---

## What was proven

On one shared Linux host, force ALL egress of a dedicated `anon` login account through a per-account socks5h shim via an `nftables meta skuid` redirect, fail-closed (default-DROP for that UID), leak-free (DNS resolved remotely over Tor, IPv6 dropped not leaked), with two bypass closures. Tor is the default endpoint; cross-user safety comes from dialling Tor with the per-account SOCKS username `anon` (empty password) so Tor's default `IsolateSOCKSAuth` gives the account its own circuit/exit. All five hand confirmations passed.

## Environment (observed)

```
uname -a   -> Linux nono 6.12.90+deb13.1-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.90-2 x86_64
os         -> Debian GNU/Linux 13 (trixie)
tor        -> Tor version 0.4.9.9  (systemctl is-active tor -> active), SocksPort 127.0.0.1:9050
nft        -> nftables v1.1.3
tools      -> curl, dig, socat, go1.26.0 present; redsocks NOT installed (shim written in Go instead)
```

## Account + shim-UID layout (created with `useradd`)

```
useradd --create-home --shell /bin/bash anon
useradd --system --no-create-home --shell /usr/sbin/nologin anon-shim
getent passwd anon anon-shim
#   anon:x:30034:30034::/home/anon:/bin/bash                 <- ANON_UID = 30034 (login acct, egress forced)
#   anon-shim:x:995:983::/home/anon-shim:/usr/sbin/nologin   <- SHIM_UID = 995, gid 983 (runs the shim; ONLY UID allowed to dial Tor)
```

## Parameters (substitute these in the ruleset / shim invocation)

```
ANON_UID   = 30034        # `anon` login account
SHIM_UID   = 995          # `anon-shim` service account (gid 983)
RELAY_PORT = 19050        # shim transparent TCP->SOCKS relay, 127.0.0.1
DNS_PORT   = 19053        # shim DNS-over-SOCKS-TCP forwarder, 127.0.0.1 (udp+tcp)
SOCKS_ADDR = 127.0.0.1
SOCKS_PORT = 9050         # local Tor SocksPort (the default endpoint)
SOCKS_USER = anon         # the account name; EMPTY password -> Tor IsolateSOCKSAuth isolates
```

## The shim + DNS-forwarder invocation

A self-contained Go binary (a validation stand-in for the future production shim, NOT `redsocks`) provides both listeners; both dial Tor `127.0.0.1:9050` with SOCKS user `anon` and an EMPTY password. Full source archived at the end of this note. Built with `go build` as an ordinary user; run AS THE SHIM UID:

```
setpriv --reuid 995 --regid 983 --clear-groups \
  ./anonctl-shim \
    -relay 127.0.0.1:19050 \
    -dns   127.0.0.1:19053 \
    -proxy 127.0.0.1:9050 \
    -socks-user anon \
    -socks-pass "" \
    -upstream-dns 1.1.1.1:53
# logs:
#   dns forwarder on 127.0.0.1:19053 -> socks 127.0.0.1:9050 (user="anon") -> 1.1.1.1:53
#   transparent relay on 127.0.0.1:19050 -> socks 127.0.0.1:9050 (user="anon")
```

The relay reads the pre-redirect destination via `SO_ORIGINAL_DST` and opens a socks5h CONNECT to it. The DNS forwarder tunnels each query to the upstream resolver over a SOCKS TCP CONNECT using DNS-over-TCP framing (the netcage `internal/dnsforwarder` pattern), so no plaintext UDP DNS ever leaves the box; fail-closed (if Tor is down the dial errors and the query is dropped, no host fallback). The `anon` username with empty password is the load-bearing isolation knob and MUST be set on BOTH the relay dial and the DNS-forwarder dial.

## The exact nftables ruleset (as it loaded; copy-pasteable, parameterised above)

Verified assumption FIRST (non-destructive probe): a REDIRECTed packet re-enters the filter output hook with the dst already rewritten to `127.0.0.1:RELAY_PORT`. Observed: a scratch counter keyed on the rewritten dst caught 4 packets; the counter keyed on the original dst caught 0. So `nat output` (priority -100 / `dstnat`) runs before `filter output` (priority 0), and the filter chain's accept-rules must match the SHIM ports, not the original destination. Confirmed.

```nft
# anonctl per-UID forced anonymized egress - inet table (IPv4 + IPv6), fail-closed.
# Governs ONLY uid 30034 (anon) and uid 995 (anon-shim); every other uid is untouched.
table inet anonctl {
    chain nat_out {
        type nat hook output priority dstnat; policy accept;   # priority -100
        meta skuid != 30034 return                              # only rewrite the anon UID
        ip daddr 127.0.0.1 tcp dport { 19050, 19053 } return    # its own shim ports: leave as-is
        ip daddr 127.0.0.1 udp dport 19053 return
        udp dport 53 redirect to :19053                         # DNS (udp) -> shim DNS port
        tcp dport 53 redirect to :19053                         # DNS (tcp) -> shim DNS port
        meta l4proto tcp redirect to :19050                     # all other TCP -> shim relay
        # (non-53 UDP / other protos fall through to the filter DROP)
    }
    chain filter_out {
        type filter hook output priority filter; policy drop;   # DEFAULT-DROP = fail-closed
        meta skuid != 30034 meta skuid != 995 accept            # this table governs only anon/shim

        # SHIM UID (995): the ONLY thing allowed to reach the Tor SocksPort.
        meta skuid 995 ip daddr 127.0.0.1 tcp dport 9050 accept
        meta skuid 995 oifname "lo" accept
        meta skuid 995 accept                                   # shim -> Tor -> world

        # ANON UID (30034):
        meta skuid 30034 ip daddr 127.0.0.1 tcp dport 9050 drop           # (b) never dial Tor directly
        meta skuid 30034 ip daddr 127.0.0.1 tcp dport { 19050, 19053 } accept  # (a) only its shim ports
        meta skuid 30034 ip daddr 127.0.0.1 udp dport 19053 accept
        meta skuid 30034 ip daddr 127.0.0.0/8 drop                        # (a) no other loopback
        meta skuid 30034 ip6 daddr ::1 drop                               # (a) no ::1
        meta skuid 30034 ip6 daddr ::/0 drop                              # IPv6: dropped, never leaked
        # anything else from the anon UID -> policy drop (fail-closed)
    }
}
```

## The confirmations (command run + observed result)

Host real IP for comparison (root, direct): `curl -s https://check.torproject.org/api/ip` -> `{"IsTor":false,"IP":"147.147.37.112"}`.

**1. Exit via Tor (anon UID, forced path).** PASS.
```
sudo -u anon curl -s https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"45.66.35.21"}
```
IsTor true; exit `45.66.35.21` differs from the host's `147.147.37.112`.

**2. DNS resolves remotely, no plaintext leak.** PASS.
```
# 2a resolution works through the forced path:
sudo -u anon curl -s https://check.torproject.org/api/ip   -> http 200, {"IsTor":true,"IP":"192.42.116.118"}
# 2c resolution works via the shim DNS port directly:
sudo -u anon dig +short @127.0.0.1 -p 19053 example.com A   -> 104.20.23.154 / 172.66.147.243
# leak check (see "The DNS subtlety"): dig at a BLACK-HOLE resolver from the anon UID:
sudo -u anon dig @192.0.2.1 example.com A                   -> ANSWER 172.66.147.243 / 104.20.23.154 in 1276ms
# nft escaped-leak counter (udp/53 from anon with off-box dst): 0 packets.
```
The `@192.0.2.1` query still returns an answer even though 192.0.2.1 is a black hole, PROVING every `@<anything>:53` is transparently redirected to the shim; and the nft "escaped-leak" counter stayed at 0, so no plaintext udp/53 packet ever left the box.

**3. Fail-closed: direct outbound DROPPED on IPv4 AND IPv6.** PASS.
```
# 3a a NON-redirected proto (raw UDP/9999) from the anon UID:
sudo -u anon socat - UDP4:1.1.1.1:9999    -> "write(...): Operation not permitted" (DROP)
# 3b direct IPv6 from the anon UID:
sudo -u anon curl -6 --max-time 6 http://[2606:4700:4700::1111]/   -> v6http=000 (exit 7, DROP)
```
Non-53 UDP is not relayable over SOCKS-TCP and is dropped; all anon IPv6 egress is dropped (leak-free, not leaked).

**4. Bypass closure (a): no other loopback service.** PASS.
```
# 4a anon UID to a DIFFERENT loopback port (9150, tor-browser's own socks):
sudo -u anon curl --socks5 127.0.0.1:9150 https://example.com   -> cb9150=000 (exit 97, DROP)
# 4b anon UID to its OWN shim relay port (sanity):
sudo -u anon bash -c 'echo > /dev/tcp/127.0.0.1/19050'          -> relay-reachable
```

**5. Bypass closure (b): anon cannot dial Tor SocksPort; shim can.** PASS.
```
# 5a anon UID direct to the Tor SocksPort:
sudo -u anon curl --socks5-hostname anon:@127.0.0.1:9050 https://check.torproject.org/api/ip  -> (exit 97, DROP)
# 5b shim UID direct to the Tor SocksPort:
sudo -u anon-shim curl --socks5-hostname anon:@127.0.0.1:9050 https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"192.42.116.118"}
```

## The DNS subtlety (important for the Go `verify` task)

The first DNS-leak attempt (`dig @1.1.1.1` from the anon UID) RETURNED an answer, which initially looked like a leak. It was NOT. Because the nat redirect is TRANSPARENT, `dig`'s query to `@1.1.1.1:53` is silently rewritten to the shim; the shim resolves via Tor and answers; `dig` still LABELS the server as `1.1.1.1` (it reports the address it was told to use, not the actual socket peer). So "a direct `dig @<resolver>` from the anon UID times out" is the WRONG expectation for a transparently-redirected setup. The correct DNS-leak checks are: (i) point `dig` at a BLACK-HOLE resolver (e.g. `192.0.2.1`, TEST-NET-1) that answers nothing, and confirm you STILL get an answer (proves interception), and (ii) assert via an nft counter that zero udp/53 packets leave with an off-box destination. anonctl's Go `verify` should use these, not a "direct dig must fail" assertion.

## Known properties / caveats (all deliberate, all observed)

- **IPv6 is drop-only.** There is no v6 `redirect` target, so the anon account has no IPv6 connectivity; all v6 egress is dropped. This is fail-closed and leak-free, but means dual-stack destinations resolve/connect over v4-via-Tor only. Documented, acceptable for v1.
- **Non-53 UDP is dropped.** SOCKS carries TCP only; QUIC/HTTP-3 and other UDP from the anon account are dropped (they fall back to TCP or fail). Fail-closed, not a leak.
- **`meta skuid` is by numeric UID.** The ruleset embeds 30034 / 995; anonctl's real code must resolve the account/shim names to UIDs and emit the numbers, and reload the ruleset if the passwd mapping changes.
- **Cleanup:** `nft delete table inet anonctl`, stop the shim, and (if desired) `userdel -r anon; userdel -r anon-shim`.

## Appendix: the validation shim source (anonctl-shim/main.go)

Go 1.26, single file, deps: `golang.org/x/net/proxy` (from the local module cache, same version netcage pins, v0.52.0). This is a VALIDATION stand-in, not the production shim (that is a later Go task); it demonstrates the SO_ORIGINAL_DST relay + DNS-over-SOCKS-TCP forwarder with the `anon`/empty-password dial.

```go
// anonctl-shim: a self-contained Tier-2 VALIDATION shim (NOT the production shim).
// Transparent TCP->SOCKS relay (SO_ORIGINAL_DST) + DNS-over-SOCKS-TCP forwarder,
// both dialling the upstream SOCKS5 proxy with SOCKS user "anon" / empty password
// so Tor's IsolateSOCKSAuth puts this account on its own circuit/exit. Fail-closed.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/proxy"
)

const soOriginalDst = 80 // linux/netfilter_ipv4.h SO_ORIGINAL_DST

func main() {
	relayAddr := flag.String("relay", "127.0.0.1:19050", "transparent TCP relay listen addr")
	dnsAddr := flag.String("dns", "127.0.0.1:19053", "DNS-over-SOCKS listen addr (udp+tcp)")
	proxyAddr := flag.String("proxy", "127.0.0.1:9050", "upstream SOCKS5 proxy (Tor SocksPort)")
	socksUser := flag.String("socks-user", "anon", "SOCKS username (drives Tor IsolateSOCKSAuth)")
	socksPass := flag.String("socks-pass", "", "SOCKS password (empty for Tor isolation)")
	upstreamDNS := flag.String("upstream-dns", "1.1.1.1:53", "upstream resolver, reached over SOCKS TCP")
	flag.Parse()

	auth := &proxy.Auth{User: *socksUser, Password: *socksPass}
	dialer, err := proxy.SOCKS5("tcp", *proxyAddr, auth, proxy.Direct)
	if err != nil {
		log.Fatalf("build SOCKS5 dialer: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := startDNS(ctx, *dnsAddr, *proxyAddr, auth, *upstreamDNS); err != nil {
		log.Fatalf("start dns: %v", err)
	}
	log.Printf("dns forwarder on %s -> socks %s (user=%q) -> %s", *dnsAddr, *proxyAddr, *socksUser, *upstreamDNS)

	ln, err := net.Listen("tcp", *relayAddr)
	if err != nil {
		log.Fatalf("listen relay %s: %v", *relayAddr, err)
	}
	log.Printf("transparent relay on %s -> socks %s (user=%q)", *relayAddr, *proxyAddr, *socksUser)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handleRelay(c.(*net.TCPConn), dialer)
	}
}

func handleRelay(c *net.TCPConn, dialer proxy.Dialer) {
	defer c.Close()
	orig, err := originalDst(c)
	if err != nil {
		log.Printf("SO_ORIGINAL_DST: %v", err)
		return
	}
	up, err := dialer.Dial("tcp", orig)
	if err != nil {
		log.Printf("socks dial %s: %v (drop, fail-closed)", orig, err)
		return
	}
	defer up.Close()
	splice(c, up)
}

func originalDst(c *net.TCPConn) (string, error) {
	f, err := c.File()
	if err != nil {
		return "", err
	}
	defer f.Close()
	fd := int(f.Fd())
	var addr syscall.RawSockaddrInet4
	sz := uint32(unsafe.Sizeof(addr))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(syscall.IPPROTO_IP), uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&sz)), 0)
	if errno != 0 {
		return "", errno
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8 | addr.Port<<8&0xff00) // ntohs
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) { _, _ = io.Copy(dst, src); done <- struct{}{} }
	go cp(a, b)
	go cp(b, a)
	<-done
}

func startDNS(ctx context.Context, listen, proxyAddr string, auth *proxy.Auth, upstream string) error {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		_ = pc.Close()
		return err
	}
	go func() { <-ctx.Done(); _ = pc.Close(); _ = ln.Close() }()
	resolve := func(q []byte) ([]byte, error) {
		conn, err := dialer.Dial("tcp", upstream)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		framed := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(q)))
		copy(framed[2:], q)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	go func() { // UDP
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := make([]byte, n)
			copy(q, buf[:n])
			go func() {
				if r, err := resolve(q); err == nil {
					_, _ = pc.WriteTo(r, addr)
				}
			}()
		}
	}()
	go func() { // TCP (RFC 7766, glibc use-vc)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					var lb [2]byte
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(lb[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					r, err := resolve(q)
					if err != nil {
						return
					}
					out := make([]byte, 2+len(r))
					binary.BigEndian.PutUint16(out[:2], uint16(len(r)))
					copy(out[2:], r)
					if _, err := c.Write(out); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return nil
}
```
