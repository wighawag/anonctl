// Command anonctl-shim is the userspace half of anonctl's per-UID forced-egress
// data path: a static Go binary (built CGO_ENABLED=0) that the nft redirect
// feeds. ONE instance runs per anon account, on that account's per-account
// loopback ports, under the account's dedicated shim UID (a later
// anonctl-shim@<account>.service unit supervises it). It is two halves in one
// binary: a transparent TCP-to-SOCKS relay (recovers each redirected
// connection's original destination via SO_ORIGINAL_DST) and a
// DNS-over-SOCKS-TCP forwarder (resolves every query remotely over the endpoint,
// socks5h). Both dial the endpoint with the per-account `<account>@` isolation
// username and both fail closed: endpoint down means the connection/query is
// dropped, never sent in the clear.
//
// anonctl (the manager) is NOT in the data path and does not import this; it
// installs the nft rules and the systemd unit that RUNS this binary. The flag
// surface mirrors the validated manual recipe
// (work/notes/findings/manual-per-uid-tor-recipe.md).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/wighawag/anonctl/internal/shim"
)

func main() {
	dnsProbe := flag.Bool("dns-probe", false, "hidden DNS round-trip mode: `anonctl-shim -dns-probe <server-ip:port> <name>` sends one A query from the CALLING uid (no NSS, no Go resolver) and prints ANSWERED/NOANSWER. anonctl verify execs this under setpriv (as the anon UID) to MEASURE whether the account's DNS actually completes through the forced path, instead of inferring it from the installed rules.")
	probe := flag.Bool("probe", false, "hidden dialer mode: `anonctl-shim -probe <network> <addr>` dials with a short timeout and prints REACHED/DROPPED. anonctl verify execs this under setpriv (as the anon UID) to observe whether a direct connection is dropped by the fail-closed rules; it reuses this already-installed static binary so verify needs no Go toolchain on the host.")
	relayAddr := flag.String("relay", "127.0.0.1:19050", "transparent TCP relay listen addr (the account's per-account relay port)")
	dnsAddr := flag.String("dns", "127.0.0.1:19053", "DNS-over-SOCKS forwarder listen addr, udp+tcp (the account's per-account DNS port)")
	proxyAddr := flag.String("proxy", "127.0.0.1:9050", "upstream socks5h endpoint (e.g. the Tor SocksPort)")
	socksUser := flag.String("socks-user", "", "per-account SOCKS username (`<account>`, drives Tor IsolateSOCKSAuth); empty for a plain socks-peruser endpoint")
	socksPass := flag.String("socks-pass", "", "SOCKS password (normally empty; the username alone isolates)")
	upstreamDNS := flag.String("upstream-dns", "1.1.1.1:53", "upstream resolver, reached over the endpoint by hostname (socks5h)")
	flag.Parse()

	// Probe mode: dial one target, print REACHED/DROPPED, exit. This is NOT the data
	// path; it is the tiny dialer `anonctl verify` needs to run AS the anon UID (via
	// setpriv) to prove a direct connection is dropped. Reusing the installed shim as
	// the probe executable removes verify's old runtime `go build` (a released binary
	// cannot assume a Go toolchain on the user's host).
	if *probe {
		args := flag.Args()
		network, addr := "", ""
		if len(args) >= 2 {
			network, addr = args[0], args[1]
		}
		reached, detail := shim.Probe(network, addr)
		fmt.Print(shim.ProbeResult(reached, detail))
		return
	}

	// DNS round-trip mode: send ONE query to a named server and print whether an
	// ANSWER came back. Also not the data path. It exists because every packet-level
	// signal can say "the DNS forcing works" while the account has no working DNS at
	// all: on a measured host the redirect fired, the shim answered over Tor, and the
	// reply was dropped by a host-owned input filter after conntrack un-NATed it back
	// to the nameserver's address. Only asking for the answer catches that.
	if *dnsProbe {
		args := flag.Args()
		server, name := "", ""
		if len(args) >= 2 {
			server, name = args[0], args[1]
		}
		answered, detail := shim.DNSProbe(server, name)
		fmt.Print(shim.DNSProbeResult(answered, detail))
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("anonctl-shim: relay %s, dns %s -> endpoint %s (socks-user=%q) -> upstream-dns %s",
		*relayAddr, *dnsAddr, *proxyAddr, *socksUser, *upstreamDNS)

	if err := shim.Run(ctx, shim.Config{
		RelayAddr:   *relayAddr,
		DNSAddr:     *dnsAddr,
		ProxyAddr:   *proxyAddr,
		SocksUser:   *socksUser,
		SocksPass:   *socksPass,
		UpstreamDNS: *upstreamDNS,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl-shim: %v\n", err)
		os.Exit(1)
	}
}
