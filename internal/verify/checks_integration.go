//go:build integration
// +build integration

package verify

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/lanexempt"
)

// icmpProbeTarget is the off-box address the icmp-drop probe pings AS the anon
// UID: a TEST-NET-1 (RFC 5737) documentation address that is safe to name and
// never a real host. The probe never depends on it replying: a dropped ping (the
// PASS) and an unreachable-but-not-dropped host both yield no reply, so the probe
// reads whether the anon UID could EMIT ICMP at all, which the policy DROP forbids.
const icmpProbeTarget = "192.0.2.1"

// udpProbeHost / udpRawProbePort are the off-box UDP destination the non-tcp-udp-drop
// probe dials AS the anon UID: a public resolver IP on a raw high port (row 5's
// hand-verified `socat UDP4:1.1.1.1:9999` shape) plus, separately, UDP/443 (QUIC).
// SOCKS carries TCP only, so any UDP that is not the redirected 53 falls through to
// the anon UID's policy DROP; the probe proves the drop.
const (
	udpProbeHost    = "1.1.1.1"
	udpRawProbePort = 9999
)

// offBoxProbeV4 is the OFF-BOX v4 destination the leak/closure probes dial AS the
// anon UID and key their escaped-leak counter on. It is a TEST-NET-1 (RFC 5737)
// documentation address, safe to name and never a real host: the probe never needs
// it to REPLY (a completed loopback handshake with the transparent relay proves
// nothing). It only needs to observe, via the counter, whether an anon-UID packet
// escaped the box STILL carrying this off-box daddr (a leak) vs was redirected into
// the shim / dropped (the PASS). offBoxProbePort is an arbitrary high TCP port.
const (
	offBoxProbeV4   = "192.0.2.1"
	offBoxProbePort = 9999
)

// LiveChecks (integration build) is the REAL assertion set: it stands up live
// probes AS the anon UID against the fail-closed ruleset the nftables task
// installed, and feeds their outcomes to the PURE assertion decisions in
// verify.go. It is compiled ONLY under the `integration` build tag (it needs root
// + setpriv + a live endpoint); the default build ships checks_default.go, which
// fails honestly instead of silently passing.
//
// It runs EVERY probe (RunVerify does not short-circuit) so the report is
// complete: the load-bearing leak drop (v4 AND v6), both bypass closures, and,
// when a LAN exemption is active (p.Exempt != ""), the split-tunnel-tight
// assertion. The anonymized-exit and dns-remote assertions egress AS THE ANON UID
// (setpriv + curl, transparently redirected into the shim) and compare against the
// host baseline, NOT by dialling the relay port as a SOCKS proxy (the relay is a
// transparent SO_ORIGINAL_DST relay, not a SOCKS server).
//
// CRITICAL probe polarity (the transparent-relay subtlety, BUG 2 of
// work/notes/findings/e2e-binary-validation.md): the shim relay is reached via the
// nat redirect, so a LOOPBACK TCP handshake with it ALWAYS completes (the relay
// accepts, then fail-closed-drops upstream). "handshake completed" is therefore
// NEVER "reached the target". The leak/closure probes read OFF-BOX reachability
// instead: a raw non-53 UDP EPERM, an IPv6 dial that fails-closed (no v6 redirect),
// or the escaped-leak counter (offBoxReachedAsAnon) keyed on an OFF-BOX daddr that
// only a genuine clear escape increments. The probes key on `meta skuid`, so they
// run under setpriv --reuid to the anon UID.
func LiveChecks(ctx context.Context, p LiveParams) []Check {
	checks := []Check{
		{Name: AssertAnonymizedExit, Run: func(ctx context.Context) Assertion {
			hostIP, herr := hostExitIP(ctx)
			exitIP, isTor, eerr := forcedExitIP(ctx, p)
			if herr != nil {
				return Assertion{Name: AssertAnonymizedExit, Err: herr}
			}
			if eerr != nil {
				return Assertion{Name: AssertAnonymizedExit, Err: eerr}
			}
			return AnonymizedExitAssertion(hostIP, exitIP, isTor, p.Class)
		}},
		{Name: AssertDNSRemote, Run: func(ctx context.Context) Assertion {
			probe, proxyResolved, hostSaw, err := dnsRemoteEvidence(ctx, p)
			if err != nil {
				return Assertion{Name: AssertDNSRemote, Err: err}
			}
			return DNSRemoteAssertion(probe, proxyResolved, hostSaw)
		}},
		{Name: AssertLeakDropV4, Run: func(ctx context.Context) Assertion {
			// A direct v4 LEAK is an anon-UID packet leaving the box with an OFF-BOX v4
			// daddr in the clear. A loopback TCP dial can NOT prove this (the transparent
			// relay always completes the handshake), so we read the escaped-leak counter
			// for a raw non-53 UDP datagram to an off-box v4 host: nat redirects only
			// tcp + udp/53, so raw UDP falls through to the policy DROP (recipe row 3's
			// `socat UDP4:1.1.1.1:9999` EPERM). If the v4 drop were broken the datagram
			// would escape with the off-box daddr and move the counter (a real leak).
			// A counter plant/read error fails LOUD (a probe that could not run is not a
			// pass), never a silent reached=false green.
			reached, err := offBoxReachedAsAnon(ctx, p, offBoxProbeV4, "udp", offBoxProbePort)
			return escapedLeakProbeAssertion(AssertLeakDropV4, "a direct v4 connection from the anon UID", reached, err)
		}},
		{Name: AssertLeakDropV6, Run: func(ctx context.Context) Assertion {
			return LeakDropAssertion("v6", probeAsAnon(ctx, p, "tcp6", "[::1]:1"))
		}},
		{Name: AssertBypassLoopbackClosure, Run: func(ctx context.Context) Assertion {
			// Closure (a): the anon UID must not reach an arbitrary destination directly.
			// Since ALL of its TCP is redirected into the shim, a loopback dial completes
			// the handshake with the relay and proves nothing; the honest, non-vacuous
			// signal is that NO anon-UID TCP escapes the box carrying an OFF-BOX daddr in
			// the clear. We dial an off-box TCP host and watch the escaped-leak counter
			// keyed on that daddr: a redirected packet has its daddr rewritten to the shim
			// (no match, PASS); a genuine escape keeps the off-box daddr (FAIL). A
			// counter plant/read error fails LOUD (a probe that could not run is not a
			// pass), the exact false-green this closes: the invalid-nft counter used to
			// swallow to reached=false and pass this closure WITHOUT probing.
			reached, err := offBoxReachedAsAnon(ctx, p, offBoxProbeV4, "tcp", 0)
			return escapedLeakProbeAssertion(AssertBypassLoopbackClosure, "the anon UID reaching a non-shim loopback destination", reached, err)
		}},
		{Name: AssertBypassEndpointClosure, Run: func(ctx context.Context) Assertion {
			// Closure (b): the anon UID dialling the upstream endpoint directly must not
			// escape the box to the endpoint's address:PORT in the clear. We dial the
			// endpoint AS the anon UID and watch the escaped-leak counter keyed on the
			// endpoint daddr AND its ORIGINAL port: the nat redirect rewrites BOTH daddr
			// and dport (to the shim relay port), so a redirected packet no longer matches
			// the endpoint port and the counter stays 0 (PASS). Keying on the endpoint PORT
			// (not any-port) is load-bearing for a LOOPBACK endpoint: an any-port 127.0.0.1
			// counter would also catch the anon UID's legitimate (redirected) shim traffic.
			// A genuine direct escape to the endpoint keeps daddr:port and moves it (FAIL).
			endpointAddr := net.JoinHostPort(p.EndpointHost, strconv.Itoa(p.EndpointPort))
			reached, err := offBoxReachedAsAnon(ctx, p, p.EndpointHost, "tcp", p.EndpointPort, "tcp4", endpointAddr)
			return escapedLeakProbeAssertion(AssertBypassEndpointClosure, "the anon UID dialling the upstream endpoint directly", reached, err)
		}},
		{Name: AssertICMPDrop, Run: func(ctx context.Context) Assertion {
			// Tails leak-catalogue row 4: an ICMP echo from the anon UID to an off-box
			// address must be DROPPED. It falls through to the policy DROP, so a ping
			// gets no reply => reached=false => PASS. The off-box target is a
			// documentation/TEST-NET address; the probe never depends on it being up
			// (a dropped ping and an unreachable host both read as reached=false, the
			// safe outcome), it reads whether the anon UID could EMIT ICMP at all.
			return ICMPDropAssertion(pingAsAnon(ctx, p, icmpProbeTarget))
		}},
		{Name: AssertNonTCPUDPDrop, Run: func(ctx context.Context) Assertion {
			// Tails leak-catalogue row 5: raw non-53 UDP AND specifically UDP/443 (QUIC)
			// from the anon UID must be DROPPED (SOCKS carries TCP only). Both dial an
			// off-box UDP destination AS the anon UID; a dropped datagram is refused /
			// times out => reached=false => PASS.
			rawUDP := net.JoinHostPort(udpProbeHost, strconv.Itoa(udpRawProbePort))
			quicUDP := net.JoinHostPort(udpProbeHost, "443")
			raw := udpSendAsAnon(ctx, p, rawUDP)
			quic := udpSendAsAnon(ctx, p, quicUDP)
			return NonTCPUDPDropAssertion(raw, quic)
		}},
		{Name: AssertNoUIDTransitionEgress, Run: func(ctx context.Context) Assertion {
			// Tails leak-catalogue row 7 (best-effort): probe the CONCRETELY ENUMERABLE
			// UID-transition escape vectors from the hand-audited finding (sudo, and the
			// documented setuid network wrappers) and assert none yields an off-box socket
			// owned by a non-anon, non-shim uid. The pure decision frames it honestly as
			// best-effort / not exhaustive; this only gathers the real per-vector outcomes.
			return NoUIDTransitionEgressAssertion(uidTransitionVectors(ctx, p))
		}},
	}
	if p.Exempt != "" {
		checks = append(checks, Check{Name: AssertSplitTunnelTight, Run: func(ctx context.Context) Assertion {
			// The exempted target is RETURNed from the nat chain (not redirected), so it
			// egresses DIRECTLY: a real handshake to it is a truthful reachability signal.
			exemptReached := probeAsAnon(ctx, p, "tcp4", p.Exempt)
			// A NON-exempt sibling in the same LAN is NOT returned: its TCP is redirected
			// into the shim, so a loopback handshake with the relay would false-"reach".
			// Read the escaped-leak counter keyed on the sibling's off-box daddr instead:
			// it stays 0 (redirected) unless the exemption widened into a real direct hole.
			// A counter plant/read error fails the assertion LOUD (a probe that could not
			// run is not a pass), never a silent reached=false green: this was the second
			// false-green (the invalid-nft counter swallowed to reached=false and passed
			// split-tunnel-tight WITHOUT probing the non-exempt sibling).
			nonExempt := nonExemptLANOf(p.Exempt)
			nonExemptReached := false
			if host, _, err := net.SplitHostPort(nonExempt); err == nil {
				reached, perr := offBoxReachedAsAnon(ctx, p, host, "tcp", 0, "tcp4", nonExempt)
				if perr != nil {
					return Assertion{Name: AssertSplitTunnelTight, Err: perr}
				}
				nonExemptReached = reached
			}
			return SplitTunnelTightAssertion(p.Exempt, exemptReached, nonExemptReached)
		}})
		checks = append(checks, Check{Name: AssertLANExemptionNotADNSHole, Run: func(ctx context.Context) Assertion {
			tcp53, udp53, err := clearLANDNSLeaked(ctx, p)
			if err != nil {
				return Assertion{Name: AssertLANExemptionNotADNSHole, Err: err}
			}
			return LANExemptionNotADNSHoleAssertion(p.Exempt, tcp53, udp53)
		}})
	}
	return checks
}

// clearLANDNSLeaked probes whether a DIRECT clear-DNS query (tcp AND udp 53) from
// the anon UID to the EXEMPTED LAN host egressed to the LAN resolver as clear DNS,
// rather than being redirected to the shim or dropped (Tails leak-catalogue row
// 2). It reads the black-hole/counter signal the DNS subtlety requires
// (work/notes/findings/manual-per-uid-tor-recipe.md): a transparent redirect means
// a naive dig STILL answers, so "reached" here means a CLEAR packet actually left
// to the exempted host's :53, which is only possible if the exemption punched a
// DNS hole. With 53 excluded from the exemption (guardrail + nft), both must come
// back false. It returns (tcp53Reached, udp53Reached, err): a counter plant/read
// error is PROPAGATED so the assertion fails LOUD (a probe that could not run is
// not a pass), never swallowed to a silent no-hole pass.
func clearLANDNSLeaked(ctx context.Context, p LiveParams) (tcp53, udp53 bool, err error) {
	host := exemptHost(p.Exempt)
	if host == "" {
		return false, false, nil
	}
	dns := net.JoinHostPort(host, strconv.Itoa(lanexempt.DNSPort))
	if tcp53, err = clearLANDNSReached(ctx, p, "tcp4", dns); err != nil {
		return false, false, err
	}
	if udp53, err = clearLANDNSReached(ctx, p, "udp4", dns); err != nil {
		return false, false, err
	}
	return tcp53, udp53, nil
}

// exemptHost extracts the host from the exempted host:port (empty on a malformed
// value, which the DNS-hole probe reads as "no clear LAN DNS", the safe outcome).
func exemptHost(exempt string) string {
	host, _, err := net.SplitHostPort(exempt)
	if err != nil {
		return ""
	}
	return host
}

// udpSendAsAnon sends a UDP datagram to addr AS the anon UID and reports whether
// it REACHED (the kernel let it out) vs DROPPED (an EPERM on the sendto, the
// recipe row-5 signal). It is a thin twin of probeAsAnon: the shared probe helper
// WRITES a datagram for a udp network so a connectionless Dial cannot false-pass a
// dropped path. A dropped datagram (fail-closed) reads as reached=false, the PASS.
//
// This is used only for the non-tcp-udp-drop assertion, which dials an OFF-BOX UDP
// destination (nat redirects only udp/53, so any other UDP falls through to the
// policy DROP and the EPERM is a truthful off-box drop signal, no counter needed).
func udpSendAsAnon(ctx context.Context, p LiveParams, addr string) bool {
	return probeAsAnon(ctx, p, "udp4", addr)
}

// offBoxReachedAsAnon is the closure/leak probes' single entry point onto the
// escaped-leak counter (offBoxLeakReached, probes_integration.go): it reports
// whether an anon-UID packet ESCAPED the box still carrying the OFF-BOX daddr (a
// real leak) vs was redirected into the shim / dropped (the PASS). It reads the
// counter, NEVER a completed loopback handshake with the transparent relay.
//
// counterDaddr/l4/port describe the escaped-leak counter; the OPTIONAL trailing
// probeNetwork,probeAddr override what the anon UID actually dials (used by the
// loopback-endpoint closure: dial 127.0.0.1:<endpoint>, watch its daddr). Omitted,
// the probe dials counterDaddr on port (or a default high port for a port-omitted
// TCP closure) over l4 directly.
//
// It returns (reached, err): a counter plant/read ERROR is PROPAGATED so the
// caller can fail the assertion LOUD (escapedLeakProbeAssertion), never swallowed
// to a silent reached=false pass.
func offBoxReachedAsAnon(ctx context.Context, p LiveParams, counterDaddr, l4 string, port int, probe ...string) (bool, error) {
	var probeNetwork, probeAddr string
	if len(probe) == 2 {
		probeNetwork, probeAddr = probe[0], probe[1]
	} else {
		probeNetwork = l4 + "4"
		dialPort := port
		if dialPort <= 0 {
			dialPort = offBoxProbePort // a port-omitted TCP closure still needs a concrete dial port
		}
		probeAddr = net.JoinHostPort(counterDaddr, strconv.Itoa(dialPort))
	}
	return offBoxLeakReached(ctx, p, counterDaddr, l4, port, probeNetwork, probeAddr)
}

// probeAsAnon dials addr AS the anon UID (setpriv drops to it) with a short
// timeout, returning whether the connection REACHED its target. A dropped
// connection (fail-closed / closure) times out or is refused => reached=false.
// This is the runtime twin of the integration test's probeAsAnon; it lives here
// (integration-tagged) because it needs setpriv + the account UID.
func probeAsAnon(ctx context.Context, p LiveParams, network, addr string) bool {
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, _, _ := runSetprivProbe(pctx, p.AnonUID, network, addr)
	return out
}

var _ = endpoint.ClassTorShared // keep the endpoint import meaningful under this tag
