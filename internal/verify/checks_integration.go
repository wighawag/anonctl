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

// LiveChecks (integration build) is the REAL assertion set: it stands up live
// probes AS the anon UID against the fail-closed ruleset the nftables task
// installed, and feeds their outcomes to the PURE assertion decisions in
// verify.go. It is compiled ONLY under the `integration` build tag (it needs root
// + setpriv + a live endpoint); the default build ships checks_default.go, which
// fails honestly instead of silently passing.
//
// It runs EVERY probe (RunVerify does not short-circuit) so the report is
// complete: the load-bearing leak drop (v4 AND v6), both bypass closures (a
// non-shim loopback dial, a direct endpoint dial), and, when a LAN exemption is
// active (p.Exempt != ""), the split-tunnel-tight assertion. The anonymized-exit
// and dns-remote assertions dial THROUGH the shim relay/DNS ports (as the anon UID
// would) and compare against the host baseline.
//
// The probes key on `meta skuid`, so they are run under setpriv --reuid to the
// anon UID; a dropped connection (fail-closed / closure) times out or is refused
// => reached=false, which the pure drop decision reads as a PASS.
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
			return LeakDropAssertion("v4", probeAsAnon(ctx, p, "tcp4", "127.0.0.1:1"))
		}},
		{Name: AssertLeakDropV6, Run: func(ctx context.Context) Assertion {
			return LeakDropAssertion("v6", probeAsAnon(ctx, p, "tcp6", "[::1]:1"))
		}},
		{Name: AssertBypassLoopbackClosure, Run: func(ctx context.Context) Assertion {
			nonShim := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.RelayPort+100))
			return BypassLoopbackClosureAssertion(probeAsAnon(ctx, p, "tcp4", nonShim))
		}},
		{Name: AssertBypassEndpointClosure, Run: func(ctx context.Context) Assertion {
			endpointAddr := net.JoinHostPort(p.EndpointHost, strconv.Itoa(p.EndpointPort))
			return BypassEndpointClosureAssertion(probeAsAnon(ctx, p, "tcp4", endpointAddr))
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
			exemptReached := probeAsAnon(ctx, p, "tcp4", p.Exempt)
			nonExemptReached := probeAsAnon(ctx, p, "tcp4", nonExemptLANOf(p.Exempt))
			return SplitTunnelTightAssertion(p.Exempt, exemptReached, nonExemptReached)
		}})
		checks = append(checks, Check{Name: AssertLANExemptionNotADNSHole, Run: func(ctx context.Context) Assertion {
			tcp53, udp53 := clearLANDNSLeaked(ctx, p)
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
// back false. It returns (tcp53Reached, udp53Reached).
func clearLANDNSLeaked(ctx context.Context, p LiveParams) (tcp53, udp53 bool) {
	host := exemptHost(p.Exempt)
	if host == "" {
		return false, false
	}
	dns := net.JoinHostPort(host, strconv.Itoa(lanexempt.DNSPort))
	tcp53 = clearLANDNSReached(ctx, p, "tcp4", dns)
	udp53 = clearLANDNSReached(ctx, p, "udp4", dns)
	return tcp53, udp53
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
func udpSendAsAnon(ctx context.Context, p LiveParams, addr string) bool {
	return probeAsAnon(ctx, p, "udp4", addr)
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
