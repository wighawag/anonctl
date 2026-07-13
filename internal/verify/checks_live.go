package verify

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/shim"
)

// icmpProbeTarget is the off-box address the icmp-drop probe pings AS the anon
// UID: a TEST-NET-1 (RFC 5737) documentation address that is safe to name and
// never a real host. The probe never depends on it replying: a dropped ping (the
// PASS) and an unreachable-but-not-dropped host both yield no reply, so the probe
// reads whether the anon UID could EMIT ICMP at all, which the policy DROP forbids.
const icmpProbeTarget = "192.0.2.1"

// probeExecBudget is the outer deadline probeAsAnon puts on the setpriv+shim exec.
// It MUST exceed shim.ProbeTimeout (the shim's own dial timeout): a silently-dropped
// SYN with no fast RST (the leak-drop-v6 PASS) burns the shim's FULL dial window,
// and an EQUAL outer deadline SIGKILLs the shim before it prints its DROPPED verdict
// -> empty output the harness misreads as "the probe could not run" (the false FAIL
// this margin closes). The +1s covers the setpriv fork/exec + privdrop that runs
// BEFORE the shim's dialer even starts its clock, mirroring the icmp-drop probe's
// `ping -W 2` under a 3s context.
var probeExecBudget = shim.ProbeTimeout + 1*time.Second

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

// nonExemptLoopbackProbe is the NON-shim, NON-exempt loopback destination the
// bypass-loopback-closure probe dials AS the anon UID (closure a). 127.0.0.2 is
// still 127.0.0.0/8 (so it is governed by the broad loopback drop) but is neither
// the shim's 127.0.0.1 ports nor an operator-exempted loopback service, so a
// counter keyed on this daddr:port proves closure (a) directly: a redirected packet
// has its daddr/dport rewritten to the shim relay (counter stays 0 => PASS), a
// genuine escape keeps 127.0.0.2:port (FAIL). This replaces the old off-box target
// so the probe now dials a real NON-exempt loopback port, per the loopback-exemption
// task: with a loopback exemption active, EVERY OTHER loopback port must still drop.
const (
	nonExemptLoopbackProbe     = "127.0.0.2"
	nonExemptLoopbackProbePort = 9999
)

// LiveChecks is the REAL assertion set: it stands up live probes AS the anon UID
// against the fail-closed ruleset the nftables task installed, and feeds their
// outcomes to the PURE assertion decisions in verify.go. It is compiled into
// EVERY build (it is runtime behaviour, like `add`/`rm`, not a test): the probing
// needs root + setpriv + the installed shim probe binary + a live endpoint, and
// FAILS LOUD at runtime when it lacks any of them (a probe that could not run is
// not a pass), never a silent green. Only the SLOW/PRIVILEGED *test* files stay
// behind the `integration` build tag.
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
// needsHostBaseline reports whether the anonymized-exit probe must take the DIRECT
// host-IP baseline (the request that reveals the REAL IP to the echo provider). It
// is needed ONLY when the exit-differs-from-host diff is the actual proof of forced
// egress: any non-tor-shared endpoint (where the diff is the ONLY available proof),
// or a tor-shared endpoint under --skip-tor-exit-check (which WAIVES the Tor-exit
// confirmation, so the diff becomes the fallback proof). On the tor-shared DEFAULT
// path the exit is proven by the Tor-exit confirmation (fetched over Tor, itself
// anonymized), so the identifying direct request is skipped. Pure so the policy is
// unit-tested without a socket.
func needsHostBaseline(class endpoint.ShareClass, skipTorCheck bool) bool {
	return class != endpoint.ClassTorShared || skipTorCheck
}

func LiveChecks(ctx context.Context, p LiveParams) []Check {
	checks := []Check{
		{Name: AssertAnonymizedExit, Run: func(ctx context.Context) Assertion {
			// The DIRECT host-IP baseline reveals the REAL IP to the echo provider, so we
			// only fetch it when the host-diff is actually the proof we need. On the Tor
			// DEFAULT path the exit is proven by the Tor-exit CONFIRMATION (fetched OVER
			// Tor, itself anonymized), which is a real positive proof and already a hard
			// requirement, so the host-diff is redundant and the identifying direct request
			// is skipped. It runs only when the diff is the ONLY (or the fallback) proof:
			// a non-tor-shared endpoint, or a tor-shared endpoint with --skip-tor-exit-check
			// (which WAIVES the Tor confirmation). See
			// work/notes/ideas/host-ip-fetch-off-by-default-and-verify-on-add.md.
			needHostBaseline := needsHostBaseline(p.Class, p.SkipTorExitCheck)
			var hostIP string
			if needHostBaseline {
				var herr error
				hostIP, herr = hostExitIP(ctx)
				if herr != nil {
					return Assertion{Name: AssertAnonymizedExit, Err: herr}
				}
			}
			exitIP, ev, eerr := forcedExitIP(ctx, p)
			if eerr != nil {
				return Assertion{Name: AssertAnonymizedExit, Err: eerr}
			}
			return AnonymizedExitAssertion(hostIP, exitIP, ev, p.Class, p.SkipTorExitCheck)
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
			reached, err := probeAsAnon(ctx, p, "tcp6", "[::1]:1")
			if err != nil {
				return Assertion{Name: AssertLeakDropV6, Err: err}
			}
			return LeakDropAssertion("v6", reached)
		}},
		{Name: AssertBypassLoopbackClosure, Run: func(ctx context.Context) Assertion {
			// Closure (a): the anon UID must reach ONLY its own shim loopback ports; every
			// OTHER 127.0.0.0/8 destination must be redirected-into-the-shim-or-dropped,
			// never reached DIRECTLY. We dial a NON-shim, NON-exempt loopback port
			// (127.0.0.2:port) AS the anon UID and watch the escaped-leak counter keyed on
			// that daddr AND port: a redirected packet has BOTH rewritten to the shim relay
			// (no match, PASS); a genuine DIRECT reach to this non-exempt loopback keeps
			// 127.0.0.2:port and moves the counter (FAIL). Keying on the loopback daddr:port
			// (not off-box, and not any-port 127.0.0.1) is load-bearing here: it proves the
			// exemption did NOT widen loopback, since a real loopback listener on the exempt
			// port is reachable (split-tunnel-tight) while THIS non-exempt loopback port is
			// not. A counter plant/read error fails LOUD (a probe that could not run is not
			// a pass).
			reached, err := offBoxReachedAsAnon(ctx, p, nonExemptLoopbackProbe, "tcp", nonExemptLoopbackProbePort, "tcp4", net.JoinHostPort(nonExemptLoopbackProbe, strconv.Itoa(nonExemptLoopbackProbePort)))
			return escapedLeakProbeAssertion(AssertBypassLoopbackClosure, "the anon UID reaching a non-shim, non-exempt loopback port", reached, err)
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
			// safe outcome), it reads whether the anon UID could EMIT ICMP at all. A
			// MISSING ping/setpriv fails the assertion LOUD (not a silent reached=false
			// pass): a probe that could not run is not a pass.
			reached, err := pingAsAnon(ctx, p, icmpProbeTarget)
			if err != nil {
				return Assertion{Name: AssertICMPDrop, Err: err}
			}
			return ICMPDropAssertion(reached)
		}},
		{Name: AssertNonTCPUDPDrop, Run: func(ctx context.Context) Assertion {
			// Tails leak-catalogue row 5: raw non-53 UDP AND specifically UDP/443 (QUIC)
			// from the anon UID must be DROPPED (SOCKS carries TCP only). Both dial an
			// off-box UDP destination AS the anon UID; a dropped datagram is refused /
			// times out => reached=false => PASS.
			// A MISSING setpriv/shim probe binary fails the assertion LOUD (not a silent
			// reached=false pass): a probe that could not run is not a pass.
			rawUDP := net.JoinHostPort(udpProbeHost, strconv.Itoa(udpRawProbePort))
			quicUDP := net.JoinHostPort(udpProbeHost, "443")
			raw, err := udpSendAsAnon(ctx, p, rawUDP)
			if err != nil {
				return Assertion{Name: AssertNonTCPUDPDrop, Err: err}
			}
			quic, err := udpSendAsAnon(ctx, p, quicUDP)
			if err != nil {
				return Assertion{Name: AssertNonTCPUDPDrop, Err: err}
			}
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
			// A MISSING setpriv/shim probe binary fails the assertion LOUD, never a silent
			// reached=false (which would misreport the exemption as broken for a tool reason).
			exemptReached, err := probeAsAnon(ctx, p, "tcp4", p.Exempt)
			if err != nil {
				return Assertion{Name: AssertSplitTunnelTight, Err: err}
			}
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
func udpSendAsAnon(ctx context.Context, p LiveParams, addr string) (bool, error) {
	return probeAsAnon(ctx, p, "udp4", addr)
}

// offBoxReachedAsAnon is the closure/leak probes' single entry point onto the
// escaped-leak counter (offBoxLeakReached, probes_live.go): it reports
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
// This is the runtime twin of the integration test's probeAsAnon; it needs
// setpriv + the installed shim probe binary + the account UID.
//
// A probe that could NOT RUN (setpriv / shim probe binary missing) returns a LOUD
// error, never a silent reached=false (which a drop assertion would read as a
// PASS): a probe that could not run is not a pass.
//
// The outer deadline MUST exceed the shim's own dial timeout (shim.ProbeTimeout),
// or the two race: a dropped SYN with no fast RST (the leak-drop-v6 PASS) burns the
// shim's FULL dial window, and if OUR context fires at the same instant exec would
// SIGKILL the shim before it printed its DROPPED verdict, yielding empty output the
// harness then MISREADS as "the probe could not run" (a false FAIL of a healthy
// host: the equal 3s/3s collision). We give a 1s margin over shim.ProbeTimeout for
// the setpriv fork/exec + privdrop that runs BEFORE the shim's dialer even starts
// its clock, mirroring the icmp-drop probe's `ping -W 2` under a 3s context. The
// drop assertions still resolve fast when the path is a quick EPERM/RST; the margin
// only matters for the genuinely-silent-drop case that must be allowed to time out
// and PRINT its DROPPED. The one REACHABILITY use (split-tunnel-tight's
// exemptReached) dials a DIRECT LAN host that answers well inside the window on a
// healthy host. The Tor-round-trip checks (anonymized-exit, dns-remote) do NOT use
// this helper and keep their generous curl/http timeouts.
func probeAsAnon(ctx context.Context, p LiveParams, network, addr string) (bool, error) {
	pctx, cancel := context.WithTimeout(ctx, probeExecBudget)
	defer cancel()
	reached, _, err := runSetprivProbe(pctx, p.AnonUID, network, addr)
	return reached, err
}
