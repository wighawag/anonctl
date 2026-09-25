package verify

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/wighawag/anonctl/internal/nssbypass"
)

// dnsControlWindow is how long the probes watch an IDLE account before running the
// lookup, to establish that the counters are quiet and therefore that what they
// record next belongs to the probe. It is short because it only has to catch a
// CONCURRENT emitter, not a rare one: a process resolving names does so
// repeatedly, and a single stray query landing exactly between the control read
// and the probe is caught by nothing here. This MITIGATES the attribution gap
// described on crossTalk; it does not close it.
const dnsControlWindow = 300 * time.Millisecond

// The DNS confinement assertions: PURE decisions over MEASURED evidence.
//
// WHAT THIS REPLACES, and why it is the highest-stakes change in this file. The
// previous `dns-remote` evidence was a successful forced fetch of a name, after
// which the probe returned `hostSaw=false` HARDCODED, reasoning in a comment that
// "the anon UID cannot do plaintext DNS off-box (udp/53 is redirected to the shim,
// tcp/53 too), so the name was resolved proxy-side and the host resolver was never
// asked". That premise was false in two independent ways on a real host, and the
// check reported clean precisely when it should not:
//
//  1. the account's getaddrinfo never used the account's own sockets at all (an
//     nscd-compatible daemon resolved it in another process under another uid, which
//     `meta skuid` cannot match), and
//  2. the account's own DNS path was broken end to end (the redirect fired, the shim
//     answered over Tor, and a host-owned input filter dropped the un-NATed reply),
//     so the leak was the ONLY reason the account had working DNS.
//
// A successful fetch proves a name resolved SOMEHOW. It never proves which
// resolver answered. So all three assertions below rest on packet counters keyed
// on the ACCOUNT's own sockets plus a round-trip answer, never on an inference
// from the rules anonctl installed. See work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md
// and docs/adr/0011.

// The counter keys the DNS probes plant and read. They are nft rule COMMENTS, so
// they appear verbatim in `nft list table` output and are parsed back out by
// parseCommentedCounters. Each names exactly one question.
const (
	// dnsCounterAnonUDP53 / dnsCounterAnonTCP53: did a DNS query leave on a socket
	// OWNED BY THE ACCOUNT at all? Planted BEFORE the nat hook (output priority
	// -300), so it sees the query with its original dport 53 whether or not the
	// redirect works. Zero while a lookup demonstrably happened means the lookup was
	// performed by somebody else: the NSS bypass, measured.
	dnsCounterAnonUDP53 = "anon-udp53"
	dnsCounterAnonTCP53 = "anon-tcp53"
	// dnsCounterTowardShimUDP / dnsCounterTowardShimTCP: did the query survive the
	// redirect and head for the shim's loopback DNS port? Planted AFTER the nat hook
	// (output priority 50), where a redirected packet carries the rewritten daddr.
	dnsCounterTowardShimUDP = "toward-shim-udp"
	dnsCounterTowardShimTCP = "toward-shim-tcp"
	// dnsCounterShimReply: did the SHIM emit an answer? Planted before the nat hook
	// so the reply is still on its shim source port (conntrack un-NATs it back to the
	// nameserver's address later). This is what separates "the shim never answered"
	// from "the shim answered and the answer was destroyed on the way back".
	dnsCounterShimReply = "shim-reply"
)

// dnsRcodeServfail is the rcode the shim's forwarder returns when it could not
// resolve over the endpoint. It is called out by name because it is the one answered
// rcode that must NOT pass `dns-forced-path-answers`.
const dnsRcodeServfail = 2

// DNSEvidence is the MEASURED evidence behind the three DNS assertions. Every
// boolean here is an observation (a counter that moved, a probe that answered),
// never an inference from the installed ruleset.
type DNSEvidence struct {
	// Probe is the unique, never-before-seen name the probes looked up. Uniqueness is
	// load-bearing: a cached answer anywhere (nscd's own cache, a forwarder's) would
	// let a lookup complete with no query on any socket, which would read as a bypass
	// that had already happened rather than one happening now.
	Probe string
	// Nameserver is the first nameserver from the host's resolver configuration: the
	// address the account's own DNS is aimed at, and therefore the address the
	// round-trip probe queries.
	Nameserver string
	// Providers are the out-of-process resolution paths detected on this host. They
	// make a failure ACTIONABLE; they are never the authority (the counters are).
	Providers []nssbypass.Provider
	// ProviderErr records that the detector could not read something, so "none
	// detected" is never silently reported as "none exist".
	ProviderErr string

	// NSSResolved / NSSAnswer: the account's NSS path (getaddrinfo, what a real
	// program uses) returned an answer for the probe name.
	NSSResolved bool
	NSSAnswer   string
	// AccountEmittedQuery: during the NSS lookup, a DNS query left a socket owned by
	// the ACCOUNT. False while the lookup completed is the decisive bypass proof.
	AccountEmittedQuery bool
	// NSSReachedShim: during the NSS lookup, a query reached the shim's loopback DNS
	// port (it survived the redirect).
	NSSReachedShim bool

	// ForcedAnswered / ForcedDetail: a raw query (no NSS) sent from the ACCOUNT's own
	// socket to Nameserver came back with an answer of any rcode.
	ForcedAnswered bool
	ForcedDetail   string
	// ForcedRcode is that answer's rcode, or -1 when it could not be read. It is
	// recorded separately because ONE rcode is not evidence of a working path: the shim
	// answers SERVFAIL when it could not resolve over the endpoint (a dead endpoint, or
	// an exchange that outran its deadline). That is the fail-closed path REPORTING
	// itself, and counting it as "the account has working, anonymized DNS" would be the
	// same class of error as the inferred verdict this file was built to remove.
	ForcedRcode int
	// ForcedReachedShim / ShimReplied: the same query's packet-level fate.
	//
	// ShimReplied deserves its exact reading, because a failure message was once written
	// on a stronger one: it is a counter proving only that A packet left the shim's DNS
	// port during the window, which glibc's own retries can satisfy. That is not "this
	// query was answered": a reply to an earlier query still in flight (a glibc retry, or
	// the NSS probe that runs just before this one) lands in the same window and moves the
	// same counter. The failure detail is written to that weaker, true reading.
	ForcedReachedShim bool
	ShimReplied       bool
	// ForcedAttempts is how many times the round trip was measured before the verdict
	// (see forcedRoundTripAttempts). It is reported in the detail, because "this failed
	// twice" and "this failed once" justify different next steps.
	ForcedAttempts int
	// ForcedEarlier holds the probe detail of each attempt BEFORE the last, so a
	// verdict drawn from the last attempt still reports what the earlier ones saw.
	ForcedEarlier []string
	// NameserverDefaulted records that the host declares no nameserver, so Nameserver
	// is glibc's 127.0.0.1 fallback rather than a configured value. It is reported,
	// not failed: that host's account DNS works, and loopback is the shape the
	// redirect serves best.
	NameserverDefaulted bool
}

// dnsPathCounterRuleset renders the throwaway nft table the DNS probes plant: two
// policy-ACCEPT chains of counter-only rules, one before the nat hook and one
// after it. It observes; it never changes forcing, and it is deleted after each
// probe. It is pure so the exact rule shapes are unit-tested with no root.
//
// The two priorities are the whole point. Output hooks run in priority order, so a
// chain at -300 sees the packet as the ACCOUNT emitted it (original dport 53, and
// a shim reply still on its shim source port), while a chain at 50 sees it AFTER
// the account's nat_out rewrote the destination (dstnat, -100). One chain alone
// cannot tell "the account never emitted a query" from "the query was emitted and
// the redirect did not fire": the pair can, and those are two different bugs with
// two different fixes.
//
// The table is `inet`, so the PRE chain counts a v4 and a v6 query with one rule
// and a v6-only lookup cannot hide behind a v4 counter. The POST chain is v4-only
// by necessity, not oversight: it matches `ip daddr 127.0.0.1` because that is
// where the redirect actually sends the query (an inet `redirect` rewrites a v6
// packet to ::1, where the shim does not listen and closure (a) drops it). So a v6
// query moves the PRE counter and not the POST one, which reads as "emitted but
// never reached the shim" -- the truthful verdict for a host whose forced DNS path
// is v6.
func dnsPathCounterRuleset(table string, anonUID, shimUID, dnsPort int) string {
	return fmt.Sprintf(`table inet %s {
    chain pre {
        type filter hook output priority -300; policy accept;
        meta skuid %d udp dport 53 counter comment "%s"
        meta skuid %d tcp dport 53 counter comment "%s"
        meta skuid %d udp sport %d counter comment "%s"
    }
    chain post {
        type filter hook output priority 50; policy accept;
        meta skuid %d ip daddr 127.0.0.1 udp dport %d counter comment "%s"
        meta skuid %d ip daddr 127.0.0.1 tcp dport %d counter comment "%s"
    }
}
`,
		table,
		anonUID, dnsCounterAnonUDP53,
		anonUID, dnsCounterAnonTCP53,
		shimUID, dnsPort, dnsCounterShimReply,
		anonUID, dnsPort, dnsCounterTowardShimUDP,
		anonUID, dnsPort, dnsCounterTowardShimTCP,
	)
}

// hostDNSCounterRuleset renders the counters for the HOST-LEVEL question "does
// glibc perform `hosts` lookups in the calling process on this box?". It watches
// ONE uid's own sockets for a DNS query and nothing else: there is no shim and no
// redirect involved, because the question is about glibc's routing, not about any
// account's forcing.
//
// The question is uid-INDEPENDENT (whether glibc consults an nscd socket or a
// delegating NSS module is a property of the host's configuration, not of who is
// asking), which is what lets `add` answer it BEFORE the account it is about to
// provision exists, by measuring with its own uid.
func hostDNSCounterRuleset(table string, uid int) string {
	return fmt.Sprintf(`table inet %s {
    chain pre {
        type filter hook output priority -300; policy accept;
        meta skuid %d udp dport 53 counter comment "%s"
        meta skuid %d tcp dport 53 counter comment "%s"
    }
}
`, table, uid, dnsCounterAnonUDP53, uid, dnsCounterAnonTCP53)
}

// parseCommentedCounters reads an `nft list table` dump and returns each commented
// counter's packet count by comment key. A line it cannot parse is simply absent
// from the map, and an absent key reads as "did not move" at every call site,
// which is the SAFE direction for the two bypass assertions (an unreadable counter
// never manufactures a pass: `AccountEmittedQuery` false is the FAILING side).
func parseCommentedCounters(listed string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(listed, "\n") {
		i := strings.Index(line, "counter packets ")
		j := strings.Index(line, `comment "`)
		if i < 0 || j < 0 || j < i {
			continue
		}
		key := line[j+len(`comment "`):]
		if k := strings.Index(key, `"`); k >= 0 {
			key = key[:k]
		}
		fields := strings.Fields(line[i:])
		if len(fields) < 3 {
			continue
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		out[key] = n
	}
	return out
}

// dnsCounterKeys is every counter the DNS probes plant: the set a CONTROL window
// checks for cross-talk.
var dnsCounterKeys = []string{
	dnsCounterAnonUDP53, dnsCounterAnonTCP53,
	dnsCounterTowardShimUDP, dnsCounterTowardShimTCP,
	dnsCounterShimReply,
}

// crossTalk reports whether ANOTHER DNS exchange belonging to this account moved a
// counter during a window in which the probe did nothing.
//
// WHY THIS EXISTS, and it is the subtlest thing in this file. The planted rules
// match `meta skuid <anonUID> ... dport 53`: they count the ACCOUNT's DNS, not
// THIS PROBE's DNS. Nothing in a counted packet ties it to the probe's name or its
// socket. So if any other process running as the account emits a DNS query while
// the probe runs, the counter moves for a reason that has nothing to do with the
// lookup under test, `AccountEmittedQuery` becomes true, and dns-remote plus
// dns-nss-not-bypassed both PASS on a host where NSS is bypassing the account's
// sockets for every name. That is the false green this whole change exists to
// remove, rebuilt one level down.
//
// It is not hypothetical on the hosts that matter. A Go binary resolves with its
// own pure-Go resolver, reading resolv.conf and emitting its own UDP: it bypasses
// NSS entirely and still moves the counter. The same goes for a musl-linked tool
// or a stray `dig`. And `verify` is documented as "re-run after any change", i.e.
// typically while the account is in use.
//
// The mitigation is a CONTROL WINDOW of comparable length in which the probe does
// nothing: if the account's counters move there, the run cannot attribute what
// follows and must say so. An unattributable measurement is reported as a probe
// that could not run (a LOUD error), never as a pass, which keeps the failure on
// the side the rest of this tool always errs to.
//
// Be precise about what this does NOT do: it catches a CONCURRENT emitter, which
// is what a resolving process is (it queries repeatedly), but a single stray query
// landing between the control read and the probe is caught by nothing here. Exact
// attribution needs the probe's packets to be distinguishable in the rule itself
// (matching the socket's cgroup, so it covers UDP and TCP alike); that is a real
// follow-up, not a refinement of this.
func crossTalk(control map[string]int) bool {
	return counterKeyMoved(control, dnsCounterKeys...)
}

// crossTalkError is the message for an unattributable run. It says plainly that
// nothing was proven, because "we could not tell" must never read as "we found a
// leak", nor as "it is fine".
func crossTalkError(control map[string]int) error {
	var moved []string
	for _, k := range dnsCounterKeys {
		if control[k] > 0 {
			moved = append(moved, fmt.Sprintf("%s=%d", k, control[k]))
		}
	}
	return fmt.Errorf("the DNS measurement could not be attributed: another process running as this account emitted DNS during the control window (%s), "+
		"and these counters cannot tell its packets from the probe's. NOTHING is proven either way by this run. "+
		"Re-run with the account idle (stop what is running as it, or verify before starting a session)", strings.Join(moved, ", "))
}

// counterKeyMoved reports whether the named counter recorded a packet.
func counterKeyMoved(counters map[string]int, keys ...string) bool {
	for _, k := range keys {
		if counters[k] > 0 {
			return true
		}
	}
	return false
}

// DNSRemoteAssertion decides `dns-remote`: the account's OWN name resolution is
// carried into the shim (and therefore resolved remotely, over the endpoint),
// rather than being performed anywhere else.
//
// The evidence is the NSS probe, because NSS is the path a real program takes. A
// raw query proves what the kernel does with a packet; only the NSS path proves
// what happens when the account actually looks a name up.
func DNSRemoteAssertion(ev DNSEvidence) Assertion {
	a := Assertion{Name: AssertDNSRemote}
	switch {
	case ev.NSSReachedShim:
		a.Ok = true
		// Say ONLY what was measured. "...so it resolved remotely via the endpoint" went
		// one step further than the counter supports: what was observed is that a packet
		// reached the shim's loopback DNS port. Whether the shim then resolved anything is
		// dns-forced-path-answers' question, and on the measured host the stronger sentence
		// would have printed while the account had no working DNS at all.
		a.Detail = fmt.Sprintf("the account's own lookup of %s was carried into the shim (measured at the shim's loopback DNS port), so its resolution goes through the forced path rather than around it", ev.Probe)
	case !ev.AccountEmittedQuery && ev.NSSResolved:
		a.Detail = fmt.Sprintf("the account resolved %s WITHOUT any query leaving its own sockets: something else resolved it (see dns-nss-not-bypassed). Its DNS is not going through the anonymizer", ev.Probe)
	case !ev.AccountEmittedQuery:
		a.Detail = fmt.Sprintf("looking up %s produced NO DNS query on any socket owned by the account, so nothing was carried into the shim: the account's resolution is happening elsewhere, or not at all (see dns-nss-not-bypassed)", ev.Probe)
	default:
		a.Detail = fmt.Sprintf("the account emitted a DNS query for %s but it never reached the shim's loopback DNS port: the redirect is not in effect, so its DNS is neither forced nor working", ev.Probe)
	}
	return a
}

// DNSNSSNotBypassedAssertion decides `dns-nss-not-bypassed`: the account's name
// resolution happens ON THE ACCOUNT'S OWN SOCKETS, where per-UID forcing can
// govern it, rather than in another process under another uid.
//
// THE MEASUREMENT IS THE AUTHORITY, not the detector. The probe name is unique, so
// no cache anywhere can answer it and any working resolution MUST produce a query
// somewhere: a lookup that completed while the account's own sockets stayed silent
// is proof that another process did the work. The detected providers only NAME the
// likely culprit and carry the remedy; an unknown daemon is caught just the same.
//
// A detector hit with a CLEAN measurement passes, and says so: if glibc did put
// the query on the account's own socket, then that provider is not in this host's
// hosts path in practice (a cache it never consults cannot serve the account
// either), and failing on the detector alone would be crying wolf over a
// measurement that disagrees with it.
func DNSNSSNotBypassedAssertion(ev DNSEvidence) Assertion {
	a := Assertion{Name: AssertDNSNSSNotBypassed}
	broad := nssbypass.Broad(ev.Providers)
	if !ev.AccountEmittedQuery {
		if ev.NSSResolved {
			a.Detail = fmt.Sprintf("the account resolved %s (answer: %s) while NO DNS query left any socket it owns: the lookup ran in another process under another uid, which `meta skuid` cannot govern",
				ev.Probe, ev.NSSAnswer)
		} else {
			a.Detail = fmt.Sprintf("looking up %s put no DNS query on any socket owned by the account: if it resolves at all, it resolves out of process, where the forcing cannot reach it", ev.Probe)
		}
		// CLOSE THE ONE REMAINING INFERENCE. "No query on the account's sockets" is
		// decisive only if the account's sockets were CAPABLE of carrying one: without
		// that, a reader can still wonder whether the lookup was attempted at all. The
		// round-trip probe already answers it from the same run, so cite it rather than
		// leave the gap: a raw query from the SAME uid that demonstrably reached the shim
		// proves the path works and that NSS chose a different one.
		if ev.ForcedReachedShim {
			a.Detail += ". A raw query from the same account DID reach the shim in this run, so its own sockets work and NSS is not using them"
		}
		if len(broad) > 0 {
			a.Detail += ". Detected: " + nssbypass.Names(broad)
		} else {
			a.Detail += ". No known provider was detected, so the delegating resolver is UNIDENTIFIED: check the host's nsswitch.conf and any nscd-protocol socket"
		}
		return a
	}
	a.Ok = true
	a.Detail = fmt.Sprintf("looking up %s put a DNS query on the account's OWN sockets, so resolution is governed by the forcing", ev.Probe)
	if len(broad) > 0 {
		a.Detail += ", despite " + nssbypass.Names(broad) + " being configured (the measurement is the authority; that provider is not serving this account's hosts lookups)"
	}
	if narrow := nssbypass.Narrow(ev.Providers); len(narrow) > 0 {
		// Honest residual, in the same spirit as no-uid-transition-egress's
		// explicitly-not-exhaustive framing: these answer only a bounded class of names
		// (.local, machine names), so they cannot carry the account's general traffic,
		// but a lookup in that class WOULD still be done by another uid.
		a.Detail += ". Residual (not covered by this probe): " + nssbypass.Names(narrow) + " answer a bounded name class out of process"
	}
	if ev.ProviderErr != "" {
		a.Detail += ". Note: " + ev.ProviderErr
	}
	return a
}

// DNSForcedPathAnswersAssertion decides `dns-forced-path-answers`: a DNS query
// from the account, through the redirect, actually COMES BACK.
//
// This is the assertion the old inferred check could never make, and the one that
// would have caught the measured host on its first run. Every packet-level signal
// there said the forcing worked: the rules were correct, the redirect fired, the
// query reached the shim, the shim resolved it over Tor. The account still had no
// DNS, because the answer is un-NATed back to the NAMESERVER's address before
// delivery and a host-owned input filter dropped it on that source address. The
// failure detail therefore distinguishes the three packet-level fates, because
// each has a different owner and a different fix.
//
// EACH DETAIL SAYS WHAT WAS MEASURED, AND ONLY THAT. The last fate's message used to
// assert the un-NAT-and-drop mechanism as established fact, which sent a real
// operator to `nft` and `conntrack` for a transient that was very likely inside
// anonctl's own forwarder (its upstream exchange deadline fired, silently, and the
// probe then waited out its whole window for an answer nobody would send:
// work/notes/observations/dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance.md).
// The counters cannot tell those apart, so the message now states the observation and
// ranks the candidates instead of picking one.
func DNSForcedPathAnswersAssertion(ev DNSEvidence) Assertion {
	a := Assertion{Name: AssertDNSForcedPathAnswers}
	server := ev.Nameserver
	if ev.NameserverDefaulted {
		server += " (glibc's default: the host declares no nameserver)"
	}
	switch {
	case ev.ForcedAnswered && ev.ForcedReachedShim && ev.ForcedRcode == dnsRcodeServfail:
		// THE SHIM ITSELF SAID IT COULD NOT RESOLVE. Without this case,
		// dns-forced-path-answers would have started PASSING on a dead endpoint, because any
		// rcode counted as ANSWERED: the shim now answers SERVFAIL instead of dropping a
		// query it cannot resolve, and "an answer came back" would have turned that honesty
		// into a green light for an account whose anonymizer is down. A SERVFAIL does prove
		// the packet path works in both directions, which is worth saying; it also proves
		// the lookup did not succeed.
		a.Detail = servfailDetail(server, ev)
		return a
	case ev.ForcedAnswered && ev.ForcedReachedShim:
		a.Ok = true
		a.Detail = fmt.Sprintf("a query from the account to %s went through the redirect into the shim and was ANSWERED (%s): the account has working, anonymized DNS", server, ev.ForcedDetail)
		if ev.ForcedAttempts > 1 {
			// A PASS THAT NEEDED THE RETRY SAYS SO. The retry exists to separate one lost
			// answer or one cold circuit from a broken path; it must never be the silent
			// reason a path passes. A healthy path passes on attempt 1, so an operator who
			// sees this line on every run has a path failing its first query every time, and
			// that is a finding, not a pass to be glad of.
			a.Detail += fmt.Sprintf(". It passed on attempt %d, NOT the first: one answer was lost or one circuit was cold. If this appears on every run, the first query is failing for a reason worth finding%s", ev.ForcedAttempts, earlierPhrase(ev.ForcedEarlier))
		}
		return a
	case ev.ForcedAnswered:
		// AN ANSWER IS NOT A PASS ON ITS OWN. Requiring only ForcedAnswered was the last
		// inferred verdict left in this file: a query that goes STRAIGHT to the nameserver
		// in the clear (the forcing table flushed, reordered, or replaced by another tool)
		// is answered too, and the old code called that "working, anonymized DNS" on
		// evidence that proves the opposite. The counter says which path carried it, so use
		// it for the verdict and not merely for the failure text.
		a.Detail = fmt.Sprintf("a query from the account to %s was ANSWERED WITHOUT passing through the redirect (%s): this query was served off the forced path, i.e. clear DNS straight to the nameserver. Check that the account's nat table is loaded and that nothing has reordered or replaced it", server, ev.ForcedDetail)
		return a
	}
	switch {
	case !ev.ForcedReachedShim:
		a.Detail = fmt.Sprintf("a query from the account to %s never reached the shim's loopback DNS port: the redirect is not in effect (%s)", server, ev.ForcedDetail)
		if hint := nameserverFamilyHint(ev.Nameserver); hint != "" {
			a.Detail += ". " + hint
		}
	case !ev.ShimReplied:
		a.Detail = fmt.Sprintf("a query from the account to %s reached the shim, which emitted NOTHING during the window%s (%s). A current shim answers every query it receives within its own deadline, with an answer or with a SERVFAIL naming the reason, so in order of likelihood: (1) the shim process is not serving (down, restarting or wedged: `systemctl status anonctl-shim@<account>`); (2) the RUNNING shim predates this anonctl (not restarted after an upgrade) and dropped a query it could not resolve in silence, which cannot say whether the endpoint was unreachable or the circuit slow: `systemctl restart anonctl-shim@<account>`, re-run verify, and a current shim will name the reason%s",
			server, attemptsPhrase(ev.ForcedAttempts), ev.ForcedDetail, earlierPhrase(ev.ForcedEarlier))
	default:
		// THE UN-NAT BRANCH, WORDED TO WHAT THE COUNTER PROVES. It used to assert the
		// un-NAT-and-drop mechanism as fact. But it fires on a counter proving only that A
		// packet left the shim's DNS port during the window, which glibc's own retries can
		// satisfy (and so can a late reply to the NSS probe that runs just before this one).
		// On the reporting host that sentence sent an operator to nft and conntrack for an
		// event inside anonctl's own forwarder. So it reports the observation and ranks.
		a.Detail = fmt.Sprintf("a query from the account to %s reached the shim and NO answer came back to the account within the window%s (%s). A packet did leave the shim's DNS port during the window, but that proves only that A packet left, not that this query was answered: glibc's own retries, and the lookup verify ran just before this one, can move the same counter. Which candidate is likelier depends on the RUNNING shim's version, and that is cheap to settle first: `systemctl restart anonctl-shim@<account>` and re-run verify. (1) If the shim is current, it answers every query within its deadline with an answer or a reasoned SERVFAIL, so a silent client means the reply was DESTROYED on the way back: conntrack un-NATs it to source %s before delivering it, and something on the host's input path drops it there. (2) If the shim predates this anonctl, it dropped a query it could not resolve in silence, because the endpoint was unreachable or because the circuit was slow, and it cannot say which. (3) Otherwise, something else on the account emitted DNS during the window%s",
			server, attemptsPhrase(ev.ForcedAttempts), ev.ForcedDetail, ev.Nameserver, earlierPhrase(ev.ForcedEarlier))
		if hint := replyDropHint(ev.Nameserver); hint != "" {
			a.Detail += ". For candidate (1) on this host: " + hint
		}
	}
	return a
}

// The failure tokens the shim attaches to a SERVFAIL as an RFC 8914 Extended DNS
// Error, and the probe reports verbatim in its detail. They are the contract between
// the two binaries (internal/shim/dnsfailure.go writes them), so they are matched
// exactly and never paraphrased.
const (
	shimFailEndpointUnreachable = "anonctl:endpoint-unreachable"
	shimFailEndpointRefused     = "anonctl:endpoint-refused"
	shimFailDeadline            = "anonctl:deadline-expired"
	shimFailStreamBroken        = "anonctl:stream-broken"
)

// servfailDetail words a SERVFAIL from the shim by its REASON, because the reasons
// call for opposite next moves: an unreachable endpoint means the anonymizer is down
// ("your Tor is down"), a deadline means it is up and the circuit was slow ("your
// circuit was slow"). Getting that wrong costs the operator the same hour the old
// un-NAT sentence did.
func servfailDetail(server string, ev DNSEvidence) string {
	head := fmt.Sprintf("a query from the account to %s went through the redirect into the shim, and the shim answered SERVFAIL%s (%s). The redirect and the shim are working and the account's DNS failed CLOSED, not open: ", server, attemptsPhrase(ev.ForcedAttempts), ev.ForcedDetail)
	var why string
	switch {
	case strings.Contains(ev.ForcedDetail, shimFailEndpointUnreachable):
		why = "the shim could not open a connection to the ENDPOINT at all, so the anonymizer (e.g. Tor) is DOWN or is not listening at the address this account's shim is configured with. Start it or correct the address, then re-run verify"
	case strings.Contains(ev.ForcedDetail, shimFailDeadline):
		why = "the endpoint accepted the shim's connection and the lookup RAN OUT OF TIME, so the anonymizer is up and its circuit was SLOW, which a cold circuit after idle routinely is"
		if ev.ForcedAttempts >= 2 {
			why += ". It happened on every attempt, which is more than one cold circuit: look at the endpoint's own health (for Tor, its log: bootstrap state, circuit build failures, clock skew)"
		} else {
			why += ". Re-run verify"
		}
	case strings.Contains(ev.ForcedDetail, shimFailEndpointRefused):
		why = "the endpoint is up and accepted the shim's connection, but could not reach the upstream resolver through it (for Tor: a circuit or an exit failed to connect). Re-run verify; if it persists, the configured upstream resolver may be unreachable from the anonymizer's exits"
	case strings.Contains(ev.ForcedDetail, shimFailStreamBroken):
		why = "the shim's stream to the upstream resolver died mid-exchange and a fresh one did not recover the query. Re-run verify"
	default:
		why = "no anonctl reason was attached, so the SERVFAIL came from the upstream resolver itself, which the shim passes through unchanged (or from a shim too old to name a reason). Re-run verify; if it persists, the upstream resolver is failing"
	}
	return head + why + earlierPhrase(ev.ForcedEarlier)
}

// earlierPhrase reports what the earlier attempts saw, when there were any, so a
// verdict built on the last attempt does not hide a DIFFERENT failure on the first
// (a slow circuit, then a dead endpoint, is two problems).
func earlierPhrase(earlier []string) string {
	if len(earlier) == 0 {
		return ""
	}
	return ". Earlier attempt(s): " + strings.Join(earlier, "; ")
}

// attemptsPhrase reports how many times the round trip was measured, because the
// number is what tells an operator whether to re-run verify or start reading the
// ruleset. It is silent about a single attempt so evidence built by hand (and every
// unit test) does not claim a measurement it did not make.
func attemptsPhrase(attempts int) string {
	if attempts < 2 {
		return ""
	}
	return fmt.Sprintf(", on %d separate attempts (so this is not one lost answer or one cold circuit)", attempts)
}

// nameserverFamilyHint names the v6 case, where the forced DNS path cannot work
// by construction: the shim's forwarder listens on 127.0.0.1, and an `inet`
// table's `redirect` rewrites a v6 packet's destination to ::1, where nothing
// listens and which the anon closure chain drops as part of closure (a). So an
// account whose resolver configuration names only v6 nameservers has no forced DNS
// path at all, and the fix is a host-side one (declare a v4 nameserver, or a
// loopback stub) rather than anything in the ruleset.
func nameserverFamilyHint(nameserver string) string {
	ip := net.ParseIP(nameserver)
	if ip == nil || ip.To4() != nil {
		return ""
	}
	return "The nameserver is IPv6, and the shim's DNS forwarder listens on 127.0.0.1 only: an `inet` redirect sends a v6 query to ::1, where nothing listens. Declare an IPv4 (or loopback) nameserver for this host"
}

// tailscaleCGNAT is the address range Tailscale uses for its own nodes and for
// MagicDNS (100.100.100.100).
var tailscaleCGNAT = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// replyDropHint names the KNOWN host-owned filter that produces the
// shim-answered-but-nothing-arrived shape, when the configured nameserver's
// address is the one that triggers it. It is a hint, not a diagnosis: anonctl
// measured that the answer was destroyed after the shim produced it, and this
// points at the first thing to look at.
//
// The known case is measured, not guessed: tailscaled installs an anti-spoofing
// rule that DROPS packets sourced from 100.64.0.0/10 arriving on any interface
// other than tailscale0, with a preceding accept for the node's own address. A
// nameserver inside that range (MagicDNS, 100.100.100.100) makes the un-NATed
// reply match it exactly: the query is accepted (its source is the node's own
// address), the answer is dropped (its source is MagicDNS's).
func replyDropHint(nameserver string) string {
	ip := net.ParseIP(nameserver)
	if ip == nil || !tailscaleCGNAT.Contains(ip.To4()) {
		return ""
	}
	return "The nameserver is inside Tailscale's 100.64.0.0/10 range, and tailscaled's `ts-input` chain drops packets sourced from that range arriving on any interface other than tailscale0, which is exactly what the un-NATed answer is. " +
		"anonctl cannot fix this without editing another tool's ruleset: point the host's resolver at a loopback address, or exclude the shim's replies in tailscaled's own configuration"
}
