package verify

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/nssbypass"
)

// The DNS confinement decisions, proven over MEASURED evidence. The cases that
// matter most are the two real-host shapes the previous (inferred) check could not
// express at all, and both are reconstructed here from the measurement that found
// them (work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md):
//
//   - the account resolves names while its OWN sockets stay silent (an
//     nscd-compatible daemon resolves in another process under another uid), and
//   - the account's own DNS path is packet-perfect and still returns nothing (the
//     shim answered; a host-owned input filter destroyed the un-NATed reply).
//
// Both used to report [PASS] dns-remote.

// healthyDNS is the evidence shape of an account whose DNS genuinely works through
// the forced path: the NSS lookup left on the account's own socket, it reached the
// shim, and a round trip to the configured nameserver came back.
func healthyDNS() DNSEvidence {
	return DNSEvidence{
		Probe:               "anonctl-probe-1.invalid",
		Nameserver:          "192.168.1.1",
		NSSResolved:         false,
		AccountEmittedQuery: true,
		NSSReachedShim:      true,
		ForcedAnswered:      true,
		ForcedDetail:        "rcode=3 answers=0",
		ForcedReachedShim:   true,
		ShimReplied:         true,
	}
}

func TestDNSAssertions_AllPassOnAHealthyForcedPath(t *testing.T) {
	ev := healthyDNS()
	for _, a := range []Assertion{DNSRemoteAssertion(ev), DNSNSSNotBypassedAssertion(ev), DNSForcedPathAnswersAssertion(ev)} {
		if !a.Ok {
			t.Fatalf("%s must PASS on a healthy forced path; got %+v", a.Name, a)
		}
	}
}

// THE REGRESSION THIS WHOLE CHANGE EXISTS FOR. The account resolved a name that
// nothing can have cached, and not one DNS query left a socket it owns. That is
// another process resolving on its behalf, and all three assertions must be RED:
// dns-remote (nothing was carried into the shim), dns-nss-not-bypassed (the
// decisive measurement), and, on the measured host, the forced path as well.
func TestDNSAssertions_FailWhenResolutionHappensInAnotherProcess(t *testing.T) {
	ev := DNSEvidence{
		Probe:               "anonctl-probe-2.invalid",
		Nameserver:          "100.100.100.100",
		NSSResolved:         true,
		NSSAnswer:           "100.71.110.44",
		AccountEmittedQuery: false, // the decisive signal: its own sockets stayed silent
		NSSReachedShim:      false,
		Providers: []nssbypass.Provider{{
			Name: "nscd/nsncd", Daemon: "nsncd", Scope: nssbypass.ScopeAllNames,
		}},
	}
	remote := DNSRemoteAssertion(ev)
	if remote.Ok {
		t.Fatalf("dns-remote must FAIL when the account's resolution never reached the shim; got %+v", remote)
	}
	nss := DNSNSSNotBypassedAssertion(ev)
	if nss.Ok {
		t.Fatalf("dns-nss-not-bypassed must FAIL when a lookup completed with no query on the account's own sockets; got %+v", nss)
	}
	// The failure has to NAME the daemon, or the operator cannot act on it.
	if !strings.Contains(nss.Detail, "nscd/nsncd") {
		t.Errorf("the failure detail must name the detected provider; got %q", nss.Detail)
	}
	if !strings.Contains(nss.Detail, "another process") {
		t.Errorf("the failure detail must state the mechanism; got %q", nss.Detail)
	}
}

// An UNIDENTIFIED bypass must still fail, and must say it is unidentified rather
// than implying anonctl knows which daemon did it. The measurement stands alone;
// the detector is only there to make the message actionable.
func TestDNSNSSNotBypassed_FailsHonestlyWhenNoProviderWasDetected(t *testing.T) {
	a := DNSNSSNotBypassedAssertion(DNSEvidence{
		Probe: "anonctl-probe-3.invalid", NSSResolved: true, NSSAnswer: "10.0.0.1",
		AccountEmittedQuery: false,
	})
	if a.Ok {
		t.Fatalf("an unexplained bypass must still FAIL; got %+v", a)
	}
	if !strings.Contains(a.Detail, "UNIDENTIFIED") {
		t.Errorf("the detail must admit the resolver is unidentified; got %q", a.Detail)
	}
}

// The detector is NOT the authority. If the measurement shows the query left on
// the account's own socket, a configured provider is not serving this account's
// hosts lookups, and failing on the detector alone would cry wolf over a
// measurement that disagrees with it.
func TestDNSNSSNotBypassed_MeasurementBeatsTheDetector(t *testing.T) {
	ev := healthyDNS()
	ev.Providers = []nssbypass.Provider{{Name: "nss-resolve", Daemon: "systemd-resolved", Scope: nssbypass.ScopeAllNames}}
	a := DNSNSSNotBypassedAssertion(ev)
	if !a.Ok {
		t.Fatalf("a clean MEASUREMENT must pass even with a provider configured; got %+v", a)
	}
	if !strings.Contains(a.Detail, "systemd-resolved") {
		t.Errorf("the pass must still disclose the configured provider; got %q", a.Detail)
	}
}

// A bounded-namespace provider (.local via avahi) is a residual, not a refusal: it
// cannot carry the account's general traffic, but it does resolve its own name
// class out of process, so the pass must SAY so instead of hiding it.
func TestDNSNSSNotBypassed_ReportsNarrowProvidersAsAResidual(t *testing.T) {
	ev := healthyDNS()
	ev.Providers = []nssbypass.Provider{{Name: "nss-mdns", Daemon: "avahi-daemon", Scope: nssbypass.ScopeNameClass}}
	a := DNSNSSNotBypassedAssertion(ev)
	if !a.Ok {
		t.Fatalf("a narrow provider must not fail the assertion; got %+v", a)
	}
	if !strings.Contains(a.Detail, "Residual") || !strings.Contains(a.Detail, "nss-mdns") {
		t.Errorf("a narrow provider must be reported as a residual; got %q", a.Detail)
	}
}

// THE SECOND REAL-HOST SHAPE: every packet-level signal is green (the redirect
// fired, the shim answered) and the account still has no DNS, because the answer
// was destroyed after conntrack un-NATed it back to the nameserver's address. The
// detail must say which of the three fates happened, since each has a different
// owner and a different fix.
func TestDNSForcedPathAnswers_FailsWhenTheShimAnsweredAndTheReplyVanished(t *testing.T) {
	a := DNSForcedPathAnswersAssertion(DNSEvidence{
		Probe: "anonctl-probe-4.invalid", Nameserver: "100.100.100.100",
		ForcedAnswered: false, ForcedDetail: "no answer: i/o timeout",
		ForcedReachedShim: true, ShimReplied: true,
	})
	if a.Ok {
		t.Fatalf("a query the account never got an answer to must FAIL; got %+v", a)
	}
	if !strings.Contains(a.Detail, "un-NAT") {
		t.Errorf("the detail must name the un-NAT of the reply as the mechanism; got %q", a.Detail)
	}
	// The measured host's culprit is nameable from the nameserver's address alone.
	if !strings.Contains(a.Detail, "tailscaled") || !strings.Contains(a.Detail, "100.64.0.0/10") {
		t.Errorf("a nameserver inside Tailscale's range must produce the ts-input hint; got %q", a.Detail)
	}
}

// The same failure with a nameserver OUTSIDE that range must not claim Tailscale
// is at fault: the hint is evidence-driven, not decoration.
func TestDNSForcedPathAnswers_DoesNotBlameTailscaleForAnOrdinaryNameserver(t *testing.T) {
	a := DNSForcedPathAnswersAssertion(DNSEvidence{
		Nameserver: "192.168.1.1", ForcedReachedShim: true, ShimReplied: true,
		ForcedDetail: "no answer: i/o timeout",
	})
	if strings.Contains(a.Detail, "tailscaled") {
		t.Errorf("the ts-input hint must only appear for a 100.64.0.0/10 nameserver; got %q", a.Detail)
	}
}

func TestDNSForcedPathAnswers_DistinguishesTheThreePacketFates(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ev         DNSEvidence
		wantDetail string
	}{
		{
			name:       "the redirect never fired",
			ev:         DNSEvidence{Nameserver: "1.1.1.1", ForcedReachedShim: false},
			wantDetail: "redirect is not in effect",
		},
		{
			name:       "the shim never answered",
			ev:         DNSEvidence{Nameserver: "1.1.1.1", ForcedReachedShim: true, ShimReplied: false},
			wantDetail: "never answered",
		},
		{
			// A host with no `nameserver` line is not a host without DNS: glibc falls back to
			// 127.0.0.1:53, which the redirect serves. It must be reported as the default it
			// is, and judged on the same counters as any other nameserver.
			name:       "glibc's default nameserver, redirect not in effect",
			ev:         DNSEvidence{Nameserver: "127.0.0.1", NameserverDefaulted: true},
			wantDetail: "glibc's default",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := DNSForcedPathAnswersAssertion(tc.ev)
			if a.Ok {
				t.Fatalf("must FAIL; got %+v", a)
			}
			if !strings.Contains(a.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", a.Detail, tc.wantDetail)
			}
		})
	}
}

// AN ANSWER IS NOT A PASS ON ITS OWN. A query that goes straight to the nameserver
// in the clear is answered too, so requiring only "an answer came back" would
// report clear DNS as "working, anonymized DNS" on evidence that proves the
// opposite. The counter says which path carried it, and the verdict must use it.
func TestDNSForcedPathAnswers_AnAnswerOffTheForcedPathIsAFailure(t *testing.T) {
	a := DNSForcedPathAnswersAssertion(DNSEvidence{
		Probe: "p.invalid.", Nameserver: "192.168.1.1",
		ForcedAnswered: true, ForcedDetail: "rcode=3 answers=0",
		ForcedReachedShim: false,
	})
	if a.Ok {
		t.Fatalf("an answer that never passed through the redirect must FAIL: it is clear DNS; got %+v", a)
	}
	if !strings.Contains(a.Detail, "clear DNS") {
		t.Errorf("the detail must name it as clear DNS; got %q", a.Detail)
	}
	// And the pass must require BOTH halves.
	both := DNSForcedPathAnswersAssertion(DNSEvidence{
		Nameserver: "192.168.1.1", ForcedAnswered: true, ForcedReachedShim: true, ForcedDetail: "rcode=3 answers=0",
	})
	if !both.Ok || !strings.Contains(both.Detail, "through the redirect") {
		t.Errorf("a query that went through the redirect AND was answered must pass, and say so; got %+v", both)
	}
}

// A v6-only nameserver cannot work through an inet `redirect` (it rewrites to ::1,
// where nothing listens and which closure (a) drops), so the failure must name
// that rather than leaving the operator to guess at the ruleset.
func TestDNSForcedPathAnswers_NamesTheIPv6NameserverCase(t *testing.T) {
	a := DNSForcedPathAnswersAssertion(DNSEvidence{Nameserver: "fd7a:115c:a1e0::53"})
	if a.Ok {
		t.Fatalf("must FAIL; got %+v", a)
	}
	if !strings.Contains(a.Detail, "IPv6") || !strings.Contains(a.Detail, "::1") {
		t.Errorf("the v6 nameserver case must be named; got %q", a.Detail)
	}
}

// --- the counter ruleset + parser the probes rest on ---

// The two chains at two priorities are the whole mechanism: one BEFORE the nat
// hook (so it sees the query as the account emitted it) and one AFTER (so it sees
// the redirect's effect). One chain alone cannot tell "the account never emitted a
// query" from "the redirect did not fire", and those are different bugs.
func TestDNSPathCounterRuleset_WatchesBothSidesOfTheNatHook(t *testing.T) {
	rs := dnsPathCounterRuleset("scratch", 8802, 413, 19053)
	for _, want := range []string{
		"type filter hook output priority -300; policy accept;",
		"type filter hook output priority 50; policy accept;",
		`meta skuid 8802 udp dport 53 counter comment "anon-udp53"`,
		`meta skuid 8802 tcp dport 53 counter comment "anon-tcp53"`,
		`meta skuid 413 udp sport 19053 counter comment "shim-reply"`,
		`meta skuid 8802 ip daddr 127.0.0.1 udp dport 19053 counter comment "toward-shim-udp"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("the planted ruleset must contain %q; got:\n%s", want, rs)
		}
	}
	// It must never DROP: it observes the live forcing, it does not change it.
	if strings.Contains(rs, "drop") {
		t.Errorf("the observation table must contain no drop:\n%s", rs)
	}
	// An inet table so a v6-only leak cannot hide behind a v4 counter.
	if !strings.HasPrefix(rs, "table inet scratch {") {
		t.Errorf("the table must be inet (v4+v6 in one ruleset); got:\n%s", rs)
	}
}

// Parsed against REAL `nft list table` output (captured on the measured host), so
// the parser is proven against the format it actually meets rather than one
// invented here.
func TestParseCommentedCounters_ReadsRealNftOutput(t *testing.T) {
	const listed = `table inet anonctl_verify_dnspath_123_1 {
	chain pre {
		type filter hook output priority -300; policy accept;
		meta skuid 8802 udp dport 53 counter packets 1 bytes 85 comment "anon-udp53"
		meta skuid 8802 tcp dport 53 counter packets 0 bytes 0 comment "anon-tcp53"
		meta skuid 413 udp sport 19053 counter packets 1 bytes 89 comment "shim-reply"
	}
	chain post {
		type filter hook output priority 50; policy accept;
		meta skuid 8802 ip daddr 127.0.0.1 udp dport 19053 counter packets 1 bytes 85 comment "toward-shim-udp"
	}
}`
	got := parseCommentedCounters(listed)
	if got["anon-udp53"] != 1 || got["shim-reply"] != 1 || got["toward-shim-udp"] != 1 {
		t.Fatalf("counters that moved must be read back; got %+v", got)
	}
	if got["anon-tcp53"] != 0 {
		t.Errorf("a zero counter must read as zero; got %+v", got)
	}
	if !counterKeyMoved(got, "anon-udp53", "anon-tcp53") {
		t.Errorf("counterKeyMoved must be true when EITHER family/protocol moved")
	}
	if counterKeyMoved(got, "anon-tcp53") {
		t.Errorf("counterKeyMoved must be false for a counter that stayed at zero")
	}
}

// An unreadable/absent counter must read as NOT MOVED, and the call sites are
// arranged so that this is the FAILING side of both bypass assertions: an
// unparseable dump can never manufacture a pass.
func TestParseCommentedCounters_GarbageReadsAsNotMoved(t *testing.T) {
	got := parseCommentedCounters("not nft output at all\ncounter packets\n")
	if len(got) != 0 {
		t.Fatalf("garbage must yield no counters; got %+v", got)
	}
	ev := DNSEvidence{Probe: "p.invalid", AccountEmittedQuery: counterKeyMoved(got, dnsCounterAnonUDP53)}
	if DNSNSSNotBypassedAssertion(ev).Ok {
		t.Errorf("an unreadable counter must land on the FAILING side, never a pass")
	}
}

// --- the resolver-configuration reader ---

func TestFirstNameserver_PrefersIPv4AndToleratesAbsence(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// The measured host's shape: a v6 MagicDNS line alongside the v4 one. The v4 one
	// is the path the redirect can actually serve, so it is the one to probe.
	v6First := write("v6first", "search example\nnameserver fd7a:115c:a1e0::53\nnameserver 100.100.100.100\noptions edns0\n")
	if got := firstNameserver(v6First); got != "100.100.100.100" {
		t.Errorf("firstNameserver must prefer the IPv4 nameserver; got %q", got)
	}
	v6Only := write("v6only", "nameserver fd7a:115c:a1e0::53\n")
	if got := firstNameserver(v6Only); got != "fd7a:115c:a1e0::53" {
		t.Errorf("a v6-only host must still report its nameserver (the assertion explains it); got %q", got)
	}
	if got := firstNameserver(dir + "/does-not-exist"); got != "" {
		t.Errorf("an absent resolv.conf must yield \"\", not a guess; got %q", got)
	}
	if got := nameserverAddr("100.100.100.100"); got != "100.100.100.100:53" {
		t.Errorf("nameserverAddr(v4) = %q", got)
	}
	if got := nameserverAddr("fd7a:115c:a1e0::53"); got != "[fd7a:115c:a1e0::53]:53" {
		t.Errorf("nameserverAddr(v6) must bracket the literal; got %q", got)
	}
}

// The live run on the measured host took the branch where the NSS lookup returned
// NOTHING (the probe name is unresolvable, so even the bypassing resolver
// NXDOMAINs it). That detail must not leave the reader wondering whether a lookup
// was attempted at all: the round-trip probe from the SAME uid, in the SAME run,
// already shows the account's own sockets reach the shim, so the message cites it
// and the last inference is closed.
func TestDNSNSSNotBypassed_CitesThatTheAccountsOwnSocketsDoWork(t *testing.T) {
	a := DNSNSSNotBypassedAssertion(DNSEvidence{
		Probe: "anonctl-probe-5.invalid", Nameserver: "100.100.100.100",
		NSSResolved: false, AccountEmittedQuery: false,
		ForcedReachedShim: true, ShimReplied: true,
	})
	if a.Ok {
		t.Fatalf("must FAIL; got %+v", a)
	}
	if !strings.Contains(a.Detail, "its own sockets work and NSS is not using them") {
		t.Errorf("the corroborating round-trip evidence must be cited; got %q", a.Detail)
	}
	// With no corroboration available, it must NOT claim it.
	b := DNSNSSNotBypassedAssertion(DNSEvidence{Probe: "p.invalid", AccountEmittedQuery: false})
	if strings.Contains(b.Detail, "own sockets work") {
		t.Errorf("the claim must only appear when the round trip actually reached the shim; got %q", b.Detail)
	}
}

// The probe name is sent through the shim to the endpoint's upstream resolver, so
// anything in it is seen there. It must therefore carry NO product string, NO pid
// and NO timestamp (a cross-run correlator), and it must be ABSOLUTE: `.invalid`
// NXDOMAINs, and on NXDOMAIN glibc walks the `search` list and retries, which
// would send this host's own search domain (a tailnet name, on the host this was
// measured on) to a public resolver over the circuit.
func TestUniqueDNSProbeName_CarriesNothingIdentifyingAndSuppressesTheSearchWalk(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		name := uniqueDNSProbeName()
		if seen[name] {
			t.Fatalf("probe names must be unique: a repeat makes the measurement unsound (%q)", name)
		}
		seen[name] = true
		if !strings.HasSuffix(name, ".invalid.") {
			t.Fatalf("the probe must be an ABSOLUTE .invalid name (trailing dot) so glibc never appends the search list; got %q", name)
		}
		for _, leak := range []string{"anonctl", "probe", "-"} {
			if strings.Contains(strings.TrimSuffix(name, ".invalid."), leak) {
				t.Errorf("the label must carry no product string or structure; %q contains %q", name, leak)
			}
		}
		label := strings.TrimSuffix(name, ".invalid.")
		if len(label) != 16 {
			t.Errorf("label = %q, want 16 hex chars from the CSPRNG", label)
		}
		if strings.Contains(label, strconv.Itoa(os.Getpid())) {
			t.Errorf("the label must not carry the pid; got %q", label)
		}
	}
}

// THE ATTRIBUTION GAP, and the control window that mitigates it. The planted rules
// count the ACCOUNT's DNS, not the probe's, so a second process running as the
// account (a Go binary resolving with the pure-Go resolver bypasses NSS entirely
// and still emits its own UDP) moves the counters. Without a control, that reads
// as "the account's own sockets carried the query" and PASSES both bypass
// assertions on a host that is leaking every name.
func TestCrossTalk_UnattributableRunIsAnErrorNeverAPass(t *testing.T) {
	quiet := map[string]int{dnsCounterAnonUDP53: 0, dnsCounterShimReply: 0}
	if crossTalk(quiet) {
		t.Fatalf("an idle control window must not report cross-talk")
	}
	for _, key := range dnsCounterKeys {
		noisy := map[string]int{key: 3}
		if !crossTalk(noisy) {
			t.Errorf("a control window in which %s moved must report cross-talk", key)
		}
		err := crossTalkError(noisy)
		if err == nil {
			t.Fatalf("cross-talk must produce an error (a probe that could not measure is not a pass)")
		}
		// The wording must not read as a leak finding NOR as an all-clear.
		if !strings.Contains(err.Error(), "NOTHING is proven") {
			t.Errorf("the error must state that nothing was proven; got %q", err)
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("the error must name the counter that moved; got %q", err)
		}
	}
}
