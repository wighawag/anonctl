package nftables_test

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
)

// mustExempt parses a LAN exemption for the tests (the guardrail is unit-tested
// on its own in internal/lanexempt; here we only need a valid Exempt value).
func mustExempt(t *testing.T, raw string) lanexempt.Exempt {
	t.Helper()
	e, err := lanexempt.Parse(raw)
	if err != nil {
		t.Fatalf("lanexempt.Parse(%q): %v", raw, err)
	}
	return e
}

// sampleParams mirrors the validated manual recipe
// (work/notes/findings/manual-per-uid-tor-recipe.md): anon UID 30034, shim UID
// 995, relay port 19050, DNS port 19053, endpoint the local Tor SocksPort
// 127.0.0.1:9050. The generator must emit the exact proven ruleset shape for
// these, so the unit test pins the security-load-bearing lines by content.
func sampleParams() nftables.Params {
	return nftables.Params{
		Account:      "anon",
		AnonUID:      30034,
		ShimUID:      995,
		RelayPort:    19050,
		DNSPort:      19053,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	}
}

// paramsWithExemptions is sampleParams plus the given parsed exemptions, for the
// tests that must hold with a direct hole open as well as without one.
func paramsWithExemptions(t *testing.T, raw ...string) nftables.Params {
	t.Helper()
	p := sampleParams()
	for _, r := range raw {
		p.Exemptions = append(p.Exemptions, mustExempt(t, r))
	}
	return p
}

// chainBody returns the text BETWEEN `chain <name> {` and its closing brace. The
// restructured ruleset puts every verdict in a per-UID closure chain, so the
// security assertions are about WHICH CHAIN a rule is in and WHERE IN THAT CHAIN
// it sits -- a whole-output strings.Contains cannot tell those apart, and that
// imprecision is part of why the original bug read as correct in the unit tests.
func chainBody(t *testing.T, out, name string) string {
	t.Helper()
	open := "chain " + name + " {"
	i := strings.Index(out, open)
	if i < 0 {
		t.Fatalf("no chain %q in:\n%s", name, out)
	}
	rest := out[i+len(open):]
	j := strings.Index(rest, "\n    }")
	if j < 0 {
		t.Fatalf("chain %q is not terminated in:\n%s", name, out)
	}
	return rest[:j]
}

// nonEmptyRules splits a chain body into its actual rules, dropping blank lines
// and `#` comments, so "the LAST rule" means the last rule the kernel will
// evaluate rather than the last line of text.
func nonEmptyRules(body string) []string {
	var rules []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

func TestGenerateIsSingleInetTable(t *testing.T) {
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// One inet table (v4 AND v6 in one ruleset: the v4-rules-v6-leaks trap is
	// closed by construction). The table name is per-account so two accounts never
	// clobber each other's ruleset.
	if !strings.Contains(out, "table inet anonctl_anon {") {
		t.Errorf("expected a single `table inet anonctl_anon`; got:\n%s", out)
	}
	// The account's table is created-if-absent, deleted, then defined fresh (the
	// atomic idempotent preamble), so its NAME appears in three lines; but there is
	// exactly one table DEFINITION (a `{` opening a body).
	if strings.Count(out, "table inet anonctl_anon {\n") != 1 {
		t.Errorf("expected exactly one inet table definition; got:\n%s", out)
	}
	if strings.Contains(out, "table ip ") || strings.Contains(out, "table ip6 ") {
		t.Errorf("expected NO separate ip/ip6 tables (v4/v6 must share one inet table); got:\n%s", out)
	}
}

func TestGenerateRedirectsAnonTCPAndDNS(t *testing.T) {
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// The nat/output chain must run before the filter chain (dstnat priority) and
	// only rewrite the anon UID. It reaches the rewrites ONLY through a POSITIVE
	// skuid jump: the negative form this replaces (`meta skuid != 30034 return`) let
	// a packet with no attributable socket owner fall through into the catch-all
	// redirect, which would push an UNINVOLVED uid's traffic into the anon shim.
	mustContain(t, out, "type nat hook output priority dstnat")
	mustContain(t, out, "meta skuid 30034 jump anon_nat")
	// Its own shim ports are left as-is (a REDIRECTed packet re-enters filter with
	// the dst already rewritten to the shim port).
	mustContain(t, out, "ip daddr 127.0.0.1 tcp dport { 19050, 19053 } return")
	mustContain(t, out, "ip daddr 127.0.0.1 udp dport 19053 return")
	// DNS (udp AND tcp 53) -> shim DNS port; all other TCP -> shim relay port.
	mustContain(t, out, "udp dport 53 redirect to :19053")
	mustContain(t, out, "tcp dport 53 redirect to :19053")
	mustContain(t, out, "meta l4proto tcp redirect to :19050")

	// The catch-all redirect must be REACHABLE ONLY from the anon UID's own chain.
	// In the negative-match form it lived in the BASE chain, one fallthrough away
	// from any packet the kernel could not attribute, and the failure mode there is
	// worse than a drop: an uninvolved uid's traffic redirected INTO the anon shim.
	natBase := chainBody(t, out, "nat_out")
	for _, rule := range nonEmptyRules(natBase) {
		if strings.HasPrefix(rule, "type ") {
			continue
		}
		if !strings.HasPrefix(rule, "meta skuid ") || !strings.Contains(rule, " jump ") {
			t.Errorf("the nat base chain must only JUMP on a positive uid match, never hold a rewrite\n"+
				"of its own; got %q in:\n%s", rule, natBase)
		}
	}
	if strings.Contains(natBase, "redirect") {
		t.Errorf("a redirect in the nat BASE chain can swallow an unattributable packet:\n%s", natBase)
	}
}

// TestGenerateFilterGovernsOnlyItsOwnUIDs pins the box-wide invariant: the filter
// base chain must never adjudicate a packet anonctl cannot attribute to one of its
// own UIDs. It is policy ACCEPT and contains NOTHING but positive-skuid jumps, so
// an uninvolved uid's packet -- and, critically, a locally generated packet with no
// attributable socket owner at all (bulk TCP data emitted from a deferred context,
// pure ACKs, the FIN, RTO retransmissions) -- takes no jump and is accepted.
//
// The shape this replaces was `policy drop` plus a NEGATIVE pass-through
// (`meta skuid != 30034 meta skuid != 995 accept`). An unattributable packet
// matches neither `skuid == u` nor `skuid != u`, so it took no accept, fell
// through, and was killed by the policy drop. Because a `drop` is terminal across
// every base chain at a hook, that broke larger TCP transfers for EVERY uid on the
// box, root included, in a chain whose own header claimed to touch no other uid.
func TestGenerateFilterGovernsOnlyItsOwnUIDs(t *testing.T) {
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "type filter hook output priority filter; policy accept;")
	mustContain(t, out, "meta skuid 995 jump shim_filter")
	mustContain(t, out, "meta skuid 30034 jump anon_filter")

	// NO negative skuid match may survive anywhere in the ruleset: that is the exact
	// construct that adjudicates unattributable packets.
	if strings.Contains(out, "skuid !=") {
		t.Errorf("a negative `meta skuid !=` match is back: it adjudicates packets that carry NO\n"+
			"socket uid and so match neither form. Match the governed UIDs POSITIVELY instead:\n%s", out)
	}

	// The filter BASE chain must hold nothing but the two jumps: any verdict on a
	// rule there would apply to traffic that has not been attributed to a governed
	// UID. (The `type ... policy accept;` declaration is the chain header, not a
	// rule, and is asserted separately above.)
	base := chainBody(t, out, "filter_out")
	for _, rule := range nonEmptyRules(base) {
		if strings.HasPrefix(rule, "type ") {
			continue
		}
		if !strings.Contains(rule, " jump ") {
			t.Errorf("the filter base chain must only JUMP on a positive uid match; the rule %q\n"+
				"carries a verdict of its own, which would adjudicate unattributable traffic:\n%s", rule, base)
		}
		if !strings.HasPrefix(rule, "meta skuid ") {
			t.Errorf("every rule in the filter base chain must be gated on a POSITIVE skuid match;\n"+
				"got %q in:\n%s", rule, base)
		}
	}
}

// TestAnonClosureChainEndsInAnUnconditionalTerminalDrop is the counterweight to the
// test above, and it guards the exact mistake that turns this fix into a silent
// un-jailing. The anon UID's real egress used to be dropped by the base chain's
// POLICY, not by any rule. Flipping that policy to accept without an unconditional
// terminal `drop` at the END of the anon closure chain does not degrade the jail,
// it REMOVES it: the anon UID's ICMP and its non-53 UDP are never redirected, so
// they arrive at this chain with their real off-box destination and are matched by
// nothing above the terminal drop (these are precisely the `verify` assertions
// icmp-drop and non-tcp-udp-drop). The standing baseline table would still drop
// that traffic, so the regression presents as "everything still passes" while the
// forcing table has silently stopped forcing.
//
// Measured, with the forcing table loaded ALONE in a namespace so the baseline
// cannot mask it: with the terminal drop present, anon ICMP and anon UDP/4444 are
// dropped; with ONLY that one line removed, both escape.
func TestAnonClosureChainEndsInAnUnconditionalTerminalDrop(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    nftables.Params
	}{
		{"plain", sampleParams()},
		{"with exemptions", paramsWithExemptions(t, "192.168.1.150:8080", "127.0.0.1:8188")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := nftables.Generate(tc.p)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			body := chainBody(t, out, "anon_filter")
			rules := nonEmptyRules(body)
			if len(rules) == 0 {
				t.Fatalf("anon_filter chain is empty:\n%s", out)
			}
			last := rules[len(rules)-1]
			if last != "drop" {
				t.Fatalf("the anon closure chain MUST end in an unconditional, unqualified `drop`.\n"+
					"Its last rule is %q. Without it the chain falls back to filter_out's policy ACCEPT\n"+
					"and the anon UID's ICMP / non-53 UDP leave IN THE CLEAR (masked in a casual test by\n"+
					"the standing baseline table dropping them instead). Chain:\n%s", last, body)
			}
			// Unconditional means unqualified: a `meta skuid <anon> drop` terminal would
			// re-introduce the original bug inside the closure chain.
			if strings.Contains(last, "skuid") {
				t.Errorf("the terminal drop must be UNCONDITIONAL, not qualified by skuid; got %q", last)
			}
		})
	}
}

// TestGenerateExemptionAcceptPrecedesTheTerminalDrop pins the split-tunnel ordering
// against the NEW terminal rule. The exemption `accept` is what lets a deliberately
// un-forced destination leave directly; if the terminal drop were ever emitted
// before it, the direct hole would be killed inside the forcing table itself --
// the same class of break that
// work/notes/findings/split-tunnel-broken-by-exemption-blind-baseline.md records,
// arrived at from a different direction.
func TestGenerateExemptionAcceptPrecedesTheTerminalDrop(t *testing.T) {
	out, err := nftables.Generate(paramsWithExemptions(t, "192.168.1.150:8080"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	body := chainBody(t, out, "anon_filter")
	accept := "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 accept"
	if !strings.Contains(body, accept) {
		t.Fatalf("missing the exemption accept %q in:\n%s", accept, body)
	}
	rules := nonEmptyRules(body)
	if rules[len(rules)-1] != "drop" {
		t.Fatalf("expected the terminal drop last; got %q", rules[len(rules)-1])
	}
	if strings.Index(body, accept) > strings.LastIndex(body, "drop") {
		t.Errorf("the exemption accept must precede the terminal drop, or split tunnelling re-breaks:\n%s", body)
	}
}

func TestGenerateShimIsOnlyUIDToReachEndpoint(t *testing.T) {
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Bypass closure (b): only the SHIM UID may reach the endpoint; the shim then
	// reaches the world.
	mustContain(t, out, "meta skuid 995 ip daddr 127.0.0.1 tcp dport 9050 accept")
	mustContain(t, out, "meta skuid 995 oifname \"lo\" accept")
	mustContain(t, out, "meta skuid 995 accept")
}

func TestGenerateAnonBypassClosures(t *testing.T) {
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	i := func(s string) int { return strings.Index(out, s) }

	// Bypass closure (b): the anon UID can NEVER dial the endpoint directly, and
	// this DROP must precede any accept so it is not shadowed.
	dropEndpoint := "meta skuid 30034 ip daddr 127.0.0.1 tcp dport 9050 drop"
	mustContain(t, out, dropEndpoint)

	// Bypass closure (a): the anon UID may reach ONLY its own shim ports; all other
	// loopback (v4 127.0.0.0/8 and v6 ::1) is dropped, and all other v6 is dropped
	// (never leaked).
	acceptShim := "meta skuid 30034 ip daddr 127.0.0.1 tcp dport { 19050, 19053 } accept"
	mustContain(t, out, acceptShim)
	mustContain(t, out, "meta skuid 30034 ip daddr 127.0.0.1 udp dport 19053 accept")
	dropLoopback := "meta skuid 30034 ip daddr 127.0.0.0/8 drop"
	mustContain(t, out, dropLoopback)
	mustContain(t, out, "meta skuid 30034 ip6 daddr ::1 drop")
	mustContain(t, out, "meta skuid 30034 ip6 daddr ::/0 drop")

	// Ordering is load-bearing: the endpoint DROP (b) precedes the shim-port ACCEPT
	// (a) so a 9050 dial can never be accepted; the shim-port ACCEPT precedes the
	// broad loopback DROP so the shim ports are not swallowed.
	if i(dropEndpoint) > i(acceptShim) {
		t.Errorf("endpoint-drop (b) must precede shim-port-accept (a) to avoid being shadowed")
	}
	if i(acceptShim) > i(dropLoopback) {
		t.Errorf("shim-port-accept (a) must precede the broad 127.0.0.0/8 drop")
	}
}

// TestGenerateParameterises proves the emitted numbers come from Params, not
// hardcoded recipe constants: a different UID/port set must show through.
func TestGenerateParameterises(t *testing.T) {
	p := nftables.Params{
		Account:      "work",
		AnonUID:      41000,
		ShimUID:      990,
		RelayPort:    29050,
		DNSPort:      29053,
		EndpointHost: "127.0.0.1",
		EndpointPort: 1080,
	}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "table inet anonctl_work {")
	mustContain(t, out, "meta skuid 41000 jump anon_nat")
	mustContain(t, out, "meta l4proto tcp redirect to :29050")
	mustContain(t, out, "udp dport 53 redirect to :29053")
	mustContain(t, out, "meta skuid 990 ip daddr 127.0.0.1 tcp dport 1080 accept")
	mustContain(t, out, "meta skuid 41000 ip daddr 127.0.0.1 tcp dport 1080 drop")
	// The old recipe anon UID must NOT leak into a different account's ruleset.
	if strings.Contains(out, "30034") {
		t.Errorf("recipe anon UID leaked into a parameterised ruleset:\n%s", out)
	}
}

// TestGenerateIPv6Endpoint proves an IPv6 endpoint host emits ip6-family closure
// rules (so closure (b) is not silently v4-only for a v6 endpoint).
func TestGenerateIPv6Endpoint(t *testing.T) {
	p := sampleParams()
	p.EndpointHost = "::1"
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "meta skuid 995 ip6 daddr ::1 tcp dport 9050 accept")
	mustContain(t, out, "meta skuid 30034 ip6 daddr ::1 tcp dport 9050 drop")
}

func TestGenerateRejectsBadParams(t *testing.T) {
	cases := map[string]func(*nftables.Params){
		"zero anon uid":      func(p *nftables.Params) { p.AnonUID = 0 },
		"zero shim uid":      func(p *nftables.Params) { p.ShimUID = 0 },
		"equal uids":         func(p *nftables.Params) { p.ShimUID = p.AnonUID },
		"zero relay port":    func(p *nftables.Params) { p.RelayPort = 0 },
		"zero dns port":      func(p *nftables.Params) { p.DNSPort = 0 },
		"empty endpoint":     func(p *nftables.Params) { p.EndpointHost = "" },
		"zero endpoint port": func(p *nftables.Params) { p.EndpointPort = 0 },
		"empty account":      func(p *nftables.Params) { p.Account = "" },
		"bad endpoint host":  func(p *nftables.Params) { p.EndpointHost = "not-an-ip" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := sampleParams()
			mutate(&p)
			if _, err := nftables.Generate(p); err == nil {
				t.Errorf("expected Generate to reject %s, got nil error", name)
			}
		})
	}
}

// TestGenerateNoExemptionsByDefault proves the exemption is OFF by default: with
// no exemptions the ruleset is byte-identical to the pre-exemption ruleset (no
// stray accept/return), so the narrow hole is opt-in and the empty case never
// widens the forced egress.
func TestGenerateNoExemptionsByDefault(t *testing.T) {
	p := sampleParams()
	p.Exemptions = nil
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// No exemption => no exemption accept/return lines at all.
	if strings.Contains(out, "# direct exemption") {
		t.Errorf("expected no exemption lines with an empty Exemptions; got:\n%s", out)
	}
}

// TestGenerateExemptHostReachableDirectly proves a configured exact RFC1918
// host:port punches the narrow direct hole: (1) a nat `return` so the anon UID's
// packet is NOT redirected into the shim (it egresses the real NIC), and (2) a
// filter `accept` so the fail-closed default-DROP does not drop it. Both halves
// are required (story 23).
func TestGenerateExemptHostReachableDirectly(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.1.150:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// (1) nat_out: the exempt daddr+port is RETURNed (not redirected to the shim),
	// for the anon UID, so it egresses the real NIC directly.
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 return")
	// (2) filter_out: the exempt daddr+port is ACCEPTed for the anon UID, before the
	// fail-closed drops.
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 accept")
}

// TestGenerateExemptExactPortPinned proves an exact-port exemption pins exactly
// `tcp dport <port>` in both the nat return and the filter accept, and renders a
// bare-IP host route as the bare address (nft idiom), not `.../32`. With the
// all-ports form removed, this is the only exemption shape.
func TestGenerateExemptExactPortPinned(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.1.150:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 return")
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 accept")
	// A /32 host route is spelled as the bare address (nft idiom), not `.../32`.
	if strings.Contains(out, "192.168.1.150/32") {
		t.Errorf("a bare-IP exemption should render as the bare address, not /32; got:\n%s", out)
	}
}

// TestGenerateExemptNeverEmitsAllPorts proves the all-ports (`tcp dport != 53`)
// path is GONE: no exemption, whatever its port, can ever emit the all-TCP-except-53
// form. That form was a deanonymization vector (a forwarding proxy on some other
// port would be reachable directly); every exemption now opens exactly one port
// (see docs/adr/0007). 53 stays redirected to the shim for the exempt host too.
func TestGenerateExemptNeverEmitsAllPorts(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.1.150:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(out, "tcp dport != 53") {
		t.Errorf("no exemption may emit the all-TCP-except-53 form any more; got:\n%s", out)
	}
	// 53 stays redirected to the shim DNS port (the exemption pins 8080 only, so it
	// never returns/accepts tcp/53 for the exempt host).
	mustContain(t, out, "tcp dport 53 redirect to :19053")
}

// TestGenerateExemptCIDRHost proves a CIDR exemption emits the network (not a
// /32), so a user who exempts a small private subnet gets exactly that.
func TestGenerateExemptCIDRHost(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.5.0/24:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.5.0/24 tcp dport 8080 accept")
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.5.0/24 tcp dport 8080 return")
}

// TestGenerateExemptV6UsesIP6Family proves Generate is family-aware: an IPv6
// exemption emits ip6-family rules (never a v4-family rule for a v6 destination),
// so the hole is punched in the right family. The guardrail (internal/lanexempt,
// mirroring netcage verbatim) is v4-only and rejects a v6 value at config time, so
// this constructs the Exempt directly (defense-in-depth: Generate stays correct if
// a v6 exemption ever reaches it).
func TestGenerateExemptV6UsesIP6Family(t *testing.T) {
	p := sampleParams()
	_, v6net, err := net.ParseCIDR("fe80::1/128")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	p.Exemptions = []lanexempt.Exempt{{Network: v6net, Port: 8080, Raw: "fe80::1:8080"}}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "meta skuid 30034 ip6 daddr fe80::1 tcp dport 8080 accept")
	mustContain(t, out, "meta skuid 30034 ip6 daddr fe80::1 tcp dport 8080 return")
}

// TestGenerateExemptDoesNotWiden proves the exemption is scoped to EXACTLY the
// named host: the rest of that host's /24 is NOT accepted, so the hole cannot
// silently widen into a leak (story 25). The exemption emits a /32 host route for
// a bare IP, and no broad private-range accept.
func TestGenerateExemptDoesNotWiden(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.1.150:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// A sibling on the same /24 must NOT appear as an accept: the exemption is a /32.
	if strings.Contains(out, "192.168.1.0/24") || strings.Contains(out, "192.168.1.151") {
		t.Errorf("exemption must not widen beyond the exact host; got:\n%s", out)
	}
	// No broad RFC1918 accept: the fail-closed default-DROP gives that for free (the
	// task forbids separate RFC1918 drop rules AND there must be no broad accept).
	if strings.Contains(out, "192.168.0.0/16 accept") || strings.Contains(out, "10.0.0.0/8 accept") {
		t.Errorf("exemption must not emit a broad private-range accept; got:\n%s", out)
	}
}

// TestGenerateExemptOrderingBeforeDrops proves the exemption accept/return sit
// BEFORE the anon-UID drops (and before the catch-all redirect), so the narrow
// hole is not shadowed by a drop or swallowed by the redirect: a first-match
// firewall is only as correct as its ordering.
func TestGenerateExemptOrderingBeforeDrops(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.1.150:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	i := func(s string) int { return strings.Index(out, s) }

	// nat_out: the exempt RETURN must precede the catch-all TCP redirect, else the
	// packet is redirected into the shim before the return is reached.
	exemptReturn := "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 return"
	redirect := "meta l4proto tcp redirect to :19050"
	if i(exemptReturn) < 0 || i(redirect) < 0 || i(exemptReturn) > i(redirect) {
		t.Errorf("exempt nat return must precede the catch-all TCP redirect")
	}

	// filter_out: the exempt ACCEPT must precede the anon-UID loopback drop and the
	// terminal drop (which is the anon closure chain's last rule).
	exemptAccept := "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 accept"
	anonLoopbackDrop := "meta skuid 30034 ip daddr 127.0.0.0/8 drop"
	if i(exemptAccept) < 0 || i(exemptAccept) > i(anonLoopbackDrop) {
		t.Errorf("exempt filter accept must precede the anon-UID drops")
	}
}

// TestGenerateLoopbackExemptReachableDirectly proves a configured loopback
// exemption (127.0.0.1:<port>) punches the same TWO-rule direct hole as a LAN one:
// (1) a nat_out `return` scoped to `ip daddr 127.0.0.1 tcp dport <port>` (so the
// catch-all TCP redirect does not swallow it into the shim) and (2) a filter_out
// `accept` before the `127.0.0.0/8 drop` (so closure (a) does not drop it). This
// is the same-host local-model case (the loopback branch of the task).
func TestGenerateLoopbackExemptReachableDirectly(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "127.0.0.1:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// (1) nat_out: the loopback exempt daddr+port is RETURNed (not redirected), for
	// the anon UID, so it reaches the same-host service directly.
	mustContain(t, out, "meta skuid 30034 ip daddr 127.0.0.1 tcp dport 8080 return")
	// (2) filter_out: the loopback exempt daddr+port is ACCEPTed for the anon UID.
	mustContain(t, out, "meta skuid 30034 ip daddr 127.0.0.1 tcp dport 8080 accept")
}

// TestGenerateLoopbackExemptOrderingBeforeDropAndRedirect proves the loopback
// exemption's rules sit BEFORE the catch-all TCP redirect (nat) and BEFORE the
// broad 127.0.0.0/8 drop (filter): a first-match firewall is only as correct as
// its ordering. Closure (a) must still DROP every OTHER loopback port, so the
// accept must precede the drop but the drop must still be present.
func TestGenerateLoopbackExemptOrderingBeforeDropAndRedirect(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "127.0.0.1:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	i := func(s string) int { return strings.Index(out, s) }

	// nat_out: the loopback exempt RETURN must precede the catch-all TCP redirect.
	exemptReturn := "meta skuid 30034 ip daddr 127.0.0.1 tcp dport 8080 return"
	redirect := "meta l4proto tcp redirect to :19050"
	if i(exemptReturn) < 0 || i(redirect) < 0 || i(exemptReturn) > i(redirect) {
		t.Errorf("loopback exempt nat return must precede the catch-all TCP redirect")
	}

	// filter_out: the loopback exempt ACCEPT must precede the broad 127.0.0.0/8 drop,
	// which must STILL be present (closure (a) does not widen: every OTHER loopback
	// port is still dropped).
	exemptAccept := "meta skuid 30034 ip daddr 127.0.0.1 tcp dport 8080 accept"
	loopbackDrop := "meta skuid 30034 ip daddr 127.0.0.0/8 drop"
	if i(exemptAccept) < 0 || i(loopbackDrop) < 0 || i(exemptAccept) > i(loopbackDrop) {
		t.Errorf("loopback exempt filter accept must precede the broad 127.0.0.0/8 drop (which must remain)")
	}
}

// TestGenerateLoopbackExemptClosureAStillHolds proves closure (a) survives a
// loopback exemption: the broad 127.0.0.0/8 drop is STILL emitted, so every
// NON-exempt loopback port stays dropped (the exemption pins exactly 8080; a
// sibling loopback port is not accepted).
func TestGenerateLoopbackExemptClosureAStillHolds(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "127.0.0.1:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "meta skuid 30034 ip daddr 127.0.0.0/8 drop")
	// The exemption does not accept a DIFFERENT loopback port.
	if strings.Contains(out, "127.0.0.1 tcp dport 9999 accept") {
		t.Errorf("a loopback exemption must not accept a non-exempt loopback port; got:\n%s", out)
	}
}

// TestGenerateLoopbackExemptClosureBStillHolds proves closure (b) survives: the
// anon-UID direct-endpoint DROP is still emitted (a loopback exemption cannot
// re-open the SOCKS/control surface). The default endpoint is 9050, which the
// guardrail already refuses as an exemption; this asserts the closure rule itself
// is intact.
func TestGenerateLoopbackExemptClosureBStillHolds(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "127.0.0.1:8080")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mustContain(t, out, "meta skuid 30034 ip daddr 127.0.0.1 tcp dport 9050 drop")
}

// TestGenerateRejectsLoopbackExemptOnAccountPort proves the account-specific half
// of the loopback port blocklist: a loopback exemption whose port equals the
// shim relay port, the shim DNS port, or the configured endpoint port is REJECTED
// at generate time (these are host-dependent, so lanexempt.Parse cannot know them;
// Generate does). Naming the port keeps the refusal self-explaining.
func TestGenerateRejectsLoopbackExemptOnAccountPort(t *testing.T) {
	cases := map[string]int{
		"relay port":    19050,
		"dns port":      19053,
		"endpoint port": 9050,
	}
	for name, port := range cases {
		t.Run(name, func(t *testing.T) {
			p := sampleParams()
			// Build a loopback exemption on the account port directly (Parse rejects the
			// static well-known 9050 already; the relay/dns ports pass Parse and must be
			// caught HERE, where the account ports are known).
			_, n, _ := net.ParseCIDR("127.0.0.1/32")
			p.Exemptions = []lanexempt.Exempt{{Network: n, Port: port, Raw: fmt.Sprintf("127.0.0.1:%d", port)}}
			if _, err := nftables.Generate(p); err == nil {
				t.Errorf("Generate must reject a loopback exemption on the account's %s (%d)", name, port)
			} else if !strings.Contains(err.Error(), strconv.Itoa(port)) {
				t.Errorf("reject should name the offending port %d; got: %v", port, err)
			}
		})
	}
}

// TestGenerateAllowsLANExemptOnAccountPort proves the account-port refusal is
// LOOPBACK-only: a LAN exemption that happens to name the same numeric port as the
// shim relay is fine (a LAN host's :19050 is a different socket than the loopback
// shim), so the account-port guard must not fire for a LAN destination.
func TestGenerateAllowsLANExemptOnAccountPort(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, fmt.Sprintf("192.168.1.150:%d", p.RelayPort))}
	if _, err := nftables.Generate(p); err != nil {
		t.Errorf("a LAN exemption on the relay port number must be allowed (different host); got: %v", err)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain:\n  %s\ngot:\n%s", needle, haystack)
	}
}

// THE INJECTIVITY HALF. TableName rewrites `-` to `_`, so an account name that
// CONTAINS an underscore collides with its all-dashes twin: `anon-a_b` and
// `anon-a-b` both render `anonctl_anon_a_b`. This test pins the collision as the
// REASON the name rule exists (if the mapping ever became injective on its own,
// this test is the place that says the rule can be relaxed).
func TestTableNameIsNotInjectiveAcrossUnderscoreAndDash(t *testing.T) {
	underscore := nftables.TableName("anon-a_b")
	dash := nftables.TableName("anon-a-b")
	if underscore != dash {
		t.Fatalf("expected the underscore/dash collision this rule exists for; got %q vs %q", underscore, dash)
	}
	if underscore != "anonctl_anon_a_b" {
		t.Errorf("TableName(anon-a_b) = %q, want anonctl_anon_a_b", underscore)
	}
}

// ...and Generate REFUSES the colliding name, so a caller that bypasses the CLI
// (name resolution is the first gate) still cannot install a ruleset whose table
// another account also maps onto, which would silently replace that account's
// forcing.
func TestGenerateRefusesAnAccountNameThatCollidesInTheTableName(t *testing.T) {
	p := nftables.Params{
		Account:      "anon-a_b",
		AnonUID:      8801,
		ShimUID:      412,
		RelayPort:    19050,
		DNSPort:      19053,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	}
	_, err := nftables.Generate(p)
	if err == nil {
		t.Fatal("Generate accepted an account name whose nft table name is ambiguous; it must refuse")
	}
	if !strings.Contains(err.Error(), "underscore") || !strings.Contains(err.Error(), "table") {
		t.Errorf("the refusal must name the nft table-name reason; got: %v", err)
	}

	// The same account with a legal name generates fine, so the guard rejects the
	// ambiguity and nothing else.
	p.Account = "anon-a-b"
	if _, err := nftables.Generate(p); err != nil {
		t.Errorf("a legal account name must still generate: %v", err)
	}
}
