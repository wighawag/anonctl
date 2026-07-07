package nftables_test

import (
	"net"
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
	// only rewrite the anon UID.
	mustContain(t, out, "type nat hook output priority dstnat")
	mustContain(t, out, "meta skuid != 30034 return")
	// Its own shim ports are left as-is (a REDIRECTed packet re-enters filter with
	// the dst already rewritten to the shim port).
	mustContain(t, out, "ip daddr 127.0.0.1 tcp dport { 19050, 19053 } return")
	mustContain(t, out, "ip daddr 127.0.0.1 udp dport 19053 return")
	// DNS (udp AND tcp 53) -> shim DNS port; all other TCP -> shim relay port.
	mustContain(t, out, "udp dport 53 redirect to :19053")
	mustContain(t, out, "tcp dport 53 redirect to :19053")
	mustContain(t, out, "meta l4proto tcp redirect to :19050")
}

func TestGenerateFilterDefaultDrop(t *testing.T) {
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// The filter/output chain is DEFAULT-DROP (fail-closed) and governs only the
	// anon + shim UIDs (every other UID is accepted so the table never touches the
	// rest of the host).
	mustContain(t, out, "type filter hook output priority filter; policy drop;")
	mustContain(t, out, "meta skuid != 30034 meta skuid != 995 accept")
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
	mustContain(t, out, "meta skuid != 41000 return")
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
	if strings.Contains(out, "# LAN exemption") {
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

// TestGenerateExemptPortOmittedAllowsAllTCP proves the port-omitted form (Port 0)
// exempts ALL TCP ports on the host (no `tcp dport` clause), per the acceptance
// criterion.
func TestGenerateExemptPortOmittedAllowsAllTCP(t *testing.T) {
	p := sampleParams()
	p.Exemptions = []lanexempt.Exempt{mustExempt(t, "192.168.1.150")}
	out, err := nftables.Generate(p)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// All TCP ports: matched by l4proto tcp with no dport, for both the nat return
	// and the filter accept.
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.1.150 meta l4proto tcp return")
	mustContain(t, out, "meta skuid 30034 ip daddr 192.168.1.150 meta l4proto tcp accept")
	// A port-omitted exemption must NOT pin a specific dport.
	if strings.Contains(out, "daddr 192.168.1.150 tcp dport") {
		t.Errorf("port-omitted exemption must not pin a dport; got:\n%s", out)
	}
	// A /32 host route is spelled as the bare address (nft idiom), not `.../32`.
	if strings.Contains(out, "192.168.1.150/32") {
		t.Errorf("a bare-IP exemption should render as the bare address, not /32; got:\n%s", out)
	}
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
	// policy drop (which lives at the chain default, after every rule).
	exemptAccept := "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 accept"
	anonLoopbackDrop := "meta skuid 30034 ip daddr 127.0.0.0/8 drop"
	if i(exemptAccept) < 0 || i(exemptAccept) > i(anonLoopbackDrop) {
		t.Errorf("exempt filter accept must precede the anon-UID drops")
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain:\n  %s\ngot:\n%s", needle, haystack)
	}
}
