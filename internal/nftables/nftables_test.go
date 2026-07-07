package nftables_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/nftables"
)

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

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain:\n  %s\ngot:\n%s", needle, haystack)
	}
}
