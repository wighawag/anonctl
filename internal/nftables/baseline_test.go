package nftables_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
)

// The BASELINE default-deny is the anon UID's RESTING STATE: a tiny, standalone
// `inet` table, SEPARATE from the per-account forcing table, that drops the anon
// UID's direct (non-loopback) egress. It is what makes "no anonctl forcing loaded"
// mean DROPPED, not free: forcing (the nat redirect) rewrites the anon UID's dst to
// a loopback shim port BEFORE any filter chain runs, so the baseline (which only
// drops NON-loopback egress) never touches forced traffic; with forcing absent the
// baseline is all there is, and the anon UID is dropped. These tests pin the pure
// GENERATION; the drop/boot behaviour is proven in the integration test.

func TestGenerateBaselineIsItsOwnInetTable(t *testing.T) {
	out, err := nftables.GenerateBaseline("anon", 30034, nil)
	if err != nil {
		t.Fatalf("GenerateBaseline: %v", err)
	}
	// It is a SEPARATE table from the forcing table (`anonctl_baseline_<account>`),
	// so it is loaded/removed independently of the per-account forcing rules: the
	// resting-state deny outlives (and precedes) the forcing.
	if !strings.Contains(out, "table inet anonctl_baseline_anon {") {
		t.Errorf("expected a dedicated `table inet anonctl_baseline_anon`; got:\n%s", out)
	}
	if strings.Contains(out, "table inet anonctl_anon {") {
		t.Errorf("the baseline must NOT be the per-account forcing table; got:\n%s", out)
	}
	// Atomic + idempotent like the forcing ruleset: create-if-absent, delete, define
	// fresh, so a re-load is a clean replace of ONLY the baseline table.
	if strings.Count(out, "table inet anonctl_baseline_anon {\n") != 1 {
		t.Errorf("expected exactly one baseline table definition; got:\n%s", out)
	}
	if !strings.Contains(out, "delete table inet anonctl_baseline_anon") {
		t.Errorf("baseline should delete-then-define for an atomic replace; got:\n%s", out)
	}
}

func TestGenerateBaselineDropsAnonDirectEgress(t *testing.T) {
	out, err := nftables.GenerateBaseline("anon", 30034, nil)
	if err != nil {
		t.Fatalf("GenerateBaseline: %v", err)
	}
	// A filter/output base chain. Its policy is ACCEPT (not drop): the baseline must
	// never affect any OTHER UID or the host's own traffic (an `accept` verdict is
	// non-terminal, so it hands the packet on; a `drop` here is the ONLY terminal
	// verdict, applied narrowly to the anon UID's real egress).
	mustContain(t, out, "type filter hook output priority filter")
	mustContain(t, out, "policy accept;")
	// The anon UID's LOOPBACK traffic is left alone (no verdict) so forcing's
	// redirected-into-the-shim traffic (dst rewritten to 127.0.0.1:<port>) is never
	// dropped by the baseline; only NON-loopback (real external) egress is dropped.
	mustContain(t, out, "meta skuid 30034 ip daddr 127.0.0.0/8 return")
	mustContain(t, out, "meta skuid 30034 ip6 daddr ::1 return")
	// The anon UID's real egress (v4 AND v6, everything not loopback) is DROPPED:
	// this is the resting-state deny. v6 must be dropped too (no v6 bypass).
	mustContain(t, out, "meta skuid 30034 ip daddr != 127.0.0.0/8 drop")
	mustContain(t, out, "meta skuid 30034 ip6 daddr != ::1 drop")
}

func TestGenerateBaselineLoopbackReturnPrecedesDrop(t *testing.T) {
	out, err := nftables.GenerateBaseline("anon", 30034, nil)
	if err != nil {
		t.Fatalf("GenerateBaseline: %v", err)
	}
	i := func(s string) int { return strings.Index(out, s) }
	// Ordering is load-bearing: the loopback RETURN must precede the broad drop, so
	// forced (loopback-redirected) traffic is handed on to the forcing table instead
	// of being caught by the baseline drop.
	if i("ip daddr 127.0.0.0/8 return") > i("ip daddr != 127.0.0.0/8 drop") {
		t.Errorf("the loopback return must precede the real-egress drop; got:\n%s", out)
	}
	if i("ip6 daddr ::1 return") > i("ip6 daddr != ::1 drop") {
		t.Errorf("the v6 loopback return must precede the v6 drop; got:\n%s", out)
	}
}

// TestGenerateBaselineReturnsExemptionsBeforeDrop is the regression for the broken
// split-tunnel: an exempted LAN destination is deliberately NOT redirected into the
// shim (forcing's nat chain returns it), so it reaches the baseline chain still
// carrying its real LAN daddr. The baseline MUST RETURN it (exactly as it returns
// loopback) BEFORE its broad `ip daddr != 127.0.0.0/8 drop`, or that terminal drop
// kills the flow before the forcing chain's exemption accept can complete it. Live,
// this manifested as: the anon UID reached non-exempt LAN hosts (redirected -> shim)
// but TIMED OUT on the one exempted host (dropped by the stale baseline).
func TestGenerateBaselineReturnsExemptionsBeforeDrop(t *testing.T) {
	e, err := lanexempt.Parse("192.168.1.150:8080")
	if err != nil {
		t.Fatalf("lanexempt.Parse: %v", err)
	}
	out, err := nftables.GenerateBaseline("anon", 30034, []lanexempt.Exempt{e})
	if err != nil {
		t.Fatalf("GenerateBaseline: %v", err)
	}
	// The exempted destination is RETURNED for the anon UID, matching the exact same
	// clause the forcing table's return+accept use (ip daddr 192.168.1.150 tcp dport 8080).
	returnRule := "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 return"
	if !strings.Contains(out, returnRule) {
		t.Fatalf("baseline must RETURN the exempted destination so the forcing accept can complete it; missing %q:\n%s", returnRule, out)
	}
	// It must PRECEDE the broad non-loopback drop, else the terminal drop kills it first.
	if strings.Index(out, returnRule) > strings.Index(out, "ip daddr != 127.0.0.0/8 drop") {
		t.Errorf("the exemption return must precede the broad non-loopback drop; got:\n%s", out)
	}
}

// TestGenerateBaselineNoExemptionsIsByteIdenticalToBefore proves the exemption
// threading is inert when there are none: an empty/nil exemption set emits NO extra
// rule, so a non-exempt account's baseline is unchanged (the hole is strictly opt-in).
func TestGenerateBaselineNoExemptionsIsByteIdenticalToBefore(t *testing.T) {
	withNil, err := nftables.GenerateBaseline("anon", 30034, nil)
	if err != nil {
		t.Fatalf("GenerateBaseline(nil): %v", err)
	}
	withEmpty, err := nftables.GenerateBaseline("anon", 30034, []lanexempt.Exempt{})
	if err != nil {
		t.Fatalf("GenerateBaseline(empty): %v", err)
	}
	if withNil != withEmpty {
		t.Errorf("nil and empty exemptions must produce identical baseline text")
	}
	if strings.Contains(withNil, "LAN exemption") {
		t.Errorf("a baseline with no exemptions must emit no exemption rule:\n%s", withNil)
	}
}

func TestGenerateBaselineGovernsOnlyTheAnonUID(t *testing.T) {
	out, err := nftables.GenerateBaseline("anon", 30034, nil)
	if err != nil {
		t.Fatalf("GenerateBaseline: %v", err)
	}
	// Every rule is keyed on the anon UID: the baseline never drops another UID's
	// egress. There is no rule that lacks a `meta skuid 30034` guard.
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, "drop") && !strings.HasSuffix(trimmed, "return") {
			continue
		}
		if !strings.Contains(trimmed, "meta skuid 30034") {
			t.Errorf("baseline verdict rule not scoped to the anon UID: %q", trimmed)
		}
	}
}

func TestGenerateBaselineParameterises(t *testing.T) {
	out, err := nftables.GenerateBaseline("work", 41000, nil)
	if err != nil {
		t.Fatalf("GenerateBaseline: %v", err)
	}
	mustContain(t, out, "table inet anonctl_baseline_work {")
	mustContain(t, out, "meta skuid 41000 ip daddr != 127.0.0.0/8 drop")
	// The sample UID must NOT leak into a different account's baseline.
	if strings.Contains(out, "30034") {
		t.Errorf("recipe anon UID leaked into a parameterised baseline:\n%s", out)
	}
}

func TestGenerateBaselineTableName(t *testing.T) {
	// nft identifiers cannot contain '-', so a named account's '-' becomes '_'
	// (mirrors TableName), and the baseline table name derives from the forcing one.
	if got := nftables.BaselineTableName("anon-work"); got != "anonctl_baseline_anon_work" {
		t.Errorf("BaselineTableName(anon-work) = %q, want anonctl_baseline_anon_work", got)
	}
}

func TestGenerateBaselineRejectsBadParams(t *testing.T) {
	if _, err := nftables.GenerateBaseline("", 30034, nil); err == nil {
		t.Errorf("expected GenerateBaseline to reject an empty account")
	}
	if _, err := nftables.GenerateBaseline("anon", 0, nil); err == nil {
		t.Errorf("expected GenerateBaseline to reject a zero anon UID")
	}
	if _, err := nftables.GenerateBaseline("anon", -1, nil); err == nil {
		t.Errorf("expected GenerateBaseline to reject a negative anon UID")
	}
}
