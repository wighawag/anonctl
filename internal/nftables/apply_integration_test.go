//go:build integration
// +build integration

package nftables_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
)

// execRunner is the real Runner for the integration test: it shells out to the
// actual `nft`, piping the ruleset on stdin (the `nft -f -` atomic-load form).
// It exists only here (behind the `integration` tag) so the default
// `go test ./...` never runs real nft.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}

// TestRealApplyIsolatesAndLeavesHostUntouched is the ONE test that loads a real
// nftables ruleset. It is guarded by the `integration` tag and is NOT part of the
// default `go test ./...`; it needs root + nftables and SKIPS (not fails) without
// them, so an ordinary `go test -tags integration ./...` still passes.
//
// Shared-write isolation (the acceptance requirement): it uses a throwaway
// account name (`anonctl-itest-<pid>`) whose table (`anonctl_anonctl_itest_...`)
// cannot collide with a real operator's, plants a SENTINEL table to prove the
// host's other rules are untouched, applies + verifies + re-applies (idempotent),
// then DELETEs only its own table and asserts the sentinel is still present. It
// ALWAYS cleans up both tables it created, so it leaves no residue on the box.
func TestRealApplyIsolatesAndLeavesHostUntouched(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration nftables apply requires root; skipping")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available; skipping")
	}

	ctx := context.Background()
	r := execRunner{}

	// A throwaway account whose table name is unlikely to collide with a real one.
	account := "anonctl-itest-" + strconv.Itoa(os.Getpid())
	table := nftables.TableName(account)

	// A SENTINEL table we plant and later assert is UNTOUCHED, proving Apply/Delete
	// scope to exactly the account's own table.
	const sentinel = "anonctl_itest_sentinel"
	mustNft(t, r, "table inet "+sentinel+" {}\n")

	// Always clean up BOTH tables this test created, even on a mid-test failure, so
	// the host is left exactly as found.
	defer func() {
		_, _, _ = r.Run(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _, _ = r.Run(ctx, "delete table inet "+sentinel, "nft", "-f", "-")
		if tableExists(t, r, table) {
			t.Errorf("cleanup left the account table %q behind", table)
		}
		if tableExists(t, r, sentinel) {
			t.Errorf("cleanup left the sentinel table %q behind", sentinel)
		}
	}()

	p := nftables.Params{
		Account:      account,
		AnonUID:      424242, // throwaway synthetic UIDs (no real user need exist to LOAD the rules)
		ShimUID:      424243,
		RelayPort:    39050,
		DNSPort:      39053,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	}

	// Apply loads the real ruleset: the kernel ACCEPTING it proves the syntax,
	// chain priorities (dstnat before filter), and family handling are all valid on
	// a real host, not just well-formed text.
	if err := nftables.Apply(ctx, r, p); err != nil {
		t.Fatalf("Apply on a real host: %v", err)
	}
	if !tableExists(t, r, table) {
		t.Fatalf("Apply did not load the account table %q", table)
	}
	// The load-bearing security lines are actually present in the loaded table, AS
	// THE KERNEL PARSED THEM (not merely as the generator spelled them).
	listed := listTable(t, r, table)
	for _, want := range []string{
		// Fail-closed is reached by a POSITIVE uid jump, never by adjudicating a
		// packet the kernel could not attribute.
		"type filter hook output priority filter; policy accept;",
		"meta skuid 424242 jump anon_filter",
		"meta skuid 424243 jump shim_filter",
		"meta skuid 424242 jump anon_nat",
	} {
		if !strings.Contains(listed, want) {
			t.Errorf("loaded table missing %q:\n%s", want, listed)
		}
	}
	// The kernel must not have a negative uid match anywhere: that is the construct
	// that adjudicates unattributable packets and broke every uid's transfers.
	if strings.Contains(listed, "skuid !=") {
		t.Errorf("the loaded table carries a negative uid match:\n%s", listed)
	}
	// Fail-closed now rests on an unconditional terminal drop ENDING the anon closure
	// chain, because the base chain no longer has a drop policy to fall back on. This
	// assertion replaces the old `policy drop` one and is what actually keeps the anon
	// UID jailed; see docs/adr/0002.
	if last := lastRuleOfListedChain(listed, "anon_filter"); last != "drop" {
		t.Errorf("the anon closure chain must END in an unconditional `drop` as loaded by the\n"+
			"kernel; its last rule is %q. Without it the anon UID's non-redirected egress\n"+
			"(ICMP, non-53 UDP) falls back to the base chain's policy ACCEPT and leaves in the\n"+
			"clear:\n%s", last, listed)
	}

	// Re-Apply must be an idempotent atomic REPLACE (no error, no duplicate rules).
	if err := nftables.Apply(ctx, r, p); err != nil {
		t.Fatalf("re-Apply (idempotency): %v", err)
	}

	// The sentinel (a stand-in for the host's other rules) is UNTOUCHED throughout.
	if !tableExists(t, r, sentinel) {
		t.Fatalf("Apply clobbered the sentinel table (host rules not isolated)")
	}

	// Delete removes ONLY the account's table; the sentinel survives.
	if err := nftables.Delete(ctx, r, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if tableExists(t, r, table) {
		t.Errorf("Delete left the account table %q behind", table)
	}
	if !tableExists(t, r, sentinel) {
		t.Errorf("Delete removed the sentinel table too (over-broad delete)")
	}
}

// TestRealApplyWithLANExemptionStaysTight is the integration proof of the narrow
// LAN exemption: it loads a REAL ruleset that exempts one exact private host:port,
// then asserts against the KERNEL-loaded table that (1) the exempt host:port is
// ACCEPTed for the anon UID (the direct hole is open), (2) the fail-closed shape
// is intact around it: the endpoint drop (closure b), the shim-only accepts, and
// the broad loopback + IPv6 drops all survive, so the exemption did not widen into
// a leak, and (3) the exemption is scoped to the exact host, not its /24. Like the
// sibling test it isolates to a throwaway table + a sentinel and asserts the host
// is left untouched (shared-write isolation).
func TestRealApplyWithLANExemptionStaysTight(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration nftables apply requires root; skipping")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available; skipping")
	}

	ctx := context.Background()
	r := execRunner{}

	account := "anonctl-itest-lan-" + strconv.Itoa(os.Getpid())
	table := nftables.TableName(account)

	const sentinel = "anonctl_itest_lan_sentinel"
	mustNft(t, r, "table inet "+sentinel+" {}\n")

	defer func() {
		_, _, _ = r.Run(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _, _ = r.Run(ctx, "delete table inet "+sentinel, "nft", "-f", "-")
		if tableExists(t, r, table) {
			t.Errorf("cleanup left the account table %q behind", table)
		}
		if tableExists(t, r, sentinel) {
			t.Errorf("cleanup left the sentinel table %q behind", sentinel)
		}
	}()

	exempt, err := lanexempt.Parse("192.168.1.150:8080")
	if err != nil {
		t.Fatalf("lanexempt.Parse: %v", err)
	}
	p := nftables.Params{
		Account:      account,
		AnonUID:      424244,
		ShimUID:      424245,
		RelayPort:    39050,
		DNSPort:      39053,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
		Exemptions:   []lanexempt.Exempt{exempt},
	}

	// The kernel ACCEPTING the ruleset proves the exemption rules (the nat return +
	// the filter accept, in both chains) are syntactically valid on a real host.
	if err := nftables.Apply(ctx, r, p); err != nil {
		t.Fatalf("Apply with exemption on a real host: %v", err)
	}
	if !tableExists(t, r, table) {
		t.Fatalf("Apply did not load the account table %q", table)
	}

	listed := listTable(t, r, table)

	// (1) The exact exempt host:port is ACCEPTed for the anon UID (the direct hole).
	if !strings.Contains(listed, "192.168.1.150") || !strings.Contains(listed, "8080") {
		t.Errorf("loaded table missing the exempt host:port accept:\n%s", listed)
	}

	// (2) The fail-closed shape survives around the hole: the endpoint drop (closure
	// b) and the broad loopback + IPv6 drops are all still present, so the exemption
	// did not remove a tightness rule.
	for _, want := range []string{
		"meta skuid 424244 ip daddr 127.0.0.1 tcp dport 9050 drop", // closure (b)
		"127.0.0.0/8", // broad loopback drop still present
		"::/0",        // IPv6 default-drop still present
	} {
		if !strings.Contains(listed, want) {
			t.Errorf("exemption widened the ruleset: missing %q:\n%s", want, listed)
		}
	}
	// The terminal drop still ENDS the chain with an exemption present. This is the
	// ordering that matters most here: a terminal drop emitted BEFORE the exemption
	// accept would kill the direct hole from inside the forcing table, and an
	// exemption that displaced the terminal drop would un-jail the account. The
	// generated text is pinned by TestGenerateExemptionAcceptPrecedesTheTerminalDrop;
	// this asserts the kernel agrees.
	if last := lastRuleOfListedChain(listed, "anon_filter"); last != "drop" {
		t.Errorf("with an exemption loaded, the anon closure chain must still END in an\n"+
			"unconditional `drop`; its last rule is %q:\n%s", last, listed)
	}
	exemptAccept := "meta skuid 424244 ip daddr 192.168.1.150 tcp dport 8080 accept"
	if i, j := strings.Index(listed, exemptAccept), strings.LastIndex(listed, "drop"); i < 0 || i > j {
		t.Errorf("the exemption accept must precede the terminal drop, or split tunnelling\n"+
			"re-breaks (see work/notes/findings/split-tunnel-broken-by-exemption-blind-baseline.md):\n%s", listed)
	}

	// (3) The exemption is scoped to the EXACT host, not its /24: no sibling range.
	if strings.Contains(listed, "192.168.1.0/24") {
		t.Errorf("exemption widened to the whole /24 (should be the exact host):\n%s", listed)
	}

	// (4) The BASELINE must RETURN the same exempted destination (the split-tunnel fix):
	// the exemption is deliberately NOT redirected, so it reaches the baseline chain
	// with its real LAN daddr; without a baseline return, the baseline's terminal
	// non-loopback drop kills the direct hole before the forcing accept completes it
	// (the live symptom: the anon UID timed out on the EXEMPTED host while reaching
	// non-exempt ones). Load the baseline WITH the exemption and assert the return is
	// present and precedes the broad drop.
	baselineTable := nftables.BaselineTableName(account)
	t.Cleanup(func() { _, _, _ = r.Run(ctx, "delete table inet "+baselineTable, "nft", "-f", "-") })
	if err := nftables.ApplyBaseline(ctx, r, account, p.AnonUID, []lanexempt.Exempt{exempt}); err != nil {
		t.Fatalf("ApplyBaseline with exemption on a real host: %v", err)
	}
	listedBaseline := listTable(t, r, baselineTable)
	exemptReturn := "meta skuid 424244 ip daddr 192.168.1.150 tcp dport 8080 return"
	if !strings.Contains(listedBaseline, exemptReturn) {
		t.Errorf("baseline must RETURN the exempted destination so the forcing accept can complete it; missing %q:\n%s", exemptReturn, listedBaseline)
	}
	if strings.Index(listedBaseline, exemptReturn) > strings.Index(listedBaseline, "ip daddr != 127.0.0.0/8 drop") {
		t.Errorf("the baseline exemption return must precede the broad non-loopback drop:\n%s", listedBaseline)
	}

	// Idempotent re-Apply, then Delete only the account table; the sentinel survives.
	if err := nftables.Apply(ctx, r, p); err != nil {
		t.Fatalf("re-Apply with exemption (idempotency): %v", err)
	}
	if !tableExists(t, r, sentinel) {
		t.Fatalf("Apply clobbered the sentinel table (host rules not isolated)")
	}
	if err := nftables.Delete(ctx, r, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if tableExists(t, r, table) {
		t.Errorf("Delete left the account table %q behind", table)
	}
	if !tableExists(t, r, sentinel) {
		t.Errorf("Delete removed the sentinel table too (over-broad delete)")
	}
}

// lastRuleOfListedChain returns the final RULE of a named chain as the KERNEL
// prints it (`nft list table`). The kernel's own formatting (tabs, its own
// spacing, its own rule normalisation) differs from the generator's, so the
// generator-side helpers in nftables_test.go cannot parse it -- and that
// difference is the point: this reads back what the kernel actually loaded, which
// is the only thing that governs traffic. The chain header (`type ...`), blank
// lines and comments are skipped so "the last rule" means the last rule the kernel
// will evaluate.
func lastRuleOfListedChain(listed, chain string) string {
	inChain := false
	last := ""
	for _, line := range strings.Split(listed, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inChain {
			if trimmed == "chain "+chain+" {" {
				inChain = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "type ") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		last = trimmed
	}
	return last
}

func mustNft(t *testing.T, r execRunner, ruleset string) {
	t.Helper()
	if _, stderr, err := r.Run(context.Background(), ruleset, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft -f -: %v: %s", err, stderr)
	}
}

func tableExists(t *testing.T, r execRunner, table string) bool {
	t.Helper()
	out, _, _ := r.Run(context.Background(), "", "nft", "list", "tables")
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "table inet "+table {
			return true
		}
	}
	return false
}

func listTable(t *testing.T, r execRunner, table string) string {
	t.Helper()
	out, stderr, err := r.Run(context.Background(), "", "nft", "list", "table", "inet", table)
	if err != nil {
		t.Fatalf("nft list table inet %s: %v: %s", table, err, stderr)
	}
	return out
}
