package nftables_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/nftables"
)

// fakeRunner records the nft invocations and the stdin fed to them, so Apply/
// Delete wiring is exercised WITHOUT touching the host's real ruleset (mirrors
// provision's fakeRunner). No `nft` ever runs on the box in the default test run.
type fakeRunner struct {
	calls [][]string
	stdin []string
	err   error
}

func (r *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	r.stdin = append(r.stdin, stdin)
	return "", "", r.err
}

func TestApplyFeedsGeneratedRulesetToNft(t *testing.T) {
	r := &fakeRunner{}
	p := sampleParams()
	if err := nftables.Apply(context.Background(), r, p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("expected one nft call, got %d: %v", len(r.calls), r.calls)
	}
	// Apply pipes the generated ruleset into `nft -f -` (read from stdin), the
	// atomic-load form. It must NOT shell out per-rule.
	call := strings.Join(r.calls[0], " ")
	if !strings.HasPrefix(call, "nft ") || !strings.Contains(call, "-f") {
		t.Errorf("expected `nft -f -`, got %q", call)
	}
	want, _ := nftables.Generate(p)
	if r.stdin[0] != want {
		t.Errorf("Apply fed a ruleset that differs from Generate's output")
	}
}

func TestApplyIsPrecededByAtomicTableReplace(t *testing.T) {
	// Re-applying must be idempotent and leave no stale rules: the generated
	// ruleset itself must delete+recreate the account's own table atomically, so a
	// second Apply is a clean replace, never an append.
	out, err := nftables.Generate(sampleParams())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// A `table inet <name> { }` + `delete table` preamble makes the -f load atomic
	// and idempotent (create-if-absent then delete, then define). Assert the
	// account-scoped delete is present so re-Apply cannot double-load.
	mustContain(t, out, "delete table inet anonctl_anon")
}

func TestDeleteRemovesOnlyTheAccountTable(t *testing.T) {
	r := &fakeRunner{}
	if err := nftables.Delete(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("expected one nft call, got %d: %v", len(r.calls), r.calls)
	}
	call := strings.Join(r.calls[0], " ")
	if !strings.HasPrefix(call, "nft ") || !strings.Contains(call, "-f") {
		t.Errorf("expected `nft -f -`, got %q", call)
	}
	// Delete removes ONLY this account's table (never `flush ruleset`, never
	// another table): the host's other rules are untouched. The command is on stdin.
	if !strings.Contains(r.stdin[0], "delete table inet anonctl_anon") {
		t.Errorf("expected `delete table inet anonctl_anon` on stdin, got %q", r.stdin[0])
	}
	if strings.Contains(r.stdin[0], "flush ruleset") {
		t.Errorf("Delete must never flush the whole ruleset: %q", r.stdin[0])
	}
}

func TestTableNameIsAccountScoped(t *testing.T) {
	if got := nftables.TableName("anon"); got != "anonctl_anon" {
		t.Errorf("TableName(anon) = %q, want anonctl_anon", got)
	}
	if got := nftables.TableName("anon-work"); got != "anonctl_anon_work" {
		t.Errorf("TableName(anon-work) = %q, want anonctl_anon_work (nft identifiers cannot contain '-')", got)
	}
}
