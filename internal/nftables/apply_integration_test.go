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
	// The load-bearing security lines are actually present in the loaded table.
	listed := listTable(t, r, table)
	for _, want := range []string{
		"policy drop",
		"meta skuid 424242",
		"meta skuid 424243",
	} {
		if !strings.Contains(listed, want) {
			t.Errorf("loaded table missing %q:\n%s", want, listed)
		}
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
