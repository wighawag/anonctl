//go:build integration
// +build integration

package provision_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/provision"
)

// TestRealProvisionRoundTrip is the ONE test that touches real account state: it
// runs the actual ExecRunner (real useradd/userdel/getent), so it is guarded
// behind the `integration` build tag and is NOT part of the default
// `go test ./...` run. It provisions a throwaway account, asserts idempotency,
// and ALWAYS cleans up the account (and its shim) it created, so it leaves no
// residue on the box. It requires root; it skips (not fails) when not root, so
// an ordinary developer's `go test -tags integration ./...` still passes.
//
// The account name is deliberately an unlikely `anon-anonctlitest` so it cannot
// collide with a real operator account.
func TestRealProvisionRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration provisioning requires root (useradd/userdel); skipping")
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("useradd not available; skipping")
	}

	ctx := context.Background()
	r := provision.ExecRunner{}
	account := cli.ResolveAccount("anonctlitest")
	shim := cli.ShimAccount(account)

	// Guarantee cleanup even if an assertion below fails: always purge the account
	// and shim this test made, and verify they are gone (the "asserts it cleans up
	// the account it made" acceptance requirement).
	defer func() {
		if _, err := provision.Rm(ctx, r, account, true /* purgeAccount */); err != nil {
			t.Errorf("cleanup Rm: %v", err)
		}
		for _, a := range []string{account, shim} {
			if present(ctx, r, a) {
				t.Errorf("cleanup left %q behind", a)
			}
		}
	}()

	// Fresh provision: creates the account and its distinct shim UID.
	res, err := provision.Add(ctx, r, account)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !res.Created {
		t.Fatalf("Add.Created = false on a fresh account")
	}
	if !present(ctx, r, account) {
		t.Fatalf("login account %q was not created", account)
	}
	if !present(ctx, r, shim) {
		t.Fatalf("shim account %q was not created", shim)
	}

	// The shim UID must DIFFER from the login UID (a distinct dedicated service
	// account, story 12).
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.UID == "" || st.ShimUID == "" || st.UID == st.ShimUID {
		t.Errorf("expected distinct UIDs, got login=%q shim=%q", st.UID, st.ShimUID)
	}

	// Idempotent re-add: a clean no-op, not an error, and no second account.
	res2, err := provision.Add(ctx, r, account)
	if err != nil {
		t.Fatalf("re-Add: %v", err)
	}
	if res2.Created {
		t.Errorf("re-Add.Created = true, want false (idempotent)")
	}
}

func present(ctx context.Context, r provision.Runner, account string) bool {
	out, _, _ := r.Run(ctx, "getent", "passwd", account)
	return strings.HasPrefix(strings.TrimSpace(out), account+":")
}
