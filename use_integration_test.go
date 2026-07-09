//go:build integration
// +build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/provision"
)

// TestUseExecLoginShellDropsToAccount is the isolated `integration`-tagged proof
// of the REAL shell drop behind `anonctl use`: it provisions a throwaway account,
// asserts execLoginShell resolves that account's real UID/GID/shell/home from
// passwd, and then proves the setpriv drop mechanism execLoginShell uses actually
// lands in the account's UID (a login shell running `id -u` prints the account's
// UID, not root's). It does NOT call execLoginShell directly (that syscall.Exec's
// and would replace the test process); it exercises the same setpriv --reuid
// --regid --init-groups drop the production path builds.
//
// It always tears the throwaway account down, and SKIPS (never fails) without
// root / setpriv / useradd, so `go test -tags integration ./...` still passes on
// an unprivileged box.
func TestUseExecLoginShellDropsToAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("use integration requires root (provisions an account, setpriv drops to it); skipping")
	}
	for _, bin := range []string{"setpriv", "useradd", "userdel", "getent", "id"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}

	ctx := context.Background()
	r := provision.ExecRunner{}
	account := cli.ResolveAccount("useitest")

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	defer func() { _, _ = provision.Rm(ctx, r, account, true /* purgeAccount */) }()

	// execLoginShell's resolver must read the account's real passwd fields.
	uid, gid, shell, home, err := accountLoginFields(ctx, r, account)
	if err != nil {
		t.Fatalf("accountLoginFields(%s): %v", account, err)
	}
	if uid <= 0 || gid <= 0 {
		t.Fatalf("resolved non-positive uid/gid for %s: uid=%d gid=%d", account, uid, gid)
	}
	if shell == "" || home == "" {
		t.Fatalf("resolved empty shell/home for %s: shell=%q home=%q", account, shell, home)
	}

	// The SAME drop primitive execLoginShell uses (setpriv --reuid --regid
	// --init-groups) must land in the account's UID: a login shell that runs
	// `id -u` prints the account UID, proving the drop is real (not still root).
	out, _, derr := runCmd(ctx, "setpriv",
		"--reuid", strconv.Itoa(uid), "--regid", strconv.Itoa(gid), "--init-groups",
		shell, "-l", "-c", "id -u")
	if derr != nil {
		t.Fatalf("setpriv drop to %s failed: %v (out=%q)", account, derr, out)
	}
	if got := strings.TrimSpace(out); got != strconv.Itoa(uid) {
		t.Errorf("dropped shell ran as uid %q, want %d (the account's UID); the drop did not land in the account", got, uid)
	}
}

// runCmd runs a command and returns trimmed stdout/stderr + the exec error.
func runCmd(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}
