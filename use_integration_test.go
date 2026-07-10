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
	"github.com/wighawag/anoncore/provision"
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

	// The session must land in the account's HOME, not the caller's CWD. Reproduce the
	// production pre-exec chdir (loginWorkingDir + os.Chdir) from a FOREIGN starting
	// dir, then assert a login shell reports HOME as its pwd. This is the regression
	// for the split environment (`use` run from /home/wighawag left the anon shell
	// there, so tools wrote under HOME=/home/anon and hit EACCES).
	prevCwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(prevCwd) })
	if err := os.Chdir("/tmp"); err != nil { // a foreign dir, standing in for the operator's own home
		t.Fatalf("chdir to foreign dir: %v", err)
	}
	want := loginWorkingDir(home)
	if err := os.Chdir(want); err != nil {
		t.Fatalf("chdir to %s's login working dir %q: %v", account, want, err)
	}
	pwdOut, _, pErr := runCmd(ctx, "setpriv",
		"--reuid", strconv.Itoa(uid), "--regid", strconv.Itoa(gid), "--init-groups",
		shell, "-l", "-c", "pwd -P")
	if pErr != nil {
		t.Fatalf("setpriv drop (pwd) to %s failed: %v (out=%q)", account, pErr, pwdOut)
	}
	if got := strings.TrimSpace(pwdOut); got != want {
		t.Errorf("dropped login shell started in %q, want the account's home %q (the session must not sit in the caller's CWD)", got, want)
	}
}

// TestExecProgramRunsAsAccount is the `integration`-tagged proof of the ONE-PROGRAM
// face (execProgram) of the shared enter-primitive: it provisions a throwaway
// account and proves that the SAME setpriv login-shell-command mechanism execProgram
// builds (`setpriv --reuid --regid --init-groups <shell> -lc "<program> <args>"`)
// runs the program as the account's UID AND forwards an arg with spaces as ONE
// argument. It does NOT call execProgram directly (that syscall.Exec's and would
// replace the test process); it exercises the identical drop + shellQuote'd command
// string production builds.
//
// It always tears the throwaway account down, and SKIPS (never fails) without root /
// setpriv / useradd, so `go test -tags integration ./...` still passes unprivileged.
func TestExecProgramRunsAsAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exec integration requires root (provisions an account, setpriv drops to it); skipping")
	}
	for _, bin := range []string{"setpriv", "useradd", "userdel", "getent", "id", "printf"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}

	ctx := context.Background()
	r := provision.ExecRunner{}
	account := cli.ResolveAccount("execitest")

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	defer func() { _, _ = provision.Rm(ctx, r, account, true /* purgeAccount */) }()

	uid, gid, shell, _, err := accountLoginFields(ctx, r, account)
	if err != nil {
		t.Fatalf("accountLoginFields(%s): %v", account, err)
	}

	// The program runs AS the account: a login-shell command running `id -u` prints the
	// account's UID, proving the drop landed (the exact setpriv form execProgram builds).
	out, _, derr := runCmd(ctx, "setpriv",
		"--reuid", strconv.Itoa(uid), "--regid", strconv.Itoa(gid), "--init-groups",
		shell, "-lc", "id -u")
	if derr != nil {
		t.Fatalf("setpriv program run as %s failed: %v (out=%q)", account, derr, out)
	}
	if got := strings.TrimSpace(out); got != strconv.Itoa(uid) {
		t.Errorf("program ran as uid %q, want %d (the account's UID); the drop did not land", got, uid)
	}

	// An arg with spaces is forwarded as ONE argument: build the SAME shellQuote'd
	// command string execProgram builds for `printf %s\0 <arg>` and assert the shell
	// hands printf the single spaced arg (its NUL-terminated echo equals the arg).
	spaced := "hello there world"
	command := shellQuote("printf") + " " + shellQuote("%s") + " " + shellQuote(spaced)
	argOut, _, aErr := runCmd(ctx, "setpriv",
		"--reuid", strconv.Itoa(uid), "--regid", strconv.Itoa(gid), "--init-groups",
		shell, "-lc", command)
	if aErr != nil {
		t.Fatalf("setpriv spaced-arg run as %s failed: %v (out=%q)", account, aErr, argOut)
	}
	if argOut != spaced {
		t.Errorf("forwarded arg = %q, want %q (a spaced arg must reach the program as ONE argument, not re-split)", argOut, spaced)
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
