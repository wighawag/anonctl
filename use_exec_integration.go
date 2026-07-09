//go:build integration
// +build integration

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/wighawag/anonctl/internal/provision"
)

// execLoginShell (integration build) is the REAL shell drop behind `anonctl use`:
// it resolves the account's UID / GID / login shell / home from its passwd entry
// (via the Runner, the same read-only truth the rest of provisioning uses) and
// REPLACES the anonctl process with the account's interactive login shell dropped
// to that UID.
//
// Mechanism: `setpriv --reuid <uid> --regid <gid> --init-groups <shell> -l`
// (recorded in the done-report / ADR). setpriv (not `su -` / `sudo -iu`) is the
// deliberate choice: it is the SAME drop primitive the shim units and every
// verify/nftables probe already use (`meta skuid` keys on the numeric UID setpriv
// sets), it adds no PAM/auth surface, and it does not depend on sudoers (the
// account is provisioned with NO sudo path). `--init-groups` gives the account its
// own supplementary groups for a normal login (vs `--clear-groups`, which the
// non-interactive probes use); `-l` makes the shell a LOGIN shell so it reads the
// account's minimal-PATH profile drop-in that `add` wrote.
//
// It exec-REPLACES this process (syscall.Exec), so on success it never returns and
// the operator is now IN the anon account's shell with the kernel forcing in
// effect. Any resolution/lookup failure returns an error (surfaced non-zero by
// runUse), never a silent fallback to a non-anonymized shell.
func execLoginShell(ctx context.Context, r provision.Runner, account string) error {
	uid, gid, shell, home, err := accountLoginFields(ctx, r, account)
	if err != nil {
		return err
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return fmt.Errorf("setpriv not found (needed to drop to %s): %w", account, err)
	}

	// Build a minimal, clean login environment for the dropped shell: HOME/USER/
	// LOGNAME for the account and a spartan PATH (the account's own profile drop-in
	// refines it on login). Not inheriting anonctl's environment keeps a root-run
	// `use` from leaking root's env into the anon session.
	env := []string{
		"HOME=" + home,
		"USER=" + account,
		"LOGNAME=" + account,
		"SHELL=" + shell,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TERM=" + os.Getenv("TERM"),
	}

	// argv0 of the shell is prefixed with `-` so it behaves as a LOGIN shell (the
	// conventional login-shell signal), reinforcing the `-l` we pass setpriv.
	argv := []string{
		setpriv,
		"--reuid", strconv.Itoa(uid),
		"--regid", strconv.Itoa(gid),
		"--init-groups",
		shell, "-l",
	}
	return syscall.Exec(setpriv, argv, env)
}

// accountLoginFields resolves an account's numeric UID, numeric GID, login shell,
// and home from its `getent passwd` entry (`name:x:uid:gid:gecos:home:shell`). It
// errors if the account is absent or its line is malformed, so `use` never drops
// to a wrong/empty target. A missing shell defaults to /bin/bash (the shell `add`
// provisions the account with).
func accountLoginFields(ctx context.Context, r provision.Runner, account string) (uid, gid int, shell, home string, err error) {
	stdout, _, _ := r.Run(ctx, "getent", "passwd", account)
	fields := strings.Split(strings.TrimSpace(stdout), ":")
	if len(fields) < 7 || fields[0] != account {
		return 0, 0, "", "", fmt.Errorf("account %q not found in passwd (provision it with `anonctl add` first)", account)
	}
	uid, err = strconv.Atoi(fields[2])
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("account %q has a non-numeric UID %q", account, fields[2])
	}
	gid, err = strconv.Atoi(fields[3])
	if err != nil {
		return 0, 0, "", "", fmt.Errorf("account %q has a non-numeric GID %q", account, fields[3])
	}
	home = fields[5]
	shell = fields[6]
	if shell == "" {
		shell = "/bin/bash"
	}
	if home == "" {
		home = filepath.Join("/home", account)
	}
	return uid, gid, shell, home, nil
}
