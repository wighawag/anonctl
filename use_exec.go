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

	"github.com/wighawag/anoncore/provision"
)

// execLoginShell is the REAL shell drop behind `anonctl use`: the INTERACTIVE face
// of the shared verify-then-enter primitive (enterAccount does the resolution +
// drop, `execProgram` is the one-shot sibling face). It is compiled into
// EVERY build (dropping to the account is runtime behaviour needing setpriv +
// root, like `add`/`rm`, not a test): the previous default-build stub that refused
// to open a shell is gone. Via enterAccount it resolves the account's UID / GID /
// login shell / home from its passwd entry
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
// Before the exec it chdirs into the account's HOME (falling back to `/` if HOME is
// unusable) so the login lands in the account's own directory, NOT the caller's CWD.
// `use` is normally run from the operator's own home, which the anon account cannot
// write; a shell left there but with HOME=/home/anon splits the environment (tools
// key paths off $PWD yet write under HOME) and yields EACCES (e.g. `pi` trying to
// mkdir a session dir named after the caller's path). Starting in HOME is what a
// real login does.
//
// It exec-REPLACES this process (syscall.Exec), so on success it never returns and
// the operator is now IN the anon account's shell with the kernel forcing in
// effect. Any resolution/lookup failure returns an error (surfaced non-zero by
// runUse), never a silent fallback to a non-anonymized shell.
func execLoginShell(ctx context.Context, r provision.Runner, account string) error {
	entry, err := enterAccount(ctx, r, account)
	if err != nil {
		return err
	}
	// argv0 of the shell is prefixed with `-` so it behaves as a LOGIN shell (the
	// conventional login-shell signal), reinforcing the `-l` we pass setpriv. This is
	// the INTERACTIVE face of the shared enter-primitive: drop into the account and
	// hand the operator its login shell.
	argv := append(entry.setprivPrefix(), entry.shell, "-l")
	return syscall.Exec(entry.setpriv, argv, entry.env)
}

// execProgram is the ONE-PROGRAM face of the same verify-then-enter primitive
// `execLoginShell` is the interactive face of. Behind the identical safety gate
// (runExec verifies GREEN before ever calling this) it drops into the account with
// the SAME setpriv mechanism, SAME clean-login env, SAME HOME chdir, but instead of
// an interactive login shell it RUNS `program` with `args` forwarded VERBATIM.
//
// It runs the program THROUGH the account's login shell as a login shell command
// (`setpriv ... <shell> -lc "<program> <args>"`) so the program inherits the same
// login environment (minimal-PATH profile drop-in) an interactive `use` shell gets.
// The command string is built by shell-quoting the program and each arg
// INDEPENDENTLY (shellQuote), so an arg with spaces or metacharacters reaches the
// program as ONE argument, never re-split or re-globbed: `anonctl exec pi -p "hi
// there"` runs pi with a single `hi there` argument. Passing the args as a
// pre-quoted command string (not via the shell's own `"$@"`) keeps the quoting
// wholly on anonctl's side, so there is no second word-splitting pass to reason
// about.
//
// It exec-REPLACES this process (syscall.Exec), so on success it never returns; the
// program becomes anonctl. Any resolution/lookup failure returns an error (surfaced
// non-zero by runExec), NEVER a silent fallback to a non-anonymized run.
func execProgram(ctx context.Context, r provision.Runner, account, program string, args []string) error {
	entry, err := enterAccount(ctx, r, account)
	if err != nil {
		return err
	}
	// Build the login-shell command: the program and every arg quoted independently so
	// the login shell re-assembles the EXACT argv anonctl was handed (no re-split, no
	// glob). shellQuote wraps each token in single quotes (POSIX-literal), so nothing
	// inside is special to the shell.
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, shellQuote(program))
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	command := strings.Join(quoted, " ")

	argv := append(entry.setprivPrefix(), entry.shell, "-lc", command)
	return syscall.Exec(entry.setpriv, argv, entry.env)
}

// accountEntry is the resolved, ready-to-drop context the verify-then-enter
// primitive produces once (via enterAccount): the located setpriv, the account's
// numeric UID/GID + login shell, and the clean login environment, with the CWD
// already moved into the account's HOME. Both faces (`execLoginShell` interactive,
// `execProgram` one-shot) consume it, differing ONLY in what they hand setpriv to
// run. This is the shape a future shared anoncore enter-primitive will host; the
// per-tool substrate (here: setpriv into the anon UID) is all that stays behind.
type accountEntry struct {
	setpriv string
	uid     int
	gid     int
	shell   string
	env     []string
}

// setprivPrefix builds the leading `setpriv --reuid <uid> --regid <gid>
// --init-groups` argv both faces share; the caller appends the shell + its
// mode-specific tail (`-l` for a login shell, `-lc <command>` for a program).
func (e accountEntry) setprivPrefix() []string {
	return []string{
		e.setpriv,
		"--reuid", strconv.Itoa(e.uid),
		"--regid", strconv.Itoa(e.gid),
		"--init-groups",
	}
}

// enterAccount is the SHARED verify-then-enter primitive's drop half (the verify
// half is the runExec/runUse gate that MUST have passed GREEN before this is
// called): it resolves the account's UID/GID/login-shell/home, locates setpriv,
// builds the clean login environment, and chdirs into the account's HOME, returning
// an accountEntry ready for either face to exec. Factoring it here keeps `use`
// (interactive) and `exec` (one program) from drifting into two different notions
// of "enter the account", and makes the later anoncore extraction trivial (this is
// exactly the primitive that moves). Any failure is returned, never swallowed: an
// enter that could not resolve/chdir must be a loud error, not a run in the clear.
func enterAccount(ctx context.Context, r provision.Runner, account string) (accountEntry, error) {
	uid, gid, shell, home, err := accountLoginFields(ctx, r, account)
	if err != nil {
		return accountEntry{}, err
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return accountEntry{}, fmt.Errorf("setpriv not found (needed to drop to %s): %w", account, err)
	}

	// Build a minimal, clean login environment for the dropped session: HOME/USER/
	// LOGNAME for the account and a spartan PATH (the account's own profile drop-in
	// refines it on login). Not inheriting anonctl's environment keeps a root-run
	// `use`/`exec` from leaking root's env into the anon session.
	env := []string{
		"HOME=" + home,
		"USER=" + account,
		"LOGNAME=" + account,
		"SHELL=" + shell,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TERM=" + os.Getenv("TERM"),
		// Mark the dropped session as an anonctl session so a nested `anonctl use`/`exec`
		// (or any root-requiring verb) run from INSIDE it refuses cleanly instead of
		// trying to sudo: the anon account has no sudo path, so a re-exec would just
		// dead-end on an anon password prompt. The value is the account, so the refusal
		// names it.
		anonctlSessionEnv + "=" + account,
	}

	// Land in the account's HOME before exec'ing. syscall.Exec inherits the caller's
	// CWD, and `use`/`exec` is typically run from the operator's own home (e.g.
	// /home/wighawag), which the anon account cannot write. A session that starts there
	// but with HOME=/home/anon is a split environment: tools derive paths from $PWD
	// (session dirs named after the caller's path) yet write under HOME, so they hit
	// EACCES on the caller's dir or on a half-created /home/anon path. A real login
	// starts in HOME, so chdir there first. If HOME is unreachable (missing/permission),
	// fall back to `/` rather than leaving the session in the caller's unwritable dir;
	// never silently keep the caller's CWD.
	cwd := loginWorkingDir(home)
	if err := os.Chdir(cwd); err != nil {
		return accountEntry{}, fmt.Errorf("could not enter working dir %q for %s's session: %w", cwd, account, err)
	}
	// PWD must agree with the CWD we just set, since login shells and tools trust $PWD
	// over a getcwd() syscall; leaving the inherited PWD would re-introduce the split.
	env = append(env, "PWD="+cwd)

	return accountEntry{setpriv: setpriv, uid: uid, gid: gid, shell: shell, env: env}, nil
}

// shellQuote wraps s in single quotes so a POSIX shell reads it as a single literal
// argument, with NO word-splitting, glob, variable, or command substitution applied.
// An embedded single quote is emitted as the classic `'\”` sequence (close-quote,
// escaped-quote, re-open-quote). This is what lets `exec` forward an arbitrary arg
// (spaces, `$`, `*`, `;`, quotes) through the account's login shell so the program
// receives it EXACTLY as anonctl was handed it, never re-split or re-globbed.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// anonctlSessionEnv marks a shell that `anonctl use` dropped into (value: the anon
// account name). It lets anonctl detect it is running INSIDE an anon session so a
// nested root-requiring verb refuses with a clear message rather than re-exec'ing
// via sudo (which an anon account cannot pass: no sudo path). It is a plain marker,
// not a security control: the real protection is the kernel forcing + default-deny.
const anonctlSessionEnv = "ANONCTL_SESSION"

// loginWorkingDir picks the directory the dropped login shell should start in: the
// account's HOME when it is a usable absolute path, else `/`. It is the pure
// decision half of the chdir (the actual os.Chdir + its permission check stays in
// execLoginShell, since only the live filesystem can say whether the account can
// enter it). It never returns the caller's inherited CWD: `use` must not leave the
// anon session sitting in the operator's own (unwritable) home. A relative or empty
// home is treated as unusable and falls back to `/`.
func loginWorkingDir(home string) string {
	if filepath.IsAbs(home) {
		return home
	}
	return "/"
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
