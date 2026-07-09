package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/wighawag/anonctl/internal/cli"
)

// Self-elevation: a root-requiring verb run without root re-execs the SAME command
// through `sudo` so the operator gets the password prompt INLINE in the terminal
// (a bare `anonctl verify` works, no `sudo anonctl` prefix needed). sudo is the
// deliberate mechanism, NOT pkexec: on a tty sudo prompts in-terminal, whereas
// pkexec pops the GNOME polkit GUI dialog this project avoids (see
// work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md). Already-root
// runs directly (no double-sudo); read verbs (list/status) and the version
// fast-path never elevate; sudo-absent falls through to the verb's own clear
// "must be root" error, never pkexec.

// elevatedSentinelEnv is the belt-and-suspenders loop guard. Before re-exec anonctl
// sets it in the child's environment; if it is ALREADY set on entry, anonctl never
// re-execs (it runs the verb directly instead). Combined with the euid!=0 gate
// (after sudo the child is euid 0, so it would not re-fire anyway), this makes a
// re-exec loop impossible even under a misconfigured sudo that failed to elevate.
const elevatedSentinelEnv = "ANONCTL_ELEVATED"

// errSudoNotFound is the sentinel elevateLookSudo returns when `sudo` is not on
// PATH, so the caller falls back to the direct "must be root" path (never pkexec).
var errSudoNotFound = errors.New("sudo not found on PATH")

// rootRequiringVerbs are the verbs that mutate the system as root and so trigger
// self-elevation when run non-root: the forcing/provisioning verbs plus `use`
// (which drops UID via setpriv). Read-only verbs (list/status) are deliberately
// ABSENT so a read never forces a password prompt.
var rootRequiringVerbs = map[string]bool{
	"add":         true,
	"rm":          true,
	"verify":      true,
	"use":         true,
	"update":      true,
	"reconfigure": true,
}

// The elevation seams: package vars so the unit tests drive dispatch-time
// self-elevation WITHOUT a real sudo, a real re-exec, or a password prompt (assert
// the re-exec argv, the already-root/read-verb no-op, the loop guard, exit-code
// propagation). Production wires the real os.Geteuid / exec.LookPath /
// os.Executable / exec-and-wait.
var (
	// elevateGeteuid reports the effective UID (os.Geteuid in production).
	elevateGeteuid = os.Geteuid
	// elevateLookSudo resolves `sudo` on PATH, or returns errSudoNotFound.
	elevateLookSudo = func() (string, error) {
		p, err := exec.LookPath("sudo")
		if err != nil {
			return "", errSudoNotFound
		}
		return p, nil
	}
	// elevateSelfPath resolves the path to THIS anonctl binary to re-exec (via
	// os.Executable, i.e. /proc/self/exe on Linux), so the child is the same binary.
	elevateSelfPath = os.Executable
	// elevateReexec runs `sudo <self> <args...>` with the given env, waits, and
	// returns the child's exit code (the value anonctl exits with, so a failing
	// verify still exits non-zero and CI-gating stays intact).
	elevateReexec = runElevated
)

// maybeElevate decides whether the invocation must self-elevate and, if so, does
// it. It returns (handled, exitCode): handled=true means the re-exec ran and
// exitCode is the child's code to exit with (the caller returns it verbatim);
// handled=false means "carry on and run the verb directly" (already root, a read
// verb, sudo absent, or the loop-guard sentinel set).
//
// It NEVER prompts or execs in a way tests can observe a password: the prompt is
// sudo's, and all three impure steps (geteuid, sudo lookup, re-exec) are behind
// seams the unit tests replace.
func maybeElevate(verb, account string, args []string) (handled bool, exitCode int) {
	if !rootRequiringVerbs[verb] {
		return false, 0 // read verbs never elevate
	}
	if elevateGeteuid() == 0 {
		return false, 0 // already root: run directly, no double-sudo
	}
	if os.Getenv(elevatedSentinelEnv) != "" {
		// Loop guard: we already tried to elevate (or a parent set the sentinel) and
		// are STILL not root. Do not re-exec (that would loop); run directly and let
		// the verb surface its own "must be root" error.
		return false, 0
	}
	if session := os.Getenv(anonctlSessionEnv); session != "" {
		// We are INSIDE an `anonctl use` session (a dropped anon shell). The anon account
		// has NO sudo path (that is the security design: anon is a privilege dead-end),
		// so a sudo re-exec from here can only dead-end on an anon password prompt, no
		// matter the target. Refuse cleanly with the accurate way to proceed instead of
		// prompting. This is a UX guard, not a security control (the kernel forcing +
		// default-deny are the real protection). Cases:
		//   - `use` of the SAME account: you are already in it, nothing to do.
		//   - `use` of a DIFFERENT account: you cannot switch in-process (no root from
		//     here); exit first, then run it from your normal (sudo-capable) account.
		//   - any other root verb: same reason; run it from your normal account.
		switch {
		case verb == "use" && account == session:
			errorf("already inside the anonctl session for %q; nothing to do (type `exit` to leave it)", session)
		case verb == "use":
			errorf("cannot switch from the anonctl session for %q to %q in place (the anon account has no sudo to re-elevate); type `exit` to leave this session, then run `%s` from your normal account", session, account, useCommandFor(account))
		default:
			errorf("%s needs root, but you are inside the anonctl session for %q (the anon account has no sudo); type `exit` to leave it, then run the command from your normal account", verb, session)
		}
		return true, 1
	}
	sudoPath, err := elevateLookSudo()
	if err != nil {
		// No sudo on PATH: fall back to the verb's direct "must be root" error. Never
		// pkexec, never a GUI prompt.
		return false, 0
	}
	self, err := elevateSelfPath()
	if err != nil {
		// Cannot resolve our own path to re-exec; fall back to the direct path rather
		// than guess a name that might not be on PATH.
		return false, 0
	}

	// Predictable + honest: a short stderr line so the coming password prompt is not
	// a surprise. STDERR, never stdout, so `--json` output stays pure. Dimmed (not red):
	// this is an informational notice, not an error.
	fmt.Fprint(os.Stderr, errStyle.Dim(fmt.Sprintf("anonctl: %s needs root; re-running via sudo...", verb))+"\n")

	// argv: sudo <self> <original args...>, preserving flags/account/--json exactly.
	argv := append([]string{sudoPath, self}, args...)
	env := append(os.Environ(), elevatedSentinelEnv+"=1")
	return true, elevateReexec(sudoPath, argv, env)
}

// useCommandFor renders the exact command a user should re-run to enter an account
// after exiting the current session: the default `anon` -> `anonctl use`, and
// `anon-<name>` -> `anonctl use <name>`. It is only for the in-session refusal
// message, so the suggestion matches what the operator would actually type.
func useCommandFor(account string) string {
	if account == cli.DefaultAccount {
		return "anonctl use"
	}
	return "anonctl use " + strings.TrimPrefix(account, cli.DefaultAccount+"-")
}

// runElevated is the production re-exec: run `sudo <self> <args...>` inheriting the
// terminal (so sudo prompts inline and the elevated verb's I/O reaches the
// operator), wait, and return the child's exit code EXACTLY (so a failing verify
// still exits non-zero). A launch failure (sudo vanished between lookup and exec)
// maps to exit 1.
func runElevated(sudoPath string, argv, env []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		errorf("re-exec via sudo failed: %v", err)
		return 1
	}
	return 0
}
