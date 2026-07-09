package main

import (
	"os"
	"strings"
	"testing"
)

// swapElevateSeams installs fake elevate seams so the dispatch-time self-elevation
// is exercised WITHOUT a real sudo, a real re-exec, or a password prompt. It
// reports a simulated euid, a resolvable-or-absent `sudo`, a fixed self path, and
// records the re-exec argv + returns a scripted child exit code. It returns a
// pointer to the recorded re-exec (nil until a re-exec is attempted) and the
// notice buffer restore is handled by t.Cleanup.
type recordedElevate struct {
	sudoPath string
	argv     []string
	env      []string
}

func swapElevateSeams(t *testing.T, euid int, sudoPresent bool, childExit int) **recordedElevate {
	t.Helper()
	var rec *recordedElevate
	origEuid, origLook, origSelf, origExec := elevateGeteuid, elevateLookSudo, elevateSelfPath, elevateReexec
	elevateGeteuid = func() int { return euid }
	elevateLookSudo = func() (string, error) {
		if sudoPresent {
			return "/usr/bin/sudo", nil
		}
		return "", errSudoNotFound
	}
	elevateSelfPath = func() (string, error) { return "/opt/anonctl/anonctl", nil }
	elevateReexec = func(sudoPath string, argv, env []string) int {
		rec = &recordedElevate{sudoPath: sudoPath, argv: argv, env: env}
		return childExit
	}
	t.Cleanup(func() {
		elevateGeteuid, elevateLookSudo, elevateSelfPath, elevateReexec = origEuid, origLook, origSelf, origExec
	})
	return &rec
}

// deref unwraps the double pointer swapElevateSeams returns into the recorded
// re-exec (nil when none happened).
func deref(pp **recordedElevate) *recordedElevate { return *pp }

// A bare (non-root) root-requiring verb re-execs via `sudo <self> <original args>`,
// preserving argv exactly, and propagates the child's exit code.
func TestElevateReexecsRootVerbAsNonRoot(t *testing.T) {
	recp := swapElevateSeams(t, 1000, true, 7)
	code := run([]string{"verify", "work", "--json"})
	rec := deref(recp)
	if rec == nil {
		t.Fatalf("non-root verify did not re-exec via sudo")
	}
	want := []string{"/usr/bin/sudo", "/opt/anonctl/anonctl", "verify", "work", "--json"}
	if strings.Join(rec.argv, " ") != strings.Join(want, " ") {
		t.Errorf("re-exec argv = %q, want %q", rec.argv, want)
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7 (the child's exit must propagate exactly)", code)
	}
}

// Each root-requiring verb elevates when non-root; the notice names the verb.
func TestElevateAppliesToAllRootVerbs(t *testing.T) {
	for _, verb := range []string{"add", "rm", "verify", "use", "update", "reconfigure"} {
		recp := swapElevateSeams(t, 1000, true, 0)
		args := []string{verb}
		if verb == "update" || verb == "reconfigure" {
			args = append(args, "--endpoint", "socks5h://127.0.0.1:9050")
		}
		run(args)
		if deref(recp) == nil {
			t.Errorf("non-root %q did not re-exec via sudo", verb)
		}
	}
}

// Already-root (euid 0) runs the verb DIRECTLY: no re-exec, no double-sudo.
func TestElevateAlreadyRootRunsDirect(t *testing.T) {
	recp := swapElevateSeams(t, 0, true, 0)
	run([]string{"verify"})
	if deref(recp) != nil {
		t.Errorf("already-root verify re-exec'd via sudo; must run directly (no double-sudo)")
	}
}

// Read verbs (list/status) and the version fast-path never elevate, even non-root.
func TestElevateReadVerbsAndVersionNeverElevate(t *testing.T) {
	for _, args := range [][]string{{"list"}, {"status"}, {"--version"}, {"version"}} {
		recp := swapElevateSeams(t, 1000, true, 0)
		run(args)
		if deref(recp) != nil {
			t.Errorf("run(%v) elevated; read verbs / version must never re-exec", args)
		}
	}
}

// The re-exec loop guard: when the ANONCTL_ELEVATED sentinel is already set, a
// non-root root-verb does NOT re-exec (it would loop). It falls through to run the
// verb directly, so a misconfigured sudo that failed to elevate can never recurse.
func TestElevateLoopGuardBlocksReexecWhenSentinelSet(t *testing.T) {
	t.Setenv(elevatedSentinelEnv, "1")
	recp := swapElevateSeams(t, 1000, true, 0)
	run([]string{"verify"})
	if deref(recp) != nil {
		t.Errorf("re-exec fired with the %s sentinel already set; the loop guard must block it", elevatedSentinelEnv)
	}
}

// When sudo is not on PATH, elevation does NOT re-exec and does NOT try pkexec: the
// verb falls through to run directly (surfacing the underlying/"must be root"
// error), never a GUI prompt.
func TestElevateSudoMissingDoesNotReexec(t *testing.T) {
	recp := swapElevateSeams(t, 1000, false, 0)
	run([]string{"verify"})
	if deref(recp) != nil {
		t.Errorf("re-exec fired with sudo absent; must fall back to the direct 'must be root' path, never pkexec")
	}
}

// captureStderrDuring runs fn with os.Stderr redirected to a buffer, returning what
// was written. Used to assert the in-session refusal messages without a terminal.
func captureStderrDuring(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// Inside an anonctl session, a nested `use` of the SAME account does NOT re-exec via
// sudo (the anon account has no sudo to pass): it refuses with "already inside" and a
// non-zero exit, so the operator never hits a dead-end anon password prompt.
func TestElevateInSessionSameAccountRefusesNoReexec(t *testing.T) {
	t.Setenv(anonctlSessionEnv, "anon")
	recp := swapElevateSeams(t, 30034, true, 0)
	var code int
	msg := captureStderrDuring(t, func() { code = run([]string{"use"}) })
	if deref(recp) != nil {
		t.Errorf("nested `use` inside a session must NOT re-exec via sudo (anon has no sudo); it re-exec'd")
	}
	if code == 0 {
		t.Errorf("nested `use` of the same account must exit non-zero, got 0")
	}
	if !strings.Contains(msg, "already inside") || !strings.Contains(msg, "anon") {
		t.Errorf("message must say you are already inside the session for anon; got %q", msg)
	}
}

// Inside a session, `use <other>` (a real switch attempt) also does NOT re-exec: it
// cannot self-elevate from anon, so it refuses and tells the operator to exit first,
// naming the exact command to run from their normal account.
func TestElevateInSessionSwitchAccountRefusesWithExitInstruction(t *testing.T) {
	t.Setenv(anonctlSessionEnv, "anon")
	recp := swapElevateSeams(t, 30034, true, 0)
	var code int
	msg := captureStderrDuring(t, func() { code = run([]string{"use", "work"}) })
	if deref(recp) != nil {
		t.Errorf("`use work` inside a session must NOT re-exec via sudo; it re-exec'd")
	}
	if code == 0 {
		t.Errorf("switching accounts in-session must exit non-zero, got 0")
	}
	if !strings.Contains(msg, "exit") || !strings.Contains(msg, "anonctl use work") {
		t.Errorf("message must tell the operator to exit and run `anonctl use work`; got %q", msg)
	}
}

// Inside a session, a NON-use root verb (e.g. verify) also refuses cleanly instead
// of re-exec'ing into a dead-end anon sudo prompt.
func TestElevateInSessionOtherVerbRefusesNoReexec(t *testing.T) {
	t.Setenv(anonctlSessionEnv, "anon")
	recp := swapElevateSeams(t, 30034, true, 0)
	var code int
	msg := captureStderrDuring(t, func() { code = run([]string{"verify"}) })
	if deref(recp) != nil {
		t.Errorf("`verify` inside a session must NOT re-exec via sudo; it re-exec'd")
	}
	if code == 0 {
		t.Errorf("a root verb in-session must exit non-zero, got 0")
	}
	if !strings.Contains(msg, "normal account") {
		t.Errorf("message must point the operator to their normal account; got %q", msg)
	}
}
