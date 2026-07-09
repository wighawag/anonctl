package verify

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// TestPkexecPolicyQueryCommand_QueriesPolkitNeverRunsPkexec proves the core of this
// task: the pkexec UID-transition vector QUERIES polkit with pkcheck (the
// non-interactive policy query), it never RUNS pkexec. The v0.1.3/v0.1.4 mechanism
// (running `pkexec --disable-internal-agent` under a scrubbed env) did NOT stop the
// GNOME polkit dialog, because polkit finds the auth agent via systemd-logind, not
// env vars (work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md).
// pkcheck WITHOUT --allow-user-interaction/-u never starts an agent and never
// prompts. The subject must be ANON-OWNED, so the query runs under `setpriv --reuid
// <anon>` and passes `--process $$` (self) via `sh -c 'exec pkcheck ...'` so $$
// stays the pkcheck process's own pid across the exec.
func TestPkexecPolicyQueryCommand_QueriesPolkitNeverRunsPkexec(t *testing.T) {
	argv := pkexecPolicyQueryCommand(30001)
	want := []string{
		"setpriv", "--reuid", "30001", "--clear-groups",
		"sh", "-c", "exec pkcheck --action-id org.freedesktop.policykit.exec --process $$",
	}
	if fmt.Sprint(argv) != fmt.Sprint(want) {
		t.Fatalf("pkexec policy-query argv = %v, want %v", argv, want)
	}
	// It must NOT run pkexec (that is what pops the dialog) and must NOT pass an
	// interaction flag (that is what would start an agent + prompt).
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "pkexec") {
		t.Fatalf("the pkexec vector must QUERY polkit (pkcheck), never RUN pkexec; got %v", argv)
	}
	if strings.Contains(joined, "--allow-user-interaction") || strings.Contains(joined, " -u ") {
		t.Fatalf("the pkcheck query must NOT pass -u/--allow-user-interaction (else it starts an agent and prompts); got %v", argv)
	}
	if !strings.Contains(joined, "pkcheck") || !strings.Contains(joined, "org.freedesktop.policykit.exec") {
		t.Fatalf("the query must ask pkcheck about the exec action org.freedesktop.policykit.exec; got %v", argv)
	}
}

// TestSetuidWrapperCommand_NonPkexecWrapperUnchanged proves the non-pkexec wrappers
// still RUN the wrapper (they are not a polkit-gated escalation): a non-pkexec
// wrapper (e.g. mullvad-exclude) is built as `setpriv --reuid <anon> <wrapper> id
// -u` with NO extra flags and inherits the ambient env unchanged. mullvad-exclude
// runs the target as the caller and cannot prompt; only the pkexec vector changed
// to the pkcheck query.
func TestSetuidWrapperCommand_NonPkexecWrapperUnchanged(t *testing.T) {
	argv := setuidWrapperCommand(30001, "mullvad-exclude")
	want := []string{"setpriv", "--reuid", "30001", "--clear-groups", "mullvad-exclude", "id", "-u"}
	if fmt.Sprint(argv) != fmt.Sprint(want) {
		t.Fatalf("mullvad-exclude probe argv = %v, want %v", argv, want)
	}
	if contains(argv, "--disable-internal-agent") {
		t.Fatalf("the dead --disable-internal-agent must not appear for any wrapper; got %v", argv)
	}
}

// TestPkexecVector_AuthRequiredIsNotEscaped proves the false-FAIL is gone on a
// normal desktop: when pkcheck reports auth is required with no interaction
// (exit 2), the anon account CANNOT pkexec-to-root unattended, so the vector reads
// as NOT escaped, and NO prompt ever appears (pkcheck without -u). exit 1 (not
// authorized) and exit 3 (dismissed) are likewise not an unattended escape. No real
// pkcheck runs; the exec seam is scripted.
func TestPkexecVector_AuthRequiredIsNotEscaped(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not on PATH: the pkexec vector short-circuits before the query")
	}
	orig := runPkcheck
	defer func() { runPkcheck = orig }()
	for _, exit := range []int{2, 1, 3} {
		var gotArgv []string
		runPkcheck = func(_ context.Context, argv []string) (int, bool) {
			gotArgv = argv
			return exit, true
		}
		v := pkexecVector(context.Background(), LiveParams{AnonUID: 30001, ShimUID: 995})
		if v.Escaped {
			t.Fatalf("pkcheck exit %d (no unattended escalation) must NOT be flagged as escaped; got %+v", exit, v)
		}
		if v.Inconclusive {
			t.Fatalf("pkcheck exit %d is a conclusive no-escape, not inconclusive; got %+v", exit, v)
		}
		// It must have QUERIED polkit (pkcheck), never RUN pkexec.
		gotJoined := strings.Join(gotArgv, " ")
		if strings.Contains(gotJoined, "pkexec") || !strings.Contains(gotJoined, "pkcheck") {
			t.Fatalf("the vector must exec the pkcheck query, never pkexec; got %v", gotArgv)
		}
	}
}

// TestPkexecVector_UnattendedAuthorizationIsEscaped proves the detection is NOT
// neutered: a host whose polkit policy authorizes the exec action WITHOUT auth
// (pkcheck exit 0) means the anon account can pkexec-to-root UNATTENDED, a real
// forcing bypass, so the vector is STILL caught as a real escape (Escaped=true).
// Scripted via the exec seam, no real pkcheck.
func TestPkexecVector_UnattendedAuthorizationIsEscaped(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not on PATH: the pkexec vector short-circuits before the query")
	}
	orig := runPkcheck
	defer func() { runPkcheck = orig }()
	runPkcheck = func(_ context.Context, _ []string) (int, bool) {
		return 0, true // authorized WITHOUT auth: unattended escalation allowed
	}

	v := pkexecVector(context.Background(), LiveParams{AnonUID: 30001, ShimUID: 995})
	if !v.Escaped {
		t.Fatalf("pkcheck exit 0 (unattended escalation allowed) MUST be caught as a real escape; got %+v", v)
	}
	if v.Detail == "" {
		t.Fatalf("an escaping vector must carry a detail line; got %+v", v)
	}
}

// TestPkexecVector_PkcheckMissingIsInconclusive proves the honest not-conclusive
// reading: when pkcheck is absent or un-runnable, the vector is neither a false
// escape nor a false conclusive no-escape; it is reported Inconclusive (best-effort
// framing), and it NEVER falls back to RUNNING pkexec. Scripted via the exec seam
// (ran=false); no real pkcheck/pkexec, no prompt.
func TestPkexecVector_PkcheckMissingIsInconclusive(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not on PATH: the pkexec vector short-circuits before the query")
	}
	orig := runPkcheck
	defer func() { runPkcheck = orig }()
	runPkcheck = func(_ context.Context, _ []string) (int, bool) {
		return 0, false // pkcheck missing / un-runnable
	}

	v := pkexecVector(context.Background(), LiveParams{AnonUID: 30001, ShimUID: 995})
	if v.Escaped {
		t.Fatalf("a missing pkcheck must NOT read as a false escape; got %+v", v)
	}
	if !v.Inconclusive {
		t.Fatalf("a missing/un-runnable pkcheck must be honestly NOT-conclusive; got %+v", v)
	}
}

// TestSudoListCommand_IsNonInteractive proves the core of this task: the sudo
// UID-transition vector is built to run STRICTLY NON-INTERACTIVELY, so a real
// `sudo anonctl verify` never pops a polkit/sudo password dialog from the sudo
// vector. sudoListCommand must build `sudo -n -l -U <account>`: the `-n` is what
// makes sudo print "a password is required" instead of prompting when listing
// another user's privileges requires auth.
func TestSudoListCommand_IsNonInteractive(t *testing.T) {
	argv := sudoListCommand("anon")
	want := []string{"sudo", "-n", "-l", "-U", "anon"}
	if fmt.Sprint(argv) != fmt.Sprint(want) {
		t.Fatalf("sudo vector argv = %v, want %v", argv, want)
	}
	if !contains(argv, "-n") {
		t.Fatalf("the sudo vector MUST pass -n so it never prompts for interactive auth; got %v", argv)
	}
}

// TestRunSudoList_ExecsTheNonInteractiveArgv proves runSudoList drives the exec
// seam with the non-interactive argv (`sudo -n -l -U <account>`) and returns the
// probe output. No real sudo runs; the seam is scripted, so the unit suite never
// prompts.
func TestRunSudoList_ExecsTheNonInteractiveArgv(t *testing.T) {
	orig := runSudoListCmd
	defer func() { runSudoListCmd = orig }()
	var gotArgv []string
	runSudoListCmd = func(_ context.Context, argv []string) (string, string) {
		gotArgv = argv
		return "", "sudo: a password is required\n"
	}

	stdout, stderr := runSudoList(context.Background(), "anon")
	want := []string{"sudo", "-n", "-l", "-U", "anon"}
	if fmt.Sprint(gotArgv) != fmt.Sprint(want) {
		t.Fatalf("runSudoList exec'd %v, want %v", gotArgv, want)
	}
	// The auth-blocked output flows back untouched; sudoprobe.ParseOutput reads it as
	// the honest Unknown (proven in internal/sudoprobe), never a false grant/denial.
	if !strings.Contains(stdout+stderr, "a password is required") {
		t.Fatalf("runSudoList must return the probe output; got stdout=%q stderr=%q", stdout, stderr)
	}
}

// TestSudoVector_AuthBlockedIsInconclusive proves the end-to-end sudo vector
// behaviour when the `-n` probe cannot list unattended: sudo prints "a password is
// required", which flows through sudoprobe.ParseOutput to Unknown, which
// sudoVectorFromVerdict maps to honestly NOT-conclusive (Inconclusive=true), NEVER
// a false Escaped (a false alarm) nor a false conclusive not-escaped (which would
// hide a real grant). Scripted via the exec seam; no real sudo, no prompt.
func TestSudoVector_AuthBlockedIsInconclusive(t *testing.T) {
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo not on PATH: sudoVector short-circuits before the probe")
	}
	orig := runSudoListCmd
	defer func() { runSudoListCmd = orig }()
	runSudoListCmd = func(_ context.Context, _ []string) (string, string) {
		return "", "sudo: a password is required\n"
	}

	v := sudoVector(context.Background(), LiveParams{Account: "anon", AnonUID: 30001, ShimUID: 995})
	if v.Escaped {
		t.Fatalf("an auth-blocked (-n) sudo probe must NOT false-alarm as an escape; got %+v", v)
	}
	if !v.Inconclusive {
		t.Fatalf("an auth-blocked (-n) sudo probe must be honestly NOT-conclusive; got %+v", v)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestRunSetprivProbeFailsLoudOnMissingShimBinary proves the load-bearing contract
// of this task's un-gating: the live anon-UID probe now runs in EVERY build (no
// `-tags integration` needed), and when the tool it needs is missing it must FAIL
// LOUD (a named error), never silently report reached=false. A silent
// reached=false would be read by the drop assertions as a PASS, i.e. a binary that
// cannot probe would "verify" green: exactly the false-green this task exists to
// close ("a probe that could not run is not a pass").
//
// It points probeShimBinary at a path that does not exist, so LookPath fails, and
// asserts runSetprivProbe returns a non-nil error naming the missing shim probe
// binary. (On a host without setpriv the setpriv branch fires first, also a loud
// error; either way the result is an error, never a silent reached=false.)
func TestRunSetprivProbeFailsLoudOnMissingShimBinary(t *testing.T) {
	orig := probeShimBinary
	probeShimBinary = "/nonexistent/anonctl-shim-probe-does-not-exist"
	defer func() { probeShimBinary = orig }()

	reached, _, err := runSetprivProbe(context.Background(), 12345, "tcp4", "192.0.2.1:9999")
	if err == nil {
		t.Fatalf("runSetprivProbe with a missing probe binary must return a LOUD error, got err=nil (reached=%v): a probe that could not run is not a pass", reached)
	}
	if reached {
		t.Fatalf("runSetprivProbe that could not run must report reached=false alongside its error, got reached=true")
	}
	// The error must name the missing tool so the operator can fix it.
	if !strings.Contains(err.Error(), "setpriv") && !strings.Contains(err.Error(), "shim") {
		t.Fatalf("the loud probe error must name the missing tool (setpriv/shim), got %q", err.Error())
	}
}

// TestProbeAsAnonPropagatesTheLoudError proves the drop-family checks' probe seam
// surfaces the loud error rather than swallowing it to a silent reached=false: the
// leak-drop-v6 / icmp-drop / non-tcp-udp-drop / split-tunnel checks call
// probeAsAnon (and udpSendAsAnon) and turn a non-nil error into a FAILING
// assertion. Here we assert the error propagates out of the seam; the checks then
// wrap it as Assertion{Err: err} (verified by the default build compiling those
// callsites).
func TestProbeAsAnonPropagatesTheLoudError(t *testing.T) {
	orig := probeShimBinary
	probeShimBinary = "/nonexistent/anonctl-shim-probe-does-not-exist"
	defer func() { probeShimBinary = orig }()

	if _, err := probeAsAnon(context.Background(), LiveParams{AnonUID: 12345}, "tcp6", "[::1]:1"); err == nil {
		t.Fatalf("probeAsAnon must propagate the loud probe error, got nil")
	}
	if _, err := udpSendAsAnon(context.Background(), LiveParams{AnonUID: 12345}, "192.0.2.1:9999"); err == nil {
		t.Fatalf("udpSendAsAnon must propagate the loud probe error, got nil")
	}
}
