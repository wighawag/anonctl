package verify

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestSetuidWrapperCommand_PkexecIsNonInteractive proves the core of this task: the
// pkexec UID-transition probe is built to run STRICTLY NON-INTERACTIVELY, so a real
// `sudo anonctl verify` never pops a polkit password dialog and never false-flags
// on the operator's interactive auth (v0.1.2 bug). setuidWrapperCommand must build
// pkexec's argv with --disable-internal-agent AND hand it a scrubbed env with the
// four session-agent handles removed (DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR,
// DISPLAY, WAYLAND_DISPLAY), so unattended pkexec fails "Request dismissed" instead
// of reaching the session polkit agent.
func TestSetuidWrapperCommand_PkexecIsNonInteractive(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"XDG_RUNTIME_DIR=/run/user/1000",
		"DISPLAY=:0",
		"WAYLAND_DISPLAY=wayland-0",
		"HOME=/home/anon",
	}
	argv, scrubbed := setuidWrapperCommand(30001, "pkexec", env)

	// argv: setpriv --reuid 30001 --clear-groups pkexec --disable-internal-agent id -u
	want := []string{"setpriv", "--reuid", "30001", "--clear-groups", "pkexec", "--disable-internal-agent", "id", "-u"}
	if fmt.Sprint(argv) != fmt.Sprint(want) {
		t.Fatalf("pkexec probe argv = %v, want %v", argv, want)
	}
	if !contains(argv, "--disable-internal-agent") {
		t.Fatalf("pkexec probe must pass --disable-internal-agent so it cannot reach an auth agent; got %v", argv)
	}

	// The scrubbed env must DROP the four session-agent handles and KEEP the rest.
	for _, banned := range []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY"} {
		if envHas(scrubbed, banned) {
			t.Fatalf("pkexec probe env must DROP %s (else it can reach the session polkit agent and prompt); got %v", banned, scrubbed)
		}
	}
	for _, kept := range []string{"PATH", "HOME"} {
		if !envHas(scrubbed, kept) {
			t.Fatalf("pkexec probe env must keep %s (only the agent handles are scrubbed); got %v", kept, scrubbed)
		}
	}
}

// TestSetuidWrapperCommand_NonPkexecWrapperUnchanged proves the scrubbing is scoped:
// a non-pkexec wrapper (e.g. mullvad-exclude) gets NO --disable-internal-agent flag
// (it is a pkexec-only flag) and inherits the ambient env unchanged (nil scrub).
// mullvad-exclude runs the target as the caller and cannot prompt, so it needs no
// special handling; only the pkexec auth-agent path is scrubbed.
func TestSetuidWrapperCommand_NonPkexecWrapperUnchanged(t *testing.T) {
	argv, scrubbed := setuidWrapperCommand(30001, "mullvad-exclude", []string{"DISPLAY=:0"})
	want := []string{"setpriv", "--reuid", "30001", "--clear-groups", "mullvad-exclude", "id", "-u"}
	if fmt.Sprint(argv) != fmt.Sprint(want) {
		t.Fatalf("mullvad-exclude probe argv = %v, want %v", argv, want)
	}
	if contains(argv, "--disable-internal-agent") {
		t.Fatalf("--disable-internal-agent is pkexec-only; must not appear for mullvad-exclude; got %v", argv)
	}
	if scrubbed != nil {
		t.Fatalf("a non-pkexec wrapper inherits the ambient env (nil scrub); got %v", scrubbed)
	}
}

// TestSetuidWrapperVector_UnattendedFailIsNotEscaped proves the false-positive is
// gone on the normal desktop: when unattended pkexec cannot escalate (it prints no
// numeric euid line, e.g. "Error executing command as another user: Request
// dismissed"), the vector reads as NOT escaped. No real pkexec runs; the exec seam
// is scripted.
func TestSetuidWrapperVector_UnattendedFailIsNotEscaped(t *testing.T) {
	orig := runSetuidWrapper
	defer func() { runSetuidWrapper = orig }()
	var gotArgv, gotEnv []string
	runSetuidWrapper = func(_ context.Context, argv, env []string) string {
		gotArgv, gotEnv = argv, env
		return "Error executing command as another user: Request dismissed\n"
	}

	v := setuidWrapperVector(context.Background(), LiveParams{AnonUID: 30001, ShimUID: 995}, "pkexec")
	if v.Escaped {
		t.Fatalf("an unattended pkexec that could not escalate must NOT be flagged as escaped; got %+v", v)
	}
	// It must have been driven non-interactively (the operator-auth false-flag path is gone).
	if !contains(gotArgv, "--disable-internal-agent") {
		t.Fatalf("the vector must exec pkexec non-interactively (--disable-internal-agent); got %v", gotArgv)
	}
	if envHas(gotEnv, "DBUS_SESSION_BUS_ADDRESS") {
		t.Fatalf("the vector must exec pkexec with a scrubbed env (no DBUS_SESSION_BUS_ADDRESS); got %v", gotEnv)
	}
}

// TestSetuidWrapperVector_UnattendedEscalationIsEscaped proves the detection is NOT
// neutered: a genuinely permissive policy (a NOPASSWD-style polkit rule that lets
// the anon account pkexec-to-root with NO auth) STILL escalates unattended, prints
// a non-anon euid, and is caught as a real escape (Escaped=true). Scripted via the
// exec seam (a fixtured unattended escalation), no real pkexec.
func TestSetuidWrapperVector_UnattendedEscalationIsEscaped(t *testing.T) {
	orig := runSetuidWrapper
	defer func() { runSetuidWrapper = orig }()
	runSetuidWrapper = func(_ context.Context, _, _ []string) string {
		return "0\n" // pkexec escalated to root with no auth (permissive policy)
	}

	v := setuidWrapperVector(context.Background(), LiveParams{AnonUID: 30001, ShimUID: 995}, "pkexec")
	if !v.Escaped {
		t.Fatalf("a permissive policy that escalates unattended MUST still be caught as a real escape; got %+v", v)
	}
	if v.Detail == "" {
		t.Fatalf("an escaping vector must carry a detail line; got %+v", v)
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

func envHas(env []string, key string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
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
