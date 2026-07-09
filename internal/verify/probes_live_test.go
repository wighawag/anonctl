package verify

import (
	"context"
	"strings"
	"testing"
)

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
