package main

import (
	"context"
	"os"
	"testing"

	"github.com/wighawag/anonctl/internal/nssbypass"
	"github.com/wighawag/anonctl/internal/systemd"
)

// TestMain neutralises the dispatch-time self-elevation seam for the whole package
// test binary by default: it makes `sudo` look ABSENT (elevateLookSudo returns
// errSudoNotFound), so a non-root root-verb never performs a REAL sudo re-exec
// during tests - it falls straight through to run the verb directly, exactly as
// before self-elevation existed. This keeps every pre-existing dispatch test
// (verify fail-closed, update-needs-endpoint, rm ordering, ...) deterministic
// without a real sudo or a password prompt. The tests that specifically exercise
// elevation (elevate_test.go) opt back in via swapElevateSeams.
// It ALSO neutralises the NSS-bypass host inspection, for the same reason and with
// more force: that guard reads the real /etc/nsswitch.conf and the real nscd
// socket, so without a default stub every `add` test would pass or fail according
// to whether the developer's box happens to run nsncd or systemd-resolved. The
// host this was written on runs nsncd, so the guard (correctly) refused every add
// in the suite the moment it was added. Tests that exercise the guard itself opt
// back in via swapNSSBypassInspector.
//
// CAUTION for whoever adds the first `integration`-tagged test in package main:
// this file is UNTAGGED, so the stub is installed under `-tags integration` too,
// and a live test that calls runAdd would silently run against a "clean host"
// regardless of the box it is on. That is the same shape as the leaked-seam
// false-green recorded in work/notes/findings/e2e-binary-validation.md. Such a
// test must call swapNSSBypassInspector itself, or restore the real detector with
// `inspectNSSBypass = nssbypass.Inspect`.
func TestMain(m *testing.M) {
	elevateLookSudo = func() (string, error) { return "", errSudoNotFound }
	inspectNSSBypass = func() ([]nssbypass.Provider, error) { return nil, nil }
	// Default the MEASUREMENT to "measured, and this host does NOT resolve in
	// process", so a test that scripts a broad provider exercises the refusal rather
	// than the could-not-measure branch (the measurement needs root and nft, which a
	// test runner does not have).
	measureHostResolution = func(context.Context) (bool, bool, string) {
		return false, true, "a lookup put NO DNS query on this process's own socket (test stub)"
	}
	// And the unit preflight, for the SAME reason spelled out above: it reads the real
	// host-owned marker under /etc/anonctl, the real unit files in systemd's search
	// path, and the real $PATH for the binaries a generated unit would name. Left
	// un-stubbed, every `add` test would depend on whether the developer's box declares
	// anonctl's units or has setpriv installed. Its own behaviour is tested against
	// scratch stores in internal/systemd and internal/forcing; tests that want the
	// refusal here use swapUnitPreflight.
	preflightUnits = func(systemd.Store, systemd.Resolver) (systemd.UnitOwnership, error) {
		return systemd.UnitOwnership{}, nil
	}
	os.Exit(m.Run())
}

// swapUnitPreflight scripts `add`'s unit preflight (the guard that must refuse
// BEFORE the account is created) and returns the restore.
func swapUnitPreflight(own systemd.UnitOwnership, err error) func() {
	orig := preflightUnits
	preflightUnits = func(systemd.Store, systemd.Resolver) (systemd.UnitOwnership, error) {
		return own, err
	}
	return func() { preflightUnits = orig }
}

// swapNSSBypassInspector points `add`'s DNS-confinement gate at a scripted host
// and returns the restore, so a test can drive the refusal, the escape hatch and
// the clean-host branches on ANY machine.
func swapNSSBypassInspector(providers []nssbypass.Provider, err error) func() {
	orig := inspectNSSBypass
	inspectNSSBypass = func() ([]nssbypass.Provider, error) { return providers, err }
	return func() { inspectNSSBypass = orig }
}

// swapHostResolutionMeasurement scripts the measurement half of the gate, so the
// three outcomes (measured in-process, measured bypassed, unmeasurable) can each
// be driven on any machine.
func swapHostResolutionMeasurement(inProcess, measured bool, why string) func() {
	orig := measureHostResolution
	measureHostResolution = func(context.Context) (bool, bool, string) { return inProcess, measured, why }
	return func() { measureHostResolution = orig }
}
