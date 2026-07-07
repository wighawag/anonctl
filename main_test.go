package main

import "testing"

// The version fast-path exits 0 before any parse (no verb, no root needed).
func TestVersionArg(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		if code := run(args); code != 0 {
			t.Errorf("run(%v) = %d, want 0", args, code)
		}
	}
}

// An unknown verb exits 2 (usage error), not 0.
func TestUnknownVerbExit(t *testing.T) {
	if code := run([]string{"frobnicate"}); code != 2 {
		t.Errorf("run(frobnicate) = %d, want 2", code)
	}
}

// No args exits 2 (usage error).
func TestNoArgsExit(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Errorf("run(nil) = %d, want 2", code)
	}
}

// update/reconfigure remain later-task stubs: they dispatch but are not
// implemented, so they exit 3 (fail loud, never a silent success).
func TestStubVerbExit(t *testing.T) {
	for _, v := range []string{"update", "reconfigure"} {
		if code := run([]string{v}); code != 3 {
			t.Errorf("run(%q) = %d, want 3 (not-implemented)", v, code)
		}
	}
}

// verify is now WIRED: it runs the assertion set and exits with the report's
// verdict. In the default build (no `integration` tag) the live probes are not
// compiled in, so verify cannot PROVE anonymization and must exit NON-ZERO (a
// fail-closed / CI-gating contract: a verification that could not run is not a
// pass, and never exit 0 by default). It must never exit 3 (the not-implemented
// stub code): the verb is implemented.
func TestVerifyDispatchesAndExitsNonZeroInDefaultBuild(t *testing.T) {
	code := run([]string{"verify"})
	if code == 0 {
		t.Errorf("run(verify) = 0, want non-zero (default build cannot PROVE anonymization; must fail-closed)")
	}
	if code == 3 {
		t.Errorf("run(verify) = 3 (not-implemented stub); the verb must be implemented")
	}
}

// verify --json exits with the same verdict (non-zero in the default build) and
// must not be mistaken for the not-implemented stub.
func TestVerifyJSONDispatches(t *testing.T) {
	code := run([]string{"verify", "--json"})
	if code == 0 {
		t.Errorf("run(verify --json) = 0, want non-zero in the default build")
	}
	if code == 3 {
		t.Errorf("run(verify --json) = 3 (stub); the verb must be implemented")
	}
}
