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

// The later-task stub verbs dispatch but are not implemented: exit 3 (fail loud,
// never a silent success).
func TestStubVerbExit(t *testing.T) {
	for _, v := range []string{"verify", "update", "reconfigure"} {
		if code := run([]string{v}); code != 3 {
			t.Errorf("run(%q) = %d, want 3 (not-implemented)", v, code)
		}
	}
}
