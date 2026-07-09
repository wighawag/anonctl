package main

import (
	"os"
	"testing"
)

// TestMain neutralises the dispatch-time self-elevation seam for the whole package
// test binary by default: it makes `sudo` look ABSENT (elevateLookSudo returns
// errSudoNotFound), so a non-root root-verb never performs a REAL sudo re-exec
// during tests - it falls straight through to run the verb directly, exactly as
// before self-elevation existed. This keeps every pre-existing dispatch test
// (verify fail-closed, update-needs-endpoint, rm ordering, ...) deterministic
// without a real sudo or a password prompt. The tests that specifically exercise
// elevation (elevate_test.go) opt back in via swapElevateSeams.
func TestMain(m *testing.M) {
	elevateLookSudo = func() (string, error) { return "", errSudoNotFound }
	os.Exit(m.Run())
}
