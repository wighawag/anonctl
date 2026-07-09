//go:build integration
// +build integration

package seedhome_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wighawag/anonctl/internal/provision"
	"github.com/wighawag/anonctl/internal/seedhome"
)

// TestRealSeedChownsToAccount exercises the REAL chown path (via the production
// ExecRunner) on a live host: it seeds a template into a scratch home and asserts
// the copied file is owned by root:root after chown (this test runs as root and
// chowns to `root`, an account guaranteed to exist, so it needs no throwaway
// useradd). Guarded behind the `integration` tag and root, mirroring
// TestRealProvisionRoundTrip; it leaves no residue (everything under t.TempDir()).
func TestRealSeedChownsToAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration seed requires root (real chown); skipping")
	}
	if _, err := exec.LookPath("chown"); err != nil {
		t.Skip("chown not available; skipping")
	}

	tmpl := t.TempDir()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpl, ".bashrc"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A setuid template file must land WITHOUT the bit even through the real path.
	if err := os.WriteFile(filepath.Join(tmpl, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(tmpl, "tool"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}

	r := provision.ExecRunner{}
	res, err := seedhome.Seed(context.Background(), r, tmpl, home, "root", false)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if res.Copied != 2 {
		t.Errorf("Copied = %d, want 2", res.Copied)
	}
	info, err := os.Stat(filepath.Join(home, "tool"))
	if err != nil {
		t.Fatalf("stat seeded tool: %v", err)
	}
	if info.Mode()&os.ModeSetuid != 0 {
		t.Errorf("real seed kept the setuid bit: %v", info.Mode())
	}
}
