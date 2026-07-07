//go:build integration
// +build integration

package systemd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// TestGeneratedTemplateUnitIsWellFormed loads the generated @-template unit into a
// SCRATCH unit dir and runs `systemd-analyze verify` on it, proving the unit text
// is well-formed on a real systemd (the [Unit]/[Service]/[Install] shape, the
// ExecStart, the ordering) WITHOUT enabling anything on the host. It is guarded by
// the `integration` tag and SKIPS (not fails) without systemd-analyze.
//
// Shared-write isolation: everything is written under a t.TempDir() scratch unit
// dir; NO real /etc/systemd file is written and NO unit is enabled, so the host's
// real units are left exactly as found (asserted: the scratch dir is not the real
// unit dir).
func TestGeneratedTemplateUnitIsWellFormed(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not available; skipping unit well-formedness check")
	}

	root := t.TempDir()
	unitDir := filepath.Join(root, "systemd")
	store := systemd.Store{
		UnitDir:  unitDir,
		EnvDir:   filepath.Join(root, "shim"),
		RulesDir: filepath.Join(root, "nftables"),
	}
	if store.UnitDir == systemd.DefaultUnitDir {
		t.Fatal("test Store must not point at the real DefaultUnitDir")
	}
	if err := store.InstallCommon(systemd.TemplateParams{}, systemd.NftablesDropInParams{}); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}

	// systemd-analyze verify wants a concrete instance for a template; point it at
	// the scratch unit file so it parses OUR generated text, not a host unit.
	unitPath := filepath.Join(unitDir, systemd.UnitName)
	if _, err := os.Stat(unitPath); err != nil {
		t.Fatalf("template unit not written: %v", err)
	}
	out, err := exec.Command("systemd-analyze", "verify", "--no-pager", unitPath).CombinedOutput()
	// systemd-analyze verify may warn about a missing ExecStart binary / EnvironmentFile
	// (they do not exist in the scratch layout); those are NOT syntax errors. We fail
	// only on a hard parse/assembler error in the unit shape.
	text := string(out)
	for _, hardErr := range []string{"Failed to parse", "Invalid section", "Unknown key name", "Unknown lvalue"} {
		if strings.Contains(text, hardErr) {
			t.Errorf("generated template unit is malformed (%s):\n%s", hardErr, text)
		}
	}
	_ = err // a non-zero exit from soft warnings is tolerated; only hard parse errors fail
}
