package main

import (
	"os"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// anonctl ships an install.sh release asset and a README "Install" section, like
// the sibling netcage, but with anonctl's ONE structural difference: the shim is
// launched by a systemd unit whose ExecStart is a FIXED path
// (internal/systemd.DefaultShimBinaryPath = /usr/local/bin/anonctl-shim), so the
// install MUST place anonctl-shim there. "Just put both on PATH" is NOT enough.
// These tests pin the install contract so the script/docs cannot silently drift
// from the unit's expected path or drop the checksum verification (never install
// an unverified anonymity tool).

func installScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	return string(raw)
}

func readme(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	return string(raw)
}

// install.sh must place anonctl-shim at the systemd unit's expected path
// (DefaultShimBinaryPath). This is the ONE way anonctl's install differs from
// netcage: the shim is not found as a sibling, it is launched by a unit at a
// fixed ExecStart path. If DefaultShimBinaryPath ever changes, this test forces
// install.sh to be updated too.
func TestInstallScriptPlacesShimAtUnitPath(t *testing.T) {
	sh := installScript(t)
	if !strings.Contains(sh, systemd.DefaultShimBinaryPath) {
		t.Errorf("install.sh must place the shim at the systemd unit's ExecStart path %q (internal/systemd.DefaultShimBinaryPath); not found", systemd.DefaultShimBinaryPath)
	}
	// Both binaries must be handled by name.
	for _, bin := range []string{"anonctl", "anonctl-shim"} {
		if !strings.Contains(sh, bin) {
			t.Errorf("install.sh must install %q; not mentioned", bin)
		}
	}
}

// install.sh must verify the sha256 checksum and FAIL LOUD (exit) on a mismatch:
// never install an unverified anonymity tool. It must download the checksums file
// and compare, refusing to install when the hashes differ.
func TestInstallScriptVerifiesChecksum(t *testing.T) {
	sh := installScript(t)
	for _, want := range []string{"checksums.txt", "sha256", "checksum mismatch"} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh must verify the download; missing %q", want)
		}
	}
	// The mismatch path must abort (err/exit), not warn-and-continue.
	if !strings.Contains(sh, `err "checksum mismatch`) {
		t.Error("install.sh must FAIL LOUD (err/exit) on a checksum mismatch, never install unverified")
	}
}

// install.sh must default to /usr/local/bin (root-writable, on the unit's path),
// support a PREFIX override and an ANONCTL_VERSION pin (like netcage), and detect
// the arch targets goreleaser builds (amd64 / arm64 / armv7 / armv6).
func TestInstallScriptDefaultsAndOverrides(t *testing.T) {
	sh := installScript(t)
	for _, want := range []string{"/usr/local/bin", "PREFIX", "ANONCTL_VERSION"} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh must support %q; not found", want)
		}
	}
	for _, target := range []string{"linux_amd64", "linux_arm64", "linux_armv7", "linux_armv6"} {
		if !strings.Contains(sh, target) {
			t.Errorf("install.sh must detect arch target %q; not found", target)
		}
	}
	// anonctl is Linux-only: the script must refuse a non-Linux uname.
	if !strings.Contains(sh, "Linux") {
		t.Error("install.sh must refuse to install off Linux (anonctl is Linux-only)")
	}
}

// The README must have an "Install" section documenting the three routes
// (curl|sh one-liner, go install for BOTH binaries + the shim-placement step,
// and manual download), each honest about the fixed shim path and the
// root/usr-local-bin default.
func TestReadmeDocumentsInstallRoutes(t *testing.T) {
	doc := readme(t)
	if !strings.Contains(doc, "## Install") {
		t.Fatal("README must have an `## Install` section")
	}
	// The curl-pipe-sh one-liner asset.
	if !strings.Contains(doc, "install.sh | ") && !strings.Contains(doc, "install.sh |sh") {
		t.Error("README Install must show the curl-pipe-sh one-liner")
	}
	// The go install route for BOTH binaries.
	for _, want := range []string{
		"go install github.com/wighawag/anonctl@latest",
		"go install github.com/wighawag/anonctl/cmd/anonctl-shim@latest",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("README Install must show the go install route %q", want)
		}
	}
	// The shim path must be named explicitly (go install does NOT put it at the
	// unit's fixed path; the user must place/symlink it there).
	if !strings.Contains(doc, systemd.DefaultShimBinaryPath) {
		t.Errorf("README Install must name the shim's fixed unit path %q so a go-install user knows to place it there", systemd.DefaultShimBinaryPath)
	}
	// Honest about root / Linux-only and the manual route.
	for _, want := range []string{"root", "Linux", "Manual"} {
		if !strings.Contains(doc, want) {
			t.Errorf("README Install must mention %q", want)
		}
	}
}
