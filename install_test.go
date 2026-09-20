package main

import (
	"os"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// anonctl ships an install.sh release asset and a README "Install" section, like
// the sibling netcage, but with anonctl's ONE structural difference: the shim is
// launched by a systemd unit, whose ExecStart must be an ABSOLUTE path because a
// unit has no useful inherited $PATH. anonctl RESOLVES that path when it writes the
// unit, preferring the anonctl-shim sitting next to the running anonctl, so the
// install contract is "both binaries in the SAME dir" rather than "the shim at one
// fixed location". (Before 0.4 the unit hard-coded /usr/local/bin/anonctl-shim
// regardless of $PREFIX, and install.sh symlinked that path to compensate.)
// These tests pin the install contract so the script/docs cannot silently drift
// from how the unit is rendered, or drop the checksum verification (never install
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

// install.sh must install BOTH binaries into the SAME directory, because that
// co-location is what lets anonctl resolve the shim as its own sibling and render
// the unit with a path that is correct for ANY $PREFIX.
func TestInstallScriptCoLocatesBothBinaries(t *testing.T) {
	sh := installScript(t)
	// Both binaries must be handled by name.
	for _, bin := range []string{"anonctl", "anonctl-shim"} {
		if !strings.Contains(sh, bin) {
			t.Errorf("install.sh must install %q; not mentioned", bin)
		}
	}
	// Both go to the SAME $dest.
	for _, want := range []string{`install_one "$BIN"`, `install_one "$SHIM"`} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh must install both binaries into the same dir (%q missing)", want)
		}
	}
	// The pre-0.4 workaround must be GONE: symlinking the shim into the old fixed path
	// is exactly the FHS assumption the unit no longer makes, and on NixOS
	// /usr/local/bin is not on any default PATH anyway.
	if strings.Contains(sh, "ln -sf \"$dest/$SHIM\" \"$SHIM_UNIT_PATH\"") {
		t.Error("install.sh must no longer symlink the shim into the old fixed unit path; anonctl now renders the unit with the resolved path")
	}
}

// anonctl bakes the absolute paths of nft and setpriv into the units it generates
// and refuses to force an account without them. A loader unit that cannot run nft is
// fail-OPEN at boot (no baseline default-deny), so the installer must surface a
// missing prerequisite rather than let it be discovered after a reboot.
func TestInstallScriptWarnsAboutMissingUnitBinaries(t *testing.T) {
	sh := installScript(t)
	for _, req := range []string{systemd.NftBinaryName, systemd.SetprivBinaryName} {
		if !strings.Contains(sh, req) {
			t.Errorf("install.sh must check for the unit prerequisite %q; not mentioned", req)
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
