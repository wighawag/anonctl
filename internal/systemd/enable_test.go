package systemd_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// ENABLEMENT without `systemctl enable`.
//
// `systemctl enable` always writes its symlink into the CONFIG dir for the scope
// (/etc/systemd/system), no matter which directory the unit file lives in. On NixOS
// that dir is a read-only Nix store symlink, so the enable fails even after the unit
// file has moved somewhere writable. anonctl therefore creates the enablement
// symlink itself, in its own unit dir, which systemd honours because it reads
// `<target>.wants/` from EVERY directory in the unit load path.

func TestEnableUnitCreatesAWantsSymlinkIntoItsOwnUnitDir(t *testing.T) {
	s := scratchStore(t)
	tp, lp := scratchParams()
	if err := s.InstallCommon(tp, lp); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	if err := s.EnableUnit(systemd.UnitName, systemd.InstanceName("anon"), systemd.ShimWantedBy); err != nil {
		t.Fatalf("EnableUnit: %v", err)
	}
	link := filepath.Join(s.UnitDir, systemd.ShimWantedBy+".wants", systemd.InstanceName("anon"))
	dest, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("no enablement symlink at %s: %v", link, err)
	}
	// systemd.unit(5): the symlink's TARGET must itself live in a unit search path,
	// or systemd ignores the dependency.
	if filepath.Dir(dest) != s.UnitDir {
		t.Errorf("symlink target %q is outside the unit dir %q; systemd would ignore it", dest, s.UnitDir)
	}
	// The instance link points at the TEMPLATE, the mapping systemctl would produce.
	if filepath.Base(dest) != systemd.UnitName {
		t.Errorf("instance link should point at the template %q, got %q", systemd.UnitName, dest)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("enablement symlink dangles: %v", err)
	}
	// It must NOT have written anywhere near the legacy config dir.
	if _, err := os.Stat(s.LegacyUnitDir); !os.IsNotExist(err) {
		t.Error("EnableUnit must not create anything in the legacy config dir")
	}
}

// `add` is re-runnable, so enabling twice must be clean rather than failing on an
// existing symlink.
func TestEnableUnitIsIdempotent(t *testing.T) {
	s := scratchStore(t)
	for i := 0; i < 2; i++ {
		if err := s.EnableUnit(systemd.LoaderUnitName, systemd.LoaderUnitName, systemd.LoaderWantedBy); err != nil {
			t.Fatalf("EnableUnit pass %d: %v", i, err)
		}
	}
	enabled, err := s.IsUnitEnabled(systemd.LoaderUnitName, systemd.LoaderUnitName, systemd.LoaderWantedBy)
	if err != nil || !enabled {
		t.Errorf("loader should read as enabled after two passes; got %v, %v", enabled, err)
	}
}

func TestDisableUnitRemovesTheSymlinkAndIsIdempotent(t *testing.T) {
	s := scratchStore(t)
	if err := s.EnableUnit(systemd.UnitName, systemd.InstanceName("anon"), systemd.ShimWantedBy); err != nil {
		t.Fatalf("EnableUnit: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := s.DisableUnit(systemd.InstanceName("anon"), systemd.ShimWantedBy); err != nil {
			t.Fatalf("DisableUnit pass %d: %v", i, err)
		}
	}
	link := filepath.Join(s.UnitDir, systemd.ShimWantedBy+".wants", systemd.InstanceName("anon"))
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("DisableUnit left the enablement symlink behind")
	}
}

// Disabling ONE account must never de-enable another: the shared `.wants` dir is
// removed only when it is empty.
func TestDisableUnitKeepsOtherAccountsEnabled(t *testing.T) {
	s := scratchStore(t)
	for _, acct := range []string{"anon", "anon-work"} {
		if err := s.EnableUnit(systemd.UnitName, systemd.InstanceName(acct), systemd.ShimWantedBy); err != nil {
			t.Fatalf("EnableUnit %s: %v", acct, err)
		}
	}
	if err := s.DisableUnit(systemd.InstanceName("anon"), systemd.ShimWantedBy); err != nil {
		t.Fatalf("DisableUnit: %v", err)
	}
	enabled, err := s.IsUnitEnabled(systemd.UnitName, systemd.InstanceName("anon-work"), systemd.ShimWantedBy)
	if err != nil {
		t.Fatalf("IsUnitEnabled: %v", err)
	}
	if !enabled {
		t.Error("disabling one account de-enabled another: the survivor would not come back at boot")
	}
}

// IsUnitEnabled is the honest local answer to "will this come back after a reboot",
// and exists because `systemctl is-enabled` cannot see a symlink outside the config
// dir and would report a false "disabled".
func TestIsUnitEnabledReportsAbsentAndForeignLinksAsNotEnabled(t *testing.T) {
	s := scratchStore(t)
	enabled, err := s.IsUnitEnabled(systemd.UnitName, systemd.InstanceName("anon"), systemd.ShimWantedBy)
	if err != nil {
		t.Fatalf("IsUnitEnabled on a missing link must not error: %v", err)
	}
	if enabled {
		t.Error("a missing enablement symlink must read as NOT enabled")
	}
	// A link pointing somewhere else is a stale/foreign definition, not anonctl's, and
	// must not be reported as anonctl's enablement.
	wants := filepath.Join(s.UnitDir, systemd.ShimWantedBy+".wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("/etc/systemd/system/"+systemd.UnitName, filepath.Join(wants, systemd.InstanceName("anon"))); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	enabled, err = s.IsUnitEnabled(systemd.UnitName, systemd.InstanceName("anon"), systemd.ShimWantedBy)
	if err != nil {
		t.Fatalf("IsUnitEnabled: %v", err)
	}
	if enabled {
		t.Error("a symlink pointing at a FOREIGN unit path must not read as anonctl's enablement")
	}
}

// --- binary resolution ---
//
// The three binaries baked into the generated units must be RESOLVED, never guessed:
// /usr/bin/setpriv and /usr/sbin/nft do not exist on NixOS, and a unit carrying them
// fails at boot. For the loader that failure is fail-OPEN.

// THE GARBAGE-COLLECTION TIME BOMB. On NixOS every tool has two absolute paths: the
// stable /run/current-system/sw/bin/<tool> symlink that each rebuild repoints, and
// the /nix/store/<hash>-.../bin/<tool> path it currently points at. Baking the store
// path works today and breaks the moment the package is updated or the system is
// rebuilt: the old store path is garbage-collected, ExecStart points at a file that
// no longer exists, the loader fails 203/EXEC, and the account is silently unjailed
// with no baseline default-deny -- weeks later, with nothing in the config changed.
//
// exec.LookPath returns the $PATH entry VERBATIM, which is the stable one. This test
// pins that anonctl never "tidies it up" by resolving it (EvalSymlinks/realpath).
func TestResolverBinaryNeverBakesAResolvedSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	// Mimic the NixOS layout: a real binary in a content-addressed "store", reached
	// through a stable symlink dir.
	store := filepath.Join(root, "nix", "store", "abc123-nftables-1.1.6", "bin")
	stable := filepath.Join(root, "run", "current-system", "sw", "bin")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	if err := os.MkdirAll(stable, 0o755); err != nil {
		t.Fatalf("mkdir stable: %v", err)
	}
	realBin := filepath.Join(store, "nft")
	if err := os.WriteFile(realBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	stableBin := filepath.Join(stable, "nft")
	if err := os.Symlink(realBin, stableBin); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// A $PATH lookup yields the STABLE symlink, exactly as exec.LookPath does.
	r := systemd.Resolver{Look: func(string) (string, error) { return stableBin, nil }}
	got, err := r.Binary(systemd.NftBinaryName)
	if err != nil {
		t.Fatalf("Binary: %v", err)
	}
	if got != stableBin {
		t.Errorf("Binary must return the $PATH entry VERBATIM (%q), got %q", stableBin, got)
	}
	if got == realBin {
		t.Error("Binary resolved the symlink and would bake a garbage-collectable store path into the unit")
	}
}

// os.Executable() RESOLVES symlinks (/proc/self/exe on Linux), so the "sibling of
// the running anonctl" rule yields a store path whenever anonctl is itself invoked
// through a stable symlink -- the normal case on NixOS. When a $PATH entry names the
// SAME file, prefer it: it is the administrator-facing alias and survives rebuilds.
func TestResolverShimPrefersAStablePathAliasOverAResolvedSibling(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "nix", "store", "abc123-anonctl", "bin")
	stable := filepath.Join(root, "run", "current-system", "sw", "bin")
	for _, d := range []string{store, stable} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	realShim := filepath.Join(store, systemd.ShimBinaryName)
	if err := os.WriteFile(realShim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	stableShim := filepath.Join(stable, systemd.ShimBinaryName)
	if err := os.Symlink(realShim, stableShim); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	r := systemd.Resolver{
		// os.Executable would hand back the RESOLVED store path.
		Executable: func() (string, error) { return filepath.Join(store, "anonctl"), nil },
		Look:       func(string) (string, error) { return stableShim, nil },
	}
	got, err := r.ShimBinary()
	if err != nil {
		t.Fatalf("ShimBinary: %v", err)
	}
	if got != stableShim {
		t.Errorf("ShimBinary should prefer the stable $PATH alias %q, got %q (a store path is garbage-collected on the next rebuild)", stableShim, got)
	}
}

// The stable-alias preference must NOT hijack a genuinely different binary: when the
// $PATH entry is a DIFFERENT file, the sibling wins (version coherence between
// anonctl and its shim).
func TestResolverShimKeepsTheSiblingWhenPathHoldsADifferentBinary(t *testing.T) {
	prefix := t.TempDir()
	other := t.TempDir()
	sibling := filepath.Join(prefix, systemd.ShimBinaryName)
	if err := os.WriteFile(sibling, []byte("#!/bin/sh\n# ours\n"), 0o755); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	stale := filepath.Join(other, systemd.ShimBinaryName)
	if err := os.WriteFile(stale, []byte("#!/bin/sh\n# stale\n"), 0o755); err != nil {
		t.Fatalf("write stale: %v", err)
	}
	r := systemd.Resolver{
		Executable: func() (string, error) { return filepath.Join(prefix, "anonctl"), nil },
		Look:       func(string) (string, error) { return stale, nil },
	}
	got, err := r.ShimBinary()
	if err != nil {
		t.Fatalf("ShimBinary: %v", err)
	}
	if got != sibling {
		t.Errorf("ShimBinary should keep the sibling %q when $PATH holds a DIFFERENT binary, got %q", sibling, got)
	}
}

func TestResolverBinaryReturnsAnAbsolutePath(t *testing.T) {
	r := systemd.Resolver{
		Look: func(name string) (string, error) { return "/nix/store/xyz/bin/" + name, nil },
	}
	got, err := r.Binary(systemd.NftBinaryName)
	if err != nil {
		t.Fatalf("Binary: %v", err)
	}
	if got != "/nix/store/xyz/bin/nft" {
		t.Errorf("Binary returned %q", got)
	}
}

// The failure must NAME the binary, so the operator knows what to install, and must
// not silently fall back to an FHS path that is not there.
func TestResolverBinaryFailsLoudlyAndNamesTheBinary(t *testing.T) {
	r := systemd.Resolver{
		Look: func(string) (string, error) { return "", errors.New("not found") },
	}
	_, err := r.Binary(systemd.SetprivBinaryName)
	if err == nil {
		t.Fatal("Binary must fail when the binary cannot be resolved")
	}
	if got := err.Error(); !strings.Contains(got, systemd.SetprivBinaryName) {
		t.Errorf("error must name the unresolved binary, got %q", got)
	}
}

// The shim is looked for NEXT TO the running anonctl first. That is what makes a
// custom $PREFIX work: install.sh puts both binaries in $PREFIX, so the shim sits
// beside the anonctl that is running right now. The old code hard-coded
// /usr/local/bin/anonctl-shim regardless of PREFIX.
func TestResolverShimPrefersTheSiblingOfTheRunningBinary(t *testing.T) {
	prefix := t.TempDir()
	shim := filepath.Join(prefix, systemd.ShimBinaryName)
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("seed shim: %v", err)
	}
	r := systemd.Resolver{
		Executable: func() (string, error) { return filepath.Join(prefix, "anonctl"), nil },
		Look:       func(string) (string, error) { return "/somewhere/else/anonctl-shim", nil },
	}
	got, err := r.ShimBinary()
	if err != nil {
		t.Fatalf("ShimBinary: %v", err)
	}
	if got != shim {
		t.Errorf("ShimBinary should prefer the sibling %q (honouring PREFIX), got %q", shim, got)
	}
}

func TestResolverShimFallsBackToPath(t *testing.T) {
	// No sibling: fall back to $PATH.
	r := systemd.Resolver{
		Executable: func() (string, error) { return filepath.Join(t.TempDir(), "anonctl"), nil },
		Look:       func(string) (string, error) { return "/run/current-system/sw/bin/anonctl-shim", nil },
	}
	got, err := r.ShimBinary()
	if err != nil {
		t.Fatalf("ShimBinary: %v", err)
	}
	if got != "/run/current-system/sw/bin/anonctl-shim" {
		t.Errorf("ShimBinary should fall back to $PATH, got %q", got)
	}
}

// When the shim is nowhere, the failure must be LOUD, never a guessed path that is
// not there. This is asserted through ResolveUnitParams rather than ShimBinary
// directly: ShimBinary's last-resort fallback stats the REAL
// DefaultShimBinaryPath, which a dev box may genuinely have, so a direct assertion
// would silently disable itself exactly where anonctl is installed. Driving it
// through a resolver whose Look always fails keeps the assertion deterministic on
// every host, because setpriv/nft resolution fails first regardless.
func TestResolveUnitParamsFailsLoudlyWhenNothingResolves(t *testing.T) {
	r := systemd.Resolver{
		Executable: func() (string, error) { return filepath.Join(t.TempDir(), "anonctl"), nil },
		Look:       func(string) (string, error) { return "", errors.New("not found") },
	}
	_, _, err := systemd.ResolveUnitParams(r)
	if err == nil {
		t.Fatal("ResolveUnitParams must fail loudly when no unit binary can be resolved")
	}
	// PreflightUnitBinaries is the `add`-time guard and must agree.
	if perr := systemd.PreflightUnitBinaries(r); perr == nil {
		t.Error("PreflightUnitBinaries must refuse before the box is touched")
	}
}

// ResolveUnitParams fails EARLY, before any unit is written, if any of the three
// binaries is missing.
func TestResolveUnitParamsFailsBeforeProducingPartialParams(t *testing.T) {
	r := systemd.Resolver{
		Executable: func() (string, error) { return "", errors.New("none") },
		Look: func(name string) (string, error) {
			if name == systemd.NftBinaryName {
				return "", errors.New("not found")
			}
			return "/fake/bin/" + name, nil
		},
	}
	if _, _, err := systemd.ResolveUnitParams(r); err == nil {
		t.Fatal("ResolveUnitParams must fail when nft cannot be resolved")
	}
}
