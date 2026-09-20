package systemd_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// MIGRATION from the pre-0.4 unit dir.
//
// anonctl <= 0.3.0 installed its units into /etc/systemd/system. That directory
// OUTRANKS the current unit dir (/usr/local/lib/systemd/system) in systemd's unit
// load path, so a unit file left behind there SHADOWS the newly installed one and
// the host silently keeps running the OLD definition. On an upgraded host that old
// definition is exactly the one whose hard-coded /usr/sbin/nft fails at boot, which
// is fail-OPEN. So the sweep is a correctness requirement, not tidiness, and these
// tests exercise the UPGRADE path rather than only a fresh install.

// seedLegacyInstall writes what a real anonctl 0.3.0 install left on disk: both unit
// files plus the enablement symlinks `systemctl enable` created for the loader and
// for each per-account shim INSTANCE.
func seedLegacyInstall(t *testing.T, legacyDir string, accounts ...string) []string {
	t.Helper()
	var seeded []string
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	for _, name := range []string{systemd.UnitName, systemd.LoaderUnitName} {
		path := filepath.Join(legacyDir, name)
		if err := os.WriteFile(path, []byte("# stale anonctl 0.3.0 unit\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		seeded = append(seeded, path)
	}
	loaderWants := filepath.Join(legacyDir, systemd.LoaderWantedBy+".wants")
	if err := os.MkdirAll(loaderWants, 0o755); err != nil {
		t.Fatalf("mkdir loader wants: %v", err)
	}
	link := filepath.Join(loaderWants, systemd.LoaderUnitName)
	if err := os.Symlink(filepath.Join(legacyDir, systemd.LoaderUnitName), link); err != nil {
		t.Fatalf("seed loader link: %v", err)
	}
	seeded = append(seeded, link)

	shimWants := filepath.Join(legacyDir, systemd.ShimWantedBy+".wants")
	if err := os.MkdirAll(shimWants, 0o755); err != nil {
		t.Fatalf("mkdir shim wants: %v", err)
	}
	for _, acct := range accounts {
		link := filepath.Join(shimWants, systemd.InstanceName(acct))
		if err := os.Symlink(filepath.Join(legacyDir, systemd.UnitName), link); err != nil {
			t.Fatalf("seed shim link for %s: %v", acct, err)
		}
		seeded = append(seeded, link)
	}
	return seeded
}

// The core guarantee: after migration there is exactly ONE definition of each unit,
// and it is not the shadowing one.
func TestMigrateRemovesEveryShadowingLegacyArtifact(t *testing.T) {
	s := scratchStore(t)
	// Three accounts, matching a real multi-account host: the upgrade must sweep EVERY
	// instance symlink, not just one.
	seeded := seedLegacyInstall(t, s.LegacyUnitDir, "anon", "anon-work", "anon-mail")

	removed, err := s.MigrateLegacyUnits()
	if err != nil {
		t.Fatalf("MigrateLegacyUnits: %v", err)
	}
	if len(removed) != len(seeded) {
		t.Errorf("migration removed %d artifacts, expected %d: %v", len(removed), len(seeded), removed)
	}
	for _, path := range seeded {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("migration left a shadowing legacy artifact behind: %s", path)
		}
	}
}

// REGRESSION: a multi-account upgrade must not silently de-enable the accounts that
// are NOT the one being added.
//
// The legacy sweep necessarily matches every `anonctl-shim@*.service` link, but the
// `add` that triggers it only re-creates the link for ONE account. A delete-only
// sweep therefore leaves every OTHER account enabled in NO load-path directory.
// Their shims keep running, so nothing looks wrong -- until the next reboot, when
// they never come back. Nothing in the tool would detect it. So the migration must
// ADOPT every enablement it removes.
func TestMigrateAdoptsEveryAccountsEnablementNotJustOne(t *testing.T) {
	s := scratchStore(t)
	accounts := []string{"anon", "anon-work", "anon-mail"}
	seedLegacyInstall(t, s.LegacyUnitDir, accounts...)

	if _, err := s.MigrateLegacyUnits(); err != nil {
		t.Fatalf("MigrateLegacyUnits: %v", err)
	}
	for _, acct := range accounts {
		enabled, err := s.IsUnitEnabled(systemd.UnitName, systemd.InstanceName(acct), systemd.ShimWantedBy)
		if err != nil {
			t.Fatalf("IsUnitEnabled %s: %v", acct, err)
		}
		if !enabled {
			t.Errorf("account %q lost its enablement in the migration: its shim would not start after a reboot", acct)
		}
	}
	// The loader's enablement is adopted too, not just dropped.
	enabled, err := s.IsUnitEnabled(systemd.LoaderUnitName, systemd.LoaderUnitName, systemd.LoaderWantedBy)
	if err != nil {
		t.Fatalf("IsUnitEnabled loader: %v", err)
	}
	if !enabled {
		t.Error("the loader lost its enablement in the migration: no baseline default-deny would load at boot (FAIL-OPEN)")
	}
}

// The migration must be surgical: it owns only anonctl's own files and must never
// disturb a foreign unit that happens to share the directory.
func TestMigrateLeavesForeignUnitsAlone(t *testing.T) {
	s := scratchStore(t)
	seedLegacyInstall(t, s.LegacyUnitDir, "anon")
	foreign := filepath.Join(s.LegacyUnitDir, "postgresql.service")
	if err := os.WriteFile(foreign, []byte("# not ours\n"), 0o644); err != nil {
		t.Fatalf("seed foreign unit: %v", err)
	}
	foreignLink := filepath.Join(s.LegacyUnitDir, systemd.ShimWantedBy+".wants", "postgresql.service")
	if err := os.Symlink(foreign, foreignLink); err != nil {
		t.Fatalf("seed foreign link: %v", err)
	}
	if _, err := s.MigrateLegacyUnits(); err != nil {
		t.Fatalf("MigrateLegacyUnits: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("migration removed a foreign unit file: %v", err)
	}
	if _, err := os.Lstat(foreignLink); err != nil {
		t.Errorf("migration removed a foreign enablement symlink: %v", err)
	}
}

// A fresh install (and every NixOS install, where the tool never ran before) has
// nothing to migrate. That must be a silent no-op, never an error.
func TestMigrateIsANoOpWithNothingToMigrate(t *testing.T) {
	s := scratchStore(t)
	removed, err := s.MigrateLegacyUnits()
	if err != nil {
		t.Fatalf("migration on a fresh install must be a no-op, got: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("migration removed %v on a fresh install", removed)
	}
	// An existing but anonctl-free legacy dir is equally a no-op.
	if err := os.MkdirAll(s.LegacyUnitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if removed, err := s.MigrateLegacyUnits(); err != nil || len(removed) != 0 {
		t.Errorf("migration over an anonctl-free legacy dir must be a no-op; got %v, %v", removed, err)
	}
}

// Guard against the migration eating the live install: if a host is deliberately
// configured with the legacy dir AS its unit dir, sweeping it would delete the units
// that were just written.
func TestMigrateRefusesToSweepItsOwnUnitDir(t *testing.T) {
	s := scratchStore(t)
	s.LegacyUnitDir = s.UnitDir
	tp, lp := scratchParams()
	if err := s.InstallCommon(tp, lp); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	if _, err := s.MigrateLegacyUnits(); err != nil {
		t.Fatalf("MigrateLegacyUnits: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.UnitDir, systemd.UnitName)); err != nil {
		t.Errorf("migration deleted the live template unit when legacy dir == unit dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.UnitDir, systemd.LoaderUnitName)); err != nil {
		t.Errorf("migration deleted the live loader unit when legacy dir == unit dir: %v", err)
	}
}

// The END-TO-END upgrade shape: a host with a 0.3.0 install is re-installed, and
// afterwards the unit resolves to the NEW location with no copy left in the old one.
func TestUpgradeFromLegacyInstallLeavesExactlyOneDefinition(t *testing.T) {
	s := scratchStore(t)
	seedLegacyInstall(t, s.LegacyUnitDir, "anon")

	tp, lp := scratchParams()
	if err := s.InstallCommon(tp, lp); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	if _, err := s.MigrateLegacyUnits(); err != nil {
		t.Fatalf("MigrateLegacyUnits: %v", err)
	}
	if err := s.EnableUnit(systemd.UnitName, systemd.InstanceName("anon"), systemd.ShimWantedBy); err != nil {
		t.Fatalf("EnableUnit: %v", err)
	}
	for _, name := range []string{systemd.UnitName, systemd.LoaderUnitName} {
		if _, err := os.Stat(filepath.Join(s.UnitDir, name)); err != nil {
			t.Errorf("unit %s missing from the new unit dir: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(s.LegacyUnitDir, name)); !os.IsNotExist(err) {
			t.Errorf("unit %s still present in the legacy dir: it OUTRANKS the new one and would shadow it", name)
		}
	}
	// The account stays enabled across the upgrade -- in the new location.
	enabled, err := s.IsUnitEnabled(systemd.UnitName, systemd.InstanceName("anon"), systemd.ShimWantedBy)
	if err != nil {
		t.Fatalf("IsUnitEnabled: %v", err)
	}
	if !enabled {
		t.Error("the account is not enabled after the upgrade: its forcing would not survive a reboot")
	}
}
