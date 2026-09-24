package forcing_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/systemd"
)

// These tests cover HOST-OWNED UNITS at the orchestration level: the mode in which
// the host declares anonctl's two shared unit files and anonctl must not write,
// rewrite or delete them. The semantics are asserted from the OUTSIDE (what is on
// disk after Install / Reconfigure / Remove), because that is what a host's next
// boot actually reads.

// hostOwnedDeps builds orchestration deps in host-owned mode: a marker file, a
// scratch "host" unit directory that the store searches, and the two unit files
// already declared there, as a host's configuration would have placed them.
//
// It deliberately places the declared units in a DIFFERENT directory from anonctl's
// own unit dir, matching the real shape: a NixOS host's `systemd.units` renders into
// /etc/systemd/system, which outranks anonctl's /usr/local/lib/systemd/system.
func hostOwnedDeps(t *testing.T) (forcing.Deps, string) {
	t.Helper()
	d, _ := testDeps(t)
	root := filepath.Dir(d.SystemdStore.UnitDir)
	hostDir := filepath.Join(root, "host-systemd")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host unit dir: %v", err)
	}
	// The binaries the host's units name must exist, because anonctl asserts them
	// before it touches the box (a declared path that is not there is a 203/EXEC at the
	// next boot, and for the loader that is fail-OPEN).
	bin := filepath.Join(root, "store", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("mkdir fake store bin: %v", err)
	}
	paths := map[string]string{}
	for _, name := range []string{"setpriv", "anonctl-shim", "nft", "sh"} {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
		paths[name] = p
	}
	// The host generates its units through the SAME exporter it would use in its
	// configuration, so this test consumes the real export path rather than a fixture.
	shim, err := systemd.Export(systemd.ExportParams{
		Kind:           systemd.KindShim,
		SetprivPath:    paths["setpriv"],
		ShimBinaryPath: paths["anonctl-shim"],
		EnvDir:         d.SystemdStore.EnvDir,
	})
	if err != nil {
		t.Fatalf("export shim unit: %v", err)
	}
	loader, err := systemd.Export(systemd.ExportParams{
		Kind:     systemd.KindNftables,
		NftPath:  paths["nft"],
		RulesDir: d.SystemdStore.RulesDir,
	})
	if err != nil {
		t.Fatalf("export loader unit: %v", err)
	}
	// The loader's ExecStart names /bin/sh, which exists on every host this runs on.
	for name, text := range map[string]string{
		systemd.UnitName:       shim,
		systemd.LoaderUnitName: loader,
	} {
		if err := os.WriteFile(filepath.Join(hostDir, name), []byte(text), 0o644); err != nil {
			t.Fatalf("write host-declared %s: %v", name, err)
		}
	}
	marker := filepath.Join(root, "units.host-owned")
	if err := os.WriteFile(marker, []byte("declared by the test host\n"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	s := d.SystemdStore
	s.HostOwnedMarker = marker
	// Search the host's dir FIRST, exactly as systemd ranks /etc above /usr/local/lib.
	s.SearchDirs = []string{hostDir, s.UnitDir}
	d.SystemdStore = s
	return d, hostDir
}

// Install in host-owned mode must write NEITHER unit file, while still writing the
// per-account enablement symlink -- the artifact that makes the account's forcing
// come back after a reboot, and the one artifact that stays anonctl's in every mode
// because its NAME says which account slot is in use.
func TestInstallWithHostOwnedUnitsWritesNoUnitFilesButStillEnablesTheAccount(t *testing.T) {
	d, hostDir := hostOwnedDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, name := range systemd.SharedUnitNames() {
		if _, err := os.Stat(filepath.Join(d.SystemdStore.UnitDir, name)); !os.IsNotExist(err) {
			t.Errorf("Install wrote %s into anonctl's unit dir while the host owns the units: that is a SECOND definition of the same unit, and the host's copy silently outranks it", name)
		}
		if _, err := os.Stat(filepath.Join(hostDir, name)); err != nil {
			t.Errorf("Install disturbed the host-declared %s: %v", name, err)
		}
	}
	// The enablement symlinks are still anonctl's, and are still written into anonctl's
	// own unit dir. Their TARGET is anonctl's (absent) copy, which is correct: systemd
	// resolves a `.wants` entry by unit NAME and loads the definition from the search
	// path, so the dependency is real (measured on systemd 260).
	for _, link := range []string{
		filepath.Join(d.SystemdStore.UnitDir, systemd.ShimWantedBy+".wants", systemd.InstanceName("anon")),
		filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderWantedBy+".wants", systemd.LoaderUnitName),
	} {
		if _, err := os.Lstat(link); err != nil {
			t.Errorf("Install did not write the enablement symlink %s in host-owned mode: the account would not come back after a reboot (%v)", link, err)
		}
	}
}

// The marker without the units is the mode's one dangerous footgun, so it is a
// REFUSAL before anything is mutated. Proceeding would enable an account whose shim
// and whose early-boot default-deny do not exist: at the next boot no baseline
// default-deny loads at all, and the anon UID egresses with the host's real IP.
func TestInstallRefusesWhenTheHostClaimsTheUnitsButHasNotDeclaredThem(t *testing.T) {
	d, hostDir := hostOwnedDeps(t)
	if err := os.Remove(filepath.Join(hostDir, systemd.LoaderUnitName)); err != nil {
		t.Fatalf("remove declared loader: %v", err)
	}
	err := forcing.Install(context.Background(), d, sampleConfig(), nil)
	if err == nil {
		t.Fatal("Install proceeded with the host-owned marker set and the loader unit missing: at the next boot there would be no standing default-deny at all (fail-OPEN)")
	}
	if !strings.Contains(err.Error(), systemd.LoaderUnitName) {
		t.Errorf("the refusal does not name the missing unit: %v", err)
	}
	// Refused with the box UNTOUCHED: no config record, no rule files, no symlinks.
	if _, serr := os.Stat(filepath.Join(d.SystemdStore.RulesDir, "anon.nft")); !os.IsNotExist(serr) {
		t.Error("a refused Install still persisted a rule file; the refusal must leave nothing behind")
	}
	if _, serr := os.Stat(filepath.Join(d.SystemdStore.UnitDir, systemd.ShimWantedBy+".wants")); !os.IsNotExist(serr) {
		t.Error("a refused Install still wrote an enablement symlink")
	}
}

// A declared unit naming a binary that does not exist is refused too, for the same
// reason and at the same moment. anonctl does not resolve those paths in this mode
// (that is the point: they are pinned by the host), so this is the only place the
// mistake can be caught before a reboot turns it into a dead unit.
func TestInstallRefusesWhenAHostDeclaredUnitNamesAMissingBinary(t *testing.T) {
	d, hostDir := hostOwnedDeps(t)
	text, err := systemd.Export(systemd.ExportParams{
		Kind:     systemd.KindNftables,
		NftPath:  "/nix/store/deadbeef-nftables-1.1.6/bin/nft", // never existed
		RulesDir: d.SystemdStore.RulesDir,
	})
	if err != nil {
		t.Fatalf("export loader: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, systemd.LoaderUnitName), []byte(text), 0o644); err != nil {
		t.Fatalf("rewrite declared loader: %v", err)
	}
	ierr := forcing.Install(context.Background(), d, sampleConfig(), nil)
	if ierr == nil {
		t.Fatal("Install accepted a host-declared loader whose nft binary does not exist: it would fail 203/EXEC at boot, leaving no standing default-deny")
	}
	if !strings.Contains(ierr.Error(), "deadbeef") {
		t.Errorf("the refusal does not name the missing binary: %v", ierr)
	}
}

// THE TEARDOWN RULE: the last account's cleanup removes the shared units in the
// ordinary mode, and must NOT when the host owns them. This is the one place where
// tidying up turns into deleting part of a machine's DECLARED configuration, and the
// deletion would be invisible until the next rebuild put the file back -- or until
// the next boot did not.
func TestRemoveLastAccountStillCleansAnonctlsOwnArtifactsInHostOwnedMode(t *testing.T) {
	d, hostDir := hostOwnedDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := forcing.Remove(context.Background(), d, "anon"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, name := range systemd.SharedUnitNames() {
		if _, err := os.Stat(filepath.Join(hostDir, name)); err != nil {
			t.Fatalf("the last account's teardown DELETED the host-declared %s: %v", name, err)
		}
	}
	// Everything anonctl DOES own is still cleaned up: its enablement symlinks and its
	// now-empty private dirs. Host ownership of the unit files is not a licence to
	// leave anonctl's own residue behind.
	for _, link := range []string{
		filepath.Join(d.SystemdStore.UnitDir, systemd.ShimWantedBy+".wants", systemd.InstanceName("anon")),
		filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderWantedBy+".wants", systemd.LoaderUnitName),
	} {
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Errorf("Remove left anonctl's own enablement symlink %s behind", link)
		}
	}
	for _, dir := range []string{d.SystemdStore.EnvDir, d.SystemdStore.RulesDir} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("Remove left the empty anonctl dir %q behind", dir)
		}
	}
}

// THE SAME RULE, in the arrangement that actually exercises it: the host declares
// the units straight INTO anonctl's own unit dir. Nothing stops a host doing that,
// and then the paths the last-account teardown deletes ARE the host's files.
//
// The fixture above puts them in a separate directory, which is realistic for NixOS
// but means the teardown's deletes miss them whether or not the guard exists. This
// case is the one that fails when the guard is removed, so it is what makes "rm
// never deletes host-owned units" a tested property rather than a comment.
func TestRemoveLastAccountNeverDeletesHostUnitsDeclaredInAnonctlsOwnUnitDir(t *testing.T) {
	d, _ := hostOwnedDeps(t)
	s := d.SystemdStore
	// Move the declaration into anonctl's unit dir and make that the only search dir.
	if err := os.MkdirAll(s.UnitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range systemd.SharedUnitNames() {
		from := filepath.Join(s.SearchDirs[0], name)
		body, err := os.ReadFile(from)
		if err != nil {
			t.Fatalf("read %s: %v", from, err)
		}
		if err := os.WriteFile(filepath.Join(s.UnitDir, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := os.Remove(from); err != nil {
			t.Fatalf("remove %s: %v", from, err)
		}
	}
	s.SearchDirs = []string{s.UnitDir}
	d.SystemdStore = s

	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := forcing.Remove(context.Background(), d, "anon"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, name := range systemd.SharedUnitNames() {
		if _, err := os.Stat(filepath.Join(s.UnitDir, name)); err != nil {
			t.Fatalf("the last account's teardown DELETED %s, which the host declares: %v", name, err)
		}
	}
}

// Reconfigure (`anonctl update`) is the OTHER writer of the shared unit files: it
// re-bakes them so a moved binary path is repaired. In host-owned mode there is
// nothing for it to re-bake, and it must not write its own copy -- one forgotten
// invocation would be enough to recreate the second definition.
func TestReconfigureWithHostOwnedUnitsRewritesNoUnitFiles(t *testing.T) {
	d, _ := hostOwnedDeps(t)
	cfg := sampleConfig()
	if err := forcing.Install(context.Background(), d, cfg, nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	cfg.EndpointPort = 9150
	if err := forcing.Reconfigure(context.Background(), d, cfg, nil); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
	for _, name := range systemd.SharedUnitNames() {
		if _, err := os.Stat(filepath.Join(d.SystemdStore.UnitDir, name)); !os.IsNotExist(err) {
			t.Errorf("Reconfigure wrote %s into anonctl's unit dir while the host owns the units", name)
		}
	}
	// It still did its real job: the env file carries the new endpoint.
	env, err := os.ReadFile(filepath.Join(d.SystemdStore.EnvDir, "anon.env"))
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if !strings.Contains(string(env), "9150") {
		t.Errorf("Reconfigure did not rewrite the endpoint in the env file: %s", env)
	}
}

// A host that owns the units does NOT have to have setpriv, the shim binary or nft
// on anonctl's $PATH: those paths belong to the host's pin, and anonctl generates
// nothing. Requiring them would refuse a correctly configured host over text that is
// thrown away, so this pins that the resolver is not consulted in this mode.
func TestInstallWithHostOwnedUnitsDoesNotNeedLocalBinariesOnPath(t *testing.T) {
	d, _ := hostOwnedDeps(t)
	d.Resolver = systemd.Resolver{
		Look:       func(name string) (string, error) { return "", os.ErrNotExist },
		Executable: func() (string, error) { return "", os.ErrNotExist },
	}
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install refused a host-owned install because anonctl could not resolve binaries it never bakes: %v", err)
	}
}
