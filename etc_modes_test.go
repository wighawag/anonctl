package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/configroot"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anonctl/internal/defaults"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/systemd"
)

// THE MODE AUDIT for `/etc/anonctl`.
//
// The live bug was that nobody owned the shared config root's mode: three stores
// wrote under it and whichever created it first decided what it was. `add` writes
// the ledger (0700) before its inline verify writes the marker (documented 0755),
// so on every real box `/etc/anonctl` ended up 0700 and the credential-free marker
// - whose entire purpose is to be readable by any UID with no anonctl binary -
// could not be read at all.
//
// Fixing that widens the ROOT, which makes the opposite mistake possible: a
// traversable parent must not make anything INSIDE it readable. So this file does
// not just assert the root; it walks the ENTIRE tree anonctl writes and checks
// every single path against an expectation, and FAILS ON ANY PATH IT DOES NOT
// RECOGNISE. A future artifact added under `/etc/anonctl` cannot slip in without
// someone classifying its mode here.

// expectedMode maps a path (relative to the config root) to the mode anonctl
// promises for it. Directories and files are both covered; the classifier below
// turns per-account names into these patterns.
//
// The promises, and why each is what it is:
//
//   - "."            the ROOT: 0755. World-traversable so any UID can reach the
//     markers. This EXPOSES THE NAMES of accounts that have markers
//     (`ls /etc/anonctl` shows `<account>.json`), which is intended: the
//     marker is credential-free by construction, and a local account
//     name is already visible to every local user in /etc/passwd.
//   - "<acct>.json"  a MARKER: 0644, world-readable by design, holds no secret.
//   - "accounts"     the LEDGER dir: 0700. Holds endpoint host/port per account.
//   - "accounts/*"   a ledger record: 0600.
//   - "shim"         the shim ENV dir: 0700. The env file carries the endpoint.
//   - "shim/*.env"   0600.
//   - "nftables"     the persisted RULES dir: 0700. anonctl-private state.
//   - "nftables/*"   0600.
//
// And the two OPERATOR-PLACED artifacts, which anonctl does not create but must
// still protect, because the 0755 root is precisely what removed the incidental
// protection they used to get from a 0700 parent:
//
//   - "default-home"   the seed template: 0700, recursively (it holds the
//     operator's dotfiles and tool configs; `sudo cp -r` would
//     otherwise leave it 0755/0644 and now world-readable).
//   - "defaults.json"  box-wide defaults: 0600.
//
// ORDER MATTERS IN THIS SWITCH. The exact-name cases come BEFORE the generic
// "root-level *.json is a marker" case, because `defaults.json` IS a root-level
// .json and would otherwise be silently blessed as 0644 world-readable - the audit
// would classify it, so the fail-on-unknown property would never fire. A classifier
// that buckets by path SHAPE has to put its exact names first.
func classify(rel string, isDir bool) (want os.FileMode, known bool) {
	sep := string(filepath.Separator)
	switch {
	case rel == ".":
		return configroot.Mode, true
	case rel == "defaults.json":
		return 0o600, true
	case rel == "default-home" || strings.HasPrefix(rel, "default-home"+sep):
		// The whole template TREE: directories 0700, files 0600. A 0700 top directory
		// over 0644 files is only as private as every path that reaches them, and the
		// operator's `cp -r` produces exactly that, so the audit walks the tree.
		if isDir {
			return 0o700, true
		}
		return 0o600, true
	case rel == "accounts", rel == "shim", rel == "nftables":
		return 0o700, true
	case !strings.Contains(rel, sep) && strings.HasSuffix(rel, ".json"):
		return 0o644, true // a marker, in the root
	case strings.HasPrefix(rel, "accounts"+string(filepath.Separator)):
		return 0o600, true
	case strings.HasPrefix(rel, "shim"+string(filepath.Separator)):
		return 0o600, true
	case strings.HasPrefix(rel, "nftables"+string(filepath.Separator)):
		return 0o600, true
	}
	return 0, false
}

// auditTree walks every path under root and asserts its mode. An UNKNOWN path is a
// failure, not a skip: this audit is only worth anything if it cannot be outgrown
// silently.
func auditTree(t *testing.T, root string) {
	t.Helper()
	var audited []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		want, known := classify(rel, d.IsDir())
		if !known {
			t.Errorf("UNCLASSIFIED path under the config root: %q (mode %#o).\n"+
				"Every child of /etc/anonctl must have a promised mode asserted here. Add it to classify() "+
				"with the reason its mode is what it is, or stop writing it.", rel, info.Mode().Perm())
			return nil
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%q: mode %#o, want %#o", rel, got, want)
		}
		audited = append(audited, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %q: %v", root, err)
	}
	sort.Strings(audited)
	t.Logf("audited %d paths under the config root: %s", len(audited), strings.Join(audited, " "))
}

// assertRealEtcUntouched pins the shared-write isolation discipline at the top
// level too: this test drives the REAL install path, so if any store silently fell
// back to its production default we would be writing the developer's /etc.
func assertRealEtcUntouched(t *testing.T) {
	t.Helper()
	before, beforeErr := os.Stat(configroot.DefaultDir)
	t.Cleanup(func() {
		after, afterErr := os.Stat(configroot.DefaultDir)
		switch {
		case beforeErr != nil && afterErr == nil:
			t.Fatalf("this test created the REAL %s", configroot.DefaultDir)
		case beforeErr == nil && afterErr != nil:
			t.Fatalf("this test removed the REAL %s: %v", configroot.DefaultDir, afterErr)
		case beforeErr == nil && afterErr == nil && before.Mode() != after.Mode():
			t.Fatalf("this test changed the mode of the REAL %s: %v -> %v", configroot.DefaultDir, before.Mode(), after.Mode())
		}
	})
}

// installThenMark drives the REAL install path against a scratch config root laid
// out exactly like production, in the REAL ORDER `add` uses (forcing first - which
// writes the ledger - then the marker, which `verify` writes on green), and returns
// the root.
func installThenMark(t *testing.T) string {
	t.Helper()
	assertRealEtcUntouched(t)

	base := t.TempDir()
	root := filepath.Join(base, "anonctl")
	deps, _ := testForcingDeps(t, base, root)

	cfg := accountconfig.Config{
		Account:       "anon",
		AnonUID:       8801,
		ShimUID:       412,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
	}
	if err := forcing.Install(context.Background(), deps, cfg, nil); err != nil {
		t.Fatalf("forcing.Install: %v", err)
	}

	markers := marker.Store{BaseDir: root}
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("marker write: %v", err)
	}
	return root
}

// THE ACCEPTANCE TEST, at the anonctl level: the real install path writes the
// ledger FIRST and the marker SECOND, and afterwards the marker directory and the
// marker file must still have the modes the contract documents.
func TestAddOrderLeavesTheMarkerPubliclyReadable(t *testing.T) {
	root := installThenMark(t)

	if got := modeOf(t, root); got != configroot.Mode {
		t.Errorf("the config root is %#o after the real install-then-mark order; want %#o.\n"+
			"The marker is documented as a dependency-free signal any UID can read; at %#o no unprivileged "+
			"consumer can even traverse into the directory.", got, configroot.Mode, got)
	}
	if got := modeOf(t, filepath.Join(root, "anon.json")); got != 0o644 {
		t.Errorf("the marker file is %#o; want 0644 (world-readable by design)", got)
	}
}

// ...and widening the root widened NOTHING inside it. Every path anonctl writes is
// audited, and an unrecognised one fails.
func TestEveryChildOfTheConfigRootHasItsPromisedMode(t *testing.T) {
	auditTree(t, installThenMark(t))
}

// THE OPERATOR-PLACED ARTIFACTS, which anonctl does not create and which the audit
// above therefore never sees.
//
// This is the case that makes widening the root a PRIVILEGE-BOUNDARY change rather
// than a bug fix. `default-home/` holds the operator's dotfiles and tool configs,
// and the README tells them to populate it with `sudo cp -r <src>/. ...`, which
// under a normal umask yields 0755 directories and 0644 files. That was harmless
// while `/etc/anonctl` was 0700 and blocked traversal outright. The moment the root
// becomes 0755 - which it must, so the credential-free marker is readable - those
// modes are all that stand between the operator's dotfiles and every local uid.
//
// So the artifacts are seeded here EXACTLY as that `cp` would leave them, and
// anonctl must tighten them.
func TestOperatorPlacedFilesAreTightenedWhenTheRootIsWidened(t *testing.T) {
	assertRealEtcUntouched(t)

	root := filepath.Join(t.TempDir(), "anonctl")
	templateDir := filepath.Join(root, "default-home", ".config", "sometool")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("seed the template tree: %v", err)
	}
	secret := filepath.Join(templateDir, "config.toml")
	if err := os.WriteFile(secret, []byte("token = \"hunter2\"\n"), 0o644); err != nil {
		t.Fatalf("seed a template file: %v", err)
	}
	defaultsPath := filepath.Join(root, "defaults.json")
	if err := os.WriteFile(defaultsPath, []byte(`{"allow":[]}`), 0o644); err != nil {
		t.Fatalf("seed defaults.json: %v", err)
	}

	// Precondition: these really are world-readable as seeded. If this ever stops
	// being true the test below is proving nothing.
	if got := modeOf(t, secret); got != 0o644 {
		t.Fatalf("precondition: the seeded template file should be 0644, got %#o", got)
	}

	store := defaults.Store{BaseDir: root}
	if err := store.Tighten(); err != nil {
		t.Fatalf("Tighten: %v", err)
	}

	if got := modeOf(t, secret); got != 0o600 {
		t.Errorf("the operator's template FILE is %#o after tightening; want 0600.\n"+
			"/etc/anonctl is world-traversable now (the marker contract requires it), so a 0644 file in the "+
			"default-home template is readable by every local uid on the box.", got)
	}
	for _, dir := range []string{
		filepath.Join(root, "default-home"),
		filepath.Join(root, "default-home", ".config"),
		templateDir,
	} {
		if got := modeOf(t, dir); got != 0o700 {
			t.Errorf("%q is %#o after tightening; want 0700 (a 0700 top directory over traversable "+
				"subdirectories protects nothing)", dir, got)
		}
	}
	if got := modeOf(t, defaultsPath); got != 0o600 {
		t.Errorf("defaults.json is %#o after tightening; want 0600", got)
	}

	// And the audit now covers them, so the promise is recorded rather than implicit.
	auditTree(t, root)
}

// Tighten is a REPAIR, not a create: a config root with neither artifact is a clean
// no-op (the directory-exists convention means absence is the normal state), and it
// must never bring either path into existence - creating `default-home/` would
// silently switch add-time home seeding ON.
func TestTightenNeverCreatesTheOperatorArtifacts(t *testing.T) {
	assertRealEtcUntouched(t)

	root := filepath.Join(t.TempDir(), "anonctl")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	store := defaults.Store{BaseDir: root}
	if err := store.Tighten(); err != nil {
		t.Fatalf("Tighten on an empty root must be a clean no-op; got %v", err)
	}
	if store.DefaultHomePresent() {
		t.Error("Tighten created default-home/, which would silently switch on add-time home seeding")
	}
	if _, err := os.Stat(filepath.Join(root, "defaults.json")); !os.IsNotExist(err) {
		t.Errorf("Tighten created defaults.json; it must only repair what exists (stat: %v)", err)
	}
}

// The reverse order must reach the same modes: the root's mode is OWNED, not a
// race between whichever store writes first. (This is the ordering half - without
// it, a fix that merely chmods in the marker path would pass the test above and
// still be one `add`-ordering change away from the same bug.)
func TestTheConfigRootHasOneOwnerWhicheverStoreWritesFirst(t *testing.T) {
	assertRealEtcUntouched(t)

	base := t.TempDir()
	root := filepath.Join(base, "anonctl")

	// Marker FIRST this time.
	markers := marker.Store{BaseDir: root}
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("marker write: %v", err)
	}
	deps, _ := testForcingDeps(t, base, root)
	if err := forcing.Install(context.Background(), deps, accountconfig.Config{
		Account: "anon", AnonUID: 8801, ShimUID: 412,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}, nil); err != nil {
		t.Fatalf("forcing.Install: %v", err)
	}
	auditTree(t, root)
}

// A box PROVISIONED BY AN OLDER BUILD has a 0700 root already on disk. The fix must
// REPAIR it on the next write, not merely get fresh boxes right - otherwise every
// existing install stays broken until someone chmods by hand.
func TestAnExistingTooTightRootIsRepairedByTheNextWrite(t *testing.T) {
	assertRealEtcUntouched(t)

	base := t.TempDir()
	root := filepath.Join(base, "anonctl")
	// Exactly what 0.6.1 leaves behind: the root created 0700 by the ledger, with a
	// ledger record already in it.
	if err := os.MkdirAll(filepath.Join(root, "accounts"), 0o700); err != nil {
		t.Fatalf("seed an old-build layout: %v", err)
	}
	if got := modeOf(t, root); got != 0o700 {
		t.Fatalf("precondition: the seeded root should be 0700, got %#o", got)
	}

	markers := marker.Store{BaseDir: root}
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("marker write: %v", err)
	}
	if got := modeOf(t, root); got != configroot.Mode {
		t.Errorf("an UPGRADED box still has a %#o root after writing a marker; want %#o (the fix must repair, not just create)", got, configroot.Mode)
	}
	if got := modeOf(t, filepath.Join(root, "accounts")); got != 0o700 {
		t.Errorf("repairing the root must not widen the ledger dir: got %#o, want 0700", got)
	}
}

// modeOf returns a path's permission bits.
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return fi.Mode().Perm()
}

// testForcingDeps wires forcing.Install against fakes (no real nft, systemctl or
// PATH lookup) and against a scratch config root laid out EXACTLY like production:
// the ledger, the shim env dir and the rules dir are all subdirectories of the same
// root the markers live in. That layout is the point - a test that pointed each
// store at an unrelated temp dir could never have caught this bug.
func testForcingDeps(t *testing.T, base, root string) (forcing.Deps, *[]string) {
	t.Helper()
	var calls []string
	return forcing.Deps{
		NftRunner:     modeAuditNft{&calls},
		SystemdRunner: modeAuditSystemctl{&calls},
		ConfigStore: accountconfig.Store{
			RootDir: root,
			BaseDir: filepath.Join(root, "accounts"),
		},
		SystemdStore: systemd.Store{
			RootDir:  root,
			EnvDir:   filepath.Join(root, "shim"),
			RulesDir: filepath.Join(root, "nftables"),
			// The unit dirs are NOT under /etc/anonctl (they are systemd's), so they point
			// at scratch dirs outside the audited root.
			UnitDir:       filepath.Join(base, "systemd"),
			LegacyUnitDir: filepath.Join(base, "legacy-systemd"),
		},
		Resolver: systemd.Resolver{
			Look:       func(name string) (string, error) { return "/fake/bin/" + name, nil },
			Executable: func() (string, error) { return "", errors.New("no executable in test") },
		},
	}, &calls
}

type modeAuditNft struct{ calls *[]string }

func (f modeAuditNft) Run(_ context.Context, stdin, name string, args ...string) (string, string, error) {
	*f.calls = append(*f.calls, name+" "+strings.Join(args, " "))
	return "", "", nil
}

type modeAuditSystemctl struct{ calls *[]string }

func (f modeAuditSystemctl) Run(_ context.Context, name string, args ...string) (string, string, error) {
	*f.calls = append(*f.calls, name+" "+strings.Join(args, " "))
	if len(args) > 0 && args[0] == "is-active" {
		return "active\n", "", nil
	}
	return "", "", nil
}
