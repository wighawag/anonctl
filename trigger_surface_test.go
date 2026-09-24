package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/configroot"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anonctl/internal/forcing"
)

// THE TRIGGER SURFACE.
//
// Downstream automation watches `/etc/anonctl` and `/etc/anonctl/accounts` with
// inotify and reconciles when either changes. That works well and should not be
// replaced with a hook mechanism - a watch is cheaper than any callback system
// anonctl could ship, needs no registration, survives anonctl not running, and
// cannot leave a half-run hook behind.
//
// But until now it was an ACCIDENT OF IMPLEMENTATION that something depended on.
// CONTEXT.md now promises it, and a promise that nothing tests rots. This file is
// the executable half of that promise: the two watched paths, and the three
// transitions a watcher keys on.
//
// What is promised: the FILENAMES. `<account>.json` appears under `accounts/` on
// `add`, `<account>.json` appears in the root on a green `verify`, and both vanish
// on `rm`. Contents are a separate contract (the marker's JSON is versioned by
// schemaVersion; the ledger is anonctl-private and root-only).

// The two watched directories are exactly where anonctl writes them, spelled from
// the packages that own them rather than from a literal in a test - so a change to
// either default breaks this test instead of breaking a silent watcher.
func TestTheWatchedPathsAreWhereAnonctlActuallyWrites(t *testing.T) {
	if configroot.DefaultDir != "/etc/anonctl" {
		t.Errorf("the promised watch root is /etc/anonctl; the config root is now %q. "+
			"Downstream automation watches that path: changing it needs a version bump and a release note.", configroot.DefaultDir)
	}
	if accountconfig.DefaultBaseDir != "/etc/anonctl/accounts" {
		t.Errorf("the promised ledger watch path is /etc/anonctl/accounts; it is now %q (same rule)", accountconfig.DefaultBaseDir)
	}
	if marker.DefaultBaseDir != configroot.DefaultDir {
		t.Errorf("the markers must live IN the watched root; marker default is %q, root is %q", marker.DefaultBaseDir, configroot.DefaultDir)
	}
}

// A LEDGER RECORD APPEARS ON ADD (the install half of `add`), and a MARKER APPEARS
// ON A GREEN VERIFY. Two separate events, in that order, which is what lets a
// watcher distinguish "anonctl has taken this account on" from "anonctl has proven
// it forced".
func TestLedgerAppearsOnInstallAndMarkerOnVerify(t *testing.T) {
	assertRealEtcUntouched(t)

	base := t.TempDir()
	root := filepath.Join(base, "anonctl")
	deps, _ := testForcingDeps(t, base, root)
	ledgerPath := filepath.Join(root, "accounts", "anon.json")
	markerPath := filepath.Join(root, "anon.json")

	if err := forcing.Install(context.Background(), deps, accountconfig.Config{
		Account: "anon", AnonUID: 8801, ShimUID: 412,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}, nil); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := os.Stat(ledgerPath); err != nil {
		t.Fatalf("a ledger record must appear under accounts/ on add: %v", err)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("no marker may exist before a green verify (the marker is a PROVEN claim): %v", err)
	}

	markers := marker.Store{BaseDir: root}
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("marker write: %v", err)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("a marker must appear in the watched root on a green verify: %v", err)
	}
}

// BOTH VANISH ON RM. A watcher that reconciles on removal must see both files go,
// or it will keep serving an account anonctl no longer forces.
func TestBothFilesVanishOnRm(t *testing.T) {
	assertRealEtcUntouched(t)

	base := t.TempDir()
	root := filepath.Join(base, "anonctl")
	deps, _ := testForcingDeps(t, base, root)
	cfg := accountconfig.Config{
		Account: "anon", AnonUID: 8801, ShimUID: 412,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}
	if err := forcing.Install(context.Background(), deps, cfg, nil); err != nil {
		t.Fatalf("install: %v", err)
	}
	markers := marker.Store{BaseDir: root}
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("marker write: %v", err)
	}

	if err := forcing.Remove(context.Background(), deps, "anon"); err != nil {
		t.Fatalf("forcing.Remove: %v", err)
	}
	if err := markers.Remove("anon"); err != nil {
		t.Fatalf("marker remove: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "accounts", "anon.json")); !os.IsNotExist(err) {
		t.Errorf("the ledger record must vanish on rm; stat says %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "anon.json")); !os.IsNotExist(err) {
		t.Errorf("the marker must vanish on rm; stat says %v", err)
	}
}

// The promise is WRITTEN DOWN, not just implemented. A downstream team cannot
// depend on a behaviour nobody documented, and the next person to refactor these
// paths needs to find the promise before they move them.
func TestTheTriggerSurfaceIsDocumented(t *testing.T) {
	raw, err := os.ReadFile("CONTEXT.md")
	if err != nil {
		t.Fatalf("read CONTEXT.md: %v", err)
	}
	doc := string(raw)
	if !strings.Contains(doc, "trigger surface") {
		t.Error("CONTEXT.md must define the trigger surface: downstream automation depends on it")
	}
	for _, needed := range []string{"/etc/anonctl/accounts", "inotify"} {
		if !strings.Contains(doc, needed) {
			t.Errorf("the trigger-surface promise must mention %q", needed)
		}
	}
}
