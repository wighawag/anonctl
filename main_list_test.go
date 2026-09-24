package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anoncore/ui"
)

// listRunner answers the passwd enumeration `list` reads, plus the per-shim
// lookups, with no real getent.
type listRunner struct{}

func (listRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	if name == "getent" && len(args) >= 2 && args[0] == "passwd" {
		switch args[1] {
		case "anon-shim":
			return "anon-shim:x:412:412::/home/anon-shim:/usr/sbin/nologin\n", "", nil
		case "anon-work-shim":
			return "anon-work-shim:x:413:413::/home/anon-work-shim:/usr/sbin/nologin\n", "", nil
		}
		if len(args) == 1 || args[1] == "" {
			return "", "", nil
		}
		return "", "", errors.New("exit status 2")
	}
	return "", "", nil
}

// swapListSeams points `list` at scratch stores and a scripted passwd table. It
// returns the ledger and marker stores so a test can seed each side independently -
// which is the whole point, since managed-ness and forcing are different questions
// with different sources.
func swapListSeams(t *testing.T) (accountconfig.Store, marker.Store) {
	t.Helper()
	origCfg, origMarker, origPasswd, origStyle := configStore, markerStore, readPasswd, outStyle

	root := filepath.Join(t.TempDir(), "anonctl")
	ledger := accountconfig.Store{RootDir: root, BaseDir: filepath.Join(root, "accounts")}
	markers := marker.Store{BaseDir: root}
	configStore, markerStore, outStyle = ledger, markers, ui.Styler{}
	readPasswd = func(context.Context, provision.Runner) []string {
		return []string{
			"root:x:0:0::/root:/bin/bash",
			"anon:x:8801:8801::/home/anon:/bin/bash",
			"anon-shim:x:412:412::/home/anon-shim:/usr/sbin/nologin",
			"anon-work:x:8802:8802::/home/anon-work:/bin/bash",
			"anon-work-shim:x:413:413::/home/anon-work-shim:/usr/sbin/nologin",
		}
	}
	t.Cleanup(func() {
		configStore, markerStore, readPasswd, outStyle = origCfg, origMarker, origPasswd, origStyle
	})
	return ledger, markers
}

func runListJSON(t *testing.T) listReport {
	t.Helper()
	var code int
	out := captureStdout(t, func() {
		code = runList(context.Background(), listRunner{}, mustParse(t, []string{"list", "--json"}))
	})
	if code != 0 {
		t.Fatalf("list --json exit = %d:\n%s", code, out)
	}
	var rep listReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("list --json must be valid JSON: %v\n%s", err, out)
	}
	return rep
}

func listRow(t *testing.T, rep listReport, account string) provision.AccountListing {
	t.Helper()
	for _, a := range rep.Accounts {
		if a.Account == account {
			return a
		}
	}
	t.Fatalf("no row for %q", account)
	return provision.AccountListing{}
}

// THE REGRESSION TEST. `list --json` used to emit `"forced": false` in every row at
// every privilege level, because nothing on the list path ever computed it. The
// decisive scenario needs no source reading: make the marker UNREADABLE (exactly
// what an unprivileged caller sees), and watch what the row claims.
func TestListNeverClaimsUnforcedFromAnUnreadableMarker(t *testing.T) {
	ledger, markers := swapListSeams(t)
	// A real marker exists AND the account is managed...
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	if err := ledger.Write(accountconfig.Config{
		Account: "anon", AnonUID: 8801, ShimUID: 412,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}
	// ...but this caller cannot read either of them (the unprivileged case).
	if os.Geteuid() == 0 {
		t.Skip("this scenario models an UNPRIVILEGED caller; root can read anything")
	}
	if err := os.Chmod(markers.BaseDir, 0o000); err != nil {
		t.Fatalf("make the config root unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(markers.BaseDir, 0o755) })

	rep := runListJSON(t)
	for _, row := range rep.Accounts {
		if row.Forcing.State != provision.StateUnknown {
			t.Errorf("%s: forcing.state = %q while the marker is UNREADABLE; want %q.\n"+
				"This is the bug: a caller that cannot determine the answer must not report one, "+
				"and reporting 'unforced' for an account that IS forced fails in the unsafe direction.",
				row.Account, row.Forcing.State, provision.StateUnknown)
		}
		if row.Managed != nil {
			t.Errorf("%s: managed = %v while the ledger is UNREADABLE; want null", row.Account, *row.Managed)
		}
	}
}

// The raw bytes matter as much as the decoded struct: a consumer greps them. The
// three bools nothing computed must be GONE, not merely correct-by-accident.
func TestListJSONNoLongerCarriesTheUncomputedBools(t *testing.T) {
	swapListSeams(t)
	out := captureStdout(t, func() {
		runList(context.Background(), listRunner{}, mustParse(t, []string{"list", "--json"}))
	})
	for _, forbidden := range []string{`"forced"`, `"sudoChecked"`, `"sudoAllowed"`} {
		if strings.Contains(out, forbidden) {
			t.Errorf("list --json still emits %s, which nothing on the list path computes:\n%s", forbidden, out)
		}
	}
}

// `list --json` is VERSIONED, so this reshape is a clean versioned change rather
// than a silent break: a consumer can guard on the version before trusting the rest.
func TestListJSONIsVersioned(t *testing.T) {
	swapListSeams(t)
	rep := runListJSON(t)
	if rep.SchemaVersion != listSchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", rep.SchemaVersion, listSchemaVersion)
	}
	if listSchemaVersion < 2 {
		t.Error("the list contract changed shape, so its version must be > 1 (version 1 is the unversioned 0.6.x array)")
	}
}

// MANAGED-NESS: the field a consumer provisioning from this list actually needs.
// On a declarative host every slot exists in passwd from the first converge, so
// passwd existence says nothing about whether anonctl has forced anything.
func TestListReportsManagedSeparatelyFromPasswdExistence(t *testing.T) {
	ledger, _ := swapListSeams(t)
	if err := ledger.Write(accountconfig.Config{
		Account: "anon", AnonUID: 8801, ShimUID: 412,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}

	rep := runListJSON(t)
	managed := listRow(t, rep, "anon")
	if managed.Managed == nil || !*managed.Managed {
		t.Errorf("anon is in the ledger; managed must be true, got %v", managed.Managed)
	}
	declared := listRow(t, rep, "anon-work")
	if !declared.Exists {
		t.Error("anon-work exists in passwd; existence must stay passwd truth")
	}
	if declared.Managed == nil || *declared.Managed {
		t.Errorf("anon-work is a declared slot anonctl never added; managed must be false, got %v", declared.Managed)
	}
}

// The UNION: an account in the ledger with no passwd entry is the drift `verify`'s
// identity precondition catches. `list` is where an operator looks for it.
func TestListShowsALedgerAccountThatHasNoPasswdEntry(t *testing.T) {
	ledger, _ := swapListSeams(t)
	if err := ledger.Write(accountconfig.Config{
		Account: "anon-ghost", AnonUID: 8899, ShimUID: 499,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}

	ghost := listRow(t, runListJSON(t), "anon-ghost")
	if ghost.Exists {
		t.Error("anon-ghost has no passwd entry; exists must be false")
	}
	if ghost.Managed == nil || !*ghost.Managed {
		t.Errorf("anon-ghost is recorded by anonctl; managed must be true, got %v", ghost.Managed)
	}

	// ...and the human output names the condition rather than printing a blank uid.
	out := captureStdout(t, func() {
		runList(context.Background(), listRunner{}, mustParse(t, []string{"list"}))
	})
	if !strings.Contains(out, "NO PASSWD ENTRY") {
		t.Errorf("the human listing must name the missing passwd entry:\n%s", out)
	}
}

// The human listing carries the two tri-states as words, with UNKNOWN visually
// distinct from "no", and explains WHY an answer is missing.
func TestHumanListShowsTriStatesAndExplainsUnknown(t *testing.T) {
	_, markers := swapListSeams(t)
	if err := markers.Write(marker.New("anon", "8801", endpoint.ClassTorShared, "0.7.0", time.Now())); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("models an unprivileged caller")
	}
	// The ledger dir exists but is unreadable: managed is UNKNOWN, forcing is not.
	if err := os.MkdirAll(configStore.BaseDir, 0o000); err != nil {
		t.Fatalf("seed an unreadable ledger: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(configStore.BaseDir, 0o700) })

	out := captureStdout(t, func() {
		runList(context.Background(), listRunner{}, mustParse(t, []string{"list"}))
	})
	if !strings.Contains(out, "MANAGED") || !strings.Contains(out, "FORCING") {
		t.Errorf("the listing must carry the managed and forcing columns:\n%s", out)
	}
	if !strings.Contains(out, "UNKNOWN") {
		t.Errorf("an undetermined managed state must print UNKNOWN, not a blank or a 'no':\n%s", out)
	}
	if !strings.Contains(out, "could not be determined") {
		t.Errorf("the listing must say WHY a column is unknown:\n%s", out)
	}
	if !strings.Contains(out, "forced") {
		t.Errorf("the account with a readable marker must still show its forcing verdict:\n%s", out)
	}
}
