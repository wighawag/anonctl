package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anoncore/ui"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/probe"
)

// probeRunner is a provision.Runner that reports a fixed account/uid from the
// passwd side, so `probe` can be dispatched end to end with no real getent.
type probeRunner struct {
	account string
	uid     string
}

func (p probeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	if name == "getent" && len(args) >= 2 && args[0] == "passwd" {
		switch args[1] {
		case p.account:
			return p.account + ":x:" + p.uid + ":" + p.uid + "::/home/" + p.account + ":/bin/bash\n", "", nil
		case p.account + "-shim":
			return p.account + "-shim:x:412:412::/home/shim:/usr/sbin/nologin\n", "", nil
		}
		return "", "", errors.New("exit status 2")
	}
	// The sudo probe: a clean "no rights" answer.
	return "", "User " + p.account + " is not allowed to run sudo on host.\n", nil
}

// swapProbeSeams isolates `probe` from the real box: a scratch marker store, a
// scripted `nft list table`, a pinned boot id, and plain (unstyled) output.
func swapProbeSeams(t *testing.T, ruleset string, rulesetErr error, bootID string) marker.Store {
	t.Helper()
	return swapProbeSeamsFull(t, ruleset, false, rulesetErr, bootID)
}

// swapProbeSeamsFull is swapProbeSeams with the tableAbsent classification too, so a
// test can stage the three DISTINCT ruleset outcomes production produces: readable
// and loaded, readable and the table is not there, and could not read at all.
func swapProbeSeamsFull(t *testing.T, ruleset string, tableAbsent bool, rulesetErr error, bootID string) marker.Store {
	t.Helper()
	origMarker, origNft, origBoot, origStyle := markerStore, probeNftRun, probeBootID, outStyle
	store := marker.Store{BaseDir: t.TempDir()}
	markerStore = store
	probeNftRun = func(context.Context, string) (string, bool, error) { return ruleset, tableAbsent, rulesetErr }
	probeBootID = func() (string, error) { return bootID, nil }
	outStyle = ui.Styler{}
	t.Cleanup(func() {
		markerStore, probeNftRun, probeBootID, outStyle = origMarker, origNft, origBoot, origStyle
	})
	return store
}

const (
	probeBoot = "9e8d05ee-29bc-418c-9565-d7b8964c87ca"
	probeUID  = 8802
)

// loadedRuleset is what `nft list table inet anonctl_anon_work` prints for a
// correctly-forced account: it contains the governing jump for the anon uid.
func loadedRuleset(uid int) string {
	return "table inet " + nftables.TableName("anon-work") + " {\n" +
		"\tchain filter_out {\n\t\t" + nftables.GoverningRule(uid) + "\n\t}\n}"
}

func seedMarker(t *testing.T, store marker.Store, uid, bootID string) {
	t.Helper()
	m := marker.New("anon-work", uid, endpoint.ClassTorShared, "0.7.0", time.Now())
	if bootID != "" {
		m = m.WithBootID(bootID)
	}
	if err := store.Write(m); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
}

// `probe` EXITS ZERO only when the account is actually jailed.
func TestProbeExitsZeroWhenJailed(t *testing.T) {
	store := swapProbeSeams(t, loadedRuleset(probeUID), nil, probeBoot)
	seedMarker(t, store, "8802", probeBoot)

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "8802"},
			mustParse(t, []string{"probe", "work"}))
	})
	if code != 0 {
		t.Fatalf("probe exit = %d, want 0 for a jailed account.\n%s", code, out)
	}
	if !strings.Contains(out, "JAILED") {
		t.Errorf("probe output should say JAILED:\n%s", out)
	}
}

// THE CONTRACT THAT MATTERS FOR AUTOMATION: a non-zero exit when the account is
// NOT jailed. A consumer gating a live web interface on this must not have to parse
// anything to find out.
func TestProbeExitsNonZeroWhenTheRulesAreGone(t *testing.T) {
	// THE POST-REBOOT FAILURE, as a ROOT operator actually meets it: the marker is
	// green, the loader never ran, so the table is simply not there. `nft list table`
	// exits non-zero for that just as it does for a permission failure, and the
	// gatherer classifies it by privilege - so the reason here must be the DETERMINED
	// table-missing, never "could not read; re-run as root", which would be the wrong
	// instruction for the one failure this verb exists to catch.
	store := swapProbeSeamsFull(t, "", true, nil, probeBoot)
	seedMarker(t, store, "8802", probeBoot)

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "8802"},
			mustParse(t, []string{"probe", "work"}))
	})
	if code == 0 {
		t.Fatalf("probe exit = 0 while the nft table could not be read; it must be non-zero.\n%s", out)
	}
	if !strings.Contains(out, "NOT JAILED") || !strings.Contains(out, probe.ReasonTableMissing) {
		t.Errorf("probe output must say NOT JAILED and name table-missing:\n%s", out)
	}
	if strings.Contains(out, "re-run as root") {
		t.Errorf("a root operator whose loader failed must not be told to re-run as root:\n%s", out)
	}
}

// ...and the UNDETERMINED case stays undetermined: a caller who could not read the
// ruleset at all gets rules-unreadable, which is a different operator action.
func TestProbeReportsAnUnreadableRulesetAsUndetermined(t *testing.T) {
	store := swapProbeSeamsFull(t, "", false, errors.New("Operation not permitted (you must be root)"), probeBoot)
	seedMarker(t, store, "8802", probeBoot)

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "8802"},
			mustParse(t, []string{"probe", "work"}))
	})
	if code == 0 {
		t.Fatalf("an unreadable ruleset must not exit 0.\n%s", out)
	}
	if !strings.Contains(out, probe.ReasonRulesUnreadable) {
		t.Errorf("output must name rules-unreadable, not a determined negative:\n%s", out)
	}
}

// An account with NO marker is not jailed, and says so with the determined reason.
func TestProbeWithNoMarkerIsNotJailed(t *testing.T) {
	swapProbeSeams(t, loadedRuleset(probeUID), nil, probeBoot)

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "8802"},
			mustParse(t, []string{"probe", "work"}))
	})
	if code == 0 {
		t.Fatalf("an account with no marker must not exit 0.\n%s", out)
	}
	if !strings.Contains(out, probe.ReasonNoMarker) {
		t.Errorf("output must name the no-marker reason:\n%s", out)
	}
}

// `probe --json` emits the versioned document, with the jailed verdict and the
// named reasons a consumer switches on.
func TestProbeJSONIsVersionedAndNamesItsReasons(t *testing.T) {
	store := swapProbeSeamsFull(t, "", true, nil, probeBoot) // table absent
	seedMarker(t, store, "8802", probeBoot)

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "8802"},
			mustParse(t, []string{"probe", "work", "--json"}))
	})
	if code == 0 {
		t.Error("a missing table must still exit non-zero with --json")
	}
	var rep probe.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("probe --json must emit valid JSON: %v\n%s", err, out)
	}
	if rep.SchemaVersion != probe.SchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", rep.SchemaVersion, probe.SchemaVersion)
	}
	if rep.Jailed {
		t.Error("jailed must be false when the table is not loaded")
	}
	if rep.FirstFailure() != probe.ReasonTableMissing {
		t.Errorf("first failure = %q, want %q", rep.FirstFailure(), probe.ReasonTableMissing)
	}
}

// UID DRIFT end to end: the account exists under a NEW uid, the marker and the
// loaded rules still refer to the old one. This is the condition that leaves an
// account completely unforced while everything durable reads green.
func TestProbeCatchesUIDDriftEndToEnd(t *testing.T) {
	// Rules still govern the OLD uid 8802; the account now has 9001.
	store := swapProbeSeams(t, loadedRuleset(8802), nil, probeBoot)
	seedMarker(t, store, "8802", probeBoot)

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "9001"},
			mustParse(t, []string{"probe", "work"}))
	})
	if code == 0 {
		t.Fatalf("uid drift must not exit 0.\n%s", out)
	}
	if !strings.Contains(out, probe.ReasonUIDDrift) {
		t.Errorf("output must name uid-drift:\n%s", out)
	}
	if !strings.Contains(out, probe.ReasonUIDNotGoverned) {
		t.Errorf("the rules check must ALSO report that the live uid is not governed (every check runs):\n%s", out)
	}
}

// A marker written in an EARLIER boot: still jailed (the rules are loaded now), but
// the report says nothing has re-proven it since the machine came up.
func TestProbeDistinguishesThisBootFromAnEarlierBoot(t *testing.T) {
	store := swapProbeSeams(t, loadedRuleset(probeUID), nil, probeBoot)
	seedMarker(t, store, "8802", "11111111-2222-3333-4444-555555555555")

	var code int
	out := captureStdout(t, func() {
		code = runProbe(context.Background(), probeRunner{account: "anon-work", uid: "8802"},
			mustParse(t, []string{"probe", "work"}))
	})
	if code != 0 {
		t.Fatalf("an earlier-boot marker with rules loaded now is still jailed; exit = %d\n%s", code, out)
	}
	if !strings.Contains(out, "EARLIER boot") {
		t.Errorf("the report must flag that the proof predates this boot:\n%s", out)
	}
}

// `probe` is dispatched by run() and is NOT a root-elevating verb: an unattended
// consumer calling it on every trigger must never get a sudo password prompt.
func TestProbeIsDispatchedAndNeverSelfElevates(t *testing.T) {
	if rootRequiringVerbs["probe"] {
		t.Error("probe must not self-elevate: it is built for unattended callers on every trigger")
	}
	swapProbeSeamsFull(t, "", false, errors.New("must be root"), probeBoot)
	code := 0
	captureStdout(t, func() { code = run([]string{"probe", "nosuchaccount"}) })
	if code == 0 {
		t.Error("probe on an unknown account must exit non-zero")
	}
}

// A compile-time guard that the probe report's uid fields line up with what
// provision.Status produces (both are strings; a silent type change here would make
// every uid comparison trivially unequal).
var _ = func() provision.AccountStatus { return provision.AccountStatus{UID: ""} }
