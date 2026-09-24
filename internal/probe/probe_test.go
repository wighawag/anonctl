package probe_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/probe"
)

const (
	testAccount = "anon-work"
	testUID     = "8802"
	testUIDNum  = 8802
)

// jailedInput is the everything-agrees case: marker present, uids equal, table
// loaded with the governing rule. Each test below breaks exactly ONE thing, so a
// failure is attributable to that thing.
func jailedInput() probe.Input {
	m := marker.Marker{
		SchemaVersion:  marker.SchemaVersion,
		Account:        testAccount,
		UID:            testUID,
		EndpointClass:  endpoint.ClassTorShared,
		CreatedAt:      "2026-09-24T10:00:00Z",
		AnonctlVersion: "0.7.0",
		BootID:         "9e8d05ee-29bc-418c-9565-d7b8964c87ca",
	}
	table := nftables.TableName(testAccount)
	return probe.Input{
		Account:       testAccount,
		AccountExists: true,
		LiveUID:       testUID,
		Marker:        &m,
		TableName:     table,
		GoverningRule: nftables.GoverningRule(testUIDNum),
		Ruleset: "table inet " + table + " {\n" +
			"\tchain filter_out {\n" +
			"\t\ttype filter hook output priority filter; policy accept;\n" +
			"\t\tmeta skuid 412 jump shim_filter\n" +
			"\t\t" + nftables.GoverningRule(testUIDNum) + "\n" +
			"\t}\n}",
		CurrentBootID: "9e8d05ee-29bc-418c-9565-d7b8964c87ca",
	}
}

func checkNamed(t *testing.T, rep probe.Report, name string) probe.Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %v", name, rep.Checks)
	return probe.Check{}
}

// The happy path: all three checks pass and the verdict is jailed.
func TestJailedWhenMarkerUIDAndRulesAllAgree(t *testing.T) {
	rep := probe.Decide(jailedInput())
	if !rep.Jailed {
		t.Fatalf("want jailed; got %+v", rep.Checks)
	}
	for _, c := range rep.Checks {
		if !c.Ok {
			t.Errorf("check %q failed unexpectedly: %s (%s)", c.Name, c.Reason, c.Detail)
		}
	}
	if rep.FirstFailure() != "" {
		t.Errorf("a jailed report must name no failure; got %q", rep.FirstFailure())
	}
	if rep.Boot.State != probe.BootThisBoot {
		t.Errorf("boot state = %q; want %q", rep.Boot.State, probe.BootThisBoot)
	}
}

// THE CASE THAT MOTIVATES THE VERB. A marker survives a reboot; the rules do not.
// If the early-boot loader failed, the account is completely unforced and every
// durable record still reads green. The marker-only check every integrator writes
// first says "jailed" here; probe must not.
func TestNotJailedWhenTheRulesAreNotLoadedButTheMarkerIsGreen(t *testing.T) {
	in := jailedInput()
	in.Ruleset = ""
	in.RulesetErr = errors.New("Error: No such file or directory")

	rep := probe.Decide(in)
	if rep.Jailed {
		t.Fatal("an account whose nft table could not be read must never be reported jailed")
	}
	// The marker check still PASSES (the claim really is there) - which is precisely
	// why a marker-only consumer gets this wrong.
	if !checkNamed(t, rep, probe.CheckMarkerPresent).Ok {
		t.Errorf("the marker really is present; that check should pass")
	}
	rules := checkNamed(t, rep, probe.CheckRulesLoaded)
	if rules.Reason != probe.ReasonRulesUnreadable {
		t.Errorf("reason = %q, want %q", rules.Reason, probe.ReasonRulesUnreadable)
	}
}

// A table that is genuinely absent (readable ruleset, no table) is TABLE-MISSING,
// distinct from "we could not look".
func TestTableMissingIsDistinctFromUnreadable(t *testing.T) {
	in := jailedInput()
	in.Ruleset = ""
	in.RulesetErr = nil

	rep := probe.Decide(in)
	if rep.Jailed {
		t.Fatal("no table means not jailed")
	}
	if got := checkNamed(t, rep, probe.CheckRulesLoaded).Reason; got != probe.ReasonTableMissing {
		t.Errorf("reason = %q, want %q", got, probe.ReasonTableMissing)
	}
}

// A table that IS loaded but does not funnel this uid into the closure chain is the
// subtle one a bare `grep skuid` would miss if the uid changed: the table exists and
// mentions other uids, so "the table is there" is not the question.
func TestLoadedTableThatDoesNotGovernThisUID(t *testing.T) {
	in := jailedInput()
	in.Ruleset = "table inet " + in.TableName + " {\n\tchain filter_out {\n\t\tmeta skuid 412 jump shim_filter\n\t}\n}"

	rep := probe.Decide(in)
	if rep.Jailed {
		t.Fatal("a table that does not govern this uid is not a jailed account")
	}
	if got := checkNamed(t, rep, probe.CheckRulesLoaded).Reason; got != probe.ReasonUIDNotGoverned {
		t.Errorf("reason = %q, want %q", got, probe.ReasonUIDNotGoverned)
	}
}

// UID DRIFT: the account was deleted and recreated (the NixOS activation case), so
// the loaded rules govern a uid this account no longer has. Everything durable
// still says jailed; probe must say otherwise, and must name the drift.
func TestUIDDriftIsNotJailed(t *testing.T) {
	in := jailedInput()
	in.LiveUID = "9001" // recreated under a new uid; the marker still says 8802
	in.GoverningRule = nftables.GoverningRule(9001)

	rep := probe.Decide(in)
	if rep.Jailed {
		t.Fatal("a uid that no longer matches the marker must not report jailed")
	}
	uid := checkNamed(t, rep, probe.CheckUIDAgreement)
	if uid.Reason != probe.ReasonUIDDrift {
		t.Errorf("reason = %q, want %q", uid.Reason, probe.ReasonUIDDrift)
	}
	if !strings.Contains(uid.Detail, "8802") || !strings.Contains(uid.Detail, "9001") {
		t.Errorf("the drift evidence must show BOTH uids; got %q", uid.Detail)
	}
	if rep.UID != "9001" || rep.MarkerUID != "8802" {
		t.Errorf("the report must carry both sides of the comparison; got uid=%q markerUid=%q", rep.UID, rep.MarkerUID)
	}
}

// An account with no passwd entry at all: the rules may still be loaded, governing
// a uid that is now free. Named as its own reason.
func TestAccountMissingIsItsOwnReason(t *testing.T) {
	in := jailedInput()
	in.AccountExists = false
	in.LiveUID = ""

	rep := probe.Decide(in)
	if rep.Jailed {
		t.Fatal("an account with no passwd entry cannot be jailed")
	}
	if got := checkNamed(t, rep, probe.CheckUIDAgreement).Reason; got != probe.ReasonAccountMissing {
		t.Errorf("reason = %q, want %q", got, probe.ReasonAccountMissing)
	}
}

// No marker is a DETERMINED negative, and distinct from an unreadable one. An
// unprivileged caller who cannot read the marker must not be told "not forced".
func TestMissingMarkerAndUnreadableMarkerAreDifferentReasons(t *testing.T) {
	absent := jailedInput()
	absent.Marker = nil
	absent.MarkerErr = marker.ErrNotFound
	if got := checkNamed(t, probe.Decide(absent), probe.CheckMarkerPresent).Reason; got != probe.ReasonNoMarker {
		t.Errorf("an ABSENT marker: reason = %q, want %q", got, probe.ReasonNoMarker)
	}

	denied := jailedInput()
	denied.Marker = nil
	denied.MarkerErr = fmt.Errorf("read marker: %w", os.ErrPermission)
	rep := probe.Decide(denied)
	if got := checkNamed(t, rep, probe.CheckMarkerPresent).Reason; got != probe.ReasonMarkerUnreadable {
		t.Errorf("an UNREADABLE marker: reason = %q, want %q", got, probe.ReasonMarkerUnreadable)
	}
	if rep.Jailed {
		t.Error("an undetermined marker must never produce a jailed verdict")
	}
}

// EVERY check runs: a report with two problems shows both, so an operator fixes the
// account once instead of discovering the second failure after the first.
func TestAllChecksRunSoTheReportIsComplete(t *testing.T) {
	in := jailedInput()
	in.Marker = nil
	in.MarkerErr = marker.ErrNotFound
	in.Ruleset = ""

	rep := probe.Decide(in)
	if len(rep.Checks) != 3 {
		t.Fatalf("want all 3 checks reported, got %d", len(rep.Checks))
	}
	failed := 0
	for _, c := range rep.Checks {
		if !c.Ok {
			failed++
		}
		if !c.Ok && c.Reason == "" {
			t.Errorf("check %q failed with no named reason", c.Name)
		}
		if c.Detail == "" {
			t.Errorf("check %q carries no evidence line", c.Name)
		}
	}
	if failed != 3 {
		t.Errorf("want all 3 checks failing (no short-circuit), got %d", failed)
	}
}

// THE BOOT DISTINCTION. A marker written in an EARLIER boot is reported as such,
// and it does NOT change the jailed verdict: the rules are checked live, so an
// account whose rules are loaded IS jailed now. What it tells a consumer is that
// nothing has re-PROVEN the path since the machine came up.
func TestEarlierBootIsReportedButDoesNotChangeTheVerdict(t *testing.T) {
	in := jailedInput()
	in.CurrentBootID = "11111111-2222-3333-4444-555555555555"

	rep := probe.Decide(in)
	if !rep.Jailed {
		t.Error("an earlier-boot marker with rules loaded now IS jailed now; the boot id is informational")
	}
	if rep.Boot.State != probe.BootEarlierBoot {
		t.Errorf("boot state = %q, want %q", rep.Boot.State, probe.BootEarlierBoot)
	}
	if rep.Boot.CurrentBootID == "" || rep.Boot.MarkerBootID == "" {
		t.Errorf("the boot report must carry both ids: %+v", rep.Boot)
	}
}

// A marker written by an OLDER anonctl has no boot id. That is UNKNOWN, never a
// mismatch, and it must not flip an otherwise-green account.
func TestAMarkerWithNoBootIDIsUnknownNotAMismatch(t *testing.T) {
	in := jailedInput()
	m := *in.Marker
	m.BootID = ""
	in.Marker = &m

	rep := probe.Decide(in)
	if rep.Boot.State != probe.BootUnknown {
		t.Errorf("boot state = %q, want %q", rep.Boot.State, probe.BootUnknown)
	}
	if !rep.Jailed {
		t.Error("a missing boot id is additive; it must not change the jailed verdict")
	}
}

// The JSON contract: a version to guard on, a single boolean to gate on, and a
// named reason per failing check.
func TestJSONContract(t *testing.T) {
	in := jailedInput()
	in.Ruleset = ""
	raw, err := json.Marshal(probe.Decide(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		SchemaVersion int    `json:"schemaVersion"`
		Account       string `json:"account"`
		Jailed        bool   `json:"jailed"`
		Checks        []struct {
			Name   string `json:"name"`
			Ok     bool   `json:"ok"`
			Reason string `json:"reason"`
		} `json:"checks"`
		Boot struct {
			State string `json:"state"`
		} `json:"boot"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.SchemaVersion != probe.SchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", doc.SchemaVersion, probe.SchemaVersion)
	}
	if doc.Account != testAccount || doc.Jailed {
		t.Errorf("account/jailed wrong: %s / %v", doc.Account, doc.Jailed)
	}
	if len(doc.Checks) != 3 {
		t.Fatalf("want 3 checks in the JSON, got %d", len(doc.Checks))
	}
	if doc.Boot.State == "" {
		t.Error("the boot state must always be present (unknown is a value, not an omission)")
	}
}

// An UNREADABLE marker must not make the uid check report "no-marker" either. The
// uid check has no recorded uid to compare against in BOTH cases, but the reasons
// an operator acts on are different: one means "this account has no claim", the
// other means "you could not look" (and is usually just a missing sudo).
func TestUnreadableMarkerDoesNotReadAsNoMarkerInTheUIDCheck(t *testing.T) {
	in := jailedInput()
	in.Marker = nil
	in.MarkerErr = fmt.Errorf("read marker: %w", os.ErrPermission)

	uid := checkNamed(t, probe.Decide(in), probe.CheckUIDAgreement)
	if uid.Reason != probe.ReasonMarkerUnreadable {
		t.Errorf("reason = %q, want %q (an unreadable marker is not an absent one)", uid.Reason, probe.ReasonMarkerUnreadable)
	}

	// ...while a genuinely ABSENT marker still reports no-marker there.
	in.MarkerErr = marker.ErrNotFound
	if got := checkNamed(t, probe.Decide(in), probe.CheckUIDAgreement).Reason; got != probe.ReasonNoMarker {
		t.Errorf("an absent marker: reason = %q, want %q", got, probe.ReasonNoMarker)
	}
}

// THE EMPTY-GOVERNING-RULE GUARD. `strings.Contains(x, "")` is unconditionally
// TRUE, so without an explicit guard an empty governing rule would report the
// rules-loaded check OK - a green verdict from a rule that was never looked for.
// The path that produces one is real: the caller only builds a governing rule when
// the account has a live uid, so an account with no passwd entry has none.
//
// It must be UNDETERMINED (rules-unreadable), not the determined uid-not-governed:
// nothing was established about the ruleset either way.
func TestAnEmptyGoverningRuleIsUndeterminedNotOk(t *testing.T) {
	in := jailedInput()
	in.GoverningRule = ""

	rep := probe.Decide(in)
	rules := checkNamed(t, rep, probe.CheckRulesLoaded)
	if rules.Ok {
		t.Fatal("an EMPTY governing rule must never report the rules check OK " +
			"(strings.Contains(x, \"\") is always true; the guard against that is load-bearing)")
	}
	if rules.Reason != probe.ReasonRulesUnreadable {
		t.Errorf("reason = %q, want %q (nothing was established about the ruleset)", rules.Reason, probe.ReasonRulesUnreadable)
	}
	if rep.Jailed {
		t.Error("jailed must be false when the governing rule could not be built")
	}
}

// The three ruleset outcomes are kept apart, and only the middle one is a
// DETERMINED negative.
func TestTheThreeRulesetOutcomesAreDistinct(t *testing.T) {
	cases := []struct {
		name       string
		ruleset    string
		absent     bool
		err        error
		wantReason string
	}{
		{"could not read at all", "", false, errors.New("Operation not permitted"), probe.ReasonRulesUnreadable},
		{"read fine, table not loaded", "", true, nil, probe.ReasonTableMissing},
		{"loaded but not governing this uid", "table inet x {\n\tchain filter_out {\n\t\tmeta skuid 412 jump shim_filter\n\t}\n}", false, nil, probe.ReasonUIDNotGoverned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := jailedInput()
			in.Ruleset, in.TableAbsent, in.RulesetErr = tc.ruleset, tc.absent, tc.err
			rules := checkNamed(t, probe.Decide(in), probe.CheckRulesLoaded)
			if rules.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", rules.Reason, tc.wantReason)
			}
		})
	}
}
