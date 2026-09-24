package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/ui"
)

// swapStatusSeams isolates `status` from the real /etc: the ledger it compares the
// box against and the marker store it reads the forced-claim from both point at
// scratch dirs. It also disables the stdout styler, so the assertions read plain
// text regardless of the test host's tty. It returns the ledger so a test can seed
// the recorded uids.
func swapStatusSeams(t *testing.T) accountconfig.Store {
	t.Helper()
	origMarker, origStyle := markerStore, outStyle
	markerStore = marker.Store{BaseDir: t.TempDir()}
	outStyle = ui.Styler{}
	t.Cleanup(func() { markerStore, outStyle = origMarker, origStyle })
	return swapConfigStore(t)
}

// recordUIDs seeds anonctl's ledger with the uids it RECORDED for an account, i.e.
// the uids the installed nft rules and shim unit actually govern.
func recordUIDs(t *testing.T, s accountconfig.Store, account string, uid, shimUID int) {
	t.Helper()
	if err := s.Write(accountconfig.Config{
		Account: account, AnonUID: uid, ShimUID: shimUID,
		EndpointHost: "127.0.0.1", EndpointPort: 9050, EndpointClass: endpoint.ClassTorShared,
	}); err != nil {
		t.Fatalf("seed ledger for %s: %v", account, err)
	}
}

func statusOutput(t *testing.T, r *declaredFakeRunner, args []string) string {
	t.Helper()
	var out string
	out = captureStdout(t, func() {
		if code := runStatus(context.Background(), r, mustParse(t, args)); code != 0 {
			t.Fatalf("status = %d, want 0 (status REPORTS; verify is the non-zero gate)", code)
		}
	})
	return out
}

// THE DELETED ACCOUNT. anonctl records the account as forced, and its passwd entry
// is gone (what a NixOS activation does to an undeclared account at every boot).
// That must read as its own unambiguous finding, naming the uid the orphaned rules
// are left governing - not as the same "not provisioned" line an account that was
// never added prints.
func TestStatusReportsDeletedAccountDistinctly(t *testing.T) {
	disableColorForTest(t)
	s := swapStatusSeams(t)
	recordUIDs(t, s, "anon-01", 8801, 412)

	r := &declaredFakeRunner{uids: map[string]int{}} // both accounts gone from passwd
	out := statusOutput(t, r, []string{"status", "01"})

	if !strings.Contains(out, "ACCOUNT MISSING") {
		t.Errorf("status on a recorded-but-deleted account must say the passwd entry is GONE; got %q", out)
	}
	if strings.Contains(out, "not provisioned") {
		t.Errorf("a deleted account must not read as never-provisioned (they need opposite actions); got %q", out)
	}
	if !strings.Contains(out, "8801") {
		t.Errorf("status must name the uid the orphaned rules still govern; got %q", out)
	}
}

// An account that was simply never added is unchanged: "not provisioned", with no
// alarming deletion wording. This is the other half of the distinction above.
func TestStatusReportsNeverProvisionedAccountAsBefore(t *testing.T) {
	disableColorForTest(t)
	swapStatusSeams(t) // empty ledger: anonctl has no record

	r := &declaredFakeRunner{uids: map[string]int{}}
	out := statusOutput(t, r, []string{"status", "01"})

	if !strings.Contains(out, "not provisioned") {
		t.Errorf("an account with no record and no passwd entry is simply not provisioned; got %q", out)
	}
	if strings.Contains(out, "ACCOUNT MISSING") {
		t.Errorf("an account anonctl never recorded must not be reported as deleted; got %q", out)
	}
}

// THE DRIFTED UID: the account exists, but owns a different uid than the one the
// installed rules govern. It is COMPLETELY UNFORCED while /etc/anonctl still records
// it as jailed, so `status` must say so, naming both uids. This is also the check
// that makes an ADOPTED account safe to live with: it is what catches the declaring
// system moving a uid out from under the forcing.
func TestStatusReportsUIDMismatch(t *testing.T) {
	disableColorForTest(t)
	s := swapStatusSeams(t)
	recordUIDs(t, s, "anon-01", 8801, 412)

	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 1500, "anon-01-shim": 412}}
	out := statusOutput(t, r, []string{"status", "01"})

	if !strings.Contains(out, "UID MISMATCH") {
		t.Errorf("status must report a uid that no longer matches the ledger as its own result; got %q", out)
	}
	for _, uid := range []string{"1500", "8801"} {
		if !strings.Contains(out, uid) {
			t.Errorf("status must name both the live uid and the recorded uid (missing %s); got %q", uid, out)
		}
	}
}

// The shim's uid drifting is its own distinct result: the endpoint-reachability
// exemption names a uid the relay no longer runs as.
func TestStatusReportsShimUIDMismatch(t *testing.T) {
	disableColorForTest(t)
	s := swapStatusSeams(t)
	recordUIDs(t, s, "anon-01", 8801, 412)

	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 8801, "anon-01-shim": 999}}
	out := statusOutput(t, r, []string{"status", "01"})

	if !strings.Contains(out, "SHIM UID MISMATCH") {
		t.Errorf("a drifted SHIM uid must be its own result; got %q", out)
	}
}

// The agreeing case says so positively (the uids the rules govern ARE this
// account's), and the not-yet-adopted case says that instead of implying a uid was
// compared: declared accounts with no anonctl record are exactly what an operator
// sees between `nixos-rebuild switch` and `anonctl add`.
func TestStatusReportsIdentityOKAndUnrecorded(t *testing.T) {
	disableColorForTest(t)
	s := swapStatusSeams(t)
	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 8801, "anon-01-shim": 412}}

	out := statusOutput(t, r, []string{"status", "01"})
	if !strings.Contains(out, "not recorded") {
		t.Errorf("an existing account anonctl has no record for must say so; got %q", out)
	}

	recordUIDs(t, s, "anon-01", 8801, 412)
	out = statusOutput(t, r, []string{"status", "01"})
	if !strings.Contains(out, "identity: ok") {
		t.Errorf("an account whose uids match its record must say so positively; got %q", out)
	}
}

// The --json contract: the identity verdict is machine-readable (a `state` a tool
// can switch on), and the PRE-EXISTING fields stay exactly where they were, so a
// consumer that already parses `status --json` is unaffected.
func TestStatusJSONCarriesIdentityAndKeepsContract(t *testing.T) {
	s := swapStatusSeams(t)
	recordUIDs(t, s, "anon-01", 8801, 412)

	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 1500, "anon-01-shim": 412}}
	out := captureStdout(t, func() {
		if code := runStatus(context.Background(), r, mustParse(t, []string{"status", "01", "--json"})); code != 0 {
			t.Fatalf("status --json = %d, want 0", code)
		}
	})

	var got struct {
		Account  string `json:"account"`
		Exists   bool   `json:"exists"`
		UID      string `json:"uid"`
		Identity struct {
			State       string `json:"state"`
			Ok          bool   `json:"ok"`
			Detail      string `json:"detail"`
			RecordedUID int    `json:"recordedUid"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("status --json emitted unparseable JSON (%v): %q", err, out)
	}
	if got.Account != "anon-01" || !got.Exists || got.UID != "1500" {
		t.Errorf("the pre-existing account fields must be unchanged; got %+v", got)
	}
	if got.Identity.State != "uid-mismatch" || got.Identity.Ok {
		t.Errorf("identity = %+v, want state uid-mismatch and ok=false", got.Identity)
	}
	if got.Identity.RecordedUID != 8801 {
		t.Errorf("identity.recordedUid = %d, want 8801 (both sides of the comparison must be machine-readable)", got.Identity.RecordedUID)
	}
	if got.Identity.Detail == "" {
		t.Errorf("identity.detail must carry the evidence line; got %+v", got.Identity)
	}
}

// THE FALSE GREEN THIS MUST NOT PRODUCE. The ledger is root-only, and `status` is
// documented as a read-only verb that needs no privilege, so an unprivileged run
// gets a PERMISSION ERROR reading the record, not a clean absence. Reporting that as
// "not recorded" would print a passing identity line for an account whose uid may
// have drifted out from under the forcing, which is precisely the condition this
// check exists to surface. It must report UNKNOWN, and `--json` must say ok=false.
func TestStatusReportsUnreadableRecordAsUnknownNotUnrecorded(t *testing.T) {
	disableColorForTest(t)
	s := swapStatusSeams(t)
	recordUIDs(t, s, "anon-01", 8801, 412)
	path, err := s.Path("anon-01")
	if err != nil {
		t.Fatalf("store.Path: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 1500, "anon-01-shim": 412}}
	out := statusOutput(t, r, []string{"status", "01"})
	if strings.Contains(out, "not recorded") || strings.Contains(out, "identity: ok") {
		t.Errorf("an unreadable record must NEVER read as 'no record' or 'ok' (that is a green line for a possibly-unforced account); got %q", out)
	}
	// Assert on the IDENTITY line specifically: `status` prints an unrelated
	// `sudo: UNKNOWN` on every run, so a bare "UNKNOWN" match would pass even with the
	// identity case deleted.
	if !strings.Contains(out, "identity: UNKNOWN") {
		t.Errorf("an unreadable record must be reported as an UNKNOWN identity; got %q", out)
	}
	if !strings.Contains(out, "could NOT be read") {
		t.Errorf("the identity line must carry the evidence, not just the verdict; got %q", out)
	}

	jsonOut := captureStdout(t, func() {
		runStatus(context.Background(), r, mustParse(t, []string{"status", "01", "--json"}))
	})
	var got struct {
		Identity struct {
			State       string `json:"state"`
			Ok          bool   `json:"ok"`
			RecordError string `json:"recordError"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil {
		t.Fatalf("unparseable JSON (%v): %q", err, jsonOut)
	}
	if got.Identity.State != "record-unreadable" || got.Identity.Ok {
		t.Errorf("identity = %+v, want state record-unreadable and ok=false (a script gating on ok must not be told green)", got.Identity)
	}
	if got.Identity.RecordError == "" {
		t.Errorf("the underlying read error must be surfaced, not just summarised; got %+v", got.Identity)
	}
}

// A shim account with no login account is half a pair, which `add` refuses. `status`
// is the cheap diagnostic run first, so it must name what `add` will object to
// rather than report a bare "not provisioned" and let the operator find out from a
// refusal.
func TestStatusNamesAStrayShimAccount(t *testing.T) {
	disableColorForTest(t)
	swapStatusSeams(t)
	r := &declaredFakeRunner{uids: map[string]int{"anon-01-shim": 412}}
	out := statusOutput(t, r, []string{"status", "01"})
	if !strings.Contains(out, "anon-01-shim") {
		t.Errorf("status must name the stray shim account; got %q", out)
	}
	if !strings.Contains(out, "half a pair") {
		t.Errorf("status must say this is the shape `add` refuses; got %q", out)
	}
}

// THE HEADLINE SCENARIO, UNPRIVILEGED. Activation deleted both accounts, and the
// operator runs `status` without root, so the record cannot be read. anonctl then
// cannot tell "never added" from "deleted while its forcing is still loaded", and it
// must NOT report the harmless one: a calm "not provisioned" here is a false
// reassurance about a host that may still have nft tables governing a freed uid.
func TestStatusDoesNotCallAMissingAccountNotProvisionedWhenTheRecordIsUnreadable(t *testing.T) {
	disableColorForTest(t)
	s := swapStatusSeams(t)
	recordUIDs(t, s, "anon-01", 8801, 412)
	path, err := s.Path("anon-01")
	if err != nil {
		t.Fatalf("store.Path: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &declaredFakeRunner{uids: map[string]int{}} // both accounts gone
	out := statusOutput(t, r, []string{"status", "01"})
	if strings.Contains(out, "not provisioned") {
		t.Errorf("a missing account whose record could not be read must NOT read as never-provisioned; got %q", out)
	}
	if !strings.Contains(out, "UNKNOWN") {
		t.Errorf("it must be reported as UNKNOWN; got %q", out)
	}
	if !strings.Contains(out, "root") {
		t.Errorf("it should name the usual cause (a root-only record read without privilege); got %q", out)
	}

	jsonOut := captureStdout(t, func() {
		runStatus(context.Background(), r, mustParse(t, []string{"status", "01", "--json"}))
	})
	var got struct {
		Identity struct {
			State string `json:"state"`
			Ok    bool   `json:"ok"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &got); err != nil {
		t.Fatalf("unparseable JSON (%v): %q", err, jsonOut)
	}
	if got.Identity.Ok {
		t.Errorf("identity = %+v, want ok=false", got.Identity)
	}
}

// `status --json` carries a SCHEMA VERSION. verify, the marker and the account
// config all had one; the two documents a sibling tool actually parses (`status`
// and `list`) did not, which is what made the `list` reshape impossible to announce
// cleanly. Adding it here is purely ADDITIVE: every existing field name is
// unchanged, so a consumer pinned to the old shape is unaffected and gains a
// version to guard on.
func TestStatusJSONIsVersionedAdditively(t *testing.T) {
	swapStatusSeams(t)
	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 1500, "anon-01-shim": 412}}
	out := captureStdout(t, func() {
		if code := runStatus(context.Background(), r, mustParse(t, []string{"status", "01", "--json"})); code != 0 {
			t.Fatalf("status --json != 0")
		}
	})

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unparseable: %v\n%s", err, out)
	}
	v, ok := got["schemaVersion"]
	if !ok {
		t.Fatalf("status --json must carry a schemaVersion:\n%s", out)
	}
	if int(v.(float64)) != statusSchemaVersion {
		t.Errorf("schemaVersion = %v, want %d", v, statusSchemaVersion)
	}
	// The additive promise: the fields a consumer already reads are all still there.
	for _, key := range []string{"account", "shim", "exists", "shimExists", "uid", "forced", "sudoChecked", "sudoAllowed", "identity"} {
		if _, ok := got[key]; !ok {
			t.Errorf("status --json dropped the pre-existing field %q; this change must be ADDITIVE:\n%s", key, out)
		}
	}
}
