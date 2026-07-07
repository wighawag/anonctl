package provision_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/provision"
)

// fakeRunner is the unit-test seam standing in for the real ExecRunner: it
// records every command the provisioning issues and answers the `getent passwd`
// existence probes from a scripted set of already-present accounts, so the whole
// add/rm/list/status wiring is exercised WITHOUT creating a real Unix user
// (mirrors netcage's recordRunner). No useradd/userdel ever hits the box.
type fakeRunner struct {
	calls   [][]string
	present map[string]bool // accounts getent should report as existing
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	// getent passwd <name>: report presence from the scripted set. A missing entry
	// is getent's exit-2 (an error with empty stdout), same as the real tool.
	if name == "getent" && len(args) >= 2 && args[0] == "passwd" {
		acct := args[1]
		if r.present != nil && r.present[acct] {
			return acct + ":x:30034:30034::/home/" + acct + ":/bin/bash", "", nil
		}
		return "", "", &exitErr{code: 2}
	}
	// useradd/userdel: pretend success, and reflect the mutation in `present` so a
	// re-run sees the account as existing (idempotency is testable).
	if name == "useradd" {
		if r.present == nil {
			r.present = map[string]bool{}
		}
		r.present[args[len(args)-1]] = true
	}
	if name == "userdel" {
		delete(r.present, args[len(args)-1])
	}
	return "", "", nil
}

type exitErr struct{ code int }

func (e *exitErr) Error() string { return "exit status" }
func (e *exitErr) ExitCode() int { return e.code }

func joined(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}

// add on a fresh box provisions BOTH the anon login account AND a distinct
// dedicated shim service account, via the injected Runner (no real useradd).
func TestAddProvisionsAccountAndShim(t *testing.T) {
	r := &fakeRunner{}
	res, err := provision.Add(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Add error: %v", err)
	}
	if res.Created != true {
		t.Errorf("Created = %v, want true on a fresh account", res.Created)
	}
	out := joined(r.calls)
	// the login account
	if !strings.Contains(out, "useradd") || !strings.Contains(out, "anon") {
		t.Errorf("expected a useradd for anon, got:\n%s", out)
	}
	// the DISTINCT dedicated shim service account (own UID)
	if !strings.Contains(out, "anon-shim") {
		t.Errorf("expected a distinct shim account anon-shim, got:\n%s", out)
	}
	// the shim must be a --system service account with a nologin shell (it never
	// logs in; it only runs the shim and dials the endpoint).
	if !strings.Contains(out, "--system") || !strings.Contains(out, "nologin") {
		t.Errorf("shim account must be --system + nologin, got:\n%s", out)
	}
}

// add is IDEMPOTENT: re-running it on an already-provisioned account is a clean
// no-op (no second useradd), not an error.
func TestAddIdempotent(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Add(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Add (existing) error: %v", err)
	}
	if res.Created {
		t.Errorf("Created = true, want false: re-add on an existing account is a no-op")
	}
	if strings.Contains(joined(r.calls), "useradd") {
		t.Errorf("re-add must NOT call useradd again, got:\n%s", joined(r.calls))
	}
}

// A named account provisions anon-<name> and its OWN shim anon-<name>-shim.
func TestAddNamed(t *testing.T) {
	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon-work"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	out := joined(r.calls)
	if !strings.Contains(out, "anon-work-shim") {
		t.Errorf("named account must get its own anon-work-shim, got:\n%s", out)
	}
}

// bare rm removes forcing hooks only (a no-op until the nft/persistence tasks
// land) and NEVER calls userdel: the account's home stays intact.
func TestRmLeavesAccountIntact(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Rm(context.Background(), r, "anon", false /* purgeAccount */)
	if err != nil {
		t.Fatalf("Rm error: %v", err)
	}
	if res.AccountRemoved {
		t.Errorf("AccountRemoved = true on a bare rm, want false")
	}
	if strings.Contains(joined(r.calls), "userdel") {
		t.Errorf("bare rm must NOT call userdel, got:\n%s", joined(r.calls))
	}
}

// rm --purge-account (the explicit opt-in) removes the account AND its shim.
func TestRmPurgeAccount(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	res, err := provision.Rm(context.Background(), r, "anon", true /* purgeAccount */)
	if err != nil {
		t.Fatalf("Rm --purge-account error: %v", err)
	}
	if !res.AccountRemoved {
		t.Errorf("AccountRemoved = false, want true under --purge-account")
	}
	out := joined(r.calls)
	if !strings.Contains(out, "userdel") || !strings.Contains(out, "anon-shim") {
		t.Errorf("purge must userdel both anon and its shim, got:\n%s", out)
	}
}

// rm --purge-account on an absent account is a clean no-op, not an error.
func TestRmPurgeAbsent(t *testing.T) {
	r := &fakeRunner{}
	res, err := provision.Rm(context.Background(), r, "anon", true)
	if err != nil {
		t.Fatalf("Rm on absent account error: %v", err)
	}
	if res.AccountRemoved {
		t.Errorf("AccountRemoved = true on an absent account, want false")
	}
}

// list enumerates the anon accounts that actually exist on the box (reads the
// account table, NOT a maintained index), and excludes the shim service accounts.
func TestListReadsFromBox(t *testing.T) {
	r := &fakeRunner{}
	accounts, err := provision.List(context.Background(), r, []string{
		"root:x:0:0::/root:/bin/bash",
		"anon:x:30034:30034::/home/anon:/bin/bash",
		"anon-shim:x:995:983::/home/anon-shim:/usr/sbin/nologin",
		"anon-work:x:30035:30035::/home/anon-work:/bin/bash",
		"anon-work-shim:x:996:984::/home/anon-work-shim:/usr/sbin/nologin",
		"alice:x:1000:1000::/home/alice:/bin/bash",
	})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("List = %v, want 2 anon accounts (anon, anon-work), no shims/root/alice", accounts)
	}
	got := map[string]bool{}
	for _, a := range accounts {
		got[a.Account] = true
	}
	if !got["anon"] || !got["anon-work"] {
		t.Errorf("List missing anon/anon-work: %v", accounts)
	}
	if got["anon-shim"] || got["anon-work-shim"] {
		t.Errorf("List must EXCLUDE shim service accounts: %v", accounts)
	}
}

// status --json emits machine-readable state read from the box: the account and
// shim existence, their UIDs, and (later) the marker. It must be valid JSON with
// the account name and both UIDs.
func TestStatusJSONMachineReadable(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.Exists {
		t.Errorf("Exists = false, want true")
	}
	if !st.ShimExists {
		t.Errorf("ShimExists = false, want true")
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("status --json is not valid JSON: %v", err)
	}
	if back["account"] != "anon" {
		t.Errorf("json account = %v, want anon (fields: %v)", back["account"], back)
	}
}

// status on an absent account reports Exists=false, not an error (a queryable
// negative, so a caller/CI can branch on it).
func TestStatusAbsent(t *testing.T) {
	r := &fakeRunner{}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status (absent) error: %v", err)
	}
	if st.Exists {
		t.Errorf("Exists = true on an absent account, want false")
	}
}
