package provision_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/marker"
	"github.com/wighawag/anonctl/internal/provision"
)

// TestMain neutralises the real login-env writer for the whole UNIT suite: these
// tests drive the fake Runner and never create a real home, so the default
// WriteLoginEnv (which touches the filesystem) would spuriously fail. Tests that
// care about the env write override the seam themselves and restore it. The
// integration test exercises the real writer against a real account.
func TestMain(m *testing.M) {
	provision.WriteLoginEnv = func(context.Context, provision.Runner, string, string) error { return nil }
	os.Exit(m.Run())
}

// fakeRunner is the unit-test seam standing in for the real ExecRunner: it
// records every command the provisioning issues and answers the `getent passwd`
// existence probes from a scripted set of already-present accounts, so the whole
// add/rm/list/status wiring is exercised WITHOUT creating a real Unix user
// (mirrors netcage's recordRunner). No useradd/userdel ever hits the box.
type fakeRunner struct {
	calls       [][]string
	present     map[string]bool // accounts getent should report as existing
	sudoAllowed bool            // when true, `sudo -l -U` reports the account CAN sudo
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	// sudo -l -U <account>: the read-only sudo-absence probe. By default report the
	// finding-observed "not allowed" (a freshly-provisioned anon account has no sudo
	// rights); a test can flip sudoAllowed to exercise the positive-detection path.
	if name == "sudo" {
		if r.sudoAllowed {
			return "User is allowed to run the following commands", "", nil
		}
		return "", "User is not allowed to run sudo on host.", &exitErr{code: 1}
	}
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

// WithMarker on an account WITH a marker reports Forced + the marker record (the
// share-class the status view carries, story 20). The marker Store is pointed at
// a scratch dir, so the real /etc is never read/written.
func TestStatus_WithMarker_ReportsForced(t *testing.T) {
	store := marker.Store{BaseDir: filepath.Join(t.TempDir(), "anonctl")}
	m := marker.New("anon", "30034", endpoint.ClassTorShared, "1.0.0", time.Now())
	if err := store.Write(m); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	st, err = st.WithMarker(store)
	if err != nil {
		t.Fatalf("WithMarker: %v", err)
	}
	if !st.Forced || st.Marker == nil {
		t.Fatalf("a present marker must set Forced+Marker; got Forced=%v Marker=%v", st.Forced, st.Marker)
	}
	if st.Marker.EndpointClass != endpoint.ClassTorShared {
		t.Errorf("status must carry the endpoint share-class; got %q", st.Marker.EndpointClass)
	}
}

// WithMarker on an account with NO marker is a clean "not forced" (Forced=false,
// Marker=nil), never an error, so status/CI can branch on absence.
func TestStatus_WithMarker_MissingIsCleanNotForced(t *testing.T) {
	store := marker.Store{BaseDir: filepath.Join(t.TempDir(), "anonctl")}
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	st, err = st.WithMarker(store)
	if err != nil {
		t.Fatalf("WithMarker (missing) must not error; got %v", err)
	}
	if st.Forced || st.Marker != nil {
		t.Fatalf("a missing marker must be a clean not-forced; got Forced=%v Marker=%v", st.Forced, st.Marker)
	}
	// And it must appear in status --json as forced:false.
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), `"forced":false`) {
		t.Errorf("status --json must report forced:false for a missing marker; got %s", b)
	}
}

// add provisions the login account with NO sudo grant: none of the commands it
// issues add the account to a sudo/wheel group or write a sudoers entry. This is
// the CLOSE-AT-ADD invariant from work/notes/findings/uid-transition-escape-surface.go:
// a socket the anon account could own via `sudo` would carry a DIFFERENT uid and
// escape the `meta skuid` forcing, so `add` must never grant it.
func TestAddGrantsNoSudo(t *testing.T) {
	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	for _, c := range r.calls {
		line := strings.Join(c, " ")
		// No group grant into sudo/wheel (via useradd --groups or usermod -aG), and no
		// visudo/sudoers write.
		if strings.Contains(line, "sudo") || strings.Contains(line, "wheel") || strings.Contains(line, "visudo") {
			t.Errorf("add must not grant sudo; offending command: %q", line)
		}
		if strings.Contains(line, "usermod") && (strings.Contains(line, "-G") || strings.Contains(line, "-aG") || strings.Contains(line, "--groups")) {
			t.Errorf("add must not add supplementary groups (a sudo/wheel path); offending command: %q", line)
		}
	}
}

// add provisions the login account with a minimal login PATH that omits the sbin
// directories holding setuid network binaries (exim4/pppd/mount.nfs per the
// audit finding), shrinking what the account can even name. The write goes
// through the injectable WriteLoginEnv seam so the unit test asserts the CONTENT
// without touching a real home directory.
func TestAddWritesMinimalLoginPATH(t *testing.T) {
	var gotAccount, gotContent string
	var wrote bool
	old := provision.WriteLoginEnv
	provision.WriteLoginEnv = func(_ context.Context, _ provision.Runner, account, content string) error {
		wrote = true
		gotAccount, gotContent = account, content
		return nil
	}
	t.Cleanup(func() { provision.WriteLoginEnv = old })

	r := &fakeRunner{}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	if !wrote {
		t.Fatalf("Add must write the account's minimal login PATH via WriteLoginEnv")
	}
	if gotAccount != "anon" {
		t.Errorf("WriteLoginEnv account = %q, want anon", gotAccount)
	}
	if !strings.Contains(gotContent, "PATH="+provision.LoginPATH) {
		t.Errorf("login env must export the minimal PATH %q; got:\n%s", provision.LoginPATH, gotContent)
	}
	// The minimal PATH must NOT expose the sbin dirs that carry the setuid network
	// binaries the audit flagged (exim4/pppd/mount.nfs live under /usr/sbin, /sbin).
	for _, sbin := range []string{"/usr/sbin", "/sbin"} {
		for _, entry := range strings.Split(provision.LoginPATH, ":") {
			if entry == sbin {
				t.Errorf("minimal LoginPATH must not include %q (setuid network binaries live there): %q", sbin, provision.LoginPATH)
			}
		}
	}
}

// re-add on an existing account does NOT rewrite the login env (idempotent: the
// env is written only when the account is freshly created, so a re-run never
// clobbers an operator's edited profile).
func TestAddIdempotentDoesNotRewriteLoginEnv(t *testing.T) {
	var wrote bool
	old := provision.WriteLoginEnv
	provision.WriteLoginEnv = func(_ context.Context, _ provision.Runner, _, _ string) error {
		wrote = true
		return nil
	}
	t.Cleanup(func() { provision.WriteLoginEnv = old })

	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	if _, err := provision.Add(context.Background(), r, "anon"); err != nil {
		t.Fatalf("Add (existing) error: %v", err)
	}
	if wrote {
		t.Errorf("re-add must NOT rewrite the login env for an already-provisioned account")
	}
}

// status positively reports the account has NO sudo rights: it runs the
// `sudo -l -U <account>` probe through the Runner and reports SudoChecked=true,
// SudoAllowed=false (a positive assertion, not merely an absence). This is the
// PROVE-IN-VERIFY sudo vector surfaced where an operator sees it.
func TestStatusReportsNoSudo(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.SudoChecked {
		t.Errorf("SudoChecked = false, want true (status must probe sudo)")
	}
	if st.SudoAllowed {
		t.Errorf("SudoAllowed = true, want false for a freshly-provisioned anon account")
	}
	// The positive no-sudo assertion must show up in status --json.
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), `"sudoAllowed":false`) {
		t.Errorf("status --json must report sudoAllowed:false; got %s", b)
	}
}

// status DETECTS sudo when it IS present (the probe is a real positive check, not
// a hard-coded false): a box that grants the account sudo is reported
// SudoAllowed=true so an operator is warned the uid-transition vector is open.
func TestStatusDetectsSudoWhenPresent(t *testing.T) {
	r := &fakeRunner{present: map[string]bool{"anon": true, "anon-shim": true}, sudoAllowed: true}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status error: %v", err)
	}
	if !st.SudoChecked || !st.SudoAllowed {
		t.Errorf("a box that grants sudo must report SudoChecked=true SudoAllowed=true; got checked=%v allowed=%v", st.SudoChecked, st.SudoAllowed)
	}
}

// status on an ABSENT account does not probe sudo (there is no account to probe):
// SudoChecked stays false so the field is not a misleading "no sudo" for a
// non-existent account.
func TestStatusAbsentDoesNotProbeSudo(t *testing.T) {
	r := &fakeRunner{}
	st, err := provision.Status(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("Status (absent) error: %v", err)
	}
	if st.SudoChecked {
		t.Errorf("SudoChecked = true on an absent account, want false")
	}
}
