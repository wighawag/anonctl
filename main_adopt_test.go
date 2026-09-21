package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/systemd"
	"github.com/wighawag/anonctl/internal/verify"
)

// declaredFakeRunner is a passwd table anonctl did NOT create: each account is
// present with the uid the DECLARING system pinned (a NixOS `users.users.<name>.uid`),
// which is the whole point of adoption - the uids are chosen elsewhere and must be
// read off the box, never assumed. An account absent from the map is absent from
// passwd. It answers BOTH passwd reads anonctl makes: the per-account lookup
// (`getent passwd <name>`) and the ENUMERATION (`getent passwd`) the shared-uid
// guard needs, so that guard runs for real in these tests instead of falling into
// its cannot-enumerate branch. Every other command is a recorded no-op, so a test
// can assert that nothing mutating (useradd/chown/...) was ever attempted.
type declaredFakeRunner struct {
	uids   map[string]int // account -> pinned uid; absent == no passwd entry
	others []string       // extra passwd lines (unrelated accounts on the box)
	calls  [][]string
}

// passwdLine renders one passwd entry: name:x:uid:gid:gecos:home:shell (gid 100 =
// `users`, the NixOS convention: its useradd carries GROUP=100 and makes no
// user-private group).
func passwdLine(account string, uid int) string {
	return account + ":x:" + strconv.Itoa(uid) + ":100::/home/" + account + ":/run/current-system/sw/bin/bash"
}

func (r *declaredFakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == "getent" && len(args) == 2 && args[0] == "passwd" {
		// A NUMERIC argument is the REVERSE lookup (uid -> name), which getent answers
		// with the FIRST match. Planted `others` lines come first, mirroring a directory
		// backend whose entry outranks the local one.
		if uid, err := strconv.Atoi(args[1]); err == nil {
			for _, line := range r.others {
				if f := strings.Split(line, ":"); len(f) > 2 && f[2] == args[1] {
					return line, "", nil
				}
			}
			for acct, u := range r.uids {
				if u == uid {
					return passwdLine(acct, u), "", nil
				}
			}
			return "", "", &exitErr{code: 2}
		}
		acct := args[1]
		uid, ok := r.uids[acct]
		if !ok {
			return "", "", &exitErr{code: 2}
		}
		return passwdLine(acct, uid), "", nil
	}
	if name == "getent" && len(args) == 1 && args[0] == "passwd" {
		// The whole table: a couple of ordinary host accounts, this box's anon accounts,
		// and whatever extra lines the test planted (a uid collision, typically).
		lines := []string{passwdLine("root", 0), passwdLine("wighawag", 1000)}
		for acct, uid := range r.uids {
			lines = append(lines, passwdLine(acct, uid))
		}
		lines = append(lines, r.others...)
		return strings.Join(lines, "\n") + "\n", "", nil
	}
	return "", "", nil
}

// mutatingCalls returns the commands the fake saw that would CHANGE the box. The
// read-only probes provisioning makes (`getent passwd`, the `sudo -l -U` sudo-absence
// probe) are excluded, so a non-empty result means `add` tried to create an account,
// touch a home, or otherwise mutate a host whose accounts it was supposed to adopt.
func (r *declaredFakeRunner) mutatingCalls() [][]string {
	var out [][]string
	for _, c := range r.calls {
		if len(c) == 0 || c[0] == "getent" || c[0] == "sudo" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// installedForcing is what the stubbed forcing install captured: the config `add`
// built (whose uids are the assertion that matters) and the exemptions it applied.
type installedForcing struct {
	calls []accountconfig.Config
}

// swapAddSeams stubs the two seams runAdd's tail would otherwise drive into a real
// host: the forcing install (nft + systemd + the ledger write) and the inline
// verify probe. The install stub WRITES the account config exactly as the real
// forcing.Install does, because that write is what makes anonctl "manage" the
// account, and the second-add refusal has to be tested against it. The verify stub
// returns a green report so the tail's messaging runs without a live probe.
func swapAddSeams(t *testing.T, store accountconfig.Store) *installedForcing {
	t.Helper()
	rec := &installedForcing{}
	origInstall, origVerify := addForcingInstall, addVerifyReport
	addForcingInstall = func(_ context.Context, _ forcing.Deps, c accountconfig.Config, _ []lanexempt.Exempt) error {
		rec.calls = append(rec.calls, c)
		return store.Write(c)
	}
	addVerifyReport = func(_ context.Context, _ provision.Runner, _ *cli.Command, _ verify.Progress) verify.Report {
		return verify.Report{Account: "stub", Assertions: []verify.Assertion{{Name: "stub", Ok: true}}}
	}
	t.Cleanup(func() { addForcingInstall, addVerifyReport = origInstall, origVerify })
	return rec
}

// swapProvisionSeams replaces anoncore's two provisioning seams so a test drives
// account creation with no real host: the shell resolver (which would otherwise
// look up a real bash/nologin on $PATH, and this test's $PATH deliberately carries
// only the three unit binaries) and the login-env write (which writes a real
// `.profile` into a real home). It returns the accounts WriteLoginEnv was called
// for, so a test can assert the login env is written on creation and NOT on
// adoption - an adopted account's home belongs to whoever declared it.
func swapProvisionSeams(t *testing.T) *[]string {
	t.Helper()
	origShells, origWrite := provision.Shells, provision.WriteLoginEnv
	provision.Shells = provision.ShellResolver{
		Look:       func(name string) (string, error) { return "/run/current-system/sw/bin/" + name, nil },
		Stat:       func(path string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		ShellsFile: filepath.Join(t.TempDir(), "shells"),
	}
	var wrote []string
	provision.WriteLoginEnv = func(_ context.Context, _ provision.Runner, account, _ string) error {
		wrote = append(wrote, account)
		return nil
	}
	t.Cleanup(func() { provision.Shells, provision.WriteLoginEnv = origShells, origWrite })
	return &wrote
}

// fakeUnitBinariesOnPath puts resolvable stand-ins for the three binaries the
// generated units name (the shim, setpriv, nft) on $PATH, so `add`'s REAL
// pre-flight (systemd.PreflightUnitBinaries) runs and passes on a test host that
// has none of them. It exercises the production guard rather than stubbing it out.
func fakeUnitBinariesOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{systemd.ShimBinaryName, systemd.SetprivBinaryName, systemd.NftBinaryName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir)
}

// ADOPTION, the acceptance case: both accounts already exist in the passwd table
// with pinned uids (declared by the host, because a host that deletes undeclared
// accounts at every activation leaves declaring them as the only safe way to run
// anonctl) and anonctl has NO ledger record of them. `add` must then install the
// forcing against the uids it reads off the box, create nothing, touch no home, and
// end green.
//
// The old gate refused exactly this, which left the worst state available: the
// accounts exist, nothing jails them, and no verb would fix it (`update` targets an
// account anonctl already manages).
func TestAddAdoptsDeclaredAccounts(t *testing.T) {
	disableColorForTest(t)
	seeded := swapSeedSeams(t, t.TempDir()) // defaults -> scratch; captures any home seeding
	store := swapConfigStore(t)             // empty ledger: anonctl manages nothing yet
	install := swapAddSeams(t, store)
	loginEnv := swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	// The uids a NixOS configuration pinned: 8801 for the login account (normal
	// range), 412 for the shim (system range). anonctl chose neither.
	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 8801, "anon-01-shim": 412}}

	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("add on declared-but-unmanaged accounts = %d, want 0 (it must ADOPT them)", code)
	}
	if len(install.calls) != 1 {
		t.Fatalf("expected exactly one forcing install, got %d", len(install.calls))
	}
	cfg := install.calls[0]
	if cfg.AnonUID != 8801 || cfg.ShimUID != 412 {
		t.Errorf("forcing installed against uid %d / shim uid %d, want 8801 / 412 (the uids must be READ from the box, never assumed)", cfg.AnonUID, cfg.ShimUID)
	}
	if muts := r.mutatingCalls(); len(muts) != 0 {
		t.Errorf("adoption mutated the box: %v; it must create no account and touch no home", muts)
	}
	if len(*seeded) != 0 {
		t.Errorf("adoption seeded the home (%v); an adopted account's home belongs to whoever declared it", *seeded)
	}
	if len(*loginEnv) != 0 {
		t.Errorf("adoption wrote the login env for %v; it must not touch an adopted account's home", *loginEnv)
	}
	if !strings.Contains(out, "adopting") {
		t.Errorf("adoption must SAY it is adopting (so the operator can abort if it is not what they meant); got %q", out)
	}
	if !strings.Contains(out, "adopted + forced") {
		t.Errorf("the success line must not claim to have provisioned an account it adopted; got %q", out)
	}
}

// The SECOND `add` on the now-adopted account is refused, because installing the
// forcing wrote anonctl's record for it: the create-only guard's real subject is
// that record (a re-add must never silently re-apply a different endpoint/config),
// and adoption is what puts it there.
func TestAddRefusesSecondAddAfterAdoption(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 8801, "anon-01-shim": 412}}
	args := []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}

	captureStdout(t, func() {
		if code := runAdd(context.Background(), r, mustParse(t, args)); code != 0 {
			t.Fatalf("first add = %d, want 0", code)
		}
	})

	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() { code = runAdd(context.Background(), r, mustParse(t, args)) })
	})
	if code == 0 {
		t.Errorf("second add = 0, want non-zero (anonctl now manages this account)")
	}
	if !strings.Contains(msg, "already exists") {
		t.Errorf("the second add must refuse with the existing-account message; got %q", msg)
	}
	if !strings.Contains(msg, "anonctl update") {
		t.Errorf("the refusal must point at `anonctl update`; got %q", msg)
	}
}

// Adoption is strictly a PAIR. With the login account present and its shim absent,
// `add` must REFUSE and name BOTH accounts: adopting the half would install forcing
// whose endpoint-reachability exemption names a shim uid that does not exist, and
// creating the missing half is wrong on the host that needs adoption (an account
// anonctl creates there is undeclared, so the next activation deletes it again).
func TestAddRefusesHalfDeclaredPair(t *testing.T) {
	disableColorForTest(t)
	seeded := swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 8801}} // shim NOT declared

	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add on a half-declared pair = 0, want non-zero (refusal)")
	}
	for _, name := range []string{"anon-01", "anon-01-shim"} {
		if !strings.Contains(msg, name) {
			t.Errorf("the refusal must name %s so the operator knows what to declare; got %q", name, msg)
		}
	}
	if len(install.calls) != 0 {
		t.Errorf("a refused half-pair still installed forcing: %v", install.calls)
	}
	if muts := r.mutatingCalls(); len(muts) != 0 {
		t.Errorf("a refused half-pair mutated the box: %v; it must NOT create the missing half", muts)
	}
	if len(*seeded) != 0 {
		t.Errorf("a refused half-pair seeded a home: %v", *seeded)
	}
}

// The mirror shape (the SHIM declared, the login account absent) is the same
// pair-integrity failure and is refused the same way: the shim account is the one
// uid permitted to dial the endpoint, so silently adopting one of unknown
// provenance while creating the login half is exactly the pairing anonctl must not
// invent.
func TestAddRefusesShimWithoutLoginAccount(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	r := &declaredFakeRunner{uids: map[string]int{"anon-01-shim": 412}} // login account NOT declared

	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add with a stray shim account = 0, want non-zero (refusal)")
	}
	for _, name := range []string{"anon-01", "anon-01-shim"} {
		if !strings.Contains(msg, name) {
			t.Errorf("the refusal must name %s; got %q", name, msg)
		}
	}
	if len(install.calls) != 0 {
		t.Errorf("a refused half-pair still installed forcing: %v", install.calls)
	}
	if muts := r.mutatingCalls(); len(muts) != 0 {
		t.Errorf("a refused half-pair mutated the box: %v", muts)
	}
}

// CREATE FROM NOTHING is unchanged: with neither account in passwd and no ledger
// record, `add` provisions both (the useradd calls reach the Runner) and installs
// the forcing against the uids the box then reports. The adoption gate must not
// have turned the ordinary first-run path into an adoption.
func TestAddStillCreatesFromNothing(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	loginEnv := swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	// createOnUseraddRunner is the absent-then-created box: `getent` reports nothing
	// until a `useradd` for that account has run, after which it reports the uid the
	// host allocated.
	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}

	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("add on an absent account = %d, want 0", code)
	}
	if len(r.created) != 2 {
		t.Errorf("created %v, want both anon-01 and anon-01-shim to be useradd'd", r.created)
	}
	if len(install.calls) != 1 || install.calls[0].AnonUID != 1002 || install.calls[0].ShimUID != 992 {
		t.Errorf("forcing installed with %+v, want uid 1002 / shim uid 992 read back after creation", install.calls)
	}
	if strings.Contains(out, "adopting") {
		t.Errorf("a create-from-nothing add must not claim to adopt; got %q", out)
	}
	if !strings.Contains(out, "provisioned + forced") {
		t.Errorf("a create-from-nothing add must still report provisioning; got %q", out)
	}
	if len(*loginEnv) != 1 || (*loginEnv)[0] != "anon-01" {
		t.Errorf("login env written for %v, want exactly [anon-01]: a FRESHLY created account still gets its minimal login PATH", *loginEnv)
	}
}

// createOnUseraddRunner extends the passwd fake with CREATION: a `useradd <account>`
// makes that account appear in subsequent `getent` reads, with the uid the host
// would have allocated. It is what lets the create-from-nothing path run end to end
// (provision.Add creates, then buildConfig reads the uids back) with no real box.
type createOnUseraddRunner struct {
	declaredFakeRunner
	allocate map[string]int // account -> uid the host hands out on creation
	created  []string
}

func (r *createOnUseraddRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if name == "useradd" {
		acct := args[len(args)-1]
		r.calls = append(r.calls, append([]string{name}, args...))
		r.created = append(r.created, acct)
		r.uids[acct] = r.allocate[acct]
		return "", "", nil
	}
	return r.declaredFakeRunner.Run(ctx, name, args...)
}

// A uid anonctl did not allocate is only as unique as whoever made it. `useradd`
// refuses a duplicate uid unless forced, so an account anonctl CREATED is unique by
// construction, but an adopted one can share its uid with an unrelated account
// (`useradd -o -u`, or a host that does not enforce uniqueness). The rules match
// `meta skuid`, which names a uid and not an account, so forcing a shared uid would
// silently redirect and default-deny that other account's egress too: the UID-reuse
// hazard reached by adoption rather than by deletion. `add` must refuse, naming the
// other account.
func TestAddRefusesAdoptingASharedUID(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	r := &declaredFakeRunner{
		uids:   map[string]int{"anon-01": 8801, "anon-01-shim": 412},
		others: []string{passwdLine("backup-operator", 8801)}, // the SAME uid, another account
	}
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add adopting a shared uid = 0, want non-zero (it would jail the other account too)")
	}
	if !strings.Contains(msg, "backup-operator") {
		t.Errorf("the refusal must NAME the other account owning the uid; got %q", msg)
	}
	if len(install.calls) != 0 {
		t.Errorf("forcing was installed for a shared uid: %v", install.calls)
	}
}

// The same guard covers the SHIM's uid: the shim uid is the one uid allowed to dial
// the upstream endpoint, so sharing it hands that privilege to whoever else owns it.
func TestAddRefusesAdoptingASharedShimUID(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	r := &declaredFakeRunner{
		uids:   map[string]int{"anon-01": 8801, "anon-01-shim": 412},
		others: []string{passwdLine("some-daemon", 412)},
	}
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add adopting a shared SHIM uid = 0, want non-zero")
	}
	if !strings.Contains(msg, "some-daemon") {
		t.Errorf("the refusal must name the account sharing the shim uid; got %q", msg)
	}
	if len(install.calls) != 0 {
		t.Errorf("forcing was installed for a shared shim uid: %v", install.calls)
	}
}

// A passwd table that cannot be ENUMERATED (a directory backend that refuses
// enumeration) proves nothing either way. Refusing there would make anonctl unusable
// on such a host for a hazard it has no evidence of, so adoption proceeds and says
// what it could not check. The per-account lookups still work, so the uids are still
// read from the box.
func TestAddAdoptsWhenPasswdCannotBeEnumerated(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	r := &unenumerableRunner{declaredFakeRunner: declaredFakeRunner{
		uids: map[string]int{"anon-01": 8801, "anon-01-shim": 412},
	}}
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code != 0 {
		t.Fatalf("add on an unenumerable passwd table = %d, want 0 (no evidence of sharing is not evidence of sharing)", code)
	}
	if len(install.calls) != 1 || install.calls[0].AnonUID != 8801 {
		t.Errorf("forcing must still be installed against the uids read per-account; got %v", install.calls)
	}
	if !strings.Contains(msg, "could not enumerate") {
		t.Errorf("it must SAY which check it could not make; got %q", msg)
	}
}

// unenumerableRunner answers per-account passwd lookups but returns nothing for the
// whole-table enumeration, like an nss backend that does not allow enumeration.
type unenumerableRunner struct{ declaredFakeRunner }

func (r *unenumerableRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if name == "getent" && len(args) == 1 && args[0] == "passwd" {
		r.calls = append(r.calls, append([]string{name}, args...))
		return "", "", nil
	}
	return r.declaredFakeRunner.Run(ctx, name, args...)
}

// THE NON-ENUMERABLE HOST. A directory backend (LDAP/SSSD/AD, nss-systemd) with
// `enumerate = false` answers `getent passwd` with the LOCAL files only, so an
// enumeration-only check looks at a complete-seeming table, finds nothing, and
// adopts a uid the directory has already given to somebody else. The reverse lookup
// (`getent passwd <uid>`) is the question such a backend DOES answer, and it must be
// asked: without it this adoption silently jails a directory user.
func TestAddRefusesASharedUIDVisibleOnlyByReverseLookup(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	// The enumeration yields nothing (this fake's whole-table read is empty), while the
	// directory resolves uid 8801 to a user of its own.
	r := &unenumerableRunner{declaredFakeRunner: declaredFakeRunner{
		uids:   map[string]int{"anon-01": 8801, "anon-01-shim": 412},
		others: []string{passwdLine("ad-user", 8801)},
	}}
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add = 0 for a uid the directory already owns; the enumeration cannot see it, so the reverse lookup must")
	}
	if !strings.Contains(msg, "ad-user") {
		t.Errorf("the refusal must name the directory account owning the uid; got %q", msg)
	}
	if len(install.calls) != 0 {
		t.Errorf("forcing installed on a uid owned by another account: %v", install.calls)
	}
}

// THE PAIR THAT APPEARS DURING THE PROMPT. `add` decides create-vs-adopt from a read
// taken BEFORE the interactive endpoint prompt, which an operator can sit on for
// minutes; on a declarative host an activation can create the accounts in that
// window. The run then becomes an adoption, and it must clear the SAME bar a
// straightforward adoption clears: deciding from the stale read would install
// forcing on accounts no guard ever vetted. Here the pair appears with a uid that is
// already owned by another account, and the run must refuse.
func TestAddVetsAPairThatAppearsDuringTheEndpointPrompt(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	// Absent at the first read; the accounts appear (sharing uid 8801 with
	// backup-operator) while the endpoint is being chosen.
	r := &appearingPairRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		appear:             map[string]int{"anon-01": 8801, "anon-01-shim": 412},
		others:             []string{passwdLine("backup-operator", 8801)},
	}
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add = 0 for a pair that appeared mid-run sharing a uid; the mutation-time read must DECIDE, not just re-check the pair rule")
	}
	if !strings.Contains(msg, "backup-operator") {
		t.Errorf("the refusal must name the account sharing the uid; got %q", msg)
	}
	if len(install.calls) != 0 {
		t.Errorf("forcing installed for an unvetted adoption: %v", install.calls)
	}
}

// And the same window with NO collision still ends green, is disclosed as an
// adoption (not reported as a provisioning), and creates nothing.
func TestAddAdoptsAndDisclosesAPairThatAppearsDuringThePrompt(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	r := &appearingPairRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		appear:             map[string]int{"anon-01": 8801, "anon-01-shim": 412},
	}
	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("add = %d, want 0", code)
	}
	if !strings.Contains(out, "adopting") {
		t.Errorf("a run that became an adoption must SAY so; got %q", out)
	}
	if !strings.Contains(out, "adopted + forced") {
		t.Errorf("it must not report provisioning it did not do; got %q", out)
	}
	if muts := r.mutatingCalls(); len(muts) != 0 {
		t.Errorf("it created something instead of adopting: %v", muts)
	}
	if len(install.calls) != 1 || install.calls[0].AnonUID != 8801 {
		t.Errorf("forcing must be installed against the uids the appeared accounts actually own; got %v", install.calls)
	}
}

// appearingPairRunner is a box whose accounts appear partway through the run: the
// FIRST whole-table enumeration (the one `add` makes before the endpoint prompt, via
// the shared-uid guard) is the trigger, after which the per-account lookups report
// the pair. It simulates a concurrent activation creating declared accounts while
// anonctl waits at the prompt.
type appearingPairRunner struct {
	declaredFakeRunner
	appear   map[string]int
	others   []string
	lookups  int
	appeared bool
}

func (r *appearingPairRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if name == "getent" && len(args) == 2 && args[0] == "passwd" && !r.appeared {
		r.lookups++
		// The pre-prompt pair check makes two lookups (account + shim); everything after
		// that sees the accounts.
		if r.lookups > 2 {
			r.appeared = true
			for acct, uid := range r.appear {
				r.uids[acct] = uid
			}
			r.declaredFakeRunner.others = r.others
		}
	}
	return r.declaredFakeRunner.Run(ctx, name, args...)
}
