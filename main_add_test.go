package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/endpoint"
)

// `add` is add-ONCE: an account anonctl ALREADY MANAGES is refused up front, before
// any provisioning or forcing, so a second `add` never silently re-applies a
// (possibly different) endpoint/config. The refusal exits non-zero and its message
// points at `update` (to change a live account) so the operator knows the right verb.
//
// "Already manages" is the LEDGER record, not the passwd entry (see
// TestAddAdoptsDeclaredAccounts for why the distinction is load-bearing), so the
// fixture is a scratch store carrying a record for the account. The refusal is a
// pure read BEFORE forcing.Install, so this unit test reaches it without a real
// nft/systemd host, and runAdd must bail with no provisioning attempted.
func TestAddRefusesManagedAccount(t *testing.T) {
	disableColorForTest(t) // assert the plain message text regardless of the test host's tty
	s := swapConfigStore(t)
	writeConfig(t, s, "anon-work", 9050, endpoint.ClassTorShared) // anonctl already manages it
	r := &seedFakeRunner{present: map[string]string{"anon-work": "/home/anon-work"}}
	var code int
	msg := captureStderrDuring(t, func() {
		code = runAdd(context.Background(), r, mustParse(t, []string{"add", "work"}))
	})
	if code == 0 {
		t.Errorf("add on an existing account = 0, want non-zero")
	}
	if !strings.Contains(msg, "already exists") {
		t.Errorf("refusal must say the account already exists; got %q", msg)
	}
	if !strings.Contains(msg, "anonctl update") {
		t.Errorf("refusal must point the operator at `anonctl update` to change a live account; got %q", msg)
	}
	// Create-only: no account was provisioned (no useradd), because the refusal is up
	// front, before provision.Add.
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "useradd" {
			t.Errorf("add refused an existing account but still ran useradd (%v); the refusal must mutate nothing", c)
		}
	}
}

// CREATE-LAST ORDERING: when a guard refuses (here the cross-identification guard,
// a socks-peruser endpoint already owned by another account), the account is NEVER
// created. Provisioning (useradd) now runs AFTER every question is answered and
// every guard passes, so a refusal leaves the box untouched (no half-provisioned
// account). The refusal is driven through the REAL runAdd with an explicit
// --endpoint (so no prompt), and we assert useradd was never invoked.
func TestAddDoesNotCreateAccountWhenEndpointRefused(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())                                 // defaultsStore -> scratch (no real /etc read)
	s := swapConfigStore(t)                                       // claim set -> scratch
	writeConfig(t, s, "anon-a", 1080, endpoint.ClassSocksPeruser) // 1080 owned by anon-a

	r := &seedFakeRunner{present: map[string]string{}} // the new account is absent
	var code int
	msg := captureStderrDuring(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:1080", "b"}))
	})
	if code == 0 {
		t.Errorf("add pointing at a taken peruser endpoint = 0, want non-zero (refused)")
	}
	if !strings.Contains(msg, "anon-a") {
		t.Errorf("refusal should name the conflicting owner; got %q", msg)
	}
	for _, c := range r.calls {
		if len(c) > 0 && c[0] == "useradd" {
			t.Errorf("add ran useradd (%v) despite the endpoint being refused; the account must be created LAST, after guards pass", c)
		}
	}
}

// A record that EXISTS but cannot be READ must never be treated as absent. Reading
// it as "no record" would let `add` re-apply a fresh endpoint/config on top of an
// account anonctl already manages, using a record it could not even read, so the
// gate fails LOUD instead. This is the fail-closed half of the new gate, and it is
// driven through the real runAdd: a corrupt record must stop it before any install.
func TestAddRefusesUnreadableRecord(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)

	path, err := store.Path("anon-01")
	if err != nil {
		t.Fatalf("store.Path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &declaredFakeRunner{uids: map[string]int{"anon-01": 8801, "anon-01-shim": 412}}
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add with an unreadable record = 0, want non-zero (it must not be read as 'no record')")
	}
	if !strings.Contains(msg, "anon-01") {
		t.Errorf("the refusal must name the account; got %q", msg)
	}
	if len(install.calls) != 0 {
		t.Errorf("add installed forcing over a record it could not read: %v", install.calls)
	}
	if muts := r.mutatingCalls(); len(muts) != 0 {
		t.Errorf("add mutated the box despite the refusal: %v", muts)
	}
}

// The post-activation shape: anonctl's record survives while the accounts do not.
// `add` must still refuse (the record is what it gates on) and point at `rm`, which
// is the command that clears the orphaned forcing and lets a later `add` re-adopt.
// Silently re-adding here would install a second set of rules while the first set
// still governs a freed uid.
func TestAddRefusesWhenRecordOutlivesTheAccounts(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	writeConfig(t, store, "anon-01", 9050, endpoint.ClassTorShared)

	r := &declaredFakeRunner{uids: map[string]int{}} // activation deleted both accounts
	var code int
	msg := captureStderrDuring(t, func() {
		captureStdout(t, func() {
			code = runAdd(context.Background(), r,
				mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
		})
	})
	if code == 0 {
		t.Errorf("add over a surviving record = 0, want non-zero")
	}
	if !strings.Contains(msg, "anonctl rm") {
		t.Errorf("the refusal must name `anonctl rm`, the command that clears the stale record; got %q", msg)
	}
	if len(install.calls) != 0 {
		t.Errorf("add installed forcing for accounts that do not exist: %v", install.calls)
	}
}
