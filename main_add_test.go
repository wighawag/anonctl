package main

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/provision"
)

// `add` is create-only: an account that already EXISTS is refused up front, before
// any provisioning or forcing, so a second `add` never silently re-applies a
// (possibly different) endpoint/config. The refusal exits non-zero and its message
// points at `update` (to change a live account) so the operator knows the right verb.
//
// The refusal happens via provision.Status (the Runner seam) BEFORE forcing.Install,
// so this unit test reaches it without a real nft/systemd host: the fake runner
// reports the account present, and runAdd must bail with no provisioning attempted.
func TestAddRefusesExistingAccount(t *testing.T) {
	disableColorForTest(t) // assert the plain message text regardless of the test host's tty
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
	s := swapConfigListStore(t)                                   // claim set -> scratch
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

// The refusal is scoped to an EXISTING account: the gate reads provision.Status and
// only fires when st.Exists. We assert the gate's INPUT for an absent account is
// not-exists (so runAdd would fall through to real provisioning), using the SAME
// Runner seam runAdd uses. Running the full runAdd for an absent account is not a
// unit test (it would reach forcing.Install / a real host), so we check the gate
// condition directly rather than drive the whole verb.
func TestAddGateDoesNotFireForAbsentAccount(t *testing.T) {
	r := &seedFakeRunner{present: map[string]string{}} // account absent
	st, err := provision.Status(context.Background(), r, "anon-work")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Exists {
		t.Errorf("gate would wrongly refuse an ABSENT account: Status.Exists = true")
	}
}
