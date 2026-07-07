package main

import (
	"testing"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/provision"
)

// The version fast-path exits 0 before any parse (no verb, no root needed).
func TestVersionArg(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"version"}} {
		if code := run(args); code != 0 {
			t.Errorf("run(%v) = %d, want 0", args, code)
		}
	}
}

// An unknown verb exits 2 (usage error), not 0.
func TestUnknownVerbExit(t *testing.T) {
	if code := run([]string{"frobnicate"}); code != 2 {
		t.Errorf("run(frobnicate) = %d, want 2", code)
	}
}

// No args exits 2 (usage error).
func TestNoArgsExit(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Errorf("run(nil) = %d, want 2", code)
	}
}

// update/reconfigure are now IMPLEMENTED (persistence task): they change an
// account's endpoint and re-apply fail-closed. A bare `update` (no --endpoint) is a
// usage error (exit 2, the required flag is missing), NOT the old not-implemented
// stub (exit 3): the verb is implemented, so it must never exit 3.
func TestUpdateRequiresEndpoint(t *testing.T) {
	for _, v := range []string{"update", "reconfigure"} {
		code := run([]string{v})
		if code != 2 {
			t.Errorf("run(%q) = %d, want 2 (missing required --endpoint)", v, code)
		}
		if code == 3 {
			t.Errorf("run(%q) = 3 (not-implemented stub); the verb must be implemented", v)
		}
	}
}

// verify is now WIRED: it runs the assertion set and exits with the report's
// verdict. In the default build (no `integration` tag) the live probes are not
// compiled in, so verify cannot PROVE anonymization and must exit NON-ZERO (a
// fail-closed / CI-gating contract: a verification that could not run is not a
// pass, and never exit 0 by default). It must never exit 3 (the not-implemented
// stub code): the verb is implemented.
func TestVerifyDispatchesAndExitsNonZeroInDefaultBuild(t *testing.T) {
	code := run([]string{"verify"})
	if code == 0 {
		t.Errorf("run(verify) = 0, want non-zero (default build cannot PROVE anonymization; must fail-closed)")
	}
	if code == 3 {
		t.Errorf("run(verify) = 3 (not-implemented stub); the verb must be implemented")
	}
}

// verifyParams READS the persisted exemption back into verify.LiveParams.Exempt,
// so the split-tunnel-tight + lan-exemption-not-a-dns-hole assertions fire live
// for an exempted account (they run only when Exempt != ""). A port-omitted
// exemption renders a dialable host:port (the split-tunnel probe needs a concrete
// port); an account with NO exemptions yields an empty Exempt (the assertions are
// cleanly skipped, as today).
func TestVerifyParamsPopulatesExemptFromConfig(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	cfg := accountconfig.Config{
		Account:       "anon",
		AnonUID:       30034,
		ShimUID:       995,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
		Exemptions:    []string{"192.168.1.150:8080"},
	}
	if err := store.Write(cfg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	st := provision.AccountStatus{Account: "anon", UID: "30034", ShimUID: "995"}
	p := verifyParams(store, "anon", st)
	if p.Exempt != "192.168.1.150:8080" {
		t.Errorf("Exempt = %q, want 192.168.1.150:8080 (read back from the persisted config)", p.Exempt)
	}

	// A port-omitted (all-TCP) exemption still yields a concrete dialable host:port.
	cfg.Exemptions = []string{"192.168.1.150"}
	if err := store.Write(cfg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	p = verifyParams(store, "anon", st)
	if p.Exempt == "" {
		t.Errorf("port-omitted exemption yielded empty Exempt; want a concrete host:port so the probe can dial")
	}

	// No exemptions => empty Exempt => the two assertions are cleanly skipped.
	cfg.Exemptions = nil
	if err := store.Write(cfg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if p := verifyParams(store, "anon", st); p.Exempt != "" {
		t.Errorf("Exempt = %q for an account with no exemptions, want empty", p.Exempt)
	}

	// An account with NO persisted config at all (never forced) yields empty Exempt.
	if p := verifyParams(store, "anon-absent", st); p.Exempt != "" {
		t.Errorf("Exempt = %q for an unconfigured account, want empty", p.Exempt)
	}
}

// verify --json exits with the same verdict (non-zero in the default build) and
// must not be mistaken for the not-implemented stub.
func TestVerifyJSONDispatches(t *testing.T) {
	code := run([]string{"verify", "--json"})
	if code == 0 {
		t.Errorf("run(verify --json) = 0, want non-zero in the default build")
	}
	if code == 3 {
		t.Errorf("run(verify --json) = 3 (stub); the verb must be implemented")
	}
}
