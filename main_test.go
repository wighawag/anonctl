package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/provision"
	"github.com/wighawag/anonctl/internal/verify"
)

// verifyHint renders the follow-up `anonctl verify` command an operator would type
// next. The DEFAULT account is a BARE verb (no name), so the hint must be exactly
// `anonctl verify` with NO trailing space where the empty account name used to go
// (the e2e finding, BUG 5); a named account appends its short name.
func TestVerifyHintHasNoTrailingSpaceForDefaultAccount(t *testing.T) {
	if got := verifyHint(cli.DefaultAccount); got != "anonctl verify" {
		t.Errorf("verifyHint(default) = %q, want %q (no trailing space)", got, "anonctl verify")
	}
	if got := verifyHint("anon-work"); got != "anonctl verify work" {
		t.Errorf("verifyHint(named) = %q, want %q", got, "anonctl verify work")
	}
}

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

// use is the verify-then-shell safe front door. These unit tests drive the
// verify-gate decision behind the injectable seams (useVerifyReport +
// useExecLoginShell + useGeteuid) so they never spawn a real shell and never need
// root: they assert the GATE polarity (green => exec attempted for the right
// account; red => NO exec, non-zero exit, failing assertions printed) and the
// root requirement. The real setpriv drop lives behind the `integration` tag.

// swapUseSeams installs fake use seams and returns a restore func + a pointer to
// the recorded exec target ("" until exec is attempted).
func swapUseSeams(t *testing.T, rep verify.Report, euid int) *string {
	t.Helper()
	var execedAccount string
	origVerify, origExec, origEuid := useVerifyReport, useExecLoginShell, useGeteuid
	useVerifyReport = func(ctx context.Context, r provision.Runner, cmd *cli.Command) verify.Report {
		return rep
	}
	useExecLoginShell = func(ctx context.Context, r provision.Runner, account string) error {
		execedAccount = account
		return nil // a real exec never returns; the fake records + returns nil
	}
	useGeteuid = func() int { return euid }
	t.Cleanup(func() {
		useVerifyReport, useExecLoginShell, useGeteuid = origVerify, origExec, origEuid
	})
	return &execedAccount
}

// greenReport / redReport are minimal reports whose Ok()/ExitCode() drive the gate.
func greenReport() verify.Report {
	return verify.Report{Account: "anon", Assertions: []verify.Assertion{{Name: "anonymized-exit", Ok: true}}}
}
func redReport() verify.Report {
	return verify.Report{Account: "anon", Assertions: []verify.Assertion{{Name: "leak-drop-v4", Ok: false, Detail: "a direct v4 connection REACHED its target (a leak)"}}}
}

// On a GREEN verify, use execs the login shell for the RESOLVED account (exit 0,
// the exec seam invoked with the right account).
func TestUseGreenExecsLoginShell(t *testing.T) {
	execed := swapUseSeams(t, greenReport(), 0)
	code := run([]string{"use"})
	if code != 0 {
		t.Errorf("run(use) on green = %d, want 0", code)
	}
	if *execed != "anon" {
		t.Errorf("exec seam invoked with account %q, want anon (green must drop into the account)", *execed)
	}
}

// A named `use <name>` on green execs the shell for the RESOLVED `anon-<name>`.
func TestUseGreenResolvesNamedAccount(t *testing.T) {
	execed := swapUseSeams(t, verify.Report{Account: "anon-work", Assertions: []verify.Assertion{{Ok: true, Name: "anonymized-exit"}}}, 0)
	if code := run([]string{"use", "work"}); code != 0 {
		t.Errorf("run(use work) on green = %d, want 0", code)
	}
	if *execed != "anon-work" {
		t.Errorf("exec seam invoked with %q, want anon-work", *execed)
	}
}

// On a RED verify, use exits NON-ZERO and does NOT exec any shell: you cannot get
// an un-anonymized shell via use.
func TestUseRedRefusesNoShell(t *testing.T) {
	execed := swapUseSeams(t, redReport(), 0)
	code := run([]string{"use"})
	if code == 0 {
		t.Errorf("run(use) on red = 0, want non-zero (must refuse a shell on a broken account)")
	}
	if *execed != "" {
		t.Errorf("exec seam invoked with %q on RED verify; use must NOT spawn a shell when verify fails", *execed)
	}
}

// use requires root (it drops to the account): a non-root invocation fails loud
// (non-zero) and does NOT run verify or exec a shell.
func TestUseRequiresRoot(t *testing.T) {
	execed := swapUseSeams(t, greenReport(), 1000)
	code := run([]string{"use"})
	if code == 0 {
		t.Errorf("run(use) as non-root = 0, want non-zero (use must require root)")
	}
	if *execed != "" {
		t.Errorf("exec seam invoked as non-root; use must refuse before dropping to the account")
	}
}

// swapRmSeams installs fake rm seams that record their calls (in order) into a
// shared event log, and returns a restore func + a pointer to that log. The
// forcing-remove fake records a "disable-shim" event (standing in for the real
// `systemctl disable --now anonctl-shim@<account>.service`); the provision-rm fake
// records a "userdel-shim" event (standing in for the real `userdel <account>-shim`).
// forceErr/rmErr let a test inject a failure into either seam to exercise
// proceed-and-report. This is the ONE place the rm ordering (disable-shim BEFORE
// userdel) is asserted at the runRm seam, mirroring swapUseSeams.
func swapRmSeams(t *testing.T, forceErr, rmErr error) *[]string {
	t.Helper()
	var events []string
	origForce, origRm := rmForcingRemove, rmProvisionRm
	rmForcingRemove = func(ctx context.Context, d forcing.Deps, account string) error {
		events = append(events, "disable-shim:"+account)
		return forceErr
	}
	rmProvisionRm = func(ctx context.Context, r provision.Runner, account string, purge bool) (provision.RmResult, error) {
		events = append(events, "userdel-shim:"+account)
		return provision.RmResult{Account: account, Shim: cli.ShimAccount(account), AccountRemoved: purge && rmErr == nil, ShimRemoved: purge && rmErr == nil}, rmErr
	}
	t.Cleanup(func() { rmForcingRemove, rmProvisionRm = origForce, origRm })
	return &events
}

// indexOfEvent returns the index of the first event with the given prefix, or -1.
func indexOfEvent(events []string, prefix string) int {
	for i, e := range events {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

// TEARDOWN ORDER (the fix for the e2e teardown regression, BUG 1): `rm` must STOP
// the shim unit (`disable --now`) BEFORE it `userdel`s the shim account. If the
// userdel runs first, it fails with "user is currently used by process" (the shim
// is still running as that UID) and the whole last-account cleanup never completes.
// This asserts the disable-shim event is recorded BEFORE the shim userdel at the
// runRm seam.
func TestRmDisablesShimBeforeUserdel(t *testing.T) {
	events := swapRmSeams(t, nil, nil)
	if code := run([]string{"rm", "--purge-account"}); code != 0 {
		t.Errorf("run(rm --purge-account) = %d, want 0", code)
	}
	disableIdx := indexOfEvent(*events, "disable-shim:")
	userdelIdx := indexOfEvent(*events, "userdel-shim:")
	if disableIdx < 0 || userdelIdx < 0 {
		t.Fatalf("expected both a disable-shim and a userdel-shim event; got %v", *events)
	}
	if disableIdx > userdelIdx {
		t.Errorf("userdel ran BEFORE disable-shim (the regression): %v", *events)
	}
}

// PROCEED-AND-REPORT: a failure disabling/removing the forcing must NOT abort the
// whole teardown. runRm still runs the userdel step (so the account is not left
// half-removed) and reports the failure with a non-zero exit. A half-torn-down
// account that silently stopped is worse than a fully-attempted, reported partial.
func TestRmProceedsToUserdelDespiteForcingRemoveError(t *testing.T) {
	events := swapRmSeams(t, errors.New("nft delete failed"), nil)
	code := run([]string{"rm", "--purge-account"})
	if code == 0 {
		t.Errorf("run(rm) with a forcing-remove failure = 0, want non-zero (the failure must be reported)")
	}
	if indexOfEvent(*events, "userdel-shim:") < 0 {
		t.Errorf("runRm aborted before the userdel step on a forcing-remove error; teardown must proceed-and-report: %v", *events)
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
