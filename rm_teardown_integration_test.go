//go:build integration
// +build integration

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anonctl/internal/systemd"
)

// TestRealRmDisablesShimBeforeUserdelLeavesNoResidue is the isolated
// `integration`-tagged proof of the teardown-ordering fix (the e2e finding's
// PART E / BUG 1): a single teardown of the LAST account on a live host, with the
// shim genuinely RUNNING as its dedicated shim UID, must STOP the shim BEFORE it
// `userdel`s the shim account, so `userdel` no longer fails with "user is currently
// used by process" and the whole cleanup completes (no anon user, no shim user, no
// nft tables, no at-rest config) while the host's OTHER nft rules stay untouched.
//
// It reproduces the finding's exact failure first (a raw `userdel` of the shim
// WHILE a process runs as its UID FAILS), then drives the SAME ordered teardown the
// production runRm now runs (rmForcingRemove -> rmProvisionRm) and asserts userdel
// succeeds and no residue remains. The running shim is stood in by a real transient
// systemd unit named EXACTLY `anonctl-shim@<account>.service` (the same instance
// forcing.Remove disables) whose ExecStart is a trivial long-lived process running
// as the shim UID, so this needs no live Tor endpoint or shim binary yet is a
// faithful "a process holds the shim UID under the shim unit" reproduction.
//
// Isolation: a PID-suffixed throwaway account (cannot collide with a real one),
// scratch config/env/rules dirs (never the real /etc/anonctl), a planted host
// sentinel nft table asserted untouched, and it ALWAYS tears everything down. It
// SKIPS (never fails) without root / systemd-run / nft / useradd, so
// `go test -tags integration ./...` still passes on an unprivileged box.
func TestRealRmDisablesShimBeforeUserdelLeavesNoResidue(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("rm teardown integration requires root (provisions accounts, runs a unit as the shim UID, loads nft); skipping")
	}
	for _, bin := range []string{"systemd-run", "systemctl", "nft", "useradd", "userdel", "getent", "sleep"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}
	// The shim-stop-before-userdel reproduction needs a real systemd (PID 1) so the
	// transient unit truly owns a process running as the shim UID. `systemctl show`
	// returns systemd's version only when the manager is actually up; a hard failure
	// (or empty output) means there is no systemd to run a transient unit against.
	if out, _, err := runCmd(context.Background(), "systemctl", "show", "-p", "Version", "systemd"); err != nil || strings.TrimSpace(out) == "" {
		t.Skip("no usable systemd (PID 1) to run a transient shim unit; skipping")
	}

	ctx := context.Background()
	r := provision.ExecRunner{}
	account := cli.ResolveAccount("rmteardown-" + strconv.Itoa(os.Getpid()))
	shim := cli.ShimAccount(account)
	instance := systemd.InstanceName(account)

	// Provision the login + dedicated shim accounts (the real useradd path).
	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}

	// Resolve the shim UID we must run the stand-in process as.
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		t.Fatalf("provision.Status(%s): %v", account, err)
	}
	shimUID := atoiOr(st.ShimUID, 0)
	if shimUID <= 0 {
		t.Fatalf("could not resolve a shim UID for %s (got %q)", shim, st.ShimUID)
	}

	// Scratch stores so we never touch the real /etc/anonctl. Persist a minimal
	// account config so forcing.Remove's ConfigStore.Remove + HasForcedAccounts see
	// a real record to clear (the last-account path).
	root := t.TempDir()
	deps := forcing.Deps{
		NftRunner:     nftExecRunner{},
		SystemdRunner: systemd.ExecRunner{},
		ConfigStore:   accountconfig.Store{BaseDir: filepath.Join(root, "cfg")},
		SystemdStore: systemd.Store{
			UnitDir:  filepath.Join(root, "systemd"),
			EnvDir:   filepath.Join(root, "shim"),
			RulesDir: filepath.Join(root, "nftables"),
		},
	}
	if err := deps.ConfigStore.Write(accountconfig.Config{
		Account:      account,
		AnonUID:      atoiOr(st.UID, 0),
		ShimUID:      shimUID,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	}); err != nil {
		t.Fatalf("persist scratch account config: %v", err)
	}

	// Load the REAL per-account forcing + baseline nft tables so teardown has real
	// tables to delete, and a planted host sentinel to prove the delete is scoped.
	table := nftables.TableName(account)
	baselineTable := nftables.BaselineTableName(account)
	const sentinel = "anonctl_rmteardown_sentinel"
	mustNft(t, ctx, "add table inet "+sentinel)
	if err := nftables.ApplyBaseline(ctx, nftExecRunner{}, account, atoiOr(st.UID, 0), nil); err != nil {
		t.Fatalf("apply baseline: %v", err)
	}
	if err := nftables.Apply(ctx, nftExecRunner{}, nftables.Params{
		Account:      account,
		AnonUID:      atoiOr(st.UID, 0),
		ShimUID:      shimUID,
		RelayPort:    accountconfig.DefaultRelayPort,
		DNSPort:      accountconfig.DefaultDNSPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	}); err != nil {
		t.Fatalf("apply forcing ruleset: %v", err)
	}

	// Start a REAL long-lived process AS the shim UID, under the EXACT shim unit name
	// forcing.Remove will disable, so the shim UID is genuinely "currently used by a
	// process" (the finding's blocking condition).
	if _, stderr, err := runCmd(ctx, "systemd-run", "--unit="+instance, "--uid="+strconv.Itoa(shimUID),
		"/bin/sleep", "600"); err != nil {
		t.Skipf("could not start the stand-in shim unit as uid %d (%v: %s); skipping", shimUID, err, stderr)
	}

	// ALWAYS tear everything down, even on a mid-test failure, so the host is left as
	// found (isolation): stop the transient unit, delete our nft tables + the
	// sentinel, and purge the accounts.
	defer func() {
		_, _, _ = runCmd(ctx, "systemctl", "stop", instance)
		_, _, _ = runCmd(ctx, "systemctl", "reset-failed", instance)
		_, _, _ = runCmd(ctx, "nft", "delete", "table", "inet", table)
		_, _, _ = runCmd(ctx, "nft", "delete", "table", "inet", baselineTable)
		_, _, _ = runCmd(ctx, "nft", "delete", "table", "inet", sentinel)
		_, _ = provision.Rm(ctx, r, account, true /* purgeAccount */)
	}()

	// Give the unit a moment to actually start its process as the shim UID.
	waitForUnitActive(t, ctx, instance, 3*time.Second)

	// REPRODUCE THE FINDING: with the shim running as its UID, a raw userdel of the
	// shim account FAILS ("user is currently used by process"). This is the exact
	// abort the old ordering hit (userdel BEFORE the disable).
	if _, stderr, err := runCmd(ctx, "userdel", "--remove", shim); err == nil {
		t.Fatalf("expected userdel of the shim %q to FAIL while its unit runs (the regression), but it succeeded", shim)
	} else if !strings.Contains(stderr, "currently used by process") {
		t.Logf("userdel of a live-shim account failed as expected but with an unexpected message: %v: %s", err, stderr)
	}

	// THE FIX, in production order: rmForcingRemove disables --now the shim FIRST (so
	// nothing runs as the shim UID), then rmProvisionRm userdels the accounts. This
	// is exactly the order runRm now runs.
	if err := rmForcingRemove(ctx, deps, account); err != nil {
		t.Fatalf("rmForcingRemove(%s): %v (the disable-shim step must succeed so userdel can follow)", account, err)
	}
	res, err := rmProvisionRm(ctx, r, account, true /* purgeAccount */)
	if err != nil {
		t.Fatalf("rmProvisionRm(%s) after disabling the shim: %v (userdel must now succeed - the whole point of the fix)", account, err)
	}
	if !res.AccountRemoved || !res.ShimRemoved {
		t.Errorf("purge did not remove both accounts: %+v", res)
	}

	// NO RESIDUE: no anon user, no shim user, no forcing/baseline nft tables, no
	// at-rest config.
	if present(ctx, r, account) {
		t.Errorf("teardown left the login account %q behind", account)
	}
	if present(ctx, r, shim) {
		t.Errorf("teardown left the shim account %q behind", shim)
	}
	if nftTableLoaded(t, ctx, table) {
		t.Errorf("teardown left the forcing table %q behind", table)
	}
	if nftTableLoaded(t, ctx, baselineTable) {
		t.Errorf("teardown left the baseline table %q behind", baselineTable)
	}
	if _, err := deps.ConfigStore.Read(account); err != accountconfig.ErrNotFound {
		t.Errorf("teardown left the at-rest config behind: %v", err)
	}

	// THE HOST IS UNTOUCHED: the planted sentinel table survives (teardown scoped to
	// exactly the account's own tables, never a broad flush).
	if !nftTableLoaded(t, ctx, sentinel) {
		t.Errorf("teardown clobbered the host's other nft rules (the sentinel table is gone)")
	}
}

// nftExecRunner is the real nftables.Runner for this integration test: it shells
// out to `nft`, piping the ruleset on stdin (`nft -f -`). Behind the `integration`
// tag so the default `go test ./...` never runs real nft.
type nftExecRunner struct{}

func (nftExecRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}

// mustNft runs a plain `nft <args...>` (no piped ruleset) and fails on error.
func mustNft(t *testing.T, ctx context.Context, args string) {
	t.Helper()
	if _, stderr, err := runCmd(ctx, "nft", strings.Fields(args)...); err != nil {
		t.Fatalf("nft %s: %v: %s", args, err, stderr)
	}
}

// nftTableLoaded reports whether `table inet <name>` is currently loaded.
func nftTableLoaded(t *testing.T, ctx context.Context, name string) bool {
	t.Helper()
	out, _, _ := runCmd(ctx, "nft", "list", "tables")
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "table inet "+name {
			return true
		}
	}
	return false
}

// waitForUnitActive polls until the unit reports active (its process is running as
// the shim UID) or the deadline passes. Best-effort: the userdel-fails reproduction
// below is the real gate on the process actually holding the UID.
func waitForUnitActive(t *testing.T, ctx context.Context, instance string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if out, _, _ := runCmd(ctx, "systemctl", "is-active", instance); strings.TrimSpace(out) == "active" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// present reports whether an account exists in passwd (getent), reused by the
// no-residue assertions.
func present(ctx context.Context, r provision.Runner, account string) bool {
	out, _, _ := r.Run(ctx, "getent", "passwd", account)
	return strings.HasPrefix(strings.TrimSpace(out), account+":")
}
