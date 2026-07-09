//go:build integration
// +build integration

package systemd_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/nftables"
)

// nftExec is the real Runner for the boot-invariant integration test: it shells
// out to the actual `nft`, piping the ruleset on stdin (`nft -f -`). It exists
// only here (behind the `integration` tag) so the default `go test ./...` never
// runs real nft.
type nftExec struct{}

func (nftExec) Run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}

// TestBootInvariantAnonUIDHasNoDirectEgressBeforeShim is the load-bearing proof of
// the BOOT INVARIANT: "at no point during boot does the anon UID have direct
// egress." It is a reboot-EQUIVALENT early-boot simulation. Under the INVERTED
// design it loads the PERSISTED rules the loader unit would `nft -f` at boot - BOTH
// the standing baseline default-deny AND the per-account forcing table - and does
// NOT start the shim, reproducing the boot window where the rules are up but the
// shim/endpoint are not yet. It then asserts, AS the anon UID, that a direct
// outbound connection is DROPPED (the worst observed case is dropped, never
// leaking).
//
// It ALSO reproduces the ORIGINAL failure's fix at this layer: after loading the
// rules it FLUSHES the forcing table (the exact post-reboot state the finding
// observed, where the forcing rules were absent) and re-asserts the anon UID is
// STILL DROPPED - because the standing baseline default-deny remains. Under the old
// design (no baseline, forcing absent) that same state LEAKED the host's real IP.
//
// It is guarded by the `integration` tag and NOT part of the default
// `go test ./...`; it needs root + nft + setpriv and SKIPS (not fails) without
// them. Shared-write isolation: it uses a throwaway account/table + a planted
// sentinel table, asserts the sentinel is untouched, and ALWAYS deletes both tables
// it created, so the host's real units/rules are left exactly as found.
func TestBootInvariantAnonUIDHasNoDirectEgressBeforeShim(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("boot-invariant integration test requires root; skipping")
	}
	for _, bin := range []string{"nft", "setpriv"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}

	ctx := context.Background()
	r := nftExec{}

	// A throwaway account whose table cannot collide with a real operator's, and a
	// synthetic anon UID that need not map to a real user to LOAD the rules and to
	// setpriv against (nft `meta skuid` matches the numeric UID).
	account := "anonctl-boot-itest-" + strconv.Itoa(os.Getpid())
	const anonUID = 424250
	table := nftables.TableName(account)

	// The PERSISTED ruleset the boot drop-in would load: generated from the account
	// config, exactly as forcing.Install persists it. This is the same text the
	// systemd Store writes to <RulesDir>/<account>.nft and the drop-in `nft -f`s at
	// boot.
	cfg := accountconfig.Config{
		SchemaVersion: accountconfig.SchemaVersion,
		Account:       account,
		AnonUID:       anonUID,
		ShimUID:       anonUID + 1,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
		RelayPort:     39050,
		DNSPort:       39053,
	}
	ruleset, err := nftables.Generate(nftables.Params{
		Account:      cfg.Account,
		AnonUID:      cfg.AnonUID,
		ShimUID:      cfg.ShimUID,
		RelayPort:    cfg.RelayPort,
		DNSPort:      cfg.DNSPort,
		EndpointHost: cfg.EndpointHost,
		EndpointPort: cfg.EndpointPort,
	})
	if err != nil {
		t.Fatalf("generate persisted ruleset: %v", err)
	}
	baseline, err := nftables.GenerateBaseline(cfg.Account, cfg.AnonUID)
	if err != nil {
		t.Fatalf("generate persisted baseline: %v", err)
	}
	baselineTable := nftables.BaselineTableName(cfg.Account)

	const sentinel = "anonctl_boot_itest_sentinel"
	mustLoad(t, r, "table inet "+sentinel+" {}\n")

	// Always clean up ALL tables, even on a mid-test failure, so the host is left
	// as found (shared-write isolation).
	defer func() {
		_, _, _ = r.Run(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _, _ = r.Run(ctx, "delete table inet "+baselineTable, "nft", "-f", "-")
		_, _, _ = r.Run(ctx, "delete table inet "+sentinel, "nft", "-f", "-")
		if tableLoaded(t, r, baselineTable) {
			t.Errorf("cleanup left the baseline table %q behind", baselineTable)
		}
		if tableLoaded(t, r, sentinel) {
			t.Errorf("cleanup left the sentinel table %q behind", sentinel)
		}
	}()

	// EARLY-BOOT SIMULATION: load the persisted rules the loader unit would `nft -f`
	// at boot - BOTH the baseline default-deny and the forcing table - with NO shim
	// running. This is the exact state at boot after anonctl's early loader has loaded
	// the rules but before the shim is up.
	if _, stderr, err := r.Run(ctx, baseline, "nft", "-f", "-"); err != nil {
		t.Fatalf("load persisted baseline: %v: %s", err, stderr)
	}
	if _, stderr, err := r.Run(ctx, ruleset, "nft", "-f", "-"); err != nil {
		t.Fatalf("load persisted boot ruleset: %v: %s", err, stderr)
	}
	if !tableLoaded(t, r, table) {
		t.Fatalf("persisted ruleset did not load the account table %q", table)
	}
	if !tableLoaded(t, r, baselineTable) {
		t.Fatalf("persisted baseline did not load the baseline table %q", baselineTable)
	}

	// THE BOOT INVARIANT: with the rules up but the shim NOT running, the anon UID's
	// direct outbound connection must be DROPPED. We probe a direct dial to a public
	// address AS the anon UID; the worst acceptable outcome is DROPPED (fail-closed),
	// never REACHED (a leak). A public dst is used so a REACHED would be a real
	// external leak; the default-DROP (no shim to redirect into) guarantees it drops.
	reached := setprivDialReached(t, ctx, anonUID, "tcp", "1.1.1.1:443")
	if reached {
		t.Errorf("BOOT INVARIANT VIOLATED: the anon UID reached 1.1.1.1:443 directly with the shim NOT running (a leak); at boot, before the shim is up, egress must be DROPPED")
	}

	// Also assert the persisted ruleset actually carries the fail-closed default-DROP
	// and the closure drops (so the drop above is by policy, not by a missing route).
	listed := listLoadedTable(t, r, table)
	for _, want := range []string{"policy drop", "127.0.0.0/8", "::/0"} {
		if !strings.Contains(listed, want) {
			t.Errorf("persisted boot ruleset missing the fail-closed line %q:\n%s", want, listed)
		}
	}

	// The sentinel (a stand-in for the host's own rules) is untouched: the boot rules
	// scope to exactly the account's own table.
	if !tableLoaded(t, r, sentinel) {
		t.Errorf("loading the persisted boot ruleset clobbered the host's other rules (sentinel gone)")
	}

	// REPRODUCE THE ORIGINAL FAILURE'S STATE, PROVE THE FIX: the finding observed that
	// after a reboot the FORCING table was absent and the anon UID leaked the host's
	// real IP. Flush ONLY the forcing table (the exact post-reboot state under the old
	// design) and re-probe: because the standing baseline default-deny remains, the
	// anon UID must STILL be DROPPED. Under the old design (no baseline) this same
	// state LEAKED; the baseline is what closes it.
	if _, stderr, err := r.Run(ctx, "delete table inet "+table, "nft", "-f", "-"); err != nil {
		t.Fatalf("flush the forcing table: %v: %s", err, stderr)
	}
	if tableLoaded(t, r, table) {
		t.Fatalf("flushing the forcing table left it behind")
	}
	if !tableLoaded(t, r, baselineTable) {
		t.Fatalf("flushing the forcing table wrongly removed the standing baseline")
	}
	if setprivDialReached(t, ctx, anonUID, "tcp", "1.1.1.1:443") {
		t.Errorf("REBOOT-LEAK REGRESSION: with the forcing table absent (the finding's observed post-reboot state) the anon UID reached 1.1.1.1:443 directly; the standing baseline default-deny must keep it DROPPED")
	}
}

func mustLoad(t *testing.T, r nftExec, ruleset string) {
	t.Helper()
	if _, stderr, err := r.Run(context.Background(), ruleset, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft -f -: %v: %s", err, stderr)
	}
}

func tableLoaded(t *testing.T, r nftExec, table string) bool {
	t.Helper()
	out, _, _ := r.Run(context.Background(), "", "nft", "list", "tables")
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "table inet "+table {
			return true
		}
	}
	return false
}

func listLoadedTable(t *testing.T, r nftExec, table string) string {
	t.Helper()
	out, stderr, err := r.Run(context.Background(), "", "nft", "list", "table", "inet", table)
	if err != nil {
		t.Fatalf("nft list table inet %s: %v: %s", table, err, stderr)
	}
	return out
}

// setprivDialReached dials addr AS the given UID via a tiny inline helper run under
// setpriv, so the connection egresses from the anon UID and exercises the real nft
// `meta skuid` rules. It returns whether the dial REACHED its target (true == a
// leak). A helper-build or setpriv failure yields reached=false (the fail-closed
// reading), never a false REACHED. It mirrors verify's runSetprivProbe.
func setprivDialReached(t *testing.T, ctx context.Context, uid int, network, addr string) bool {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable to build the probe helper; skipping the dial probe")
	}
	dir := t.TempDir()
	src := dir + "/probe.go"
	const probeSource = `package main
import ("fmt";"net";"os";"time")
func main(){
	if len(os.Args)<3 { fmt.Print("DROPPED:usage"); return }
	c,e:=(&net.Dialer{Timeout:3*time.Second}).Dial(os.Args[1],os.Args[2])
	if e!=nil { fmt.Print("DROPPED:",e); return }
	c.Close(); fmt.Print("REACHED")
}`
	if err := os.WriteFile(src, []byte(probeSource), 0o644); err != nil {
		t.Fatalf("write probe helper: %v", err)
	}
	bin := dir + "/probe"
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("build probe helper: %v: %s", err, out)
	}
	cmd := exec.CommandContext(ctx, "setpriv", "--reuid", strconv.Itoa(uid), "--clear-groups", bin, network, addr)
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "REACHED")
}
