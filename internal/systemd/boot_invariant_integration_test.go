//go:build integration
// +build integration

package systemd_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
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
	baseline, err := nftables.GenerateBaseline(cfg.Account, cfg.AnonUID, nil)
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

	// Also assert the persisted ruleset actually carries the fail-closed drops (so the
	// drop above is by an EXPLICIT RULE, not by a missing route).
	//
	// This used to assert `policy drop` on the base chain. It no longer can, and the
	// reason matters to this test specifically: that drop policy was adjudicating
	// packets the kernel could not attribute to ANY uid, which killed every other
	// uid's larger TCP transfers box-wide. The base chain is now policy ACCEPT holding
	// only positive-uid jumps, and fail-closed moved into the anon closure chain's
	// unconditional TERMINAL DROP (docs/adr/0002). The boot invariant this test guards
	// is unchanged -- un-forced still means dropped -- so the assertion FOLLOWS the
	// rule that now enforces it rather than being deleted.
	listed := listLoadedTable(t, r, table)
	for _, want := range []string{
		fmt.Sprintf("meta skuid %d jump anon_filter", anonUID),
		"127.0.0.0/8",
		"::/0",
	} {
		if !strings.Contains(listed, want) {
			t.Errorf("persisted boot ruleset missing the fail-closed line %q:\n%s", want, listed)
		}
	}
	if strings.Contains(listed, "skuid !=") {
		t.Errorf("the persisted boot ruleset carries a NEGATIVE uid match: at boot this chain\n"+
			"adjudicates every packet the host sends, so it must only ever match the uids it\n"+
			"governs positively:\n%s", listed)
	}
	if last := lastAnonFilterRule(listed); last != "drop" {
		t.Errorf("BOOT INVARIANT AT RISK: the anon closure chain must END in an unconditional\n"+
			"`drop`; its last rule is %q. Without it the anon UID's non-redirected egress falls\n"+
			"back to the base chain's policy ACCEPT. The probe above would still pass, because\n"+
			"the standing baseline table drops that traffic too -- which is exactly how this\n"+
			"regression hides:\n%s", last, listed)
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

// lastAnonFilterRule returns the final rule of the anon closure chain as the
// KERNEL prints it, which is where fail-closed now lives. See docs/adr/0002.
func lastAnonFilterRule(listed string) string {
	inChain := false
	last := ""
	for _, line := range strings.Split(listed, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inChain {
			if trimmed == "chain anon_filter {" {
				inChain = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "type ") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		last = trimmed
	}
	return last
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
// leak).
//
// A PROBE THAT COULD NOT RUN IS NOT A PASS, and getting that wrong here is
// specifically dangerous because of the POLARITY: every caller asserts reached ==
// false, so "the probe never ran" and "the packet was dropped" produce the same
// verdict and the boot invariant certifies itself without being tested. This used
// to discard the exit status and read the verdict from the ABSENCE of a token
// (`out, _ := cmd.CombinedOutput(); return strings.Contains(out, "REACHED")`), so
// setpriv refusing the uid, the helper failing to exec, or the deadline firing all
// read as a clean DROP. Demonstrated under `unshare -rn`, where the uid is unmapped
// and `setpriv --reuid` fails outright: the test passed having dialled nothing.
//
// The helper ALWAYS prints exactly `REACHED` or `DROPPED:<reason>`, so the honest
// contract is to REQUIRE one of them and fail loudly on neither, which is what
// verify's runSetprivProbe already does. Do not weaken this back into an
// absence-of-token inference.
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
	out, runErr := cmd.CombinedOutput()
	return readProbeVerdict(t, ctx, uid, network, addr, string(out), runErr)
}

// readProbeVerdict turns a probe helper's output into a verdict, REFUSING to infer
// one from the absence of a token. Neither sentinel means the probe did not run to
// completion under the anon UID, which is an un-runnable probe, not a dropped
// connection: it fails the test loudly rather than handing back the value every
// caller reads as a pass. The two ways that happens are distinguished so the
// failure names the real cause instead of sending diagnosis down the wrong path.
func readProbeVerdict(t *testing.T, ctx context.Context, uid int, network, addr, out string, runErr error) bool {
	t.Helper()
	switch {
	case strings.Contains(out, "REACHED"):
		return true
	case strings.Contains(out, "DROPPED"):
		return false
	case ctx.Err() == context.DeadlineExceeded:
		t.Fatalf("the anon-UID probe timed out before printing a verdict (dial to %s %s outran the deadline); "+
			"this is NOT a drop and must not be read as one: %q", network, addr, strings.TrimSpace(out))
	default:
		t.Fatalf("the anon-UID probe COULD NOT RUN (setpriv could not drop to uid %d, or the helper did not execute): %v: %q. "+
			"A probe that never ran is not a pass: the assertions here all expect reached==false, so returning false "+
			"would certify the boot invariant without testing it.", uid, runErr, strings.TrimSpace(out))
	}
	return false
}
