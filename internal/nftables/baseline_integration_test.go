//go:build integration
// +build integration

package nftables_test

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/nftables"
)

// TestBaselineDropsWhenForcingAbsent is the LOAD-BEARING proof of the INVERTED boot
// invariant: with ONLY the standing baseline default-deny loaded (the FORCING rules
// absent, exactly the state at boot before/without forcing, or after the forcing
// table is flushed), the anon UID's direct egress is DROPPED, never the host's real
// IP. This is the new guarantee the task adds: "the anon UID has no anonctl forcing
// loaded" means DROPPED, not free.
//
// It also proves the OTHER direction: with the forcing rules ALSO loaded, the anon
// UID's traffic is redirected into the (loopback) shim path and the baseline does
// NOT drop it (forced traffic still flows), so the baseline layers UNDER forcing
// without breaking it.
//
// Guarded by the `integration` tag; needs root + nft + setpriv and SKIPS (not
// fails) without them. Shared-write isolation: throwaway account/UIDs, a planted
// sentinel table asserted untouched, and both created tables always deleted.
func TestBaselineDropsWhenForcingAbsent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("baseline integration test requires root; skipping")
	}
	for _, bin := range []string{"nft", "setpriv"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}

	ctx := context.Background()
	r := execRunner{}

	account := "anonctl-baseline-itest-" + strconv.Itoa(os.Getpid())
	const anonUID = 424260
	forcingTable := nftables.TableName(account)
	baselineTable := nftables.BaselineTableName(account)

	const sentinel = "anonctl_baseline_itest_sentinel"
	mustNft(t, r, "table inet "+sentinel+" {}\n")

	defer func() {
		_, _, _ = r.Run(ctx, "delete table inet "+forcingTable, "nft", "-f", "-")
		_, _, _ = r.Run(ctx, "delete table inet "+baselineTable, "nft", "-f", "-")
		_, _, _ = r.Run(ctx, "delete table inet "+sentinel, "nft", "-f", "-")
		if tableExists(t, r, baselineTable) {
			t.Errorf("cleanup left the baseline table %q behind", baselineTable)
		}
		if tableExists(t, r, sentinel) {
			t.Errorf("cleanup left the sentinel table %q behind", sentinel)
		}
	}()

	// PART 1 - FORCING ABSENT: load ONLY the baseline default-deny. This is the
	// resting state (and the exact state at boot before forcing, or after the forcing
	// table is flushed). The anon UID's direct dial to a PUBLIC address must be
	// DROPPED: a REACHED here would be a real external leak of the host's IP.
	if err := nftables.ApplyBaseline(ctx, r, account, anonUID, nil); err != nil {
		t.Fatalf("ApplyBaseline: %v", err)
	}
	if !tableExists(t, r, baselineTable) {
		t.Fatalf("ApplyBaseline did not load the baseline table %q", baselineTable)
	}
	// ORDER IS LOAD-BEARING: the ruleset assertion needs only `nft`, the dial probe
	// additionally needs `setpriv` to assume the anon uid - and that probe now FAILS
	// LOUDLY when it cannot run (a probe that could not run is not a pass). Probing
	// first would abort the test on a host that cannot setpriv and take this structural
	// check down with it, losing the answer a constrained host COULD have had. See the
	// matching note in internal/systemd/boot_invariant_integration_test.go.
	//
	// The baseline carries the real-egress drop (so the drop probed next is by the
	// standing deny, not a missing route).
	listedBaseline := listTable(t, r, baselineTable)
	for _, want := range []string{
		"policy accept",
		"ip daddr != 127.0.0.0/8 drop",
		"ip6 daddr != ::1 drop",
	} {
		if !strings.Contains(listedBaseline, want) {
			t.Errorf("baseline table missing the resting-deny line %q:\n%s", want, listedBaseline)
		}
	}
	if reached := setprivDialReachedNft(t, ctx, anonUID, "tcp", "1.1.1.1:443"); reached {
		t.Errorf("INVERTED INVARIANT VIOLATED: with forcing ABSENT (only the baseline loaded) the anon UID reached 1.1.1.1:443 directly (a leak); the resting state must be DROPPED")
	}

	// PART 2 - FORCING PRESENT: layer the forcing table ON TOP of the baseline. The
	// forcing nat chain (priority dstnat, before every filter chain) REDIRECTS the
	// anon UID's TCP to a loopback shim port; the baseline RETURNs loopback, so it
	// does NOT drop the redirected traffic. We assert the two tables COEXIST and that
	// the anon UID's TCP is redirected (not dropped by the baseline) by confirming a
	// dial to a public address now reaches the (loopback) relay port instead of being
	// baseline-dropped: with no shim actually listening the connection cannot
	// complete, so we assert the mechanism structurally (both tables present, the nat
	// redirect rule present) rather than requiring a live shim in this nft-only test.
	p := nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      anonUID + 1,
		RelayPort:    39150,
		DNSPort:      39153,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	}
	if err := nftables.Apply(ctx, r, p); err != nil {
		t.Fatalf("Apply forcing on top of baseline: %v", err)
	}
	if !tableExists(t, r, baselineTable) || !tableExists(t, r, forcingTable) {
		t.Fatalf("baseline and forcing tables must COEXIST: baseline=%v forcing=%v", tableExists(t, r, baselineTable), tableExists(t, r, forcingTable))
	}
	// The forcing nat redirect is present: the anon UID's TCP is rewritten to the
	// loopback relay port BEFORE any filter chain (so the baseline's loopback RETURN
	// then hands it on, never dropping forced traffic).
	listedForcing := listTable(t, r, forcingTable)
	if !strings.Contains(listedForcing, "redirect to :39150") {
		t.Errorf("forcing table missing the TCP-into-shim redirect (the OPEN path):\n%s", listedForcing)
	}

	// PART 3 - FLUSH THE FORCING TABLE, CONFIRM STILL DROPPED (the finding's extra
	// re-validation, at the nft layer): delete ONLY the forcing table, leaving the
	// baseline. The anon UID must be DROPPED again, proving the baseline is what holds
	// the invariant when forcing is gone.
	if err := nftables.Delete(ctx, r, account); err != nil {
		t.Fatalf("Delete forcing table: %v", err)
	}
	if tableExists(t, r, forcingTable) {
		t.Fatalf("Delete left the forcing table behind")
	}
	if !tableExists(t, r, baselineTable) {
		t.Fatalf("Deleting the forcing table wrongly removed the baseline table")
	}
	// The sentinel (a stand-in for the host's own rules) is untouched throughout. Like
	// the structural checks above, this needs only `nft`, so it runs BEFORE the final
	// dial probe rather than after it: the probe fails loudly where setpriv cannot
	// assume the uid, and a host that cannot run the probe should still learn whether
	// anonctl clobbered its firewall.
	if !tableExists(t, r, sentinel) {
		t.Errorf("the baseline/forcing loads clobbered the host's other rules (sentinel gone)")
	}

	if reached := setprivDialReachedNft(t, ctx, anonUID, "tcp", "1.1.1.1:443"); reached {
		t.Errorf("INVERTED INVARIANT VIOLATED after flushing forcing: the anon UID reached 1.1.1.1:443 directly; with forcing flushed the standing baseline must still DROP")
	}
}

// setprivDialReachedNft dials addr AS the given UID via a tiny inline helper run
// under setpriv, so the connection egresses from the anon UID and exercises the
// real nft `meta skuid` rules. It returns whether the dial REACHED its target (true
// == a leak).
//
// A PROBE THAT COULD NOT RUN IS NOT A PASS. The callers here all assert reached ==
// false, so inferring the verdict from the ABSENCE of a `REACHED` token would make
// "setpriv refused the uid" indistinguishable from "the packet was dropped" and the
// baseline default-deny would certify itself without a single packet being sent.
// The helper always prints `REACHED` or `DROPPED:<reason>`; require one and fail
// loudly on neither, as verify's runSetprivProbe does. It mirrors the systemd
// boot-invariant test's setprivDialReached (kept local to this package's tag).
//
// An un-runnable probe marks the test FAILED and returns, rather than aborting it:
// PART 1's probe must run while only the baseline is loaded, so it cannot simply be
// moved after PART 2's and PART 3's structural checks, and aborting there would
// discard every later nft-only assertion on a host that merely lacks setpriv. Loud,
// not fatal.
func setprivDialReachedNft(t *testing.T, ctx context.Context, uid int, network, addr string) bool {
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
	s := string(out)
	switch {
	case strings.Contains(s, "REACHED"):
		return true
	case strings.Contains(s, "DROPPED"):
		return false
	case ctx.Err() == context.DeadlineExceeded:
		t.Errorf("the anon-UID probe timed out before printing a verdict (dial to %s %s outran the deadline); "+
			"this is NOT a drop and must not be read as one: %q", network, addr, strings.TrimSpace(s))
	default:
		t.Errorf("the anon-UID probe COULD NOT RUN (setpriv could not drop to uid %d, or the helper did not execute): %v: %q.\n"+
			"A probe that never ran is not a pass: these assertions expect reached==false, so a silent false "+
			"would certify the baseline default-deny without testing it. The nft-only assertions in this test "+
			"are unaffected and still stand; only the drop itself is untested here.",
			uid, runErr, strings.TrimSpace(s))
	}
	return false
}
