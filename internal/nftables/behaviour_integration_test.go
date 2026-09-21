//go:build integration
// +build integration

package nftables_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/nftables"
)

// This file is the BEHAVIOURAL half of the nftables tests, and it exists because
// the generator's other tests assert on generated rule TEXT -- which is exactly
// what let a box-wide bug through. The old filter chain was a base chain on the
// output hook with `policy drop` whose only pass-through for uninvolved UIDs was a
// NEGATIVE match (`meta skuid != <anon> meta skuid != <shim> accept`). The text
// looked correct and the semantics were not: a locally generated packet carrying no
// attributable socket UID matches neither `skuid == u` nor `skuid != u`, so it took
// no accept, fell through, and was killed by the policy drop. Since a `drop` is
// terminal across every base chain at a hook, that silently broke larger TCP
// transfers for EVERY uid on the box, root included.
//
// So these tests LOAD the real generated ruleset and push real traffic through it.
//
// ISOLATION (the repo's test-isolation rule). Everything runs inside a FRESH
// NETWORK NAMESPACE (`unshare --net`), so the rules are loaded into a ruleset that
// starts empty and is destroyed with the namespace: the host's own nftables cannot
// be affected even if the ruleset under test is catastrophically wrong, which
// matters here because the regression being guarded is precisely "this chain kills
// the box's networking". A throwaway account name and a planted sentinel table
// give the same account-scoping proof the sibling apply tests make, and the host's
// ruleset is captured before and after and asserted byte-identical.
//
// The namespace is entered by re-executing THIS TEST BINARY under `unshare --net`
// (the helper below), because a network namespace is a property of the process.

const (
	helperEnv    = "ANONCTL_NFT_NETNS_HELPER"
	helperOutEnv = "ANONCTL_NFT_NETNS_OUT"

	// offBoxAddr is TEST-NET-3 (RFC 5737, documentation-only): it is never routable
	// off the namespace, and the namespace has no real uplink regardless. It stands
	// in for "the anon UID's real, non-loopback egress".
	offBoxAddr = "203.0.113.9"

	// loopbackPort is where the in-namespace HTTP server listens for the bulk
	// transfer, and the port both observation chains key on.
	loopbackPort = 18080

	// anonUID / shimUID are synthetic UIDs for the throwaway account. They need not
	// exist in /etc/passwd: nft matches numerically, and `setpriv --reuid` takes a
	// number. They must NOT be the uid the test itself runs as (root/0), because the
	// whole point is to prove an UNINVOLVED uid is untouched.
	anonUID = 424242
	shimUID = 424243
)

// probeResult is what the in-namespace helper reports back to the test.
type probeResult struct {
	Scenario string `json:"scenario"`

	// Bulk-transfer outcome (the uninvolved-uid scenario).
	Attempts  int `json:"attempts"`
	Succeeded int `json:"succeeded"`
	Bytes     int `json:"bytes"`

	// TcpExtTCPRetransFail delta across the transfers: a retransmission that the
	// local output path REFUSED. This is the counter that went up on the host where
	// the bug was found, and it must stay at zero.
	RetransFailDelta int `json:"retransFailDelta"`

	// The bracketing observation counters. `Pre` counts the packets of the traffic
	// under test that ENTERED the forcing filter chain (an observation chain at
	// filter priority -50: after nat_out at dstnat/-100, before filter_out at 0).
	// `Post` counts the ones that SURVIVED it (priority 50). Anything the forcing
	// chain dropped is counted by Pre and missing from Post, so `Pre - Post` is the
	// number of packets the forcing table adjudicated away.
	//
	// This is the faithful translation of the original investigation's "keep a
	// counter rule just below the pass-through and assert it is ZERO". The fixed
	// chain has no pass-through rule to sit below (an uninvolved packet takes no
	// jump at all), so the counter is placed where the question is actually decided:
	// it measures whether ANY packet of an uninvolved uid's flow was dropped,
	// whatever shape the chain has. It cannot rot the way a position-dependent
	// counter would.
	Pre  int `json:"pre"`
	Post int `json:"post"`

	Err string `json:"err"`
}

// TestUninvolvedUIDIsNeverAdjudicated is the regression test for the box-wide bug.
// It loads the REAL generated forcing ruleset for a throwaway account whose anon
// and shim UIDs are NOT the uid running the test, then pushes enough data through a
// loopback socket to generate the packets the old chain could not attribute (bulk
// TCP output is emitted from a deferred context where `meta skuid` has no socket
// owner to read; so are pure ACKs, the FIN, and RTO retransmissions).
//
// It asserts three things, and the third is the one that proves the property rather
// than merely observing a symptom:
//
//  1. every transfer completes, at 600KB and at 5MB (the old chain passed 10KB and
//     stalled at larger sizes, which is why this was misdiagnosed for a while);
//  2. the TcpExtTCPRetransFail delta is ZERO (no retransmission was refused by the
//     local output path);
//  3. ZERO packets of the uninvolved uid's flow were adjudicated away by the
//     forcing chain at all -- not "the transfer survived", but "no uninvolved
//     packet was ever dropped".
func TestUninvolvedUIDIsNeverAdjudicated(t *testing.T) {
	requireNamespaceCapableRoot(t)

	before := hostRuleset(t)

	for _, sizeKB := range []int{600, 5120} {
		t.Run(fmt.Sprintf("%dKB", sizeKB), func(t *testing.T) {
			const attempts = 10
			got := runInNamespace(t, "uninvolved", map[string]string{
				"SIZE_KB":  strconv.Itoa(sizeKB),
				"ATTEMPTS": strconv.Itoa(attempts),
			})

			if got.Succeeded != attempts {
				t.Errorf("only %d/%d loopback transfers of %dKB completed as an UNINVOLVED uid.\n"+
					"This is the box-wide bug: the forcing chain is adjudicating packets it cannot\n"+
					"attribute to the account it governs, so every uid's larger TCP transfers stall.",
					got.Succeeded, attempts, sizeKB)
			}
			if got.RetransFailDelta != 0 {
				t.Errorf("TcpExtTCPRetransFail rose by %d during %d uninvolved-uid transfers: the local\n"+
					"output path REFUSED a retransmission. A retransmission carries no socket uid, so a\n"+
					"chain that adjudicates unattributable packets kills it and the transfer stalls with\n"+
					"no error on either side.", got.RetransFailDelta, attempts)
			}
			if got.Pre != got.Post {
				t.Errorf("the forcing chain dropped %d of the %d packets belonging to an UNINVOLVED uid\n"+
					"(%d entered the chain, %d survived it). It must drop NONE: every drop has to live\n"+
					"inside a chain entered only by a POSITIVE `meta skuid` match.",
					got.Pre-got.Post, got.Pre, got.Pre, got.Post)
			}
			// `<= 0`, not `== 0`: counter() returns -1 when the observation table could
			// not be READ, precisely so a failed read can never be mistaken for a genuine
			// zero. With `== 0` a double read failure gives Pre == Post == -1, which
			// satisfies the drop assertion above AND slips past this guard, so the test
			// goes green having measured nothing.
			if got.Pre <= 0 {
				t.Errorf("the observation chain reported %d packets (%d bytes transferred): the probe did\n"+
					"not exercise the rules, or the counters could not be read, so a zero drop count\n"+
					"would be a false pass", got.Pre, got.Bytes)
			}
		})
	}

	assertHostRulesetUntouched(t, before)
}

// TestAnonUIDIsStillDroppedByAnExplicitRule is the counterweight, and it guards the
// trap that turns the fix above into a silent un-jailing.
//
// Before the fix the anon UID's real egress was dropped by the base chain's POLICY,
// not by any rule. Flipping that policy to `accept` without an unconditional
// terminal `drop` at the end of the anon closure chain does not degrade the jail,
// it REMOVES it. The traffic that proves this is the anon UID's non-53 UDP: it is
// never redirected by the nat chain, so it arrives at the filter chain with its
// real off-box destination and is matched by NOTHING above the terminal drop. (Anon
// ICMP travels the identical path; it is the `verify` assertion icmp-drop.)
//
// The forcing table is loaded ALONE here, with the standing baseline table
// deliberately NOT loaded, because the baseline would drop this traffic too and
// would therefore MASK a missing terminal drop -- the regression would present as
// "everything still passes" while the forcing table had stopped forcing.
func TestAnonUIDIsStillDroppedByAnExplicitRule(t *testing.T) {
	requireNamespaceCapableRoot(t)
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not available; skipping the anon-uid probe")
	}

	before := hostRuleset(t)

	got := runInNamespace(t, "anon", nil)

	if got.Pre == 0 {
		t.Fatalf("the anon-uid probe generated no traffic, so this assertion would be a false pass "+
			"(helper error: %q)", got.Err)
	}
	if got.Post != 0 {
		t.Errorf("%d of the anon UID's non-53 UDP packets SURVIVED the forcing chain (%d entered, %d\n"+
			"survived). With the baseline not loaded, that means the anon closure chain no longer ends\n"+
			"in an unconditional terminal `drop`, so the anon UID's ordinary egress leaves IN THE CLEAR.\n"+
			"On a real host the standing baseline table would mask this and everything would still look\n"+
			"like it passes, while the forcing table had silently stopped forcing.",
			got.Post, got.Pre, got.Post)
	}

	assertHostRulesetUntouched(t, before)
}

// --- harness ---------------------------------------------------------------

func requireNamespaceCapableRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("loading a real nftables ruleset requires root; skipping")
	}
	for _, bin := range []string{"nft", "ip", "unshare"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}
}

// hostRuleset captures the HOST's ruleset so the test can prove it never changed.
// The probes run in their own network namespace, so this should be trivially true;
// it is asserted anyway, because "the isolation mechanism still works" is precisely
// what a test that loads real firewall rules must not take on trust.
//
// It reads the ruleset STATELESSLY (`nft -s`), which omits the packet/byte counters
// attached to rules and stateful objects. That is not a convenience, it is required
// for the assertion to mean anything: on any live host the firewall's own counters
// are incrementing continuously (tailscale, mDNS, ordinary traffic), so a plain
// `nft list ruleset` differs from itself milliseconds later and the comparison
// fails every single run while telling you nothing. What this test needs to know is
// whether the ruleset's STRUCTURE changed -- a table, chain or rule appearing,
// vanishing or being edited -- and `-s` is exactly that view.
func hostRuleset(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "-s", "list", "ruleset").Output()
	if err != nil {
		t.Fatalf("read the host ruleset: %v", err)
	}
	return string(out)
}

// assertHostRulesetUntouched proves the namespace isolation held. On a mismatch it
// reports the DIFFERING LINES only: dumping two complete rulesets buries the one
// line that matters (on a real host that is hundreds of lines, twice) and makes a
// failure unreadable.
func assertHostRulesetUntouched(t *testing.T, before string) {
	t.Helper()
	after := hostRuleset(t)

	// The specific thing that would go wrong, checked directly and independently of
	// the comparison below: a table this test created escaping its namespace into the
	// host's ruleset. Asserted by name so it holds even if the structural comparison
	// is ever loosened.
	for _, leaked := range []string{nftables.TableName("anonctl-probe"), "anonctl_probe_obs", sentinelTable} {
		if strings.Contains(after, leaked) {
			t.Errorf("the probe's table %q is present in the HOST's ruleset: it escaped the network\n"+
				"namespace and is now adjudicating this machine's traffic", leaked)
		}
	}

	if after == before {
		return
	}
	added, removed := lineDiff(before, after)
	t.Errorf("the HOST's nftables ruleset changed STRUCTURALLY across this test: the namespace\n"+
		"isolation leaked. (Counters are excluded from this comparison, so this is a real\n"+
		"table/chain/rule change, not traffic.)\nremoved:\n%s\nadded:\n%s",
		indentLines(removed), indentLines(added))
}

// lineDiff returns the lines present in only one of the two rulesets. It is a set
// difference rather than a real diff: nft's output order is stable, so "which lines
// appeared or vanished" is the whole question here.
func lineDiff(before, after string) (added, removed []string) {
	count := func(s string) map[string]int {
		m := make(map[string]int)
		for _, l := range strings.Split(s, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				m[l]++
			}
		}
		return m
	}
	b, a := count(before), count(after)
	for l, n := range a {
		for i := 0; i < n-b[l]; i++ {
			added = append(added, l)
		}
	}
	for l, n := range b {
		for i := 0; i < n-a[l]; i++ {
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func indentLines(lines []string) string {
	if len(lines) == 0 {
		return "    (none)"
	}
	const max = 40
	truncated := ""
	if len(lines) > max {
		truncated = fmt.Sprintf("\n    ... and %d more", len(lines)-max)
		lines = lines[:max]
	}
	return "    " + strings.Join(lines, "\n    ") + truncated
}

// runInNamespace re-executes this test binary as the in-namespace helper, inside a
// fresh network namespace, and returns what it measured.
func runInNamespace(t *testing.T, scenario string, extra map[string]string) probeResult {
	t.Helper()

	outFile := t.TempDir() + "/result.json"
	// No --mount-proc is needed: /proc/net is a symlink to /proc/self/net, so the
	// helper's own /proc/net/netstat already reports the NEW namespace's counters.
	args := []string{"--net", os.Args[0], "-test.run=TestNetnsHelperProcess", "-test.v"}
	cmd := exec.Command("unshare", args...)
	cmd.Env = append(os.Environ(),
		helperEnv+"="+scenario,
		helperOutEnv+"="+outFile,
	)
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	combined, err := cmd.CombinedOutput()

	raw, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Fatalf("the in-namespace helper produced no result (%v).\nhelper exit: %v\nhelper output:\n%s",
			readErr, err, combined)
	}
	var res probeResult
	if e := json.Unmarshal(raw, &res); e != nil {
		t.Fatalf("unreadable helper result: %v\nraw: %s\nhelper output:\n%s", e, raw, combined)
	}
	if res.Err != "" {
		t.Fatalf("the in-namespace helper failed: %s\nhelper output:\n%s", res.Err, combined)
	}
	return res
}

// TestNetnsHelperProcess is NOT a test. It is the body that runs INSIDE the fresh
// network namespace, re-executed as this binary by runInNamespace. It is inert
// during a normal run (the env var is unset, so it skips immediately).
func TestNetnsHelperProcess(t *testing.T) {
	scenario := os.Getenv(helperEnv)
	if scenario == "" {
		t.Skip("not the in-namespace helper")
	}
	res := probeResult{Scenario: scenario}
	if err := runScenario(scenario, &res); err != nil {
		res.Err = err.Error()
	}
	blob, _ := json.Marshal(res)
	if err := os.WriteFile(os.Getenv(helperOutEnv), blob, 0o600); err != nil {
		t.Fatalf("write helper result: %v", err)
	}
}
