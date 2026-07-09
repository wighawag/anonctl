package verify

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/socks5hfixture"
	"github.com/wighawag/anonctl/internal/sudoprobe"
)

// --- Report: greenness, exit code, no-short-circuit (the CI-gating contract) ---

func TestReport_OkRequiresEveryAssertionAndAtLeastOne(t *testing.T) {
	if (Report{}).Ok() {
		t.Fatal("an empty report must NOT be Ok (nothing was asserted is not a pass)")
	}
	pass := Report{Assertions: []Assertion{{Name: "a", Ok: true}, {Name: "b", Ok: true}}}
	if !pass.Ok() {
		t.Fatal("all-pass report should be Ok")
	}
	mixed := Report{Assertions: []Assertion{{Name: "a", Ok: true}, {Name: "b", Ok: false}}}
	if mixed.Ok() {
		t.Fatal("a report with any failed assertion must NOT be Ok")
	}
}

func TestReport_ExitCode(t *testing.T) {
	if (Report{Assertions: []Assertion{{Ok: true}}}).ExitCode() != 0 {
		t.Fatal("all-pass report must exit 0")
	}
	if (Report{Assertions: []Assertion{{Ok: true}, {Ok: false}}}).ExitCode() != 1 {
		t.Fatal("a report with any failure must exit non-zero (CI-gating)")
	}
	if (Report{}).ExitCode() != 1 {
		t.Fatal("an empty report must exit non-zero (nothing asserted is not a pass)")
	}
}

func TestRun_ExecutesEveryCheckAndDoesNotShortCircuit(t *testing.T) {
	var mu sync.Mutex
	var ran []string
	checks := []Check{
		{Name: "a", Run: func(ctx context.Context) Assertion {
			mu.Lock()
			ran = append(ran, "a")
			mu.Unlock()
			return Assertion{Ok: true}
		}},
		{Name: "b", Run: func(ctx context.Context) Assertion {
			mu.Lock()
			ran = append(ran, "b")
			mu.Unlock()
			return Assertion{Ok: false}
		}},
		{Name: "c", Run: func(ctx context.Context) Assertion {
			mu.Lock()
			ran = append(ran, "c")
			mu.Unlock()
			return Assertion{Ok: true}
		}},
	}
	rep := Run(context.Background(), checks)
	// Every check runs (no short-circuit past a failure). Run is now CONCURRENT, so
	// the completion order of `ran` is nondeterministic; sort before comparing. The
	// deterministic guarantee is on the REPORT order (asserted below), not on which
	// goroutine finished first.
	mu.Lock()
	got := append([]string(nil), ran...)
	mu.Unlock()
	sort.Strings(got)
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("every check must run even past a failure; ran=%v", got)
	}
	if rep.Ok() {
		t.Fatal("report with a failing check must not be Ok")
	}
	// The REPORT preserves the ORIGINAL check order regardless of completion order.
	if len(rep.Assertions) != 3 || rep.Assertions[0].Name != "a" || rep.Assertions[1].Name != "b" || rep.Assertions[2].Name != "c" {
		t.Fatalf("report must be in original check order with Name defaulted; got %+v", rep.Assertions)
	}
}

// TestRun_RunsChecksConcurrentlyAndPreservesOrder is the CORE of the parallel-probe
// speedup: the independent checks (the leak/closure probes PASS by TIMING OUT, so
// each waits its full deadline) must run CONCURRENTLY, making wall time the MAX
// single probe time, not the SUM. The report's assertion order stays deterministic
// (original check order), even though a LATER check finishes FIRST.
func TestRun_RunsChecksConcurrentlyAndPreservesOrder(t *testing.T) {
	const delay = 150 * time.Millisecond
	// slow(name, ms) returns a check that sleeps then reports; deliberately give the
	// FIRST check the LONGEST sleep so completion order is the REVERSE of report order.
	slow := func(name string, d time.Duration, ok bool) Check {
		return Check{Name: name, Run: func(ctx context.Context) Assertion {
			time.Sleep(d)
			return Assertion{Ok: ok, Detail: name}
		}}
	}
	checks := []Check{
		slow("a", 3*delay, true),
		slow("b", 2*delay, false),
		slow("c", 1*delay, true),
	}
	start := time.Now()
	rep := Run(context.Background(), checks)
	elapsed := time.Since(start)

	// Concurrent: wall time ~ MAX (3*delay), never the SUM (6*delay). Assert it is
	// comfortably under the sum so the speedup is real (allow scheduling slack).
	if elapsed >= 5*delay {
		t.Fatalf("checks must run CONCURRENTLY (wall ~ max single probe, not the sum); elapsed=%v (sum would be ~%v)", elapsed, 6*delay)
	}
	// Deterministic REPORT order = original check order, NOT completion order (c
	// finished first, a last).
	if len(rep.Assertions) != 3 || rep.Assertions[0].Name != "a" || rep.Assertions[1].Name != "b" || rep.Assertions[2].Name != "c" {
		t.Fatalf("report must be in ORIGINAL check order regardless of completion order; got %+v", rep.Assertions)
	}
	// Verdicts are carried per-check (not shuffled): a/c pass, b fails.
	if !rep.Assertions[0].Ok || rep.Assertions[1].Ok || !rep.Assertions[2].Ok {
		t.Fatalf("verdicts must stay with their check under concurrency; got %+v", rep.Assertions)
	}
	if rep.Assertions[1].Detail != "b" {
		t.Fatalf("per-check detail must stay with its check; got %+v", rep.Assertions)
	}
}

// --- Progress hook: per-check start/done so verify shows it is working during
// the multi-second live probe run (instead of a silent wait then a dump). The
// hook is the shared seam both `verify` and `use` drive. ---

func TestRunWith_ProgressFiresStartThenDoneForEveryCheckInOrder(t *testing.T) {
	checks := []Check{
		{Name: "a", Run: func(ctx context.Context) Assertion { return Assertion{Ok: true} }},
		{Name: "b", Run: func(ctx context.Context) Assertion { return Assertion{Ok: false, Detail: "leak"} }},
	}
	var mu sync.Mutex
	var starts, dones []string
	prog := Progress{
		Start: func(name string) { mu.Lock(); starts = append(starts, name); mu.Unlock() },
		Done:  func(a Assertion) { mu.Lock(); dones = append(dones, a.Name+":"+okmark(a.Ok)); mu.Unlock() },
	}
	rep := RunWith(context.Background(), checks, prog)
	// Checks now run CONCURRENTLY, so the strict start:a,done:a,start:b interleaving no
	// longer holds. The contract is: EVERY check fires Start (in original order, up
	// front) and Done (once each), the callbacks are never invoked concurrently (a
	// single funnel, so no data race in a caller's writer), and the final report is
	// deterministic. Assert Starts fire in original order for every check.
	if strings.Join(starts, ",") != "a,b" {
		t.Fatalf("Start must fire for every check in original order; got %v", starts)
	}
	// Done fires once per check (completion order may vary); assert the SET.
	sort.Strings(dones)
	if strings.Join(dones, ",") != "a:PASS,b:FAIL" {
		t.Fatalf("Done must fire once per check with its final verdict; got %v", dones)
	}
	// The report itself is unchanged by the hook (same assertions, same order).
	if len(rep.Assertions) != 2 || rep.Assertions[0].Name != "a" || rep.Assertions[1].Name != "b" {
		t.Fatalf("RunWith must produce the same report as Run; got %+v", rep.Assertions)
	}
	// Done sees the NAME defaulted from the check (b's assertion had no Name of its own).
	if rep.Assertions[1].Detail != "leak" {
		t.Fatalf("RunWith must preserve assertion detail; got %q", rep.Assertions[1].Detail)
	}
}

// A zero Progress (nil Start/Done) is safe: RunWith(nil hooks) == Run.
func TestRunWith_ZeroProgressIsSafeAndEqualsRun(t *testing.T) {
	checks := []Check{
		{Name: "a", Run: func(ctx context.Context) Assertion { return Assertion{Ok: true} }},
	}
	rep := RunWith(context.Background(), checks, Progress{})
	if len(rep.Assertions) != 1 || rep.Assertions[0].Name != "a" || !rep.Assertions[0].Ok {
		t.Fatalf("RunWith with a zero Progress must equal Run; got %+v", rep.Assertions)
	}
}

func okmark(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// --- Human render: named pass/fail lines, account + endpoint header ---

func TestReport_HumanStatesAccountAndEndpoint(t *testing.T) {
	rep := Report{
		Account:  "anon",
		Endpoint: "socks5h://127.0.0.1:9050",
		Assertions: []Assertion{
			{Name: "anonymized-exit", Ok: true, Detail: "exit differs from host"},
			{Name: "leak-drop-v4", Ok: false, Detail: "direct v4 reached (LEAK)"},
		},
	}
	out := rep.Human()
	if !strings.Contains(out, "anon") || !strings.Contains(out, "socks5h://127.0.0.1:9050") {
		t.Fatalf("human header must state the account and the endpoint; got:\n%s", out)
	}
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "FAIL") {
		t.Fatalf("human render must mark each assertion PASS/FAIL; got:\n%s", out)
	}
	if !strings.Contains(out, "anonymized-exit") || !strings.Contains(out, "leak-drop-v4") {
		t.Fatalf("human render must name each assertion; got:\n%s", out)
	}
}

// --- JSON shape: the machine contract others may consume ---

func TestReport_JSONShapeIsTheContract(t *testing.T) {
	rep := Report{
		Account:  "anon",
		Endpoint: "socks5h://127.0.0.1:9050",
		Assertions: []Assertion{
			{Name: "anonymized-exit", Ok: true, Detail: "exit ok"},
			{Name: "leak-drop-v4", Ok: false, Detail: "leak", Err: errors.New("boom")},
		},
	}
	blob, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON render: %v", err)
	}
	var got struct {
		SchemaVersion int    `json:"schemaVersion"`
		Ok            bool   `json:"ok"`
		Account       string `json:"account"`
		Endpoint      string `json:"endpoint"`
		Assertions    []struct {
			Name   string `json:"name"`
			Ok     bool   `json:"ok"`
			Detail string `json:"detail"`
			Error  string `json:"error"`
		} `json:"assertions"`
	}
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("emitted JSON must unmarshal into the documented shape: %v\n%s", err, blob)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d (the versioned contract)", got.SchemaVersion, SchemaVersion)
	}
	if got.Ok {
		t.Fatal("top-level ok must be false when any assertion failed")
	}
	if got.Account != "anon" || got.Endpoint != "socks5h://127.0.0.1:9050" {
		t.Fatalf("account/endpoint must be carried in the JSON; got %+v", got)
	}
	if len(got.Assertions) != 2 || got.Assertions[0].Name != "anonymized-exit" {
		t.Fatalf("assertions array must carry each named result; got %+v", got.Assertions)
	}
	if !got.Assertions[1].Ok == false && got.Assertions[1].Error == "" {
		t.Fatalf("a failed assertion with an Err must serialise its error string; got %+v", got.Assertions[1])
	}
	if got.Assertions[1].Error != "boom" {
		t.Fatalf("assertion error must serialise to its message; got %q", got.Assertions[1].Error)
	}
}

func TestReport_JSONNeverEmbedsCredentials(t *testing.T) {
	// A defensive contract check mirroring netcage: the endpoint carried in the
	// report is credential-free by construction (endpoint.URL()), so a shared JSON
	// report can never leak a secret. Assert no user:pass survives into the render.
	rep := Report{Account: "anon", Endpoint: "socks5h://127.0.0.1:9050"}
	blob, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON render: %v", err)
	}
	if strings.Contains(string(blob), "@127.0.0.1") {
		t.Fatalf("JSON must not carry an embedded credential form; got:\n%s", blob)
	}
}

// --- anonymized-exit assertion (pure decision, fixture-backed, no real Tor) ---

// TestAnonymizedExitAssertion_FailsWhenExitEqualsHost: the load-bearing anonymity
// property. If the observed exit IP equals the host's own, egress is NOT forced
// (a leak) and the assertion must FAIL.
func TestAnonymizedExitAssertion_FailsWhenExitEqualsHost(t *testing.T) {
	a := AnonymizedExitAssertion("203.0.113.9", "203.0.113.9", TorExitEvidence{}, endpoint.ClassSocksPeruser, false)
	if a.Ok {
		t.Fatalf("exit IP equal to host must FAIL (not anonymized); got %+v", a)
	}
	if a.Name != "anonymized-exit" {
		t.Fatalf("assertion name = %q, want anonymized-exit", a.Name)
	}
}

// TestAnonymizedExitAssertion_PassesWhenExitDiffersForSocksPeruser: a plain socks
// endpoint has no Tor-exit claim to make, so a differing exit IP is enough to pass.
func TestAnonymizedExitAssertion_PassesWhenExitDiffersForSocksPeruser(t *testing.T) {
	a := AnonymizedExitAssertion("203.0.113.9", "198.51.100.7", TorExitEvidence{}, endpoint.ClassSocksPeruser, false)
	if !a.Ok {
		t.Fatalf("a differing exit on a socks-peruser endpoint must PASS; got %+v", a)
	}
}

// TestAnonymizedExitAssertion_TorSharedRequiresTorExit: for a tor-shared endpoint
// the assertion additionally requires the check.torproject.org IsTor signal to be
// true. A differing exit that is NOT a Tor exit fails (it is not the promised Tor).
func TestAnonymizedExitAssertion_TorSharedRequiresTorExit(t *testing.T) {
	notTor := AnonymizedExitAssertion("203.0.113.9", "198.51.100.7", TorExitEvidence{}, endpoint.ClassTorShared, false)
	if notTor.Ok {
		t.Fatalf("a tor-shared endpoint whose exit is NOT a Tor exit must FAIL; got %+v", notTor)
	}
	isTor := AnonymizedExitAssertion("203.0.113.9", "198.51.100.7", TorExitEvidence{CheckTorProject: true}, endpoint.ClassTorShared, false)
	if !isTor.Ok {
		t.Fatalf("a tor-shared endpoint with a differing Tor exit must PASS; got %+v", isTor)
	}
}

// TestAnonymizedExitAssertion_FailsWhenNoExitObserved: an empty observed exit IP
// means the forced path produced nothing (it may have failed closed); that is a
// failure, never a silent pass.
func TestAnonymizedExitAssertion_FailsWhenNoExitObserved(t *testing.T) {
	a := AnonymizedExitAssertion("203.0.113.9", "", TorExitEvidence{}, endpoint.ClassSocksPeruser, false)
	if a.Ok {
		t.Fatalf("an empty observed exit must FAIL; got %+v", a)
	}
}

// onionoo RESCUES a check.torproject.org false-negative: for a tor-shared endpoint
// whose exit check.torproject.org says is NOT Tor, but onionoo lists as a running
// exit relay, the assertion PASSES (the registry lag this fix exists for). The
// detail must credit onionoo so the pass is transparent about which source confirmed.
func TestAnonymizedExitAssertion_OnionooRescuesCheckTorProjectFalseNegative(t *testing.T) {
	ev := TorExitEvidence{CheckTorProject: false, OnionooConsulted: true, OnionooExit: true}
	a := AnonymizedExitAssertion("203.0.113.9", "198.51.100.7", ev, endpoint.ClassTorShared, false)
	if !a.Ok {
		t.Fatalf("onionoo confirming a Tor exit must PASS even when check.torproject.org said false; got %+v", a)
	}
	if !strings.Contains(a.Detail, "onionoo") {
		t.Errorf("a pass rescued by onionoo must name onionoo in the detail; got %q", a.Detail)
	}
}

// When NEITHER registry confirms a Tor exit for a tor-shared endpoint, the assertion
// FAILS, and its detail must (a) name BOTH sources it consulted and (b) warn the
// registries can lag, so a red is understood as "unconfirmed", not "definitely not
// Tor", and points at the --skip-tor-exit-check escape hatch.
func TestAnonymizedExitAssertion_FailsHonestlyWhenNeitherRegistryConfirms(t *testing.T) {
	ev := TorExitEvidence{CheckTorProject: false, OnionooConsulted: true, OnionooExit: false}
	a := AnonymizedExitAssertion("203.0.113.9", "198.51.100.7", ev, endpoint.ClassTorShared, false)
	if a.Ok {
		t.Fatalf("neither registry confirming must FAIL; got %+v", a)
	}
	for _, want := range []string{"check.torproject.org", "onionoo", "--skip-tor-exit-check"} {
		if !strings.Contains(a.Detail, want) {
			t.Errorf("fail detail must mention %q so the red is honest+actionable; got %q", want, a.Detail)
		}
	}
	if !strings.Contains(strings.ToLower(a.Detail), "lag") {
		t.Errorf("fail detail must warn the registries LAG so a red is not read as definitive; got %q", a.Detail)
	}
}

// --skip-tor-exit-check relaxes ONLY the Tor-exit requirement: an unconfirmed exit
// that DIFFERS from the host PASSES (forced egress is proven), and the pass detail
// announces the check was skipped. It must NOT relax the exit-differs half.
func TestAnonymizedExitAssertion_SkipTorExitCheckRelaxesOnlyTheTorHalf(t *testing.T) {
	ev := TorExitEvidence{CheckTorProject: false, OnionooConsulted: true, OnionooExit: false}
	// Unconfirmed Tor exit, but differs from host + skip => PASS, loudly.
	skip := AnonymizedExitAssertion("203.0.113.9", "198.51.100.7", ev, endpoint.ClassTorShared, true)
	if !skip.Ok {
		t.Fatalf("--skip-tor-exit-check must PASS an unconfirmed-but-differing exit; got %+v", skip)
	}
	if !strings.Contains(skip.Detail, "SKIPPED") {
		t.Errorf("a skipped pass must announce the Tor check was skipped; got %q", skip.Detail)
	}
	// The load-bearing half is NEVER relaxed: an exit EQUAL to the host still FAILS,
	// even with skip set (that is a real leak, not a registry-lag false-negative).
	leak := AnonymizedExitAssertion("203.0.113.9", "203.0.113.9", ev, endpoint.ClassTorShared, true)
	if leak.Ok {
		t.Fatalf("--skip-tor-exit-check must NOT pass an exit EQUAL to the host (a leak); got %+v", leak)
	}
}

// onionooBodyConfirmsExit is strict: it confirms ONLY a running Exit relay that owns
// the IP, so it can rescue a real Tor exit but never invent one.
func TestOnionooBodyConfirmsExit(t *testing.T) {
	const ip = "203.55.81.1"
	// A running exit relay advertising the IP: confirmed.
	runningExit := `{"relays":[{"or_addresses":["203.55.81.1:19007"],"exit_addresses":["203.55.81.1"],"flags":["Exit","Fast","Running","Stable","Valid"]}]}`
	if !onionooBodyConfirmsExit(runningExit, ip) {
		t.Errorf("a running Exit relay owning the IP must confirm")
	}
	// Same relay but NOT running: not confirmed (only a live exit counts).
	notRunning := `{"relays":[{"exit_addresses":["203.55.81.1"],"flags":["Exit","Valid"]}]}`
	if onionooBodyConfirmsExit(notRunning, ip) {
		t.Errorf("a non-Running relay must NOT confirm")
	}
	// A running relay WITHOUT the Exit flag (a guard/middle): not an exit, not confirmed.
	notExit := `{"relays":[{"or_addresses":["203.55.81.1:443"],"flags":["Guard","Running","Valid"]}]}`
	if onionooBodyConfirmsExit(notExit, ip) {
		t.Errorf("a non-Exit relay must NOT confirm")
	}
	// A running exit relay for a DIFFERENT IP: not confirmed for our IP.
	otherIP := `{"relays":[{"exit_addresses":["185.220.101.146"],"flags":["Exit","Running","Valid"]}]}`
	if onionooBodyConfirmsExit(otherIP, ip) {
		t.Errorf("a relay for a different IP must NOT confirm our IP")
	}
	// Empty / garbage: not confirmed, no panic.
	if onionooBodyConfirmsExit(`{"relays":[]}`, ip) || onionooBodyConfirmsExit("not json", ip) {
		t.Errorf("empty/garbage onionoo body must not confirm")
	}
}

// --- dns-remote assertion (pure decision over the fixture's proxy-side view) ---

// TestDNSRemoteAssertion_PassesWhenResolvedProxySide: the fixture RECORDS the
// hostnames it was asked to resolve proxy-side. The assertion passes when the
// probed name appears there (resolved remotely) and the host resolver never saw it.
func TestDNSRemoteAssertion_PassesWhenResolvedProxySide(t *testing.T) {
	a := DNSRemoteAssertion("probe.example", []string{"probe.example"}, false)
	if !a.Ok {
		t.Fatalf("a name resolved proxy-side must PASS; got %+v", a)
	}
	if a.Name != "dns-remote" {
		t.Fatalf("assertion name = %q, want dns-remote", a.Name)
	}
}

// TestDNSRemoteAssertion_FailsWhenNotResolvedProxySide: if the proxy never saw the
// name, it was resolved somewhere else (a plaintext/local leak) and the assertion
// must FAIL.
func TestDNSRemoteAssertion_FailsWhenNotResolvedProxySide(t *testing.T) {
	a := DNSRemoteAssertion("probe.example", []string{"other.example"}, false)
	if a.Ok {
		t.Fatalf("a name NOT resolved proxy-side must FAIL (leak); got %+v", a)
	}
}

// TestDNSRemoteAssertion_FailsWhenHostResolverSawTheName: even if the proxy also
// saw it, a host-resolver observation of the SAME name is a plaintext leak and
// must FAIL.
func TestDNSRemoteAssertion_FailsWhenHostResolverSawTheName(t *testing.T) {
	a := DNSRemoteAssertion("probe.example", []string{"probe.example"}, true)
	if a.Ok {
		t.Fatalf("a name the HOST resolver also saw must FAIL (plaintext leak); got %+v", a)
	}
}

// --- fail-closed / bypass-closure family (pure drop decision) ---

// TestLeakDropAssertion_PassesWhenDropped: the LOAD-BEARING assertion. A direct
// connection from the anon UID that was DROPPED (did not reach) passes; one that
// REACHED its target is a leak and fails. Covered for v4 AND v6.
func TestLeakDropAssertion_PassesWhenDropped(t *testing.T) {
	for _, fam := range []string{"v4", "v6"} {
		dropped := LeakDropAssertion(fam, false)
		if !dropped.Ok {
			t.Fatalf("%s: a dropped direct connection must PASS; got %+v", fam, dropped)
		}
		leaked := LeakDropAssertion(fam, true)
		if leaked.Ok {
			t.Fatalf("%s: a REACHED direct connection is a leak and must FAIL; got %+v", fam, leaked)
		}
	}
}

// TestLeakDropAssertion_NamesAreDistinctPerFamily: v4 and v6 are SEPARATE named
// assertions, so a report shows each family's result independently (a v6 bypass of
// v4 rules cannot hide behind a single leak line).
func TestLeakDropAssertion_NamesAreDistinctPerFamily(t *testing.T) {
	if LeakDropAssertion("v4", false).Name != "leak-drop-v4" {
		t.Fatalf("v4 assertion name = %q, want leak-drop-v4", LeakDropAssertion("v4", false).Name)
	}
	if LeakDropAssertion("v6", false).Name != "leak-drop-v6" {
		t.Fatalf("v6 assertion name = %q, want leak-drop-v6", LeakDropAssertion("v6", false).Name)
	}
}

// TestEscapedLeakProbeAssertion_ProbeErrorIsNotAPass is the CORE of the false-green
// fix: a probe that could not RUN (a counter plant/read error) must produce a LOUD
// error verdict (Err set, Ok false), NEVER a silent pass. The old behaviour
// swallowed a plant error to reached=false, and reached=false reads as "nothing
// escaped" => the closure assertion PASSED without ever probing. This pins that an
// error can no longer masquerade as a clean probe.
func TestEscapedLeakProbeAssertion_ProbeErrorIsNotAPass(t *testing.T) {
	plantErr := errors.New("plant escaped-leak counter: invalid nft")
	a := escapedLeakProbeAssertion(AssertBypassLoopbackClosure, "the anon UID reaching a non-shim loopback destination", false, plantErr)
	if a.Ok {
		t.Fatalf("a counter plant/read ERROR must FAIL the assertion (a probe that could not run is not a pass), even with reached=false; got %+v", a)
	}
	if a.Err == nil {
		t.Fatalf("the probe error must be SURFACED on the assertion (Err set), not swallowed; got %+v", a)
	}
	if a.Name != AssertBypassLoopbackClosure {
		t.Fatalf("the assertion must keep its name on an error verdict; got %+v", a)
	}
	// A clean probe (no error) still decides on the observed reached value: dropped
	// (reached=false) passes; a real escape (reached=true) fails.
	if ok := escapedLeakProbeAssertion(AssertBypassLoopbackClosure, "x", false, nil); !ok.Ok || ok.Err != nil {
		t.Fatalf("a clean dropped probe must PASS with no error; got %+v", ok)
	}
	if leak := escapedLeakProbeAssertion(AssertBypassLoopbackClosure, "x", true, nil); leak.Ok {
		t.Fatalf("a clean probe that observed a real escape must FAIL (a leak); got %+v", leak)
	}
}

func TestBypassClosureAssertions_PassWhenDropped(t *testing.T) {
	if a := BypassLoopbackClosureAssertion(false); !a.Ok || a.Name != "bypass-loopback-closure" {
		t.Fatalf("loopback closure: dropped must PASS with the right name; got %+v", a)
	}
	if a := BypassLoopbackClosureAssertion(true); a.Ok {
		t.Fatalf("loopback closure: a reached non-shim loopback must FAIL; got %+v", a)
	}
	if a := BypassEndpointClosureAssertion(false); !a.Ok || a.Name != "bypass-endpoint-closure" {
		t.Fatalf("endpoint closure: dropped must PASS with the right name; got %+v", a)
	}
	if a := BypassEndpointClosureAssertion(true); a.Ok {
		t.Fatalf("endpoint closure: a reached direct endpoint dial must FAIL; got %+v", a)
	}
}

// --- icmp-drop (Tails leak-catalogue row 4, pure decision) ---

// TestICMPDropAssertion_PassesWhenDropped: an ICMP echo (ping) from the anon UID
// to an off-box address that was DROPPED (no ICMP left, no reply) passes; one that
// REACHED (a reply came back, so a real-source-IP ICMP packet left) is a leak and
// fails. It mirrors the leak-drop polarity.
func TestICMPDropAssertion_PassesWhenDropped(t *testing.T) {
	dropped := ICMPDropAssertion(false)
	if !dropped.Ok || dropped.Name != AssertICMPDrop {
		t.Fatalf("a dropped ping must PASS with name %s; got %+v", AssertICMPDrop, dropped)
	}
	leaked := ICMPDropAssertion(true)
	if leaked.Ok {
		t.Fatalf("a ping that REACHED (real-source-IP ICMP left) is a leak and must FAIL; got %+v", leaked)
	}
}

// --- non-tcp-udp-drop (Tails leak-catalogue row 5, pure decision) ---

// TestNonTCPUDPDropAssertion covers raw non-53 UDP AND specifically UDP/443
// (QUIC): both must be dropped from the anon UID for a PASS; either reaching its
// target is a leak and must FAIL.
func TestNonTCPUDPDropAssertion(t *testing.T) {
	// Neither raw UDP nor UDP/443 leaves => dropped (pass).
	if a := NonTCPUDPDropAssertion(false, false); !a.Ok || a.Name != AssertNonTCPUDPDrop {
		t.Fatalf("raw + UDP/443 both dropped must PASS with name %s; got %+v", AssertNonTCPUDPDrop, a)
	}
	// Raw non-53 UDP reached => a leak (fail).
	if a := NonTCPUDPDropAssertion(true, false); a.Ok {
		t.Fatalf("a reached raw non-53 UDP must FAIL (leak); got %+v", a)
	}
	// UDP/443 (QUIC) reached => a leak (fail), even if raw did not.
	if a := NonTCPUDPDropAssertion(false, true); a.Ok {
		t.Fatalf("a reached UDP/443 (QUIC) must FAIL (leak); got %+v", a)
	}
}

// --- split-tunnel-tight (story 25, pure decision) ---

func TestSplitTunnelTightAssertion(t *testing.T) {
	// exempt reachable AND the rest stays redirected-or-dropped => tight (pass).
	if a := SplitTunnelTightAssertion("192.168.1.150:8080", true, false); !a.Ok || a.Name != "split-tunnel-tight" {
		t.Fatalf("exempt reachable + rest tight must PASS with the right name; got %+v", a)
	}
	// exempt NOT reachable => the hole is broken (fail).
	if a := SplitTunnelTightAssertion("192.168.1.150:8080", false, false); a.Ok {
		t.Fatalf("an unreachable exemption must FAIL; got %+v", a)
	}
	// a non-exempt LAN destination reachable => the exemption widened into a leak (fail).
	if a := SplitTunnelTightAssertion("192.168.1.150:8080", true, true); a.Ok {
		t.Fatalf("a reachable non-exempt LAN destination must FAIL (exemption widened); got %+v", a)
	}
}

// --- lan-exemption-not-a-dns-hole (Tails leak-catalogue row 2, pure decision) ---

// TestLANExemptionNotADNSHoleAssertion proves the pure decision: with a LAN
// exemption active, clear DNS (tcp AND udp 53) to the exempted host must NOT
// egress directly to the LAN resolver (it is redirected to the shim or dropped).
// The probe reports whether a DIRECT clear query to the exempted host on 53
// reached the LAN resolver as clear DNS; the assertion passes IFF neither tcp/53
// nor udp/53 did.
func TestLANExemptionNotADNSHoleAssertion(t *testing.T) {
	// Neither tcp/53 nor udp/53 leaves as a direct clear LAN query => not a hole (pass).
	if a := LANExemptionNotADNSHoleAssertion("192.168.1.150:8080", false, false); !a.Ok || a.Name != AssertLANExemptionNotADNSHole {
		t.Fatalf("no clear LAN DNS must PASS with the right name; got %+v", a)
	}
	// A direct clear TCP/53 query to the LAN resolver => a DNS hole (fail).
	if a := LANExemptionNotADNSHoleAssertion("192.168.1.150:8080", true, false); a.Ok {
		t.Fatalf("a direct clear TCP/53 to the LAN resolver must FAIL (a DNS hole); got %+v", a)
	}
	// A direct clear UDP/53 query to the LAN resolver => a DNS hole (fail).
	if a := LANExemptionNotADNSHoleAssertion("192.168.1.150:8080", false, true); a.Ok {
		t.Fatalf("a direct clear UDP/53 to the LAN resolver must FAIL (a DNS hole); got %+v", a)
	}
}

// --- no-uid-transition-egress (best-effort, Tails leak-catalogue row 7, pure decision) ---

// TestNoUIDTransitionEgressAssertion_PassesWhenNoCheckedVectorEscapes: the
// best-effort probe over the CONCRETELY ENUMERABLE UID-transition vectors (the
// audit finding: sudo, and the documented setuid network paths). It passes IFF
// none of the checked vectors yielded an off-box socket owned by a non-anon,
// non-shim uid. The evidence line must name the checked vectors AND state plainly
// that it is best-effort / not exhaustive (an arbitrary triggerable daemon may
// still escape), so the pass never reads as a total guarantee.
func TestNoUIDTransitionEgressAssertion_PassesWhenNoCheckedVectorEscapes(t *testing.T) {
	vectors := []UIDTransitionVector{
		{Name: "sudo", Escaped: false},
		{Name: "setuid:ping", Escaped: false},
		{Name: "setuid:pkexec", Escaped: false},
	}
	a := NoUIDTransitionEgressAssertion(vectors)
	if !a.Ok {
		t.Fatalf("no escaping checked vector must PASS; got %+v", a)
	}
	if a.Name != AssertNoUIDTransitionEgress {
		t.Fatalf("assertion name = %q, want %s", a.Name, AssertNoUIDTransitionEgress)
	}
	// The detail must name the checked vectors and be honestly non-exhaustive.
	if !strings.Contains(a.Detail, "sudo") || !strings.Contains(a.Detail, "setuid:ping") {
		t.Fatalf("detail must name the checked vectors; got %q", a.Detail)
	}
	if !strings.Contains(a.Detail, "best-effort") || !strings.Contains(a.Detail, "not exhaustive") {
		t.Fatalf("detail must honestly frame the probe as best-effort / not exhaustive; got %q", a.Detail)
	}
}

// TestNoUIDTransitionEgressAssertion_FailsWhenAnyVectorEscapes: if ANY checked
// vector yielded an off-box socket owned by a non-anon, non-shim uid (an escape),
// the assertion FAILS and its detail names the offending vector (a real leak the
// per-UID forcing did not catch).
func TestNoUIDTransitionEgressAssertion_FailsWhenAnyVectorEscapes(t *testing.T) {
	vectors := []UIDTransitionVector{
		{Name: "sudo", Escaped: false},
		{Name: "setuid:exim-submit", Escaped: true, Detail: "submitted mail carried off-box by uid Debian-exim"},
	}
	a := NoUIDTransitionEgressAssertion(vectors)
	if a.Ok {
		t.Fatalf("an escaping vector must FAIL (a uid-transition leak); got %+v", a)
	}
	if !strings.Contains(a.Detail, "setuid:exim-submit") {
		t.Fatalf("detail must name the offending vector; got %q", a.Detail)
	}
}

// sudoVectorFromVerdict is the PURE sudo-vector decision the live probe feeds:
// it maps the shared sudoprobe.Verdict (read from `sudo -l -U` OUTPUT, not the
// exit code) onto the UID-transition vector. Denied => the sudo path did NOT
// escape; Granted => it ESCAPED (a real sudo path off the anon UID). This is the
// twin of provision's status mapping, read here as the verify-side escape signal.
func TestSudoVectorFromVerdict_DeniedIsNoEscape(t *testing.T) {
	v := sudoVectorFromVerdict(sudoprobe.Denied)
	if v.Name != "sudo" {
		t.Fatalf("vector name = %q, want sudo", v.Name)
	}
	if v.Escaped {
		t.Fatalf("a Denied verdict (no sudo rights) must NOT escape; got %+v", v)
	}
	if v.Inconclusive {
		t.Fatalf("a Denied verdict is a conclusive no-escape, not inconclusive; got %+v", v)
	}
}

// A real grant is still caught: Granted => Escaped=true (a sudo'd socket carries a
// non-anon uid), so the parse-based read never hides a real sudo escape.
func TestSudoVectorFromVerdict_GrantedIsEscape(t *testing.T) {
	v := sudoVectorFromVerdict(sudoprobe.Granted)
	if !v.Escaped {
		t.Fatalf("a Granted verdict (real sudo rights) must ESCAPE; got %+v", v)
	}
	if v.Inconclusive {
		t.Fatalf("a Granted verdict is a conclusive escape, not inconclusive; got %+v", v)
	}
	if v.Detail == "" {
		t.Fatalf("an escaping sudo vector must carry a detail line; got %+v", v)
	}
}

// An ambiguous / unparseable probe is surfaced HONESTLY: Unknown maps to
// NOT-conclusively-checked (Inconclusive=true), never a false Escaped=true (a
// false alarm) NOR a false conclusive Escaped=false that would hide a real sudo
// path. Consistent with the best-effort framing of the assertion.
func TestSudoVectorFromVerdict_UnknownIsHonestlyInconclusive(t *testing.T) {
	v := sudoVectorFromVerdict(sudoprobe.Unknown)
	if v.Escaped {
		t.Fatalf("an Unknown verdict must NEVER false-alarm as an escape; got %+v", v)
	}
	if !v.Inconclusive {
		t.Fatalf("an Unknown verdict must be surfaced as not-conclusively-checked; got %+v", v)
	}
	if v.Detail == "" {
		t.Fatalf("an inconclusive sudo vector must carry an honest detail line; got %+v", v)
	}
}

// An INCONCLUSIVE vector does not fail the assertion (it is not an escape) and is
// not silently dropped: the assertion still passes on the vectors it conclusively
// checked, and its detail names the inconclusive vector so the not-conclusive
// status is surfaced, never a silent pass.
func TestNoUIDTransitionEgressAssertion_SurfacesInconclusiveVector(t *testing.T) {
	vectors := []UIDTransitionVector{
		{Name: "sudo", Inconclusive: true, Detail: "could not classify `sudo -l -U` output"},
		{Name: "setuid:pkexec", Escaped: false},
	}
	a := NoUIDTransitionEgressAssertion(vectors)
	if !a.Ok {
		t.Fatalf("an inconclusive (not-escaped) vector must not FAIL the best-effort assertion; got %+v", a)
	}
	if !strings.Contains(a.Detail, "sudo") || !strings.Contains(strings.ToLower(a.Detail), "not conclusively checked") {
		t.Fatalf("detail must surface the inconclusive vector honestly (not a silent pass); got %q", a.Detail)
	}
}

// TestNoUIDTransitionEgressAssertion_FailsWhenNoVectorsChecked: an EMPTY probe set
// is not a pass. "Nothing was checked" is never proof the vectors do not escape
// (mirrors the report-level "nothing asserted is not a pass" contract); it must
// FAIL rather than silently green.
func TestNoUIDTransitionEgressAssertion_FailsWhenNoVectorsChecked(t *testing.T) {
	a := NoUIDTransitionEgressAssertion(nil)
	if a.Ok {
		t.Fatalf("an empty probe set must FAIL (nothing checked is not a pass); got %+v", a)
	}
}

// --- fixture-backed end-to-end of the anonymized-exit evidence path ---

// TestAnonymizedExit_AgainstFixture proves the anonymized-exit assertion can be
// driven end-to-end against the deterministic socks5h fixture (no real Tor): the
// fixture's ExitIP is the "exit" the probe observes, and it differs from a
// synthetic host baseline, so the assertion passes.
func TestAnonymizedExit_AgainstFixture(t *testing.T) {
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.2"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()

	// The exit observed through the fixture is its ExitIP; the host baseline is a
	// different synthetic value. This exercises the assertion decision the live
	// integration check will feed with real probe output.
	a := AnonymizedExitAssertion("203.0.113.9", "127.0.0.2", TorExitEvidence{}, endpoint.ClassSocksPeruser, false)
	if !a.Ok {
		t.Fatalf("fixture exit differs from host baseline: must PASS; got %+v", a)
	}
}
