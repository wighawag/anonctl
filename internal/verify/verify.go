// Package verify is anonctl's trust anchor and signature ONGOING verb: it PROVES
// an anon account is anonymized rather than assuming it, and it is meant to be
// re-run after setup, after a reboot, and after any Tor/kernel/nftables change.
// It mirrors netcage's internal/verify: named assertions, run-EVERY-check (no
// short-circuit) so the report is complete, a non-zero process exit on ANY
// failure (the CI-gating contract), and a `--json` machine shape others may
// consume.
//
// The assertions it makes (each named, each a separate line/JSON entry):
//
//   - anonymized-exit: the account's exit IP DIFFERS from the host's; for a
//     tor-shared endpoint it is additionally a Tor exit (check.torproject.org).
//   - dns-remote: DNS resolves REMOTELY via the endpoint (the proxy saw the
//     lookup), never locally / in plaintext (the host resolver did NOT see it).
//   - leak-drop-v4 / leak-drop-v6 (LOAD-BEARING): a direct, non-anonymized
//     connection from the anon UID is actually DROPPED, on IPv4 AND IPv6. This is
//     the fail-closed proof: fail-closed is DEMONSTRATED, not assumed.
//   - bypass-loopback-closure: the anon UID reaching any loopback destination
//     other than its own shim port is DROPPED (recipe closure a).
//   - bypass-endpoint-closure: the anon UID dialling the upstream endpoint
//     directly is DROPPED (recipe closure b) so it can never skip the shim or its
//     `<account>@` isolation username.
//   - icmp-drop: an ICMP echo (`ping`) from the anon UID to an off-box address is
//     DROPPED (it does not emit an ICMP packet carrying the real source IP). Tails
//     leak-catalogue row 4; it falls through to the anon UID's policy DROP.
//   - non-tcp-udp-drop: raw non-53 UDP from the anon UID, specifically including
//     UDP/443 (QUIC / HTTP-3), is DROPPED. SOCKS carries TCP only, so UDP/443 is
//     unrelayable; Tails leak-catalogue row 5, it falls through to the policy DROP.
//   - split-tunnel-tight (with a LAN exemption active): the exempted host:port is
//     reachable directly, but the rest of that /24, other loopback, and everything
//     else stay redirected-or-dropped.
//   - lan-exemption-not-a-dns-hole (with a LAN exemption active): clear DNS (tcp
//     AND udp 53) to the exempted host does NOT egress directly to the LAN
//     resolver (it is redirected to the shim or dropped), so the LAN hole can
//     never become a clear-DNS hole (Tails leak-catalogue row 2).
//
// The DESIGN split mirrors the rest of the repo (provision's Runner seam,
// nftables' Generate-vs-Apply): this file is the PURE assertion/render/exit
// logic (Report, Assertion, Run, the per-assertion decision functions), unit-
// tested EVERYWHERE against internal/socks5hfixture with NO real Tor; the LIVE
// checks that stand up real probes as the anon UID against a real ruleset live in
// checks_live.go / probes_live.go and are compiled into EVERY build (runtime
// behaviour needing root + setpriv + the installed shim probe binary + a live
// endpoint, like `add`/`rm`; they FAIL LOUD when a tool/probe cannot run, never a
// silent pass). The `integration` build tag now gates only the slow/privileged
// *test* files. The assertion NAMES and the JSON SHAPE are a deliberate contract
// (ADR 0003); the checks feed the pure decisions here so the verdict logic is
// proven without privilege.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/sudoprobe"
)

// SchemaVersion is the version of the `--json` report CONTRACT. It evolves
// ADDITIVELY only (new optional fields), so a consumer pinned to this version
// keeps working; a breaking change bumps it. It is emitted as `schemaVersion` so
// a machine consumer can guard on the shape it understands. It mirrors
// detect-proxy's SchemaVersion discipline.
const SchemaVersion = 1

// Assertion names. They are the STABLE public identifiers a machine consumer or a
// CI gate keys on, so they are declared once here (never spelled inline) and are
// part of the JSON contract (ADR 0003). kebab-case mirrors netcage's assertion
// names (e.g. `forced-egress-exit-ip-differs-from-host`).
const (
	// AssertAnonymizedExit: the exit IP differs from the host's (and is a Tor exit
	// for a tor-shared endpoint).
	AssertAnonymizedExit = "anonymized-exit"
	// AssertDNSRemote: DNS resolves remotely via the endpoint, not locally.
	AssertDNSRemote = "dns-remote"
	// AssertLeakDropV4 / AssertLeakDropV6: a direct connection from the anon UID is
	// DROPPED on IPv4 / IPv6 (the load-bearing fail-closed proof).
	AssertLeakDropV4 = "leak-drop-v4"
	AssertLeakDropV6 = "leak-drop-v6"
	// AssertBypassLoopbackClosure: the anon UID reaching non-shim loopback is
	// DROPPED (recipe closure a).
	AssertBypassLoopbackClosure = "bypass-loopback-closure"
	// AssertBypassEndpointClosure: the anon UID dialling the endpoint directly is
	// DROPPED (recipe closure b).
	AssertBypassEndpointClosure = "bypass-endpoint-closure"
	// AssertSplitTunnelTight: with a LAN exemption active, the exempted host:port
	// is reachable but everything else stays redirected-or-dropped.
	AssertSplitTunnelTight = "split-tunnel-tight"
	// AssertLANExemptionNotADNSHole: with a LAN exemption active, clear DNS (tcp+udp
	// 53) to the exempted host does NOT egress directly to the LAN resolver
	// (redirected-or-dropped), so the LAN hole is never a clear-DNS hole (Tails
	// leak-catalogue row 2).
	AssertLANExemptionNotADNSHole = "lan-exemption-not-a-dns-hole"
	// AssertICMPDrop: an ICMP echo (ping) from the anon UID to an off-box address is
	// DROPPED, so no ICMP packet carrying the real source IP leaves (Tails
	// leak-catalogue row 4).
	AssertICMPDrop = "icmp-drop"
	// AssertNonTCPUDPDrop: raw non-53 UDP from the anon UID (incl. UDP/443 QUIC) is
	// DROPPED, since SOCKS carries TCP only and UDP/443 is unrelayable (Tails
	// leak-catalogue row 5).
	AssertNonTCPUDPDrop = "non-tcp-udp-drop"
	// AssertNoUIDTransitionEgress: the CONCRETELY ENUMERABLE UID-transition escape
	// vectors (sudo, and the documented setuid network paths from the audit finding)
	// do NOT yield an off-box socket owned by a non-anon, non-shim uid that bypasses
	// the `meta skuid` forcing (Tails leak-catalogue row 7). It is BEST-EFFORT and
	// explicitly NOT exhaustive: verify cannot enumerate every daemon on every host,
	// so it proves only that the CHECKED vectors do not escape, never total absence.
	AssertNoUIDTransitionEgress = "no-uid-transition-egress"
)

// Assertion is one named verify result. Ok is the pass/fail; Detail is the
// human-readable evidence (observed vs expected); Err is non-nil when the probe
// itself errored, which COUNTS AS a failure (a check that could not run is not a
// pass). It mirrors netcage's Assertion.
type Assertion struct {
	Name   string `json:"name"`
	Ok     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Err    error  `json:"-"` // serialised via jsonAssertion.Error, never as a Go error value
}

// Report is the outcome of a verify run: the account and its credential-free
// endpoint (the header, so `verify` answers "which account/endpoint did I prove?")
// plus the ordered named assertions. Ok/ExitCode derive the CI-gating verdict from
// the assertions; a report is a pass IFF every assertion passed AND at least one
// ran (nothing asserted is not a pass).
type Report struct {
	// Account is the anon account verify ran against (`anon` / `anon-<name>`).
	Account string
	// Endpoint is the credential-free socks5h URL the account is forced through
	// (endpoint.URL()); it never carries an embedded user:pass@ so a shared/logged
	// report leaks no secret.
	Endpoint string
	// Assertions are the named results, in run order.
	Assertions []Assertion
}

// Ok reports whether EVERY assertion passed. A verify run is a pass iff Ok. An
// empty report is NOT Ok (nothing asserted is not a proof).
func (r Report) Ok() bool {
	for _, a := range r.Assertions {
		if !a.Ok {
			return false
		}
	}
	return len(r.Assertions) > 0
}

// ExitCode is the process exit code: 0 iff every assertion passed, else 1. This
// is the CI-gating contract (story 18): any failed assertion makes `anonctl
// verify` exit non-zero.
func (r Report) ExitCode() int {
	if r.Ok() {
		return 0
	}
	return 1
}

// Human renders the account+endpoint header followed by one PASS/FAIL line per
// named assertion (with its detail and any probe error), so `anonctl verify`
// reads clearly at a glance. The header states which account and endpoint were
// proven; it prints only the credential-free socks5h URL.
func (r Report) Human() string {
	var b strings.Builder
	if r.Account != "" || r.Endpoint != "" {
		fmt.Fprintf(&b, "verify %s", r.Account)
		if r.Endpoint != "" {
			fmt.Fprintf(&b, " (endpoint: %s)", r.Endpoint)
		}
		b.WriteString("\n")
	}
	for _, a := range r.Assertions {
		mark := "FAIL"
		if a.Ok {
			mark = "PASS"
		}
		fmt.Fprintf(&b, "[%s] %s", mark, a.Name)
		if a.Detail != "" {
			fmt.Fprintf(&b, ": %s", a.Detail)
		}
		if a.Err != nil {
			fmt.Fprintf(&b, " (error: %v)", a.Err)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// jsonReport is the wire shape of the `--json` contract (ADR 0003). It is a
// distinct type (not the in-memory Report) so the contract is EXPLICIT and stable:
// a versioned envelope carrying the derived top-level `ok`, the account +
// credential-free endpoint, and the array of named assertion results with the
// probe error flattened to a string. The shape evolves additively only.
type jsonReport struct {
	SchemaVersion int             `json:"schemaVersion"`
	Ok            bool            `json:"ok"`
	Account       string          `json:"account"`
	Endpoint      string          `json:"endpoint,omitempty"`
	Assertions    []jsonAssertion `json:"assertions"`
}

// jsonAssertion is one assertion on the wire: the name, its pass/fail, the detail,
// and any probe error flattened to its message string (never a Go error object).
type jsonAssertion struct {
	Name   string `json:"name"`
	Ok     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// JSON renders the report as the versioned machine contract. The top-level `ok`
// is the derived greenness (== Ok()), so a consumer can gate on one boolean
// without re-walking the array. It never embeds credentials (Endpoint is the
// credential-free URL). It is the deliberate contract others may consume.
func (r Report) JSON() ([]byte, error) {
	out := jsonReport{
		SchemaVersion: SchemaVersion,
		Ok:            r.Ok(),
		Account:       r.Account,
		Endpoint:      r.Endpoint,
		Assertions:    make([]jsonAssertion, 0, len(r.Assertions)),
	}
	for _, a := range r.Assertions {
		ja := jsonAssertion{Name: a.Name, Ok: a.Ok, Detail: a.Detail}
		if a.Err != nil {
			ja.Error = a.Err.Error()
		}
		out.Assertions = append(out.Assertions, ja)
	}
	return json.MarshalIndent(out, "", "  ")
}

// Check is one named verify check: it runs (a live probe in the integration
// build, or a fixture-backed one in tests) and returns the named assertion. The
// orchestrator composes the set and Run executes them.
type Check struct {
	Name string
	Run  func(ctx context.Context) Assertion
}

// Progress is an OPTIONAL per-check observation hook so a caller can show that
// verify is WORKING during its multi-second live probe run (each check is a real
// connection through the shim; the exit-IP check dials Tor), instead of a silent
// wait followed by the whole report dumped at once. Start fires just BEFORE a
// check runs (with the check's Name), Done fires just AFTER it completes (with the
// finished Assertion, its Name already defaulted from the check). Either field may
// be nil (a zero Progress is a no-op), so it is purely additive: `Run` is
// `RunWith` with a zero Progress and the buffered report is byte-for-byte
// unchanged.
//
// It is deliberately just two callbacks (not an io.Writer or a tty flag): WHERE
// and HOW progress is rendered (stderr vs interleaved, plain line vs spinner,
// suppressed under --json) is the COMMAND's concern, not this pure package's, so
// the render policy lives in main and this seam stays testable with no terminal.
type Progress struct {
	Start func(name string)
	Done  func(a Assertion)
}

// Run executes the checks IN ORDER and collects them into a Report. It does NOT
// short-circuit: every assertion runs so the report is complete (a leak-test must
// show ALL failures, not just the first). A check whose returned assertion has no
// Name inherits the check's Name. It is RunWith with no progress hook.
func Run(ctx context.Context, checks []Check) Report {
	return RunWith(ctx, checks, Progress{})
}

// RunWith is Run with an optional per-check Progress hook. It runs the checks
// CONCURRENTLY (each in its own goroutine): the leak/closure probes PASS by TIMING
// OUT (a dropped packet never answers, so each waits its full deadline), and they
// are INDEPENDENT (different off-box destinations / assertions), so running them in
// parallel makes verify's wall time the MAX single probe time, not the SUM of every
// timeout, a multi-x speedup with identical coverage.
//
// Concurrency does NOT weaken any contract:
//   - ORDER: the Report's assertions are collected into a pre-sized slice at each
//     check's ORIGINAL index, so the report is deterministic (original check order),
//     regardless of which goroutine finishes first. No short-circuit: every check
//     runs (a leak-test must show ALL failures), and a check whose assertion has no
//     Name inherits the check's Name.
//   - PROGRESS: prog.Start fires for every check UP FRONT in original order (the
//     checks now start together, so there is no per-check "about to start" moment to
//     interleave), and prog.Done fires once per check as it COMPLETES. Both hooks are
//     funnelled through one mutex so they are NEVER invoked concurrently: the caller's
//     writer (main renders to stderr) sees serialised calls and needs no locking of
//     its own. A nil/zero Progress makes RunWith a pure concurrent Run.
//
// A shared parent ctx is fine: each check already applies its own per-probe timeout.
func RunWith(ctx context.Context, checks []Check, prog Progress) Report {
	rep := Report{Assertions: make([]Assertion, len(checks))}
	// Fire every Start up front, in original order: the checks run concurrently, so
	// there is no sequential "about to run this one" point to interleave with Done.
	if prog.Start != nil {
		for _, c := range checks {
			prog.Start(c.Name)
		}
	}
	var wg sync.WaitGroup
	var doneMu sync.Mutex // serialises prog.Done so a caller's writer never races
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			a := c.Run(ctx)
			if a.Name == "" {
				a.Name = c.Name
			}
			// Disjoint index per goroutine: no two goroutines write the same slot, so
			// there is no data race on rep.Assertions (each element is written once).
			rep.Assertions[i] = a
			if prog.Done != nil {
				doneMu.Lock()
				prog.Done(a)
				doneMu.Unlock()
			}
		}(i, c)
	}
	wg.Wait()
	return rep
}

// LiveParams is everything the LIVE assertion set needs to stand up its real
// probes against a provisioned account on this host: the account and its
// endpoint (for the report header + the anonymized-exit / dns-remote checks), the
// anon+shim UIDs and the shim's loopback ports (for the leak/closure probes run
// AS the anon UID), and the exempted destination for the split-tunnel-tight check
// (empty when no LAN exemption is active, which SKIPS that assertion cleanly).
//
// It is the seam between the runtime command (main wiring, which discovers these
// from the provisioned account) and LiveChecks. LiveChecks is compiled into EVERY
// build (the probing is runtime behaviour needing root + setpriv + the installed
// shim probe binary + a live endpoint, like `add`/`rm`; it FAILS LOUD at runtime
// when it lacks any, never a silent pass). The pure assertion decisions in this
// file are what the unit suite proves against the fixture with no privilege.
type LiveParams struct {
	// Account is the anon account being verified (`anon` / `anon-<name>`).
	Account string
	// Endpoint is the credential-free socks5h URL the account is forced through
	// (endpoint.URL()); it is the report header and is NEVER credentialed.
	Endpoint string
	// Class is the endpoint's share-class; the anonymized-exit assertion additionally
	// requires a Tor exit for ClassTorShared.
	Class endpoint.ShareClass
	// AnonUID / ShimUID are the account's forced UID and its dedicated shim UID; the
	// live probes run AS AnonUID (the nft rules key on `meta skuid`).
	AnonUID int
	ShimUID int
	// RelayPort / DNSPort are the shim's loopback ports (the ONLY loopback the anon
	// UID may reach); the closure probes dial NON-shim loopback to prove the drop.
	RelayPort int
	DNSPort   int
	// EndpointHost / EndpointPort is the upstream endpoint the shim dials; the
	// direct-endpoint bypass closure (b) probes it AS the anon UID to prove the drop.
	EndpointHost string
	EndpointPort int
	// Exempt is the LAN-exempted host:port (story 25), empty when no exemption is
	// active; when empty the split-tunnel-tight assertion is not run.
	Exempt string
	// SkipTorExitCheck relaxes the anonymized-exit Tor-exit REQUIREMENT for a
	// tor-shared endpoint (from `--skip-tor-exit-check`): the exit must still DIFFER
	// from the host (forced egress proven), but an exit no registry confirms as Tor no
	// longer fails. It exists for the registry-lag false-negative (a brand-new Tor
	// exit check.torproject.org + onionoo have not yet catalogued); the pass says so.
	SkipTorExitCheck bool
}

// RunVerify is the runtime orchestrator behind `anonctl verify`: it composes the
// account+endpoint header and runs the LIVE assertion set (LiveChecks) with no
// short-circuit, so the report is complete and the exit code is the CI-gating
// verdict. It is the single entry point main wires to; the header states which
// account/endpoint was proven, and every assertion runs. A probe that cannot run
// (missing root/setpriv/shim/endpoint) fails LOUD, so verify can never silently
// "pass" verification.
func RunVerify(ctx context.Context, p LiveParams) Report {
	return RunVerifyWith(ctx, p, Progress{})
}

// RunVerifyWith is RunVerify with an optional per-check Progress hook (see
// Progress and RunWith): the SHARED entry point both `anonctl verify` and
// `anonctl use`'s gating verify drive, so wiring the hook here gives `use` the
// same progress for free. A zero Progress makes it identical to RunVerify; the
// composed header, assertion set, order, and exit code are unchanged.
func RunVerifyWith(ctx context.Context, p LiveParams, prog Progress) Report {
	rep := RunWith(ctx, LiveChecks(ctx, p), prog)
	rep.Account = p.Account
	rep.Endpoint = p.Endpoint
	return rep
}

// TorExitEvidence carries what each Tor-exit registry said about the observed exit
// IP, so the anonymized-exit decision (and its message) can be HONEST about its
// sources rather than trusting one lagging endpoint. CheckTorProject is the
// check.torproject.org IsTor field; OnionooExit is whether Tor's authoritative
// relay database (onionoo) lists the exit IP as a running exit relay. Either being
// true confirms a Tor exit; onionoo exists to rescue check.torproject.org's
// well-known false-negatives (its exit-address list LAGS the live consensus, so a
// genuine new exit reads as not-Tor there). OnionooConsulted/OnionooError record
// whether onionoo was reachable, so a corroboration that could NOT run is framed as
// "unconfirmed", never silently treated as "not Tor".
type TorExitEvidence struct {
	CheckTorProject  bool
	OnionooExit      bool
	OnionooConsulted bool
	OnionooError     string
}

// confirmsTor reports whether ANY consulted registry confirms the exit is a Tor
// exit. onionoo confirming is enough even when check.torproject.org said false
// (that is the false-negative this closes); neither confirming leaves it unproven.
func (e TorExitEvidence) confirmsTor() bool { return e.CheckTorProject || e.OnionooExit }

// AnonymizedExitAssertion is the PURE decision for the anonymized-exit assertion.
// Given the host's own direct exit IP (hostIP), the exit IP observed through the
// forced path (exitIP), the Tor-exit EVIDENCE from the registries, the endpoint's
// share-class, and whether the operator asked to skip the Tor-exit requirement
// (skipTorCheck), it returns the named Assertion:
//
//   - an EMPTY observed exit fails (the forced path produced nothing; it may have
//     failed closed) rather than silently pass;
//   - an exit EQUAL to the host's fails (egress is NOT forced: a leak);
//   - for a tor-shared endpoint the exit must ALSO be confirmed a Tor exit by AT
//     LEAST ONE registry (check.torproject.org OR onionoo); a differing exit that
//     NEITHER registry confirms fails, UNLESS skipTorCheck relaxes that half;
//   - otherwise it passes.
//
// The load-bearing half (exit differs from host => forced egress) is NEVER relaxed:
// skipTorCheck only drops the Tor-exit sub-requirement, and a skipped pass says so
// loudly. The detail always NAMES the registries consulted and warns they can lag,
// so a red is understood as "no registry confirmed this exit", not a definitive
// "you are not on Tor".
//
// It is pure so the verdict is unit-tested against the fixture without real Tor;
// the live check feeds it the real probe output.
func AnonymizedExitAssertion(hostIP, exitIP string, ev TorExitEvidence, class endpoint.ShareClass, skipTorCheck bool) Assertion {
	a := Assertion{Name: AssertAnonymizedExit}
	if exitIP == "" {
		a.Detail = "the forced path produced no exit IP (it may have failed closed): not anonymized"
		return a
	}
	if hostIP != "" && exitIP == hostIP {
		a.Detail = "exit IP " + exitIP + " EQUALS the host's: traffic is NOT forced through the endpoint (leak)"
		return a
	}
	if class != endpoint.ClassTorShared {
		a.Ok = true
		a.Detail = "exit IP " + exitIP + " differs from host " + hostIP + " (forced egress active)"
		return a
	}
	// tor-shared: the exit should be a Tor exit. Confirmed by EITHER registry passes.
	if ev.confirmsTor() {
		a.Ok = true
		a.Detail = "exit IP " + exitIP + " differs from host " + hostIP + " and is a Tor exit (" + torSourceDetail(ev) + ")"
		return a
	}
	// Neither registry confirmed it. Either skip (relax the Tor-exit half, loudly) or
	// fail with a message that names what was consulted and warns the registries lag.
	if skipTorCheck {
		a.Ok = true
		a.Detail = "exit IP " + exitIP + " differs from host " + hostIP + " (forced egress active); Tor-exit check SKIPPED (--skip-tor-exit-check): " + torSourceDetail(ev) + " - forced egress is proven, but the exit was NOT confirmed a Tor exit"
		return a
	}
	a.Detail = "exit IP " + exitIP + " differs from the host but was NOT confirmed a Tor exit for a tor-shared endpoint (" + torSourceDetail(ev) + "). These registries LAG the live Tor consensus, so a genuine, brand-new Tor exit can read as not-Tor here: if you trust your Tor, re-run (a later circuit usually picks a listed exit) or pass --skip-tor-exit-check to accept forced-egress-only"
	return a
}

// torSourceDetail renders which registries were consulted and what they said, so
// every anonymized-exit message (pass, fail, or skip) is transparent about its
// evidence rather than citing a single opaque source.
func torSourceDetail(ev TorExitEvidence) string {
	ctp := "check.torproject.org IsTor=false"
	if ev.CheckTorProject {
		ctp = "check.torproject.org IsTor=true"
	}
	switch {
	case ev.OnionooExit:
		return ctp + ", onionoo lists it as a Tor exit relay"
	case !ev.OnionooConsulted:
		return ctp + ", onionoo not consulted"
	case ev.OnionooError != "":
		return ctp + ", onionoo could not be reached (" + ev.OnionooError + ")"
	default:
		return ctp + ", onionoo does not list it as a Tor exit"
	}
}

// DNSRemoteAssertion is the PURE decision for the dns-remote assertion. Given the
// unique probe name, the hostnames the ENDPOINT (proxy) was asked to resolve
// proxy-side (proxyResolved), and whether the HOST resolver observed the same name
// (hostResolverSaw), it passes IFF the name was resolved proxy-side AND the host
// resolver never saw it: DNS goes via the anonymizer, never a plaintext/local
// lookup. It is pure so it is unit-tested against the fixture's ResolvedHosts view
// with no real resolver.
func DNSRemoteAssertion(probeName string, proxyResolved []string, hostResolverSaw bool) Assertion {
	a := Assertion{Name: AssertDNSRemote}
	if hostResolverSaw {
		a.Detail = "the host resolver observed " + probeName + ": DNS leaked locally in plaintext"
		return a
	}
	for _, h := range proxyResolved {
		if h == probeName {
			a.Ok = true
			a.Detail = probeName + " was resolved proxy-side (remotely, via the endpoint), not locally"
			return a
		}
	}
	a.Detail = probeName + " was NOT resolved proxy-side: DNS did not go through the anonymizer"
	return a
}

// dropAssertion is the shared PURE decision for the fail-closed / bypass-closure
// family (leak-drop-v4/v6, the two bypass closures): every one of them PASSES iff
// the probed direct connection was DROPPED (did NOT reach its target) and FAILS if
// it egressed (a leak). reached is what the live probe observed; a probe that
// could not run at all is passed as reached=false by the caller only when that
// genuinely means no egress (fail-closed), matching netcage's FailClosedProbe
// polarity. name+what let each closure render its own evidence line.
func dropAssertion(name, what string, reached bool) Assertion {
	a := Assertion{Name: name}
	if reached {
		a.Detail = what + " REACHED its target: fail-closed is broken (a leak)"
		return a
	}
	a.Ok = true
	a.Detail = what + " was DROPPED (fail-closed holds)"
	return a
}

// LeakDropAssertion is the load-bearing fail-closed assertion for one IP family: a
// direct, non-anonymized connection from the anon UID must be DROPPED. family is
// "v4" or "v6" and selects the assertion name (leak-drop-v4 / leak-drop-v6);
// reached is whether the direct probe egressed (true == a LEAK == fail).
func LeakDropAssertion(family string, reached bool) Assertion {
	name := AssertLeakDropV4
	if family == "v6" {
		name = AssertLeakDropV6
	}
	return dropAssertion(name, "a direct "+family+" connection from the anon UID", reached)
}

// escapedLeakProbeAssertion turns an escaped-leak-counter probe's outcome into a
// named drop assertion, treating a probe ERROR as a LOUD failure (Err set, Ok
// false), never a silent pass. This is the discipline the two closures on the
// escaped-leak counter (bypass-loopback-closure, split-tunnel-tight) were MISSING:
// their live probe planted an nft counter, and a plant/read error was swallowed to
// reached=false, which dropAssertion reads as "nothing escaped" => PASS. A probe
// that could not run is NOT a pass (ADR 0003; mirrors the anonymized-exit /
// dns-remote checks, which surface a probe error via Assertion.Err). So when err
// is non-nil the assertion FAILS with that error surfaced; otherwise the pure
// leak/no-leak decision (dropAssertion) stands on the observed reached value.
func escapedLeakProbeAssertion(name, what string, reached bool, err error) Assertion {
	if err != nil {
		return Assertion{Name: name, Err: err}
	}
	return dropAssertion(name, what, reached)
}

// BypassLoopbackClosureAssertion is closure (a): the anon UID reaching any loopback
// destination OTHER than its own shim port must be DROPPED. reached is whether the
// probe to the non-shim loopback destination egressed (true == the closure is
// broken == fail).
func BypassLoopbackClosureAssertion(reached bool) Assertion {
	return dropAssertion(AssertBypassLoopbackClosure, "the anon UID reaching a non-shim loopback destination", reached)
}

// BypassEndpointClosureAssertion is closure (b): the anon UID dialling the upstream
// endpoint DIRECTLY must be DROPPED (so it can never skip the shim or its
// isolation username). reached is whether the anon UID's direct dial of the
// endpoint egressed (true == the closure is broken == fail).
func BypassEndpointClosureAssertion(reached bool) Assertion {
	return dropAssertion(AssertBypassEndpointClosure, "the anon UID dialling the upstream endpoint directly", reached)
}

// ICMPDropAssertion is the Tails leak-catalogue row-4 decision: an ICMP echo
// (`ping`) from the anon UID to an off-box address must be DROPPED, so no ICMP
// packet carrying the real source IP ever leaves the box. It falls through to the
// anon UID's policy DROP in the shipped ruleset (there is no ICMP accept for the
// anon UID), so this assertion PROVES the drop rather than assuming it. reached is
// whether the ping egressed / got a reply (true == a leak == fail); a dropped ping
// (no ICMP left, no reply) is reached=false and PASSES. anonctl drops ICMP for the
// anon UID ONLY (not OS-wide), so unlike Tails it does NOT tune PMTU / set
// `tcp_mtu_probing` (recorded as a threat-model caveat, not a mutation).
func ICMPDropAssertion(reached bool) Assertion {
	return dropAssertion(AssertICMPDrop, "an ICMP echo (ping) from the anon UID to an off-box address", reached)
}

// NonTCPUDPDropAssertion is the Tails leak-catalogue row-5 decision: raw non-53
// UDP from the anon UID must be DROPPED, specifically INCLUDING UDP/443 (QUIC /
// HTTP-3). SOCKS carries TCP only, so any UDP that is not the redirected 53 is
// unrelayable and falls through to the anon UID's policy DROP; this assertion
// PROVES the drop. rawReached / quic443Reached are whether a raw non-53 UDP
// datagram and, specifically, a UDP/443 datagram egressed from the anon UID (true
// == a leak == fail); both must be dropped for a PASS. A real client is expected
// to degrade UDP/443 to TCP rather than leak (client behaviour, a docs note, not a
// tested assertion here).
func NonTCPUDPDropAssertion(rawReached, quic443Reached bool) Assertion {
	a := Assertion{Name: AssertNonTCPUDPDrop}
	switch {
	case rawReached:
		a.Detail = "raw non-53 UDP from the anon UID REACHED its target: fail-closed is broken (a leak)"
	case quic443Reached:
		a.Detail = "UDP/443 (QUIC) from the anon UID REACHED its target: fail-closed is broken (a leak)"
	default:
		a.Ok = true
		a.Detail = "raw non-53 UDP and UDP/443 (QUIC) from the anon UID were DROPPED (fail-closed holds; a real client degrades to TCP)"
	}
	return a
}

// SplitTunnelTightAssertion is the split-tunnel-tight decision (story 25), only
// meaningful with a LAN exemption active. It passes IFF the exempted host:port was
// reachable directly (exemptReached) AND a non-exempt destination in the same LAN
// was still redirected-or-dropped (nonExemptReached == false): the exemption works
// but did not silently widen. exempt names the exempted destination for the
// evidence line.
func SplitTunnelTightAssertion(exempt string, exemptReached, nonExemptReached bool) Assertion {
	a := Assertion{Name: AssertSplitTunnelTight}
	switch {
	case !exemptReached:
		a.Detail = "the exempted destination " + exempt + " was NOT reachable directly: the split-tunnel hole is broken"
	case nonExemptReached:
		a.Detail = "a NON-exempt LAN destination was reachable directly: the exemption widened into a leak"
	default:
		a.Ok = true
		a.Detail = "exempted " + exempt + " reachable, but the rest of the LAN / loopback stays redirected-or-dropped (tight)"
	}
	return a
}

// UIDTransitionVector is one CONCRETELY ENUMERABLE UID-transition escape vector the
// no-uid-transition-egress probe checked, and whether it ESCAPED. Escaped is true
// iff the vector yielded an off-box socket owned by a non-anon, non-shim uid (it
// does NOT match `skuid == anonUID`, so it egresses in the clear, bypassing the
// forcing): a real leak. Name identifies the vector for the evidence line (e.g.
// "sudo", "setuid:ping"); Detail is optional extra context for an escaping vector.
// The vectors come from the hand-audited finding
// (work/notes/findings/uid-transition-escape-surface.md), NOT a guessed list.
//
// Inconclusive marks a vector whose probe ran but could NOT be classified either
// way (e.g. sudo's `sudo -l -U` output was ambiguous / unparseable on a build we
// cannot read): it is NOT an escape (so it never false-alarms) and NOT a
// conclusive no-escape (so it never silently hides a real path). The assertion
// surfaces it honestly, consistent with the best-effort framing. Inconclusive and
// Escaped are mutually exclusive; a conclusive no-escape leaves both false.
type UIDTransitionVector struct {
	Name         string
	Escaped      bool
	Inconclusive bool
	Detail       string
}

// NoUIDTransitionEgressAssertion is the BEST-EFFORT row-7 decision (Tails
// leak-catalogue): the concretely enumerable UID-transition escape vectors (sudo,
// and the documented setuid network paths the audit found) must NOT yield an
// off-box socket owned by a non-anon, non-shim uid. It PASSES iff at least one
// vector was checked AND none escaped; ANY escaping vector fails (a real leak the
// per-UID forcing did not catch), and an EMPTY probe set fails (nothing checked is
// not a pass, mirroring the report-level contract).
//
// It is HONESTLY framed: the detail always names the checked vectors AND states
// plainly that the probe is best-effort and NOT exhaustive (an arbitrary
// triggerable daemon on a busy host may still escape; the per-UID model cannot
// close that, only netns can). A false total-guarantee here would be worse than an
// honest partial one, so the honesty framing is load-bearing, not decoration. It
// is pure so the verdict is unit-tested with no privilege; the live check feeds it
// the real per-vector probe outcomes.
func NoUIDTransitionEgressAssertion(vectors []UIDTransitionVector) Assertion {
	a := Assertion{Name: AssertNoUIDTransitionEgress}
	if len(vectors) == 0 {
		a.Detail = "no UID-transition vectors were checked: nothing was proved (a probe that could not run is not a pass)"
		return a
	}
	names := make([]string, 0, len(vectors))
	var escaped []string
	var inconclusive []string
	for _, v := range vectors {
		names = append(names, v.Name)
		if v.Escaped {
			if v.Detail != "" {
				escaped = append(escaped, v.Name+" ("+v.Detail+")")
			} else {
				escaped = append(escaped, v.Name)
			}
			continue
		}
		if v.Inconclusive {
			if v.Detail != "" {
				inconclusive = append(inconclusive, v.Name+" ("+v.Detail+")")
			} else {
				inconclusive = append(inconclusive, v.Name)
			}
		}
	}
	checked := strings.Join(names, ", ")
	if len(escaped) > 0 {
		a.Detail = "a checked UID-transition vector ESCAPED forcing (an off-box socket owned by a non-anon, non-shim uid egressed in the clear): " + strings.Join(escaped, "; ") + ". Checked: " + checked
		return a
	}
	a.Ok = true
	a.Detail = "the checked UID-transition vectors did not yield an off-box socket owned by a non-anon, non-shim uid (checked: " + checked + "). This is best-effort, not exhaustive: verify cannot enumerate every daemon on every host, so an arbitrary triggerable daemon may still escape the per-UID forcing (only netns-strength confinement closes that class)"
	// An inconclusive vector (a probe that ran but could not be classified) is NOT
	// an escape, but it is not a conclusive no-escape either: surface it honestly so
	// the pass never reads as a total guarantee for that vector (never a silent pass).
	if len(inconclusive) > 0 {
		a.Detail += ". NOT conclusively checked (probe ran but was inconclusive): " + strings.Join(inconclusive, "; ")
	}
	return a
}

// sudoVectorFromVerdict is the PURE sudo UID-transition vector decision: it maps
// the shared sudoprobe.Verdict (read from `sudo -l -U <account>` OUTPUT, never the
// exit code) onto the vector, so a lenient exit-0 no-rights sudo build no longer
// reports a false sudo escape. It is the twin of provision's status mapping (the
// same `sudo -l -U` truth, the same shared parse), read here as the verify-side
// escape signal, and is pure so the mapping is unit-tested with no real sudo; the
// integration sudoVector feeds it the parsed real-probe verdict.
//
//   - Denied  => the sudo path did NOT escape (Escaped=false): no sudo rights.
//   - Granted => the sudo path ESCAPED (Escaped=true): a real sudo'd socket carries
//     a non-anon uid, bypassing the `meta skuid` forcing.
//   - Unknown => honestly NOT-conclusively-checked (Inconclusive=true): never a
//     false Escaped=true (a false alarm) nor a false conclusive Escaped=false that
//     would hide a real sudo path. Consistent with the best-effort framing.
func sudoVectorFromVerdict(v sudoprobe.Verdict) UIDTransitionVector {
	out := UIDTransitionVector{Name: "sudo"}
	switch v {
	case sudoprobe.Granted:
		out.Escaped = true
		out.Detail = "the account is permitted sudo (`sudo -l -U` listed rights): a sudo'd socket carries a non-anon uid"
	case sudoprobe.Denied:
		// Escaped=false, Inconclusive=false: a conclusive no-escape.
	case sudoprobe.Unknown:
		out.Inconclusive = true
		out.Detail = "could not classify `sudo -l -U` output (neither a not-allowed denial nor a permitted-commands listing): the sudo vector is not conclusively checked"
	}
	return out
}

// LANExemptionNotADNSHoleAssertion is the Tails leak-catalogue row-2 decision, only
// meaningful with a LAN exemption active. Even when the exemption punches a direct
// hole to a private host, clear DNS to that host must NEVER egress directly to the
// LAN resolver: a `@192.168.x.x` clear-DNS query can reveal the local network's
// public IP (a deanonymization vector). It passes IFF neither a direct clear
// TCP/53 nor a direct clear UDP/53 query to the exempted host reached the LAN
// resolver as clear DNS (each 53 packet is redirected to the shim or dropped).
//
// tcp53Reached / udp53Reached are what the live probe observed for a DIRECT clear
// query to the exempted host on port 53. Per the DNS subtlety
// (work/notes/findings/manual-per-uid-tor-recipe.md), a transparent redirect means
// a naive `dig` may STILL get an answer (from the shim), so the live probe must
// read a black-hole/counter signal for a CLEAR query that actually left the box,
// not merely "dig returned nothing"; this pure decision reads that signal as
// reached==true (a leak) vs false (redirected-or-dropped). exempt names the
// exempted destination for the evidence line.
func LANExemptionNotADNSHoleAssertion(exempt string, tcp53Reached, udp53Reached bool) Assertion {
	a := Assertion{Name: AssertLANExemptionNotADNSHole}
	switch {
	case tcp53Reached:
		a.Detail = "a direct clear TCP/53 query to the exempted host " + exempt + " reached the LAN resolver: the LAN exemption is a clear-DNS hole (can reveal the local network's public IP)"
	case udp53Reached:
		a.Detail = "a direct clear UDP/53 query to the exempted host " + exempt + " reached the LAN resolver: the LAN exemption is a clear-DNS hole (can reveal the local network's public IP)"
	default:
		a.Ok = true
		a.Detail = "clear DNS (tcp+udp 53) to the exempted host " + exempt + " does not egress directly (redirected to the shim or dropped): the LAN hole is not a DNS hole"
	}
	return a
}
