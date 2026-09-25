package verify

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wighawag/anonctl/internal/nssbypass"
	"github.com/wighawag/anonctl/internal/shim"
)

// The LIVE half of the DNS confinement checks: it MEASURES what the account's
// name resolution actually does, and feeds the pure decisions in dns.go.
//
// Two probes, run as the anon UID with counters planted around each:
//
//   - the NSS probe (`getent ahostsv4 <unique>.invalid`), because NSS is the path a
//     real program takes. It answers "does resolving a name put a query on the
//     ACCOUNT's own sockets, or does somebody else do the work?"
//   - the round-trip probe (`anonctl-shim -dns-probe <nameserver> <unique>.invalid`),
//     which sends one query from the account's own socket with no NSS involved. It
//     answers "when the account does use its own socket, does an answer come back?"
//
// Neither probe resolves a name that exists, and both use a fresh random label
// under `.invalid` (RFC 2606), which is guaranteed never to resolve anywhere. That
// gives three properties worth stating: no cache on the host or upstream can
// answer it (so any completed lookup MUST have produced a query somewhere, which
// is what makes the bypass measurable), nothing identifying is emitted, and an
// NXDOMAIN is the expected healthy answer rather than a failure.

// resolvConfPath is the resolver configuration the round-trip probe reads to learn
// which nameserver the account's DNS is aimed at. A package var so the unit suite
// can point it at a fixture.
var resolvConfPath = "/etc/resolv.conf"

// dnsCounterTable is the scratch-table prefix for the DNS path counters, distinct
// from the escaped-leak scratch tables so a concurrent probe of either kind can
// never tear down the other's live counters.
const dnsCounterTable = "anonctl_verify_dnspath"

// dnsSettleDelay is how long to wait after a probe before reading the counters, so
// a reply landing around the probe's deadline is still counted. Without it the
// fate this assertion exists for (the shim answered and the answer was destroyed)
// can be misreported as "the shim never answered", which sends the operator to
// their endpoint instead of to their host's input filter.
const dnsSettleDelay = 250 * time.Millisecond

// dnsCounterSeq makes each scratch table unique within this process; the pid makes
// it unique across two concurrent `anonctl verify` processes on one host.
var dnsCounterSeq atomic.Uint64

func uniqueDNSCounterTable() string {
	return fmt.Sprintf("%s_%d_%d", dnsCounterTable, os.Getpid(), dnsCounterSeq.Add(1))
}

// dnsProbeNameSeq is the fallback uniqueness source when the CSPRNG is
// unavailable; a repeated probe name would make the measurement unsound, so this
// never degrades to a constant.
var dnsProbeNameSeq atomic.Uint64

// uniqueDNSProbeName returns a name that has never been looked up before, can
// never resolve, and CARRIES NOTHING ABOUT THIS HOST OR THIS TOOL.
//
// Uniqueness is what makes the NSS bypass MEASURABLE rather than inferable: a
// cached name can be answered with no query on any socket, so a cacheable probe
// could not distinguish "somebody else resolved it" from "it was already known".
//
// TWO PROPERTIES OF THE SPELLING ARE LOAD-BEARING, and an earlier version of this
// function got both wrong in a way that made `verify` itself a small privacy leak:
//
//   - A BARE RANDOM LABEL, from the CSPRNG, with no product string, no pid and no
//     timestamp. The probe is carried through the shim to the endpoint's upstream
//     resolver, so anything in the name is seen there: `anonctl-probe-<pid>-<nanos>`
//     handed that resolver a product fingerprint plus a high-resolution cross-run
//     correlator, on a tool whose whole business is not being correlatable.
//   - A TRAILING DOT, making it absolute. `.invalid` is guaranteed to NXDOMAIN, and
//     on NXDOMAIN glibc walks the `search` list and retries. So a non-absolute probe
//     name is re-queried as `<probe>.<search-domain>`, which sends the HOST'S OWN
//     search domain to that upstream resolver. On the host this was measured on, that
//     domain is the tailnet name: precisely the identifying string the account exists
//     to keep away from a public resolver. The trailing dot suppresses the search
//     walk entirely. (shim.BuildDNSQuery trims it, so the round-trip probe is
//     unaffected.)
func uniqueDNSProbeName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano())^dnsProbeNameSeq.Add(1))
	}
	return hex.EncodeToString(b[:]) + ".invalid."
}

// dnsEvidenceCache runs the DNS measurement ONCE per verify run and shares it
// across the three DNS assertions. The checks run concurrently, so without this
// each would plant its own counters and run its own lookups: three times the wall
// time, and three different probe names whose counters could not be compared.
type dnsEvidenceCache struct {
	once sync.Once
	ev   DNSEvidence
	err  error
}

func (c *dnsEvidenceCache) get(ctx context.Context, p LiveParams) (DNSEvidence, error) {
	c.once.Do(func() { c.ev, c.err = dnsEvidence(ctx, p) })
	return c.ev, c.err
}

// dnsEvidence performs both probes and returns the measured evidence. An error
// here means a probe could NOT RUN (a missing tool, an unplantable counter), which
// every caller turns into a LOUD failing assertion: a probe that could not run is
// not a pass, and that rule matters more here than anywhere else, because the
// assertion this replaces used to pass by construction.
func dnsEvidence(ctx context.Context, p LiveParams) (DNSEvidence, error) {
	ev := DNSEvidence{Probe: uniqueDNSProbeName()}

	providers, perr := nssbypass.Inspect()
	ev.Providers = providers
	if perr != nil {
		ev.ProviderErr = perr.Error()
	}
	ev.Nameserver, ev.NameserverDefaulted = resolverAddress(resolvConfPath)

	// Probe 1: the NSS path, the one a real program takes.
	counters, err := measureWithDNSCounters(ctx, p, func(pctx context.Context) error {
		resolved, answer, lerr := nssLookupAsAnon(pctx, p, ev.Probe)
		ev.NSSResolved, ev.NSSAnswer = resolved, answer
		return lerr
	})
	if err != nil {
		return ev, err
	}
	ev.AccountEmittedQuery = counterKeyMoved(counters, dnsCounterAnonUDP53, dnsCounterAnonTCP53)
	ev.NSSReachedShim = counterKeyMoved(counters, dnsCounterTowardShimUDP, dnsCounterTowardShimTCP)

	// Probe 2: the round trip on the account's own socket, ATTEMPTED TWICE before a
	// verdict.
	//
	// WHY A SECOND ATTEMPT IS A MEASUREMENT AND NOT A LENIENCY. This assertion gates
	// `use` and `exec`, so its false-negative rate is the rate at which an operator is
	// locked out of a healthy account, and it is single-shot on a path whose honest
	// variance was measured at tenfold (0.26s to 3.6s, median ~2.2s). One sample cannot
	// separate "one answer was lost, or one circuit was cold" from "this path is
	// broken", which is precisely the distinction the check exists to draw. Two failures
	// draw it; one does not.
	//
	// It cannot make a broken path pass: a path that does not answer does not answer
	// twice, and each attempt is a FULL re-measurement (its own counters, its own
	// control window), so the evidence a verdict rests on always belongs to the attempt
	// that produced it. And it retries ONLY what a second attempt can tell apart
	// (forcedRetryWarranted): an answer from off the forced path, a redirect not in
	// effect, or an unreachable endpoint is judged on the first attempt, so none of them
	// can be hidden behind a second-attempt pass. An earlier version retried on anything
	// but a non-SERVFAIL answer, which let exactly that happen. On a healthy path it
	// costs nothing, because the first attempt answers and the loop stops.
	for attempt := 1; attempt <= forcedRoundTripAttempts; attempt++ {
		// A FRESH unique name per attempt, for the same reason the probe name is unique at
		// all, and now for a second reason as well: the shim's own forwarder caches answers
		// (including negative ones), so re-asking the SAME name could be answered from that
		// cache in microseconds and would measure anonctl's cache rather than the path.
		roundTrip := uniqueDNSProbeName()
		counters, err = measureWithDNSCounters(ctx, p, func(pctx context.Context) error {
			answered, detail, rerr := forcedDNSRoundTripAsAnon(pctx, p, ev.Nameserver, roundTrip)
			ev.ForcedAnswered, ev.ForcedDetail = answered, detail
			ev.ForcedRcode = probeRcode(detail)
			return rerr
		})
		if err != nil {
			// A probe that could not RUN is a loud error, on the first attempt as on the last:
			// retrying a missing setpriv or an unplantable counter would only hide it.
			return ev, err
		}
		ev.ForcedAttempts = attempt
		ev.ForcedReachedShim = counterKeyMoved(counters, dnsCounterTowardShimUDP, dnsCounterTowardShimTCP)
		ev.ShimReplied = counterKeyMoved(counters, dnsCounterShimReply)
		this := ForcedAttempt{
			Answered: ev.ForcedAnswered, ReachedShim: ev.ForcedReachedShim, ShimReplied: ev.ShimReplied,
			Rcode: ev.ForcedRcode, Detail: ev.ForcedDetail,
		}
		if attempt == forcedRoundTripAttempts || !forcedRetryWarranted(this) {
			break
		}
		ev.ForcedEarlier = append(ev.ForcedEarlier, this)
	}
	return ev, nil
}

// forcedRoundTripAttempts is how many times the forced round trip is measured before
// a verdict. Two, not more: the point is to separate a lost answer or a cold circuit
// from a broken path, and a third attempt buys no new distinction while adding
// another window to every genuine failure.
const forcedRoundTripAttempts = 2

// HostResolvesHostsInProcess measures whether THIS HOST's glibc performs `hosts`
// lookups in the CALLING PROCESS, rather than handing them to a daemon under
// another uid. It is the question `add` must answer before it provisions
// anything, and it is uid-independent, so it is measured with the caller's own uid
// (add runs as root) rather than with an account that does not exist yet.
//
// WHY A MEASUREMENT AND NOT THE DETECTOR. internal/nssbypass reports an
// nscd-compatible socket as a broad provider because glibc consults such a socket
// before nsswitch.conf. That is the right DEFAULT reading and it is what found the
// original leak, but the socket's EXISTENCE does not prove the daemon serves
// hosts: nsncd with `NSNCD_IGNORE_HOSTS=true` keeps its socket (it still serves
// passwd and group) while refusing hosts, which is the REMEDY anonctl itself
// recommends. Refusing on the socket alone therefore refuses exactly the hosts an
// operator has just fixed, telling them to do what they already did. Measured on
// telemaque after the remedy landed: the detector still reported nscd/nsncd, and
// the account's own lookups demonstrably went through its own sockets.
//
// It returns (inProcess, measured): measured=false means the question could not be
// answered here (no nft, no getent, or another process was emitting DNS during the
// control window), and the caller must NOT read that as either answer.
func HostResolvesHostsInProcess(ctx context.Context) (inProcess bool, measured bool, why string) {
	if _, err := exec.LookPath("nft"); err != nil {
		return false, false, "nft is not on PATH, so the host's resolution path could not be measured"
	}
	getent, err := exec.LookPath("getent")
	if err != nil {
		return false, false, "getent is not on PATH, so the host's resolution path could not be measured"
	}
	table := uniqueDNSCounterTable()
	if _, stderr, err := nftRun(ctx, hostDNSCounterRuleset(table, os.Getuid()), "nft", "-f", "-"); err != nil {
		return false, false, fmt.Sprintf("could not plant the host DNS counters: %v (%s)", err, stderr)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _, _ = nftRun(dctx, "delete table inet "+table, "nft", "-f", "-")
	}()

	// The same control window the per-account measurement uses, for the same reason:
	// these counters see every DNS query this uid makes, so a concurrent one would be
	// indistinguishable from the probe's.
	select {
	case <-time.After(dnsControlWindow):
	case <-ctx.Done():
		return false, false, "interrupted before the host's resolution path could be measured"
	}
	controlOut, _, err := nftRun(ctx, "", "nft", "list", "table", "inet", table)
	if err != nil {
		return false, false, fmt.Sprintf("could not read the host DNS counters: %v", err)
	}
	if control := parseCommentedCounters(controlOut); crossTalk(control) {
		return false, false, "another process on this host emitted DNS during the control window, so the measurement could not be attributed"
	}

	cctx, cancel := context.WithTimeout(ctx, dnsProbeBudget(5*time.Second))
	defer cancel()
	probe := uniqueDNSProbeName()
	_ = exec.CommandContext(cctx, getent, "ahostsv4", probe).Run()

	select {
	case <-time.After(dnsSettleDelay):
	case <-ctx.Done():
	}
	out, _, err := nftRun(ctx, "", "nft", "list", "table", "inet", table)
	if err != nil {
		return false, false, fmt.Sprintf("could not read the host DNS counters: %v", err)
	}
	counters := parseCommentedCounters(out)
	if counterKeyMoved(counters, dnsCounterAnonUDP53, dnsCounterAnonTCP53) {
		return true, true, "a lookup of " + probe + " put a DNS query on this process's own socket, so glibc resolves `hosts` in-process here"
	}
	return false, true, "a lookup of " + probe + " put NO DNS query on this process's own socket, so something else resolved it"
}

// measureWithDNSCounters plants the DNS path counters, runs one probe, reads the
// counters back and deletes the scratch table. A plant/read failure is
// PROPAGATED: counters that were never planted read as "nothing moved", which is
// the shape of a passing bypass check, so swallowing the error here would rebuild
// exactly the false-green this change exists to remove.
func measureWithDNSCounters(ctx context.Context, p LiveParams, run func(context.Context) error) (map[string]int, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("dns path probe cannot run: nft not found: %w", err)
	}
	table := uniqueDNSCounterTable()
	if _, stderr, err := nftRun(ctx, dnsPathCounterRuleset(table, p.AnonUID, p.ShimUID, p.DNSPort), "nft", "-f", "-"); err != nil {
		return nil, fmt.Errorf("plant dns path counters: %w (%s)", err, stderr)
	}
	// The delete runs on a context that SURVIVES cancellation. With the probe's own
	// ctx, a Ctrl+C during the run kills the delete too and leaves the scratch table
	// loaded in the kernel forever, where the next operator finds an `anonctl_verify_*`
	// table and has no way to know whether it is live instrumentation or debris.
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _, _ = nftRun(dctx, "delete table inet "+table, "nft", "-f", "-")
	}()

	// THE CONTROL WINDOW: watch the account while the probe does NOTHING. The planted
	// rules count the ACCOUNT's DNS, not this probe's, so a counter that moves here
	// belongs to some other process running as the account and the run cannot
	// attribute anything that follows. Report that as a probe that could not run
	// (loud), never as a pass: this is the one place where "the counter moved" would
	// otherwise manufacture a green on a host that is bypassing every lookup. See
	// crossTalk in dns.go.
	select {
	case <-time.After(dnsControlWindow):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	controlOut, stderr, err := nftRun(ctx, "", "nft", "list", "table", "inet", table)
	if err != nil {
		return nil, fmt.Errorf("read dns path control counters: %w (%s)", err, stderr)
	}
	if control := parseCommentedCounters(controlOut); crossTalk(control) {
		return nil, crossTalkError(control)
	}

	if err := run(ctx); err != nil {
		return nil, err
	}

	// Let the last packets of the exchange land before reading. The three-fate
	// classification turns on the SHIM REPLY counter, and the fate this assertion
	// exists for (the shim answered and the answer was destroyed) is exactly the one
	// where the reply arrives around the probe's deadline: reading instantly can
	// misreport it as "the shim never answered", which points the operator at their
	// endpoint instead of at their host's input filter.
	select {
	case <-time.After(dnsSettleDelay):
	case <-ctx.Done():
	}

	out, stderr, err := nftRun(ctx, "", "nft", "list", "table", "inet", table)
	if err != nil {
		return nil, fmt.Errorf("read dns path counters: %w (%s)", err, stderr)
	}
	return parseCommentedCounters(out), nil
}

// dnsProbeBudget is the per-probe exec window, sized so the control window plus the
// settle delay plus the probe's own deadline all fit inside whatever the caller
// allowed. It exists so a slow-but-healthy forced path is not cut off by the
// harness before it can print its verdict (the same margin rule probeExecBudget
// states for the dial probes).
func dnsProbeBudget(probe time.Duration) time.Duration {
	return dnsControlWindow + dnsSettleDelay + probe + 2*time.Second
}

// nssLookupAsAnon resolves name AS THE ANON UID through the ordinary NSS path
// (`getent ahostsv4`, which calls getaddrinfo exactly as any program does). It
// returns whether an answer came back and the first address of that answer.
//
// It deliberately does NOT use the Go resolver: Go's pure-Go resolver would bypass
// NSS entirely and measure a path no real program takes, turning the one question
// that matters here ("who does the account's resolving?") into a question about
// anonctl's own binary. `getent` is glibc's own front end to the same
// configuration every other program on the box uses.
//
// A missing getent/setpriv is a LOUD error: a probe that could not run is not a
// pass, and "no answer" is the shape the bypass assertion PASSES on.
func nssLookupAsAnon(ctx context.Context, p LiveParams, name string) (resolved bool, answer string, err error) {
	if _, e := exec.LookPath("setpriv"); e != nil {
		return false, "", fmt.Errorf("need setpriv on PATH to run the NSS bypass probe as the anon UID: %w", e)
	}
	getent, e := exec.LookPath("getent")
	if e != nil {
		return false, "", fmt.Errorf("need getent on PATH to run the NSS bypass probe (it is glibc's own front end to the account's real resolution path): %w", e)
	}
	cctx, cancel := context.WithTimeout(ctx, dnsProbeBudget(5*time.Second))
	defer cancel()
	cmd := exec.CommandContext(cctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		getent, "ahostsv4", name)
	var errb strings.Builder
	cmd.Stderr = &errb
	// STDOUT ONLY, and the exit code classified. An earlier version read
	// CombinedOutput and treated ANY non-empty output as "the account resolved it",
	// so a setpriv failure (not root, uid gone) wrote a diagnostic to stderr and the
	// report then stated that the account had resolved the probe with the answer
	// "setpriv:". That is a measurement invented from a probe that did not run, which
	// is the exact discipline this file exists to enforce.
	out, runErr := cmd.Output()
	stdout := strings.TrimSpace(string(out))
	// A lookup KILLED BY OUR OWN DEADLINE is an OBSERVATION, not a broken probe.
	//
	// On a host whose forced DNS path does not answer (the measured defect: the shim
	// replies and the answer is destroyed), glibc retries until its resolver timeout,
	// so `getent` outlives this budget and is SIGKILLed. Treating that as "the probe
	// could not run" threw away a measurement we already had: the COUNTERS are the
	// evidence for both bypass assertions, and they are equally valid whether or not
	// the lookup ever completed. It also reported the wrong thing, telling the
	// operator their probe was broken when what was broken was the account's DNS.
	if cctx.Err() == context.DeadlineExceeded {
		return false, "", nil
	}
	if stdout != "" {
		// Something resolved a name that cannot exist. On an .invalid probe that means an
		// out-of-process resolver (or a hijacking upstream) invented an answer, which is
		// worth reporting verbatim.
		if fields := strings.Fields(stdout); len(fields) > 0 {
			return true, fields[0], nil
		}
		return true, stdout, nil
	}
	// getent exits 2 for "not found", the EXPECTED outcome for an .invalid name: the
	// probe's subject is whether a QUERY WAS EMITTED, not whether the name exists.
	// Any other non-zero exit with no stdout means the probe did not run, which is a
	// loud error, never a quiet "did not resolve" (that reads as the passing side).
	if runErr != nil && exitCodeOf(runErr) != 2 {
		return false, "", fmt.Errorf("the NSS bypass probe could not run as uid %d (%v): %s", p.AnonUID, runErr, strings.TrimSpace(errb.String()))
	}
	return false, "", nil
}

// exitCodeOf returns a command's exit status, or -1 when it did not run at all.
func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// forcedDNSRoundTripAsAnon sends ONE DNS query AS THE ANON UID from the account's
// own socket to the configured nameserver, with no NSS involved, and reports
// whether an answer came back. It execs the installed shim binary's `-dns-probe`
// mode under setpriv, the same way the other probes reuse the shim as their
// dialer, so verify needs no extra tool (no dig, no python) on the host.
//
// Output that is NEITHER token means the probe never ran to completion under the
// anon UID, which is an UN-RUNNABLE probe and a loud error, never a silent "no
// answer" (which would fail the assertion for the wrong reason and send the
// operator hunting a leak that is really a missing binary).
func forcedDNSRoundTripAsAnon(ctx context.Context, p LiveParams, nameserver, name string) (answered bool, detail string, err error) {
	if _, e := exec.LookPath("setpriv"); e != nil {
		return false, "", fmt.Errorf("need setpriv on PATH to run the DNS round-trip probe as the anon UID: %w", e)
	}
	shimPath, e := shimProbePath()
	if e != nil {
		return false, "", fmt.Errorf("need the installed anonctl-shim binary to run the DNS round-trip probe: %w", e)
	}
	if _, e := exec.LookPath(shimPath); e != nil {
		return false, "", fmt.Errorf("need the installed shim probe binary %q to run the DNS round-trip probe: %w", shimPath, e)
	}
	_ = shim.DNSProbeTimeout // the deadline below is derived from the shim's own budget; see that constant
	// The outer deadline exceeds the shim's own DNS probe deadline so a genuinely
	// dropped answer gets to PRINT its NOANSWER verdict instead of being SIGKILLed
	// mid-probe and misread as "could not run" (the same margin discipline
	// probeExecBudget applies to the dial probes).
	cctx, cancel := context.WithTimeout(ctx, dnsProbeBudget(shim.DNSProbeTimeout))
	defer cancel()
	cmd := exec.CommandContext(cctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		shimPath, "-dns-probe", nameserverAddr(nameserver), name)
	out, runErr := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	switch {
	case strings.HasPrefix(s, "ANSWERED:"):
		return true, strings.TrimPrefix(s, "ANSWERED:"), nil
	case strings.HasPrefix(s, "NOANSWER:"):
		return false, strings.TrimPrefix(s, "NOANSWER:"), nil
	}
	if cctx.Err() == context.DeadlineExceeded {
		return false, s, fmt.Errorf("the DNS round-trip probe timed out before printing a verdict (query to %s outran the probe deadline): %s", nameserver, s)
	}
	// Name the likeliest cause rather than leaving the operator with a generic
	// could-not-run: an anonctl upgraded ahead of its installed shim hits exactly this
	// path, because the older shim has no -dns-probe flag and Go's flag package prints
	// "flag provided but not defined".
	if strings.Contains(s, "not defined") || strings.Contains(s, "-dns-probe") {
		return false, s, fmt.Errorf("the installed shim at %s does not support -dns-probe (it predates this anonctl): reinstall anonctl-shim alongside anonctl, then re-run verify: %s", shimPath, s)
	}
	return false, s, fmt.Errorf("the DNS round-trip probe could not run (setpriv could not drop to uid %d, or the shim probe did not execute): %v: %s", p.AnonUID, runErr, s)
}

// probeRcode reads the rcode out of a DNSProbe detail (`rcode=<n> answers=<m>`), or
// -1 when there is none to read. It is the one part of the probe's answer that the
// verdict depends on beyond "something came back", because the shim answers SERVFAIL
// to report that it could not resolve over the endpoint.
func probeRcode(detail string) int {
	for _, field := range strings.Fields(detail) {
		if !strings.HasPrefix(field, "rcode=") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(field, "rcode="))
		if err != nil {
			return -1
		}
		return n
	}
	return -1
}

// nameserverAddr renders a bare nameserver address as the host:port the probe
// dials, defaulting to the DNS port. A v6 literal is bracketed.
func nameserverAddr(ns string) string {
	if strings.Contains(ns, ":") && !strings.Contains(ns, "]") {
		return "[" + ns + "]:53"
	}
	return ns + ":53"
}

// resolverAddress returns the nameserver the account's DNS is aimed at, and
// whether it is glibc's DEFAULT rather than a declared one.
//
// A resolver configuration with no `nameserver` line is NOT a host without DNS:
// glibc falls back to 127.0.0.1:53. That case used to be reported as "the host
// declares no nameserver, so the account has no DNS to force", which is both wrong
// and consequential, since a red assertion refuses `use`/`exec` on a host whose
// account DNS works perfectly (loopback is exactly the shape the redirect serves
// best).
func resolverAddress(path string) (ns string, defaulted bool) {
	if declared := firstNameserver(path); declared != "" {
		return declared, false
	}
	return "127.0.0.1", true
}

// firstNameserver returns the first nameserver the host's resolver configuration
// declares, preferring an IPv4 one.
//
// The v4 preference is not cosmetic. The shim's DNS forwarder listens on
// 127.0.0.1, and an `inet` table's `redirect` sends a v6 packet to ::1, where
// nothing listens (and which the anon closure chain drops anyway). So a host whose
// FIRST nameserver is v6 would have its probe measure a path that cannot work by
// construction while a working v4 nameserver sits on the next line. Preferring v4
// measures the path the account actually has; the v6-only case is reported by the
// assertion with its own hint rather than silently mismeasured.
func firstNameserver(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var firstAny string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(strings.TrimSpace(sc.Text()))
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ns := fields[1]
		if firstAny == "" {
			firstAny = ns
		}
		if !strings.Contains(ns, ":") {
			return ns // an IPv4 nameserver: the path the redirect can actually serve
		}
	}
	return firstAny
}
