//go:build integration
// +build integration

package verify

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/nssbypass"
	"github.com/wighawag/anonctl/internal/socks5hfixture"
)

// The LIVE half of the DNS confinement measurement: real throwaway accounts, the
// real nft ruleset, the real shim against a deterministic socks5h fixture, and the
// REAL production probe (`dnsEvidence`) run against them.
//
// IT IS DELIBERATELY IN-PACKAGE (`package verify`, not `verify_test`) so it calls
// the PRODUCTION function rather than a re-implementation of it. The sibling suite
// in verify_integration_test.go necessarily re-implements its counter probe as a
// test twin (`offBoxLeakReachedTest`), and this repo has already paid for that
// once: the twin and production drifted, production rendered an INVALID nft rule,
// the plant error was swallowed to "no leak", and two closure assertions passed
// unconditionally (work/notes/findings/e2e-binary-validation.md, finding 2). The
// only way a live test can prove the thing that ships is to call the thing that
// ships.
//
// Isolation: throwaway `anon-dnsit-<pid>` accounts, a per-account nft table that
// cannot collide with an operator's, a fixture endpoint instead of real Tor, a
// fake upstream resolver instead of the real internet, and a package-var resolver
// configuration so the host's /etc/resolv.conf is never read or touched. Every
// test tears all of it down. It SKIPS (never fails) without root and the tools.

// requireLiveDNSHost skips unless this box can actually run the measurement.
func requireLiveDNSHost(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("live DNS measurement requires root (provisions accounts, loads nft, setpriv); skipping")
	}
	for _, bin := range []string{"nft", "setpriv", "getent", "go"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping live DNS measurement", bin)
		}
	}
}

// dnsLiveEnv is a standing forced account with a working forced DNS path.
type dnsLiveEnv struct {
	params   LiveParams
	table    string
	shimUID  int
	stopShim context.CancelFunc
}

// setupDNSLive builds the whole forced path for a throwaway account and points the
// probes at it. The returned cleanup ALWAYS runs the teardown.
func setupDNSLive(t *testing.T) (*dnsLiveEnv, func()) {
	t.Helper()
	ctx := context.Background()
	r := dnsITRunner{}

	account := "anon-dnsit-" + strconv.Itoa(os.Getpid())
	shimAccount := account + "-shim"
	table := nftables.TableName(account)

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	cleanups := []func(){}
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
		_, _, _ = nftRun(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _ = provision.Rm(ctx, r, account, true)
	}
	fail := func(format string, args ...any) {
		cleanup()
		t.Fatalf(format, args...)
	}

	anonUID := dnsITUidOf(t, account)
	shimUID := dnsITUidOf(t, shimAccount)

	// A fake upstream resolver speaking DNS-over-TCP (RFC 7766 framing), which is
	// what the shim's forwarder speaks to its upstream. Nothing leaves this box.
	responder, respAddr := startFakeTCPResolver(t)
	cleanups = append(cleanups, func() { responder.Close() })

	// The socks5h endpoint fixture, with every CONNECT redirected to the fake
	// resolver, so the shim's upstream dial lands there deterministically.
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.1", RedirectTarget: respAddr})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		fail("start socks5h fixture: %v", err)
	}
	cleanups = append(cleanups, func() { fx.Close() })
	_, endpointPortStr, _ := net.SplitHostPort(fx.Addr())
	endpointPort, _ := strconv.Atoi(endpointPortStr)

	// Ports distinct from the sibling suite's, so the two can run in one go test.
	const relayPort, dnsPort = 39150, 39153

	// THE ACCOUNT'S RESOLVER, pointed at loopback. This is a package var precisely
	// so a test never depends on (or reads) the host's own /etc/resolv.conf: the
	// measurement would otherwise vary with whatever this box's resolver happens to
	// be, which is the thing under test on a real host and pure noise here.
	// 127.0.0.1:53 is redirected into the shim by the ruleset below.
	scratch := dnsITWorldReadableDir(t)
	resolvPath := scratch + "/resolv.conf"
	if err := os.WriteFile(resolvPath, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		fail("write test resolv.conf: %v", err)
	}
	origResolv := resolvConfPath
	resolvConfPath = resolvPath
	cleanups = append(cleanups, func() { resolvConfPath = origResolv })

	// The real shim binary: the round-trip probe execs it in `-dns-probe` mode, and
	// the harness runs it as the SHIM below. It must be executable by BOTH throwaway
	// uids: setpriv drops privilege and THEN execs, so a root-owned 0700 temp dir
	// (os.MkdirTemp's default) fails the exec with EACCES on the directory rather
	// than running anything, which the harness would then report as "the probe could
	// not run".
	shimBin := scratch + "/anonctl-shim"
	build := exec.Command("go", "build", "-o", shimBin, "github.com/wighawag/anonctl/cmd/anonctl-shim")
	if out, err := build.CombinedOutput(); err != nil {
		cleanup()
		t.Skipf("could not build anonctl-shim (%v): %s", err, out)
	}
	if err := os.Chmod(shimBin, 0o755); err != nil {
		fail("chmod shim binary: %v", err)
	}
	origProbeBin := probeShimBinary
	probeShimBinary = shimBin
	cleanups = append(cleanups, func() { probeShimBinary = origProbeBin })

	if err := nftables.Apply(ctx, dnsITNftRunner{}, nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: endpointPort,
	}); err != nil {
		fail("apply ruleset: %v", err)
	}

	// THE SHIM RUNS UNDER ITS OWN UID, as a child process, NOT in-process.
	//
	// The sibling suite runs it in-process and says so: its closures are enforced by
	// `meta skuid <anonUID>` and hold regardless of who runs the shim. That does NOT
	// carry over here. The shim-reply counter is a claim ABOUT THE SHIM'S UID ("the
	// shim, specifically, emitted an answer"), and the test binary runs as root, so
	// an in-process shim replies from uid 0 and the rule cannot match it. Measured
	// when this harness did run it in-process: the whole round trip succeeded
	// (ForcedAnswered=true) while ShimReplied stayed false, and the reply-drop test's
	// `meta skuid <shimUID>` rule dropped nothing. Both were harness artifacts, and a
	// test that cannot observe the uid separation cannot prove the rule that rests on
	// it. Running it the way production does (setpriv to the shim uid) is also the
	// more faithful test.
	shimCtx, stopShim := context.WithCancel(ctx)
	shimCmd := exec.CommandContext(shimCtx, "setpriv",
		"--reuid", strconv.Itoa(shimUID), "--clear-groups",
		shimBin,
		"-relay", net.JoinHostPort("127.0.0.1", strconv.Itoa(relayPort)),
		"-dns", net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort)),
		"-proxy", fx.Addr(),
		"-socks-user", account)
	var shimLog strings.Builder
	shimCmd.Stdout = &shimLog
	shimCmd.Stderr = &shimLog
	if err := shimCmd.Start(); err != nil {
		stopShim()
		fail("start shim as uid %d: %v", shimUID, err)
	}
	cleanups = append(cleanups, func() {
		stopShim()
		_ = shimCmd.Wait()
	})
	if err := dnsITWaitForShim(relayPort); err != nil {
		fail("the shim never came up under uid %d: %v (shim output: %s)", shimUID, err, shimLog.String())
	}

	return &dnsLiveEnv{
		params: LiveParams{
			Account:      account,
			Class:        endpoint.ClassTorShared,
			AnonUID:      anonUID,
			ShimUID:      shimUID,
			RelayPort:    relayPort,
			DNSPort:      dnsPort,
			EndpointHost: "127.0.0.1",
			EndpointPort: endpointPort,
		},
		table:    table,
		shimUID:  shimUID,
		stopShim: stopShim,
	}, cleanup
}

// TestLiveDNSForcedPathAnswersOnAHealthyPath is the green case, and it is the one
// test that proves the planted counter ruleset is VALID NFT IN A LIVE KERNEL. No
// unit test can: `dnsPathCounterRuleset` is only ever string-compared there, and
// an invalid rule would fail to plant, which is exactly how this repo's earlier
// counter false-green happened.
func TestLiveDNSForcedPathAnswersOnAHealthyPath(t *testing.T) {
	requireLiveDNSHost(t)
	env, cleanup := setupDNSLive(t)
	defer cleanup()

	ev, err := dnsEvidence(context.Background(), env.params)
	if err != nil {
		t.Fatalf("dnsEvidence on a healthy forced path must not error: %v", err)
	}

	// The round-trip half: the account's own query went through the redirect, the
	// shim answered, and the answer came back.
	if !ev.ForcedReachedShim {
		t.Errorf("the query must reach the shim through the redirect; evidence: %+v", ev)
	}
	if !ev.ShimReplied {
		t.Errorf("the shim must emit a reply; evidence: %+v", ev)
	}
	if !ev.ForcedAnswered {
		t.Errorf("the answer must come back to the account; evidence: %+v", ev)
	}
	if a := DNSForcedPathAnswersAssertion(ev); !a.Ok {
		t.Errorf("dns-forced-path-answers must PASS on a healthy path; got %+v", a)
	}

	// The NSS half is a property of THIS HOST's resolution configuration, which the
	// test cannot control (there is no per-process way to stop glibc consulting an
	// nscd socket). Only ONE direction is a real invariant, and an earlier version of
	// this test asserted both, which was wrong and a live run caught it:
	//
	//   - no broad provider detected => the lookup MUST have used the account's own
	//     sockets. Sound: there is nothing else that could have resolved it.
	//   - broad provider detected => the lookup must NOT have. UNSOUND, because the
	//     detector reports an nscd socket from its EXISTENCE, and nsncd with
	//     NSNCD_IGNORE_HOSTS=true keeps its socket (it still serves passwd/group)
	//     while refusing hosts. That is the remedy anonctl recommends, so the
	//     configuration this test called a contradiction is the CORRECT one.
	//
	// So assert the sound direction, and merely REPORT the other, which is also how
	// the product treats it: the measurement is the authority and the detector only
	// makes a failure actionable.
	providers, _ := nssbypass.Inspect()
	broad := nssbypass.Broad(providers)
	if len(broad) == 0 && !ev.AccountEmittedQuery {
		t.Errorf("this host has no broad out-of-process resolver, so the account's own NSS lookup MUST have emitted a query; evidence: %+v", ev)
	}
	if len(broad) > 0 && ev.AccountEmittedQuery {
		t.Logf("detector reports %s, but the measurement shows the account's own sockets carrying the lookup: the daemon is present and not serving hosts (the remedied configuration)", nssbypass.Names(broad))
	}
	if ev.AccountEmittedQuery {
		if a := DNSNSSNotBypassedAssertion(ev); !a.Ok {
			t.Errorf("dns-nss-not-bypassed must PASS on a host that resolves in-process; got %+v", a)
		}
		if a := DNSRemoteAssertion(ev); !a.Ok {
			t.Errorf("dns-remote must PASS when the account's lookup reached the shim; got %+v", a)
		}
	} else {
		t.Logf("this host resolves the account's names out of process (%s), so the bypass assertions are expected RED here: that is the finding, not a test failure", nssbypass.Names(broad))
	}
}

// TestLiveDNSAnswerDestroyedAfterTheShimReplied reproduces the MEASURED failure
// shape: the redirect fires, the shim answers, and the answer never arrives. On
// the real host the killer is tailscaled's input-side anti-spoof rule matching the
// un-NATed reply's source address; here the same OBSERVABLE FATE is produced by
// dropping the shim's reply on its way out, scoped by `meta skuid` to the
// THROWAWAY shim uid so nothing else on the box can be affected.
//
// The drop sits at priority -250: after the probe's own counter chain (-300, which
// must still SEE the reply, since "the shim replied" is the signal that separates
// this fate from "the shim never answered") and before the nat hook (-100, which
// un-NATs the reply's source and would make the `udp sport <dnsPort>` match stop
// matching).
func TestLiveDNSAnswerDestroyedAfterTheShimReplied(t *testing.T) {
	requireLiveDNSHost(t)
	env, cleanup := setupDNSLive(t)
	defer cleanup()
	ctx := context.Background()

	const dropTable = "anonctl_dnsit_replydrop"
	ruleset := fmt.Sprintf(`table inet %s {
    chain out {
        type filter hook output priority -250; policy accept;
        meta skuid %d udp sport %d drop
    }
}
`, dropTable, env.shimUID, env.params.DNSPort)
	if _, stderr, err := nftRun(ctx, ruleset, "nft", "-f", "-"); err != nil {
		t.Fatalf("plant the reply-drop table: %v: %s", err, stderr)
	}
	defer func() { _, _, _ = nftRun(ctx, "delete table inet "+dropTable, "nft", "-f", "-") }()

	ev, err := dnsEvidence(ctx, env.params)
	if err != nil {
		t.Fatalf("dnsEvidence must still measure when the answer is destroyed: %v", err)
	}
	if !ev.ForcedReachedShim {
		t.Errorf("the query must still reach the shim; evidence: %+v", ev)
	}
	if !ev.ShimReplied {
		t.Fatalf("the shim must be observed REPLYING (this is what separates this fate from a silent shim); evidence: %+v", ev)
	}
	if ev.ForcedAnswered {
		t.Fatalf("the answer was dropped, so it cannot have arrived; evidence: %+v", ev)
	}
	a := DNSForcedPathAnswersAssertion(ev)
	if a.Ok {
		t.Fatalf("dns-forced-path-answers must FAIL when the answer never arrives; got %+v", a)
	}
	// The detail must report the OBSERVATION and offer the un-NAT mechanism as a
	// candidate. It must NOT assert that mechanism as established fact: the counters
	// cannot distinguish "this query's answer was destroyed" from "the shim never
	// answered this query and the packet seen was another query's reply", and a message
	// that picks one sent a real operator to `nft` for a failure inside the forwarder.
	if !strings.Contains(a.Detail, "NO answer came back") {
		t.Errorf("the failure must state what was measured (no answer reached the account); got %q", a.Detail)
	}
	if !strings.Contains(a.Detail, "un-NATs") {
		t.Errorf("the un-NAT mechanism must still be offered as a candidate, since it is the measured real-host defect; got %q", a.Detail)
	}
	if !strings.Contains(a.Detail, "proves only that A packet left") {
		t.Errorf("the failure must be explicit that the shim-reply counter proves only that A packet left during the window, not that this query was answered; got %q", a.Detail)
	}
}

// TestLiveDNSCrossTalkIsReportedAsUnattributable is the regression test for the
// attribution gap found in review: the counters match `meta skuid <anon> dport 53`,
// so they count the ACCOUNT's DNS rather than the PROBE's, and another process
// running as the account moves them. Before the control window this run would have
// reported a PASS on both bypass assertions; it must now refuse to conclude
// anything.
func TestLiveDNSCrossTalkIsReportedAsUnattributable(t *testing.T) {
	requireLiveDNSHost(t)
	env, cleanup := setupDNSLive(t)
	defer cleanup()
	ctx := context.Background()

	// A second process running AS THE ACCOUNT, resolving continuously: the shape of
	// any Go binary (its pure-Go resolver bypasses NSS and emits its own UDP) or a
	// stray `dig` in a live session.
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			noise := exec.Command("setpriv", "--reuid", strconv.Itoa(env.params.AnonUID), "--clear-groups",
				probeShimBinary, "-dns-probe", "127.0.0.1:53", "noise.invalid.")
			_ = noise.Run()
		}
	}()
	defer func() { stop.Store(true); <-done }()
	time.Sleep(200 * time.Millisecond) // let the noise start flowing

	_, err := dnsEvidence(ctx, env.params)
	if err == nil {
		t.Fatalf("a run it cannot attribute must be an ERROR, never a pass: concurrent account DNS moved the counters and the measurement claimed a result anyway")
	}
	if !strings.Contains(err.Error(), "could not be attributed") {
		t.Errorf("the error must name the attribution failure; got %v", err)
	}
	if !strings.Contains(err.Error(), "NOTHING is proven") {
		t.Errorf("the error must not read as a leak finding nor as an all-clear; got %v", err)
	}
}

// --- harness ---

// dnsITRunner is the real exec Runner for provisioning.
type dnsITRunner struct{}

func (dnsITRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// dnsITNftRunner adapts the stdin-carrying nftables.Runner shape.
type dnsITNftRunner struct{}

func (dnsITNftRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

// dnsITUidOf reads an account's uid from the passwd table.
func dnsITUidOf(t *testing.T, account string) int {
	t.Helper()
	out, _, err := dnsITRunner{}.Run(context.Background(), "getent", "passwd", account)
	if err != nil {
		t.Fatalf("getent passwd %s: %v", account, err)
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 3 {
		t.Fatalf("malformed passwd line for %s: %q", account, out)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		t.Fatalf("unparseable uid for %s: %q", account, fields[2])
	}
	return uid
}

// dnsITWorldReadableDir makes a scratch dir the ANON UID can traverse. os.MkdirTemp
// gives 0700 owned by root, and the probes exec their binary AFTER setpriv has
// dropped to the anon uid, so a 0700 ancestor fails the exec with EACCES on the
// directory rather than running the probe (which the harness would then report as
// "the probe could not run").
func dnsITWorldReadableDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "anonctl-dnsit")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod scratch dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startFakeTCPResolver serves DNS-over-TCP (RFC 7766 2-byte length framing) and
// answers every query with NXDOMAIN, echoing the query id AND THE QUESTION. It is
// what the shim's forwarder talks to through the fixture, so the whole round trip
// is local and deterministic: no real resolver, no network, and NXDOMAIN is the
// expected healthy answer for an `.invalid` probe anyway.
//
// ECHOING THE QUESTION IS NOT COSMETIC. A first version replied with a bare
// 12-byte header (QDCOUNT=0, no question section). anonctl's own `-dns-probe`
// accepted it, because it only reads the header, so the round-trip half of the
// suite passed. GLIBC DOES NOT: it matches the response's question against the
// one it asked, discards a reply that does not carry it, and retries until its
// resolver timeout, so `getent` burned the whole probe budget and was SIGKILLed
// ("the NSS bypass probe could not run ... signal: killed").
//
// Worth noticing WHY that only appeared once the host was fixed: before, nsncd
// answered every `getaddrinfo` out of process, so getent never reached this
// responder at all and nothing validated its replies. The bug was always here; the
// host fix is what made the test exercise it.
func startFakeTCPResolver(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake resolver: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					_ = c.SetDeadline(time.Now().Add(10 * time.Second))
					var lenBuf [2]byte
					if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
					if _, err := io.ReadFull(c, query); err != nil || len(query) < 12 {
						return
					}
					// Header (id echoed, QR+RD+RA set, rcode 3) then the QUESTION verbatim.
					resp := make([]byte, 12, 12+len(query))
					copy(resp[0:2], query[0:2])                   // echo the id
					binary.BigEndian.PutUint16(resp[2:4], 0x8183) // QR + RD + RA + NXDOMAIN
					binary.BigEndian.PutUint16(resp[4:6], 1)      // QDCOUNT: we echo one question
					resp = append(resp, query[12:]...)            // the question section, unchanged
					framed := make([]byte, 2+len(resp))
					binary.BigEndian.PutUint16(framed[:2], uint16(len(resp)))
					copy(framed[2:], resp)
					if _, err := c.Write(framed); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln, ln.Addr().String()
}

// dnsITWaitForShim polls until the shim's relay port accepts, so the tests never
// race a not-yet-bound shim. A flat sleep would either be too short on a loaded
// box (a flake that reads as "the shim never answered", the exact fate one of
// these tests is about) or waste time on every run.
func dnsITWaitForShim(relayPort int) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(relayPort))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("relay port %d never accepted within 5s", relayPort)
}
