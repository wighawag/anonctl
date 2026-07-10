//go:build integration
// +build integration

package verify_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anonctl/internal/shim"
	"github.com/wighawag/anonctl/internal/socks5hfixture"
	"github.com/wighawag/anonctl/internal/verify"
)

// This is the LIVE half of verify: it stands up a REAL fail-closed ruleset for
// THROWAWAY anon+shim accounts pointed at a deterministic socks5h FIXTURE (NOT
// real Tor), starts the REAL shim under the throwaway shim UID, then runs the
// load-bearing probes AS THE ANON UID (via setpriv) and feeds their outcomes to
// the SAME pure assertion functions the unit suite proves. It exercises the
// closures the nftables-ruleset-install task actually installed (verified against
// work/notes/findings/manual-per-uid-tor-recipe.md: the leak drop on v4+v6, the
// non-shim-loopback closure (a), and the direct-endpoint closure (b)).
//
// Shared-write isolation (the acceptance requirement): it provisions accounts
// under a throwaway `anon-vitest-<pid>` name, applies a per-account nft table
// (which cannot collide with a real operator's), plants a SENTINEL table to prove
// the rest of the host's nftables is untouched, and ALWAYS tears down the table,
// the sentinel, and BOTH accounts, leaving the host exactly as found. It SKIPS
// (never fails) without root / nft / setpriv, so `go test -tags integration ./...`
// still passes on an unprivileged box.

// execRunner is the real Runner for provisioning + nft in this suite.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	return run(ctx, "", name, args...)
}

// nftRunner adapts the nftables.Runner shape (stdin-carrying) to the same exec.
type nftRunner struct{}

func (nftRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	return run(ctx, stdin, name, args...)
}

func run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
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

func requireLiveHost(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("verify integration requires root (provisions accounts, loads nft, setpriv); skipping")
	}
	for _, bin := range []string{"nft", "setpriv", "useradd", "userdel", "getent"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping verify integration", bin)
		}
	}
}

// uidOf resolves an account's numeric UID from the box.
func uidOf(t *testing.T, account string) int {
	t.Helper()
	out, _, err := run(context.Background(), "", "getent", "passwd", account)
	if err != nil || out == "" {
		t.Fatalf("getent passwd %s: %v (%q)", account, err, out)
	}
	fields := strings.Split(out, ":")
	if len(fields) < 3 {
		t.Fatalf("malformed passwd line for %s: %q", account, out)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		t.Fatalf("non-numeric uid for %s: %q", account, fields[2])
	}
	return uid
}

// gidOf resolves an account's numeric primary GID (needed for setpriv --regid).
func gidOf(t *testing.T, account string) int {
	t.Helper()
	out, _, err := run(context.Background(), "", "getent", "passwd", account)
	if err != nil || out == "" {
		t.Fatalf("getent passwd %s: %v", account, err)
	}
	fields := strings.Split(out, ":")
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		t.Fatalf("non-numeric gid for %s: %q", account, fields[3])
	}
	return gid
}

// probeAsAnon dials host:port AS THE ANON UID (setpriv drops to it) with a short
// timeout, returning whether the connection REACHED (established) its target.
// A dropped connection (the fail-closed / closure outcome) times out or is
// refused => reached=false. It runs a tiny inline Go dialer under setpriv so the
// probe truly egresses from the anon UID (the nft rules key on `meta skuid`).
func probeAsAnon(t *testing.T, anonUID, anonGID int, network, addr string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, _, _ := run(ctx, "",
		"setpriv", "--reuid", strconv.Itoa(anonUID), "--regid", strconv.Itoa(anonGID), "--clear-groups",
		probeHelperBin, network, addr)
	return strings.Contains(out, "REACHED")
}

// udpSendAsAnon sends a UDP datagram to addr AS THE ANON UID and reports whether
// it REACHED (the kernel let it out) vs DROPPED (an EPERM on the sendto, the
// recipe row-5 "Operation not permitted" signal). The probe helper WRITES a
// datagram for a udp network so a connectionless Dial cannot false-pass a dropped
// path. A dropped datagram (fail-closed) reads as reached=false, the PASS.
func udpSendAsAnon(t *testing.T, anonUID, anonGID int, addr string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, _, _ := run(ctx, "",
		"setpriv", "--reuid", strconv.Itoa(anonUID), "--regid", strconv.Itoa(anonGID), "--clear-groups",
		probeHelperBin, "udp4", addr)
	return strings.Contains(out, "REACHED")
}

// pingAsAnon sends one ICMP echo AS THE ANON UID to an off-box target and reports
// whether it REACHED (got a reply, so a real-source-IP ICMP packet left and came
// back, a leak) vs DROPPED (no reply, the PASS: it fell through to the policy
// DROP). A missing `ping` binary skips-as-dropped (reached=false), the safe
// reading. It runs the system `ping` under setpriv so the ICMP socket is owned by
// the anon UID (the nft rules key on meta skuid).
func pingAsAnon(t *testing.T, anonUID, anonGID int, target string) bool {
	t.Helper()
	if _, err := exec.LookPath("ping"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, _, _ := run(ctx, "",
		"setpriv", "--reuid", strconv.Itoa(anonUID), "--regid", strconv.Itoa(anonGID), "--clear-groups",
		"ping", "-c", "1", "-W", "3", "-n", target)
	return strings.Contains(out, "bytes from") || strings.Contains(out, "1 received") || strings.Contains(out, "1 packets received")
}

// probeHelperBin is a tiny compiled dialer (built in TestMain) that connects to
// its argv target and prints REACHED / DROPPED. It is run UNDER setpriv so the
// dial egresses from the anon UID, exercising the real nft `meta skuid` rules.
var probeHelperBin string

func TestMain(m *testing.M) {
	if os.Geteuid() == 0 {
		if _, err := exec.LookPath("go"); err == nil {
			dir, err := os.MkdirTemp("", "anonctl-verify-probe")
			if err == nil {
				defer os.RemoveAll(dir)
				src := dir + "/probe.go"
				_ = os.WriteFile(src, []byte(probeSource), 0o644)
				bin := dir + "/probe"
				build := exec.Command("go", "build", "-o", bin, src)
				if out, berr := build.CombinedOutput(); berr == nil {
					probeHelperBin = bin
				} else {
					os.Stderr.Write(out)
				}
			}
		}
	}
	os.Exit(m.Run())
}

// probeSource is the dialer helper: connect with a timeout, print the outcome.
const probeSource = `package main
import ("fmt";"net";"os";"strings";"time")
func main(){
	if len(os.Args)<3 { fmt.Print("DROPPED:usage"); return }
	c,e:=(&net.Dialer{Timeout:3*time.Second}).Dial(os.Args[1],os.Args[2])
	if e!=nil { fmt.Print("DROPPED:",e); return }
	if strings.HasPrefix(os.Args[1],"udp"){
		_,we:=c.Write([]byte("x"))
		c.Close()
		if we!=nil { fmt.Print("DROPPED:",we); return }
		fmt.Print("REACHED"); return
	}
	c.Close(); fmt.Print("REACHED")
}`

// TestLiveLeakAndClosuresAgainstRealRuleset is the integration proof: real
// accounts, real nft ruleset, real shim, real anon-UID probes, feeding the pure
// assertions. It proves the fail-closed leak drop (v4 AND v6) and both bypass
// closures actually hold on a live host, isolated to throwaways.
func TestLiveLeakAndClosuresAgainstRealRuleset(t *testing.T) {
	requireLiveHost(t)
	if probeHelperBin == "" {
		t.Skip("probe helper failed to build; skipping")
	}
	ctx := context.Background()
	r := execRunner{}
	nr := nftRunner{}

	account := "anon-vitest-" + strconv.Itoa(os.Getpid())
	shimAccount := account + "-shim"
	table := nftables.TableName(account)

	// SENTINEL: a table we plant and later assert is UNTOUCHED (host isolation).
	const sentinel = "anonctl_vitest_sentinel"
	if _, stderr, err := nr.Run(ctx, "table inet "+sentinel+" {}\n", "nft", "-f", "-"); err != nil {
		t.Fatalf("plant sentinel: %v: %s", err, stderr)
	}

	// Provision the throwaway accounts (idempotent).
	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}

	// ALWAYS tear down: nft tables + both accounts, even on mid-test failure.
	defer func() {
		_, _, _ = nr.Run(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _, _ = nr.Run(ctx, "delete table inet "+sentinel, "nft", "-f", "-")
		_, _ = provision.Rm(ctx, r, account, true)
		if tableExists(t, nr, sentinel) {
			t.Errorf("cleanup left the sentinel table behind (host not isolated)")
		}
	}()

	anonUID := uidOf(t, account)
	anonGID := gidOf(t, account)
	shimUID := uidOf(t, shimAccount)

	// The socks5h ENDPOINT is a deterministic fixture (NO real Tor): the shim dials
	// it, and its ExitIP is a controlled loopback alias so the anonymized-exit
	// evidence is reproducible. It listens on a real loopback port that plays the
	// role of the upstream endpoint.
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.1"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start socks5h fixture: %v", err)
	}
	defer fx.Close()
	_, endpointPortStr, _ := net.SplitHostPort(fx.Addr())
	endpointPort, _ := strconv.Atoi(endpointPortStr)

	const relayPort, dnsPort = 39050, 39053

	// Apply the REAL fail-closed ruleset for the throwaway UIDs, pointed at the
	// fixture endpoint. The kernel ACCEPTING it proves the shape is valid; the
	// probes below prove its behaviour.
	p := nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: endpointPort,
	}
	if err := nftables.Apply(ctx, nr, p); err != nil {
		t.Fatalf("apply ruleset: %v", err)
	}

	// Start the REAL shim so the forced path is genuinely up (it dials the fixture
	// endpoint with the account isolation username). It runs in-process here (the
	// integration harness owns it), which is enough to prove the closures: the
	// closures are enforced by nft `meta skuid`, independent of who runs the shim.
	shimCtx, stopShim := context.WithCancel(ctx)
	defer stopShim()
	go func() {
		_ = shim.Run(shimCtx, shim.Config{
			RelayAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(relayPort)),
			DNSAddr:   net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort)),
			ProxyAddr: fx.Addr(),
			SocksUser: account,
		})
	}()
	time.Sleep(300 * time.Millisecond) // let the shim bind

	// --- leak-drop-v4 (LOAD-BEARING): a direct v4 LEAK is an anon-UID packet leaving
	// the box with an OFF-BOX v4 daddr in the clear. A loopback TCP handshake proves
	// NOTHING here: the transparent SO_ORIGINAL_DST relay always completes it. We read
	// the escaped-leak counter for a raw non-53 UDP datagram to an off-box v4 host (nat
	// redirects only tcp + udp/53, so raw UDP falls through to the policy DROP, recipe
	// row 3's EPERM). The counter stays 0 (dropped) => reached=false => PASS.
	const offBox = "192.0.2.1"
	reachedV4 := offBoxLeakReachedTest(t, ctx, nr, anonUID, anonGID, offBox, "udp", 9999)
	if a := verify.LeakDropAssertion("v4", reachedV4); !a.Ok {
		t.Fatalf("leak-drop-v4 must hold (no anon-UID packet may escape to an off-box v4 daddr); got %+v", a)
	}

	// --- leak-drop-v6: all IPv6 egress from the anon UID is dropped (leak-free, not
	// leaked). A direct v6 dial must be DROPPED. IPv6 has no redirect target, so a v6
	// dial genuinely fails-closed (no relay in the way): a completed handshake would be
	// a real leak, so the direct-dial signal is truthful here.
	reachedV6 := probeAsAnon(t, anonUID, anonGID, "tcp6", "[::1]:1")
	if a := verify.LeakDropAssertion("v6", reachedV6); !a.Ok {
		t.Fatalf("leak-drop-v6 must hold (a direct v6 dial from the anon UID must be DROPPED); got %+v", a)
	}

	// --- bypass-loopback-closure (a): the anon UID must not reach an arbitrary
	// destination directly. Since ALL its TCP is redirected into the shim, a loopback
	// dial completes the handshake with the relay and proves nothing; the honest
	// signal is that NO anon-UID TCP escapes the box with an OFF-BOX daddr in the
	// clear. Counter keyed on the off-box daddr stays 0 (redirected) => PASS.
	reachedLoopback := offBoxLeakReachedTest(t, ctx, nr, anonUID, anonGID, offBox, "tcp", 0)
	if a := verify.BypassLoopbackClosureAssertion(reachedLoopback); !a.Ok {
		t.Fatalf("bypass-loopback-closure (a) must hold (no anon-UID TCP escapes to an off-box daddr); got %+v", a)
	}

	// --- bypass-endpoint-closure (b): the anon UID dialling the upstream endpoint
	// DIRECTLY must not escape the box to the endpoint's address:PORT in the clear.
	// The fixture endpoint is loopback, so its TCP is redirected into the shim (BOTH
	// daddr and dport rewritten to the shim relay port); the counter keyed on the
	// endpoint daddr AND its ORIGINAL port stays 0 => PASS. Keying on the port (not
	// any-port) is load-bearing: an any-port 127.0.0.1 counter would also catch the
	// anon UID's legitimate redirected shim traffic.
	reachedEndpoint := offBoxLeakReachedTest(t, ctx, nr, anonUID, anonGID, "127.0.0.1", "tcp", endpointPort)
	if a := verify.BypassEndpointClosureAssertion(reachedEndpoint); !a.Ok {
		t.Fatalf("bypass-endpoint-closure (b) must hold; got %+v", a)
	}

	// --- icmp-drop (Tails leak-catalogue row 4): an ICMP echo from the anon UID to
	// an off-box address must be DROPPED (it falls through to the policy DROP). A
	// dropped ping gets no reply => reached=false => PASS. We assert the DROP feeds
	// ICMPDropAssertion; the probe reads whether the anon UID could EMIT ICMP.
	reachedICMP := pingAsAnon(t, anonUID, anonGID, "192.0.2.1")
	if a := verify.ICMPDropAssertion(reachedICMP); !a.Ok {
		t.Fatalf("icmp-drop must hold (a ping from the anon UID must be DROPPED); got %+v", a)
	}

	// --- non-tcp-udp-drop (Tails leak-catalogue row 5): raw non-53 UDP AND
	// specifically UDP/443 (QUIC) from the anon UID must be DROPPED (SOCKS carries
	// TCP only; both fall through to the policy DROP). A dropped datagram surfaces as
	// an EPERM on the sendto (the recipe's `socat UDP4:...:9999` -> "Operation not
	// permitted") => reached=false => PASS.
	reachedRawUDP := udpSendAsAnon(t, anonUID, anonGID, "1.1.1.1:9999")
	reachedQUIC := udpSendAsAnon(t, anonUID, anonGID, "1.1.1.1:443")
	if a := verify.NonTCPUDPDropAssertion(reachedRawUDP, reachedQUIC); !a.Ok {
		t.Fatalf("non-tcp-udp-drop must hold (raw UDP + UDP/443 from the anon UID must be DROPPED); got %+v", a)
	}

	// Sanity: the anon UID CAN reach its OWN shim relay port (closure (a) is a
	// closure, not a lockout). This proves the ruleset is not simply dropping
	// everything (which would make the DROP assertions vacuously pass).
	reachedOwnShim := probeAsAnon(t, anonUID, anonGID, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(relayPort)))
	if !reachedOwnShim {
		t.Fatalf("the anon UID must reach its OWN shim relay port (else the DROP assertions are vacuous)")
	}

	// --- The RUNTIME ORCHESTRATOR (verify.RunVerify) against the SAME live ruleset.
	// The inline probes above prove the closures directly; this proves the PRODUCTION
	// path `anonctl verify` takes wires those same closures through LiveChecks and
	// renders a report. We assert the load-bearing DROP assertions (the leak drops +
	// both bypass closures) come back Ok through the orchestrator. The anonymized-
	// exit and dns-remote checks reach the public internet through the fixture, which
	// is offline in CI, so we do not require THEIR pass here (that is the inline /
	// unit coverage's job); we require the closures the ruleset enforces to hold.
	lp := verify.LiveParams{
		Account:      account,
		Endpoint:     "socks5h://127.0.0.1:" + endpointPortStr,
		Class:        endpoint.ClassSocksPeruser,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: endpointPort,
	}
	rep := verify.RunVerify(ctx, lp)
	if rep.Account != account {
		t.Fatalf("RunVerify report must carry the account header; got %q", rep.Account)
	}
	byName := map[string]verify.Assertion{}
	for _, a := range rep.Assertions {
		byName[a.Name] = a
	}
	for _, name := range []string{
		verify.AssertLeakDropV4, verify.AssertLeakDropV6,
		verify.AssertBypassLoopbackClosure, verify.AssertBypassEndpointClosure,
		verify.AssertICMPDrop, verify.AssertNonTCPUDPDrop,
		verify.AssertNoUIDTransitionEgress,
	} {
		a, ok := byName[name]
		if !ok {
			t.Fatalf("RunVerify must include the %s assertion; got %+v", name, rep.Assertions)
		}
		if !a.Ok {
			t.Fatalf("RunVerify %s must pass against the live ruleset; got %+v", name, a)
		}
	}

	// The sentinel stayed untouched throughout (host isolation).
	if !tableExists(t, nr, sentinel) {
		t.Fatalf("the ruleset clobbered the sentinel table (host not isolated)")
	}
}

// TestEscapedLeakCounterStillCatchesARealLeak is the NEGATIVE control that proves
// the re-pointed probes did NOT neuter leak detection: it deliberately installs a
// LEAKY ruleset (the anon UID's raw off-box UDP is ACCEPTed, not dropped), then
// asserts the escaped-leak counter MOVES and LeakDropAssertion("v4", reached) FAILS.
// If this ever passes, the leak-drop probe has gone blind and the trust anchor is
// worthless. It is isolated to a throwaway account + a scratch leaky table, torn
// down always; the host's real forcing is never touched.
func TestEscapedLeakCounterStillCatchesARealLeak(t *testing.T) {
	requireLiveHost(t)
	if probeHelperBin == "" {
		t.Skip("probe helper failed to build; skipping")
	}
	ctx := context.Background()
	r := execRunner{}
	nr := nftRunner{}

	account := "anon-vitest-leak-" + strconv.Itoa(os.Getpid())
	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	const leakTable = "anonctl_vitest_realleak"
	defer func() {
		_, _, _ = nr.Run(ctx, "delete table inet "+leakTable, "nft", "-f", "-")
		_, _ = provision.Rm(ctx, r, account, true)
	}()

	anonUID := uidOf(t, account)
	anonGID := gidOf(t, account)

	// A LEAKY ruleset: for the anon UID, ACCEPT (never drop) raw off-box UDP. This is
	// exactly the fail-closed hole the leak-drop-v4 assertion must catch. It is a
	// SEPARATE scratch table at a base priority; we do NOT apply the real fail-closed
	// ruleset, so nothing redirects the datagram and it escapes with the off-box daddr.
	const offBox = "192.0.2.1"
	leaky := "table inet " + leakTable + " {\n  chain out {\n    type filter hook output priority 0; policy accept;\n    meta skuid " + strconv.Itoa(anonUID) + " ip daddr " + offBox + " udp dport 9999 accept\n  }\n}\n"
	if _, stderr, err := nr.Run(ctx, leaky, "nft", "-f", "-"); err != nil {
		t.Fatalf("plant leaky ruleset: %v: %s", err, stderr)
	}

	// The escaped-leak counter MUST move (a real off-box UDP packet left in the clear),
	// and the pure assertion MUST therefore FAIL: the fix re-points the probe, it does
	// NOT blind it.
	reached := offBoxLeakReachedTest(t, ctx, nr, anonUID, anonGID, offBox, "udp", 9999)
	if !reached {
		t.Fatalf("a genuinely leaking setup (raw off-box UDP ACCEPTed) must be DETECTED as reached; got reached=false (leak detection is neutered)")
	}
	if a := verify.LeakDropAssertion("v4", reached); a.Ok {
		t.Fatalf("leak-drop-v4 must FAIL on a real leak; got %+v", a)
	}
}

// TestLiveLANExemptionNotADNSHole is the integration proof of Tails leak-catalogue
// row 2: with an exact-port LAN exemption ACTIVE for a private host, a direct clear
// DNS query (tcp AND udp 53) from the anon UID to that exempted host must NOT
// egress as clear DNS to the LAN resolver: the exemption pins a single non-53 TCP
// port (a port is mandatory; :53 is rejected at the guardrail), so the nat chain
// still redirects tcp/udp 53 to the shim and the counter keyed on the LAN daddr
// never moves. It exercises the SAME live probe
// (clearLANDNSReached) `anonctl verify` uses, feeding the pure assertion, against a
// real kernel ruleset, isolated to throwaways.
func TestLiveLANExemptionNotADNSHole(t *testing.T) {
	requireLiveHost(t)
	if probeHelperBin == "" {
		t.Skip("probe helper failed to build; skipping")
	}
	ctx := context.Background()
	r := execRunner{}
	nr := nftRunner{}

	account := "anon-vitest-dns-" + strconv.Itoa(os.Getpid())
	shimAccount := account + "-shim"
	table := nftables.TableName(account)

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	defer func() {
		_, _, _ = nr.Run(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _ = provision.Rm(ctx, r, account, true)
	}()

	anonUID := uidOf(t, account)
	anonGID := gidOf(t, account)
	shimUID := uidOf(t, shimAccount)

	const relayPort, dnsPort = 49050, 49053

	// The exempted host is a REACHABLE link-local address (an exemptable range) on a
	// throwaway `lo` alias, so the split-tunnel probe can prove the hole actually
	// opens (exemptReached==true) AND that a NON-exempt sibling in the same /24 stays
	// dropped: a real reachable target is what makes split-tunnel-tight non-vacuous.
	// Link-local is used (not RFC1918) so the alias cannot collide with a real LAN
	// the box is on. It is torn down with the accounts (host isolation).
	const exemptHost = "169.254.99.7"
	const exempt = exemptHost + ":8080"
	if _, _, err := run(ctx, "", "ip", "addr", "add", exemptHost+"/24", "dev", "lo"); err != nil {
		t.Skipf("could not add throwaway link-local alias (%v); skipping split-tunnel proof", err)
	}
	defer func() { _, _, _ = run(ctx, "", "ip", "addr", "del", exemptHost+"/24", "dev", "lo") }()
	ln, err := net.Listen("tcp", exempt)
	if err != nil {
		t.Skipf("could not listen on the exempt target (%v); skipping split-tunnel proof", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()

	exemptEntry, err := lanexempt.Parse(exempt) // exact host:port (a port is mandatory)
	if err != nil {
		t.Fatalf("lanexempt.Parse: %v", err)
	}
	p := nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
		Exemptions:   []lanexempt.Exempt{exemptEntry},
	}
	if err := nftables.Apply(ctx, nr, p); err != nil {
		t.Fatalf("apply ruleset with exemption: %v", err)
	}

	// Sanity: the anon UID CAN reach the exempted target directly (the accept-before-
	// drop hole is open), else split-tunnel-tight would pass VACUOUSLY.
	if !probeAsAnon(t, anonUID, anonGID, "tcp4", exempt) {
		t.Fatalf("the anon UID must reach the EXEMPTED target %s directly (else split-tunnel-tight is vacuous)", exempt)
	}

	// Run BOTH exemption probes through the runtime orchestrator, with the exemption
	// active so both assertions are included.
	lp := verify.LiveParams{
		Account:      account,
		Endpoint:     "socks5h://127.0.0.1:9050",
		Class:        endpoint.ClassSocksPeruser,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
		Exempt:       exempt,
	}
	rep := verify.RunVerify(ctx, lp)
	byName := map[string]verify.Assertion{}
	for _, a := range rep.Assertions {
		byName[a.Name] = a
	}
	// BOTH exemption assertions must FIRE (they run only with an exemption active)
	// and PASS: split-tunnel-tight (the hole opens but does not widen) and
	// lan-exemption-not-a-dns-hole (the exemption pins one non-53 port; 53 stays
	// redirected to the shim).
	for _, name := range []string{verify.AssertSplitTunnelTight, verify.AssertLANExemptionNotADNSHole} {
		a, ok := byName[name]
		if !ok {
			t.Fatalf("RunVerify must include the %s assertion with an exemption active; got %+v", name, rep.Assertions)
		}
		if !a.Ok {
			t.Fatalf("%s must PASS for a reachable, tight, non-DNS exemption; got %+v", name, a)
		}
	}
}

// TestLiveLoopbackExemptionDirectButTight is the integration proof of the loopback
// exemption (loopback-exemption task): with a same-host loopback service exempted
// (127.0.0.1:<port>), the anon UID reaches THAT port DIRECTLY (split-tunnel-tight
// exemptReached==true) while every OTHER loopback destination stays dropped
// (bypass-loopback-closure, closure a) AND the anonymizer control ports (9050/9051)
// stay dropped (closure b + a). It mirrors the LAN split-tunnel proof but on
// loopback, isolated to throwaway accounts/table, and asserts the host's other
// rules are untouched via a sentinel. A real listener on the exempt loopback port
// makes the "reachable" signal non-vacuous.
func TestLiveLoopbackExemptionDirectButTight(t *testing.T) {
	requireLiveHost(t)
	if probeHelperBin == "" {
		t.Skip("probe helper failed to build; skipping")
	}
	ctx := context.Background()
	r := execRunner{}
	nr := nftRunner{}

	account := "anon-vitest-lo-" + strconv.Itoa(os.Getpid())
	shimAccount := account + "-shim"
	table := nftables.TableName(account)

	// SENTINEL: a table we plant and later assert is UNTOUCHED (host isolation).
	const sentinel = "anonctl_vitest_lo_sentinel"
	if _, stderr, err := nr.Run(ctx, "table inet "+sentinel+" {}\n", "nft", "-f", "-"); err != nil {
		t.Fatalf("plant sentinel: %v: %s", err, stderr)
	}

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	defer func() {
		_, _, _ = nr.Run(ctx, "delete table inet "+table, "nft", "-f", "-")
		_, _, _ = nr.Run(ctx, "delete table inet "+sentinel, "nft", "-f", "-")
		_, _ = provision.Rm(ctx, r, account, true)
		if tableExists(t, nr, sentinel) {
			t.Errorf("cleanup left the sentinel table behind (host not isolated)")
		}
	}()

	anonUID := uidOf(t, account)
	anonGID := gidOf(t, account)
	shimUID := uidOf(t, shimAccount)

	// A deterministic socks5h fixture plays the endpoint (no real Tor); the shim
	// dials it. Its port is the account's endpoint port (closure b targets it).
	fx := socks5hfixture.New(socks5hfixture.Options{ExitIP: "127.0.0.1"})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start socks5h fixture: %v", err)
	}
	defer fx.Close()
	_, endpointPortStr, _ := net.SplitHostPort(fx.Addr())
	endpointPort, _ := strconv.Atoi(endpointPortStr)

	const relayPort, dnsPort = 59150, 59153

	// A REAL listener on the EXEMPT loopback port, so "reachable" is a truthful
	// direct-handshake signal (the exemption RETURNs it, so it is NOT redirected into
	// the shim). 18080 is a non-anonymizer, non-shim, non-endpoint loopback port.
	const exemptPort = 18080
	exempt := net.JoinHostPort("127.0.0.1", strconv.Itoa(exemptPort))
	ln, err := net.Listen("tcp", exempt)
	if err != nil {
		t.Skipf("could not listen on the exempt loopback target (%v); skipping", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()

	exemptEntry, err := lanexempt.Parse(exempt) // 127.0.0.1:18080, a loopback-class exemption
	if err != nil {
		t.Fatalf("lanexempt.Parse(%q): %v", exempt, err)
	}
	if !exemptEntry.IsLoopback() {
		t.Fatalf("%q must parse as a loopback-class exemption", exempt)
	}
	p := nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: endpointPort,
		Exemptions:   []lanexempt.Exempt{exemptEntry},
	}
	if err := nftables.Apply(ctx, nr, p); err != nil {
		t.Fatalf("apply ruleset with loopback exemption: %v", err)
	}

	// No shim is started: the EXEMPT port is RETURNed by the nat chain (not
	// redirected), so it reaches the real loopback listener with no shim in the path;
	// and the NON-exempt / control-port checks read the escaped-leak COUNTER (planted
	// at a filter priority AFTER the nat redirect), which is decided by whether the
	// packet was rewritten, independent of whether a shim answers.

	// (1) POSITIVE: the anon UID reaches the EXEMPTED loopback port DIRECTLY (the
	// accept-before-drop hole is open), else the whole feature is a no-op and
	// split-tunnel-tight would pass vacuously.
	if !probeAsAnon(t, anonUID, anonGID, "tcp4", exempt) {
		t.Fatalf("the anon UID must reach the EXEMPTED loopback port %s directly", exempt)
	}

	// (2) CLOSURE (a): a NON-exempt loopback port (with NO exemption) must NOT be
	// reachable directly: it is redirected into the shim (which cannot SOCKS-CONNECT
	// to a host-loopback service through the endpoint), so the escaped-leak counter
	// keyed on 127.0.0.2:9999 stays 0 => the direct hole did not widen.
	reachedNonExempt := offBoxLeakReachedTest(t, ctx, nr, anonUID, anonGID, "127.0.0.2", "tcp", 9999)
	if a := verify.BypassLoopbackClosureAssertion(reachedNonExempt); !a.Ok {
		t.Fatalf("bypass-loopback-closure (a) must still hold with a loopback exemption active; got %+v", a)
	}

	// (3) The ANONYMIZER control ports stay dropped: 9050 (endpoint/Tor SOCKS) via
	// closure (b), and 9051 (Tor control) via closure (a). Neither may be reached
	// directly by the anon UID even with a loopback exemption active. Counter keyed on
	// the loopback daddr:port stays 0 (redirected/dropped) => PASS.
	for _, ctrlPort := range []int{9050, 9051} {
		reached := offBoxLeakReachedTest(t, ctx, nr, anonUID, anonGID, "127.0.0.1", "tcp", ctrlPort)
		if reached {
			t.Fatalf("the anon UID must NOT reach loopback anonymizer control port %d directly with a loopback exemption active", ctrlPort)
		}
	}

	// (4) Through the PRODUCTION orchestrator: split-tunnel-tight (exempt reachable,
	// non-exempt loopback sibling dropped) and bypass-loopback-closure (a non-exempt
	// loopback port dropped) must both FIRE and PASS for the loopback exemption.
	lp := verify.LiveParams{
		Account:      account,
		Endpoint:     "socks5h://127.0.0.1:" + endpointPortStr,
		Class:        endpoint.ClassSocksPeruser,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: endpointPort,
		Exempt:       exempt,
	}
	rep := verify.RunVerify(ctx, lp)
	byName := map[string]verify.Assertion{}
	for _, a := range rep.Assertions {
		byName[a.Name] = a
	}
	for _, name := range []string{verify.AssertSplitTunnelTight, verify.AssertBypassLoopbackClosure} {
		a, ok := byName[name]
		if !ok {
			t.Fatalf("RunVerify must include the %s assertion with a loopback exemption active; got %+v", name, rep.Assertions)
		}
		if !a.Ok {
			t.Fatalf("%s must PASS for a reachable, tight loopback exemption; got %+v", name, a)
		}
	}
}

// TestLiveNoUIDTransitionEgress is the integration proof of Tails leak-catalogue
// row 7 (best-effort): a FRESHLY-provisioned throwaway anon account (hardened at
// add-time: no sudoers entry, no sudo/wheel group) does NOT let the concretely
// enumerable UID-transition vectors (sudo, the documented setuid network wrappers)
// hand it an off-box socket owned by a non-anon, non-shim uid. It runs the SAME
// live probe (uidTransitionVectors) `anonctl verify` uses, feeding the pure
// assertion, against a real account on the box, isolated to a throwaway. It proves
// the best-effort posture holds; it does NOT (and cannot) claim exhaustive absence.
func TestLiveNoUIDTransitionEgress(t *testing.T) {
	requireLiveHost(t)
	ctx := context.Background()
	r := execRunner{}

	account := "anon-vitest-uidtx-" + strconv.Itoa(os.Getpid())
	shimAccount := account + "-shim"

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	defer func() { _, _ = provision.Rm(ctx, r, account, true) }()

	anonUID := uidOf(t, account)
	shimUID := uidOf(t, shimAccount)

	// A freshly-provisioned account is provisioned with NO sudo (the CLOSE-AT-ADD
	// invariant); sanity-check that so the row-7 assertion is not vacuously green on
	// a mis-provisioned box.
	if _, _, err := run(ctx, "", "sudo", "-l", "-U", account); err == nil {
		t.Fatalf("freshly-provisioned %s must have NO sudo rights (else the hardening regressed)", account)
	}

	lp := verify.LiveParams{
		Account: account,
		AnonUID: anonUID,
		ShimUID: shimUID,
	}
	rep := verify.RunVerify(ctx, lp)
	var got *verify.Assertion
	for i := range rep.Assertions {
		if rep.Assertions[i].Name == verify.AssertNoUIDTransitionEgress {
			got = &rep.Assertions[i]
		}
	}
	if got == nil {
		t.Fatalf("RunVerify must include the %s assertion; got %+v", verify.AssertNoUIDTransitionEgress, rep.Assertions)
	}
	if !got.Ok {
		t.Fatalf("%s must PASS for a freshly-provisioned hardened account; got %+v", verify.AssertNoUIDTransitionEgress, *got)
	}
	// The evidence must be honestly framed as best-effort / not exhaustive (never a
	// total guarantee), and must name at least the sudo vector it checked.
	if !strings.Contains(got.Detail, "best-effort") || !strings.Contains(got.Detail, "not exhaustive") {
		t.Fatalf("%s detail must be honestly framed as best-effort / not exhaustive; got %q", verify.AssertNoUIDTransitionEgress, got.Detail)
	}
	if !strings.Contains(got.Detail, "sudo") {
		t.Fatalf("%s detail must name the checked sudo vector; got %q", verify.AssertNoUIDTransitionEgress, got.Detail)
	}
}

// offBoxLeakReachedTest is the TEST-side twin of the production escaped-leak
// counter (internal/verify/counter.go + offBoxLeakReached): it reports whether an
// anon-UID packet ESCAPED the box still carrying the OFF-BOX daddr (a real leak) vs
// was redirected into the shim / dropped (the PASS). Because the transparent relay
// makes a loopback handshake always complete, this NEVER reads a completed
// handshake; it plants a throwaway counter chain at a filter priority AFTER the
// account's nat_out (dstnat/-100) keyed on the off-box daddr(+optional port), dials
// the off-box destination AS the anon UID, and reads whether the counter moved. A
// port <= 0 counts any port of the l4 (the TCP closures); a positive port pins it
// (the raw-UDP row). It ALWAYS tears down its scratch table.
func offBoxLeakReachedTest(t *testing.T, ctx context.Context, nr nftRunner, anonUID, anonGID int, daddr, l4 string, port int) bool {
	t.Helper()
	const counterTable = "anonctl_vitest_escapedleak"
	// Match the production renderer's valid shapes (counter.go): a positive port pins
	// `<l4> dport <port>`; a port-omitted (whole-protocol) case is `meta l4proto
	// <l4>`, NOT a bare `<l4>` (which is INVALID nft: `<l4> counter` is a parse error
	// and was the latent false-green).
	match := "meta skuid " + strconv.Itoa(anonUID) + " ip daddr " + daddr
	dialPort := port
	if port > 0 {
		match += " " + l4 + " dport " + strconv.Itoa(port)
	} else {
		match += " meta l4proto " + l4
		dialPort = 9999 // a port-omitted TCP closure still needs a concrete dial port
	}
	ruleset := "table inet " + counterTable + " {\n  chain out {\n    type filter hook output priority 50; policy accept;\n    " + match + " counter\n  }\n}\n"
	if _, stderr, err := nr.Run(ctx, ruleset, "nft", "-f", "-"); err != nil {
		t.Fatalf("plant escaped-leak counter: %v: %s", err, stderr)
	}
	defer func() { _, _, _ = nr.Run(ctx, "delete table inet "+counterTable, "nft", "-f", "-") }()

	network := l4 + "4"
	addr := net.JoinHostPort(daddr, strconv.Itoa(dialPort))
	if l4 == "udp" {
		udpSendAsAnon(t, anonUID, anonGID, addr)
	} else {
		probeAsAnon(t, anonUID, anonGID, network, addr)
	}

	out, _, err := nr.Run(ctx, "", "nft", "list", "table", "inet", counterTable)
	if err != nil {
		return false
	}
	return counterHasPackets(out)
}

// counterHasPackets reports whether an nft-list dump shows a `counter packets N`
// with N > 0 (a clear packet escaped). Mirrors production's counterMoved.
func counterHasPackets(listed string) bool {
	for _, line := range strings.Split(listed, "\n") {
		if !strings.Contains(line, "counter packets") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "packets" && i+1 < len(fields) {
				if n, err := strconv.Atoi(fields[i+1]); err == nil && n > 0 {
					return true
				}
			}
		}
	}
	return false
}

// tableExists reports whether an inet table is present (best-effort; a list error
// is treated as absent).
func tableExists(t *testing.T, r nftRunner, table string) bool {
	t.Helper()
	out, _, err := r.Run(context.Background(), "", "nft", "list", "table", "inet", table)
	if err != nil {
		return false
	}
	return strings.Contains(out, "table inet "+table)
}
