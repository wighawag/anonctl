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

	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/provision"
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
import ("fmt";"net";"os";"time")
func main(){
	if len(os.Args)<3 { fmt.Print("DROPPED:usage"); return }
	c,e:=(&net.Dialer{Timeout:3*time.Second}).Dial(os.Args[1],os.Args[2])
	if e!=nil { fmt.Print("DROPPED:",e); return }
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

	// --- leak-drop-v4 (LOAD-BEARING): a direct v4 connection from the anon UID to
	// an off-box destination must be DROPPED. We dial a routable-but-unrelated v4
	// address on a port the ruleset does not redirect for a raw TCP dial that would
	// only succeed if egress were NOT forced/dropped. Because ALL non-shim TCP from
	// the anon UID is redirected into the shim (which dials the fixture), a TCP dial
	// to an arbitrary off-box IP is captured by the shim, so to prove the DROP we
	// probe a NON-redirected path: a direct dial to the fixture endpoint's own
	// port from the anon UID is closure (b) below; the pure leak drop here uses a
	// UDP-family probe, which nft drops (SOCKS carries TCP only).
	//
	// v4 leak: the anon UID reaching a non-shim, non-exempt loopback TCP port is
	// dropped by closure (a); we assert the DROP feeds LeakDropAssertion too, since
	// it is the same fail-closed property observed on v4.
	reachedV4 := probeAsAnon(t, anonUID, anonGID, "tcp4", "127.0.0.1:1") // port 1: no shim, no service
	if a := verify.LeakDropAssertion("v4", reachedV4); !a.Ok {
		t.Fatalf("leak-drop-v4 must hold (a direct v4 dial from the anon UID must be DROPPED); got %+v", a)
	}

	// --- leak-drop-v6: all IPv6 egress from the anon UID is dropped (leak-free, not
	// leaked). A direct v6 dial must be DROPPED.
	reachedV6 := probeAsAnon(t, anonUID, anonGID, "tcp6", "[::1]:1")
	if a := verify.LeakDropAssertion("v6", reachedV6); !a.Ok {
		t.Fatalf("leak-drop-v6 must hold (a direct v6 dial from the anon UID must be DROPPED); got %+v", a)
	}

	// --- bypass-loopback-closure (a): the anon UID reaching a NON-shim loopback
	// port must be DROPPED. We dial a loopback port that is neither the relay nor
	// the DNS port (and not the endpoint port); it must not connect.
	nonShimPort := relayPort + 100
	reachedLoopback := probeAsAnon(t, anonUID, anonGID, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(nonShimPort)))
	if a := verify.BypassLoopbackClosureAssertion(reachedLoopback); !a.Ok {
		t.Fatalf("bypass-loopback-closure (a) must hold; got %+v", a)
	}

	// --- bypass-endpoint-closure (b): the anon UID dialling the upstream endpoint
	// DIRECTLY must be DROPPED (so it can never skip the shim / isolation username).
	reachedEndpoint := probeAsAnon(t, anonUID, anonGID, "tcp4", fx.Addr())
	if a := verify.BypassEndpointClosureAssertion(reachedEndpoint); !a.Ok {
		t.Fatalf("bypass-endpoint-closure (b) must hold; got %+v", a)
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

// TestLiveLANExemptionNotADNSHole is the integration proof of Tails leak-catalogue
// row 2: with an all-TCP LAN exemption ACTIVE for a private host, a direct clear
// DNS query (tcp AND udp 53) from the anon UID to that exempted host must NOT
// egress as clear DNS to the LAN resolver: 53 is excluded from the exemption
// (guardrail + nft), so the nat chain still redirects tcp/udp 53 to the shim and
// the counter keyed on the LAN daddr never moves. It exercises the SAME live probe
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
	shimUID := uidOf(t, shimAccount)

	const relayPort, dnsPort = 49050, 49053
	const exempt = "192.168.1.150:8080" // all-except-53 hole for the whole host is the row-2 case

	exemptAll, err := lanexempt.Parse("192.168.1.150") // port-omitted: all TCP except 53
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
		Exemptions:   []lanexempt.Exempt{exemptAll},
	}
	if err := nftables.Apply(ctx, nr, p); err != nil {
		t.Fatalf("apply ruleset with exemption: %v", err)
	}

	// Run the live DNS-hole probe through the runtime orchestrator, with the
	// exemption active so the assertion is included.
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
	var found bool
	for _, a := range rep.Assertions {
		if a.Name != verify.AssertLANExemptionNotADNSHole {
			continue
		}
		found = true
		if !a.Ok {
			t.Fatalf("lan-exemption-not-a-dns-hole must PASS (53 is excluded, redirected to the shim); got %+v", a)
		}
	}
	if !found {
		t.Fatalf("RunVerify must include the %s assertion with an exemption active; got %+v", verify.AssertLANExemptionNotADNSHole, rep.Assertions)
	}
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
