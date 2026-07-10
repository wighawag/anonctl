//go:build integration
// +build integration

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/provision"
	"github.com/wighawag/anonctl/internal/verify"
)

// TestLiveVerifyParamsThreadsExemptionEndToEnd is the end-to-end proof of the
// wiring this task threads: an operator's LAN exemption, PERSISTED in the account
// config (the same field `add --allow` writes), must be READ BACK by
// verifyParams into verify.LiveParams.Exempt, so that a live `anonctl verify`
// runs BOTH exemption assertions (split-tunnel-tight AND lan-exemption-not-a-dns-
// hole) for that account. Unlike the internal/verify integration test (which sets
// Exempt directly), this drives the PRODUCTION verifyParams seam off the persisted
// config, proving the CLI -> Config -> verify thread is closed.
//
// It isolates to throwaway accounts and a scratch config store (never the real
// /etc), a link-local `lo` alias for the reachable exempt target, and always tears
// everything down. It SKIPS (never fails) without root / nft / setpriv, so
// `go test -tags integration ./...` still passes on an unprivileged box.
func TestLiveVerifyParamsThreadsExemptionEndToEnd(t *testing.T) {
	requireLiveVerifyHost(t)
	ctx := context.Background()
	r := provision.ExecRunner{}

	account := "anon-vitest-e2e-" + strconv.Itoa(os.Getpid())
	table := nftables.TableName(account)

	if _, err := provision.Add(ctx, r, account); err != nil {
		t.Fatalf("provision.Add(%s): %v", account, err)
	}
	defer func() {
		_, _, _ = execRun(ctx, "", "nft", "delete", "table", "inet", table)
		_, _ = provision.Rm(ctx, r, account, true)
	}()

	st, err := provision.Status(ctx, r, account)
	if err != nil {
		t.Fatalf("provision.Status: %v", err)
	}
	anonUID := atoiOr(st.UID, 0)
	shimUID := atoiOr(st.ShimUID, 0)
	anonGID := gidOfAccount(t, account)

	const relayPort, dnsPort = 59050, 59053

	// A REACHABLE link-local exempt target (an exemptable range) on a throwaway `lo`
	// alias, so split-tunnel-tight is non-vacuous: the hole opens (exemptReached)
	// while a non-exempt sibling stays dropped. Link-local (not RFC1918) so it
	// cannot collide with a real LAN the box is on.
	const exemptHost = "169.254.88.7"
	const exemptRaw = exemptHost + ":8080"
	if _, _, err := execRun(ctx, "", "ip", "addr", "add", exemptHost+"/24", "dev", "lo"); err != nil {
		t.Skipf("could not add throwaway link-local alias (%v); skipping", err)
	}
	defer func() { _, _, _ = execRun(ctx, "", "ip", "addr", "del", exemptHost+"/24", "dev", "lo") }()
	ln, err := net.Listen("tcp", exemptRaw)
	if err != nil {
		t.Skipf("could not listen on the exempt target (%v); skipping", err)
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

	// PERSIST the account config WITH the exemption, exactly as `add --allow`
	// would, in a SCRATCH store (never the real /etc). This is the record
	// verifyParams reads back.
	store := accountconfig.Store{BaseDir: t.TempDir()}
	cfg := accountconfig.Config{
		Account:       account,
		AnonUID:       anonUID,
		ShimUID:       shimUID,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassSocksPeruser,
		RelayPort:     relayPort,
		DNSPort:       dnsPort,
		Exemptions:    []string{exemptRaw},
	}
	if err := store.Write(cfg); err != nil {
		t.Fatalf("persist account config with exemption: %v", err)
	}

	// Apply the REAL fail-closed ruleset carrying the exemption (the same holes
	// `add` would install). A no-exemptions command makes exemptionsForUpdate fall
	// back to the PERSISTED config's exemptions (the same re-parse path production
	// update takes), proving that thread too.
	exemptions, err := exemptionsForUpdate(&cli.Command{Verb: "update", Account: account}, cfg)
	if err != nil {
		t.Fatalf("resolve exemptions: %v", err)
	}
	p := nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    relayPort,
		DNSPort:      dnsPort,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
		Exemptions:   exemptions,
	}
	if err := nftables.Apply(ctx, nftables.ExecRunner{}, p); err != nil {
		t.Fatalf("apply ruleset with exemption: %v", err)
	}

	// Sanity: the anon UID reaches the exempted target directly (the hole is open),
	// else split-tunnel-tight would pass vacuously.
	if !probeAsAnonUID(t, anonUID, anonGID, exemptRaw) {
		t.Fatalf("the anon UID must reach the EXEMPTED target %s directly (else split-tunnel-tight is vacuous)", exemptRaw)
	}

	// THE WIRING UNDER TEST: verifyParams reads the persisted exemption back into
	// LiveParams.Exempt, so RunVerify includes BOTH exemption assertions.
	lp := verifyParams(store, account, st)
	if lp.Exempt != exemptRaw {
		t.Fatalf("verifyParams must read the persisted exemption into Exempt; got %q, want %q", lp.Exempt, exemptRaw)
	}
	rep := verify.RunVerify(ctx, lp)
	byName := map[string]verify.Assertion{}
	for _, a := range rep.Assertions {
		byName[a.Name] = a
	}
	for _, name := range []string{verify.AssertSplitTunnelTight, verify.AssertLANExemptionNotADNSHole} {
		a, ok := byName[name]
		if !ok {
			t.Fatalf("RunVerify (via verifyParams) must include the %s assertion for an exempted account; got %+v", name, rep.Assertions)
		}
		if !a.Ok {
			t.Fatalf("%s must PASS end-to-end for a reachable, tight, non-DNS exemption; got %+v", name, a)
		}
	}
}

// requireLiveVerifyHost skips unless the box can run the live verify probes
// (root + the tools the probes shell out to), mirroring the internal/verify
// integration harness's gate.
func requireLiveVerifyHost(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("main verify integration requires root (provisions accounts, loads nft, setpriv); skipping")
	}
	for _, bin := range []string{"nft", "setpriv", "useradd", "userdel", "getent", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available; skipping", bin)
		}
	}
}

// execRun runs a command (optionally with stdin), returning trimmed stdout/stderr.
func execRun(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
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

// gidOfAccount resolves an account's numeric primary GID (setpriv --regid needs it).
func gidOfAccount(t *testing.T, account string) int {
	t.Helper()
	out, _, err := execRun(context.Background(), "", "getent", "passwd", account)
	if err != nil || out == "" {
		t.Fatalf("getent passwd %s: %v", account, err)
	}
	fields := strings.Split(out, ":")
	if len(fields) < 4 {
		t.Fatalf("malformed passwd line for %s: %q", account, out)
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		t.Fatalf("non-numeric gid for %s: %q", account, fields[3])
	}
	return gid
}

// probeAsAnonUID dials host:port AS THE ANON UID (setpriv drops to it) with a
// short timeout, returning whether the connection REACHED its target. It shells a
// tiny inline dialer so the dial truly egresses from the anon UID (the nft rules
// key on `meta skuid`).
func probeAsAnonUID(t *testing.T, anonUID, anonGID int, addr string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	const dialer = `package main
import ("net";"os";"time";"fmt")
func main(){
	c,e:=(&net.Dialer{Timeout:3*time.Second}).Dial("tcp4",os.Args[1])
	if e!=nil { fmt.Print("DROPPED"); return }
	c.Close(); fmt.Print("REACHED")
}`
	dir := t.TempDir()
	src := dir + "/dialer.go"
	if err := os.WriteFile(src, []byte(dialer), 0o644); err != nil {
		return false
	}
	bin := dir + "/dialer"
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Logf("build dialer: %v: %s", err, out)
		return false
	}
	out, _, _ := execRun(ctx, "",
		"setpriv", "--reuid", strconv.Itoa(anonUID), "--regid", strconv.Itoa(anonGID), "--clear-groups",
		bin, addr)
	return strings.Contains(out, "REACHED")
}
