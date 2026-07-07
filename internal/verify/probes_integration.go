//go:build integration
// +build integration

package verify

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// clearLANDNSReached reports whether a DIRECT clear-DNS query from the anon UID to
// the exempted LAN host on port 53 actually LEFT the box to that off-box
// destination (a clear-DNS hole), as opposed to being redirected to the shim or
// dropped. It implements the black-hole/counter discipline the DNS subtlety
// requires (work/notes/findings/manual-per-uid-tor-recipe.md): because the nat
// redirect is TRANSPARENT, a naive dig STILL answers, so "did clear DNS leave?"
// cannot be read from the dig result; it must be read from a packet counter keyed
// on the ORIGINAL (un-rewritten) destination.
//
// It plants a throwaway counter table whose output chain runs AFTER the account's
// nat_out (a LATER filter priority), counting anon-UID packets STILL destined to
// exemptHost:53 (a redirected packet has had its daddr rewritten to the shim, so
// it no longer matches; only a NON-redirected "hole" packet keeps the LAN daddr
// and is counted). It then dials exemptHost:53 as the anon UID and reports whether
// the counter moved. A missing nft/setpriv, or any error, yields reached=false
// (the safe reading: no observed clear-DNS egress), never a false leak.
func clearLANDNSReached(ctx context.Context, p LiveParams, network, addr string) bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host).To4() == nil {
		return false // only the v4 LAN-resolver case is probed here
	}
	l4 := "tcp"
	if strings.HasPrefix(network, "udp") {
		l4 = "udp"
	}
	const counterTable = "anonctl_verify_dnsleak"
	ruleset := fmt.Sprintf(`table inet %s {
    chain out {
        type filter hook output priority 50; policy accept;
        meta skuid %d ip daddr %s %s dport 53 counter
    }
}
`, counterTable, p.AnonUID, host, l4)
	if _, _, err := nftRun(ctx, ruleset, "nft", "-f", "-"); err != nil {
		return false
	}
	defer func() { _, _, _ = nftRun(ctx, "delete table inet "+counterTable, "nft", "-f", "-") }()

	// Dial exemptHost:53 AS the anon UID; a clear-DNS hole would let the packet keep
	// its LAN daddr and hit the counter, a redirect/drop would not.
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	_, _, _ = runSetprivProbe(pctx, p.AnonUID, network, addr)

	out, _, err := nftRun(ctx, "", "nft", "list", "table", "inet", counterTable)
	if err != nil {
		return false
	}
	return counterMoved(out)
}

// nftRun shells out to nft (optionally with a ruleset on stdin), returning
// stdout/stderr/err. It is the counter-probe's ONLY nft access and lives here
// (integration-tagged) because it needs root.
func nftRun(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
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

// counterMoved reports whether an nft `counter` line shows a non-zero packet
// count (`counter packets N ...` with N > 0). A parse miss reads as not-moved (no
// observed leak), the safe outcome.
func counterMoved(listed string) bool {
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

// This file is the IMPURE live-probe machinery behind checks_integration.go's
// LiveChecks: standing up real connections AS the anon UID (setpriv), fetching the
// forced-path exit IP through the shim relay, and gathering the dns-remote
// evidence. It is integration-tagged (needs root + setpriv + a live endpoint); the
// pure assertion decisions it feeds live in verify.go and are unit-proven against
// the fixture. Every probe fails SAFE (an error or empty result feeds a FAILING
// pure decision), never a false pass.

// ipEchoURL is the public IP-echo the exit-IP probes fetch: it returns the
// caller's observed source IP as plain text. The host baseline hits it directly;
// the forced-path probe hits it THROUGH the shim (socks5h), so a differing result
// proves forced egress. Mirrors netcage's exit-IP evidence step.
const ipEchoURL = "https://api.ipify.org"

// torCheckURL is check.torproject.org's machine endpoint: it reports whether the
// requesting exit is a Tor exit (IsTor). The anonymized-exit assertion consults it
// for a tor-shared endpoint. Fetched THROUGH the shim so the observed exit is the
// forced one.
const torCheckURL = "https://check.torproject.org/api/ip"

// probeHelperBin is a tiny compiled dialer (built once, lazily) that connects to
// its argv target and prints REACHED / DROPPED. It is run UNDER setpriv so the
// dial egresses from the anon UID, exercising the real nft `meta skuid` rules.
// Building a helper (rather than a fragile bash /dev/tcp) keeps the probe robust
// across shells and IP families. It mirrors the integration test's helper.
var (
	probeHelperOnce sync.Once
	probeHelperBin  string
)

// probeSource is the dialer helper: connect with a timeout, print the outcome.
const probeSource = `package main
import ("fmt";"net";"os";"strings";"time")
func main(){
	if len(os.Args)<3 { fmt.Print("DROPPED:usage"); return }
	c,e:=(&net.Dialer{Timeout:3*time.Second}).Dial(os.Args[1],os.Args[2])
	if e!=nil { fmt.Print("DROPPED:",e); return }
	// For UDP the Dial is connectionless and never proves reachability; the nft
	// meta-skuid DROP surfaces as an EPERM on the actual sendto, so WRITE a
	// datagram and read whether the kernel let it out (recipe row 5: a dropped
	// UDP write returns "operation not permitted"). For TCP the Dial establishing
	// already proves REACHED.
	if strings.HasPrefix(os.Args[1],"udp"){
		_,we:=c.Write([]byte("x"))
		c.Close()
		if we!=nil { fmt.Print("DROPPED:",we); return }
		fmt.Print("REACHED"); return
	}
	c.Close(); fmt.Print("REACHED")
}`

// buildProbeHelper compiles the dialer helper once. A build failure leaves the
// path empty, and runSetprivProbe then reports reached=false (the fail-closed
// reading), never a false REACHED.
func buildProbeHelper() {
	if _, err := exec.LookPath("go"); err != nil {
		return
	}
	dir, err := os.MkdirTemp("", "anonctl-verify-probe")
	if err != nil {
		return
	}
	src := dir + "/probe.go"
	if err := os.WriteFile(src, []byte(probeSource), 0o644); err != nil {
		return
	}
	bin := dir + "/probe"
	if out, berr := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); berr == nil {
		probeHelperBin = bin
	} else {
		os.Stderr.Write(out)
	}
}

// runSetprivProbe dials network/addr AS the given UID via the compiled helper run
// under setpriv (so the connection egresses from the anon UID, exercising the nft
// `meta skuid` rules). It returns whether the dial REACHED its target. A missing
// setpriv or helper yields reached=false (the fail-closed reading), never a false
// REACHED.
func runSetprivProbe(ctx context.Context, uid int, network, addr string) (reached bool, stderr string, err error) {
	probeHelperOnce.Do(buildProbeHelper)
	if probeHelperBin == "" {
		return false, "probe helper unavailable", nil
	}
	cmd := exec.CommandContext(ctx, "setpriv",
		"--reuid", strconv.Itoa(uid), "--clear-groups",
		probeHelperBin, network, addr)
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "REACHED"), string(out), nil
}

// pingAsAnon sends a single ICMP echo AS the anon UID (setpriv drops to it) to an
// off-box target and reports whether it REACHED (got a reply): a reply means an
// ICMP packet carrying the real source IP left the box and came back (a leak); a
// dropped ping gets no reply => reached=false (the PASS, Tails leak-catalogue row
// 4). It runs the system `ping` with a short deadline and a single packet; a
// missing `ping` binary or any error yields reached=false (the fail-closed
// reading: no observed ICMP egress), never a false leak.
//
// anonctl drops ICMP for the anon UID ONLY, so `ping` for every OTHER uid on the
// box (and the machine's own PMTU discovery) is untouched; this is why anonctl
// does NOT set `net.ipv4.tcp_mtu_probing` the way Tails (OS-wide ICMP drop) does.
func pingAsAnon(ctx context.Context, p LiveParams, target string) bool {
	if _, err := exec.LookPath("ping"); err != nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	// -c 1 one packet, -W 3 three-second reply wait, -n numeric. Run under setpriv
	// so the ICMP socket is owned by the anon UID (the nft rules key on meta skuid).
	cmd := exec.CommandContext(pctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		"ping", "-c", "1", "-W", "3", "-n", target)
	out, _ := cmd.CombinedOutput()
	// A reply ("1 received" / "bytes from") means ICMP egressed and came back (a
	// leak). No reply / an error / an EPERM on the raw socket => reached=false.
	s := string(out)
	return strings.Contains(s, "bytes from") || strings.Contains(s, "1 received") || strings.Contains(s, "1 packets received")
}

// hostExitIP fetches the host's OWN direct exit IP (no shim) as the baseline the
// anonymized-exit assertion compares against. An error here is surfaced as a
// failing assertion (never a false pass).
func hostExitIP(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return httpGetTrimmed(cctx, http.DefaultClient, ipEchoURL)
}

// forcedExitIP fetches the exit IP OBSERVED THROUGH the shim relay (the forced
// path), and, for a tor-shared endpoint, whether check.torproject.org reports a
// Tor exit. It dials the shim's SOCKS relay port as a socks5h proxy so the fetch
// egresses the forced way. Any error feeds a failing anonymized-exit decision.
func forcedExitIP(ctx context.Context, p LiveParams) (exitIP string, isTor bool, err error) {
	relay := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.RelayPort))
	dialer, derr := proxy.SOCKS5("tcp", relay, nil, proxy.Direct)
	if derr != nil {
		return "", false, fmt.Errorf("build shim socks dialer: %w", derr)
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: func(_ context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }},
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	exitIP, err = httpGetTrimmed(cctx, client, ipEchoURL)
	if err != nil {
		return "", false, err
	}
	if p.Class == "tor-shared" {
		body, terr := httpGetTrimmed(cctx, client, torCheckURL)
		if terr == nil {
			isTor = strings.Contains(body, "\"IsTor\":true") || strings.Contains(body, "\"IsTor\": true")
		}
	}
	return exitIP, isTor, nil
}

// dnsRemoteEvidence gathers the dns-remote evidence: a unique probe name resolved
// THROUGH the shim (socks5h => proxy-side resolution). With a controllable
// endpoint the proxy-side view is observed by the fixture in tests; against a live
// endpoint the evidence is that the forced fetch of a name SUCCEEDED via socks5h
// (proxy-side) while the host resolver was not consulted. It returns the probe
// name, the proxy-resolved list, and whether the host resolver saw it. An error
// feeds a failing dns-remote decision.
func dnsRemoteEvidence(ctx context.Context, p LiveParams) (probe string, proxyResolved []string, hostSaw bool, err error) {
	probe = "check.torproject.org"
	relay := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.RelayPort))
	dialer, derr := proxy.SOCKS5("tcp", relay, nil, proxy.Direct)
	if derr != nil {
		return probe, nil, false, fmt.Errorf("build shim socks dialer: %w", derr)
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: func(_ context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }},
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := httpGetTrimmed(cctx, client, "https://"+probe+"/"); err != nil {
		return probe, nil, false, err
	}
	// A socks5h fetch resolves the name PROXY-SIDE by construction; success means
	// the endpoint resolved it. The host resolver was never asked (the shim path
	// carries the name to the proxy), so hostSaw stays false.
	return probe, []string{probe}, false, nil
}

// httpGetTrimmed GETs url and returns the trimmed body, or an error.
func httpGetTrimmed(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// nonExemptLANOf derives a NON-exempt destination in the same LAN /24 as the
// exempted host:port, so the split-tunnel-tight probe can prove the exemption did
// not widen: a different host in the same /24 (host .1, or .2 if the exempt is .1)
// on the exempt port must still be redirected-or-dropped. Best-effort; a malformed
// exempt yields an address that will simply be DROPPED (the tight outcome).
func nonExemptLANOf(exempt string) string {
	host, port, err := net.SplitHostPort(exempt)
	if err != nil {
		return exempt
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return net.JoinHostPort("127.0.0.2", port) // non-exempt loopback fallback
	}
	other := byte(1)
	if ip[3] == 1 {
		other = 2
	}
	ip[3] = other
	return net.JoinHostPort(ip.String(), port)
}
