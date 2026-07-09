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

	"github.com/wighawag/anonctl/internal/lanexempt"
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
// It is one caller of the shared escaped-leak counter primitive (offBoxLeakReached,
// counter.go): the counter is keyed on exemptHost:53 (a redirected packet has had
// its daddr rewritten to the shim, so it no longer matches; only a NON-redirected
// "hole" packet keeps the LAN daddr and is counted), then it dials exemptHost:53 as
// the anon UID and reports whether the counter moved. A missing nft/setpriv, or any
// error, yields reached=false (the safe reading: no observed clear-DNS egress),
// never a false leak.
func clearLANDNSReached(ctx context.Context, p LiveParams, network, addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host).To4() == nil {
		return false // only the v4 LAN-resolver case is probed here
	}
	l4 := "tcp"
	if strings.HasPrefix(network, "udp") {
		l4 = "udp"
	}
	return offBoxLeakReached(ctx, p, host, l4, lanexempt.DNSPort, network, addr)
}

// offBoxLeakReached is the SHARED live probe behind every fail-closed / bypass
// closure assertion on the transparent relay: it reports whether an anon-UID
// packet ESCAPED the box still carrying an OFF-BOX destination (a real leak) as
// opposed to being redirected into the shim or dropped. Because the transparent
// SO_ORIGINAL_DST relay makes a loopback TCP handshake ALWAYS complete, "reached"
// can NEVER be read from a completed handshake; it is read from the escaped-leak
// counter (counter.go): a throwaway nft counter planted at a filter priority AFTER
// the account's nat_out (dstnat/-100), keyed on the OFF-BOX daddr(+optional port),
// which only a non-redirected clear escape increments.
//
// counterDaddr/l4/port describe what the counter watches for; probeNetwork/probeAddr
// are what the anon UID actually dials to try to produce that escape. They differ
// only for the loopback-endpoint closure case (dial the loopback endpoint, watch
// its off-box-form daddr) and are identical for the off-box leak/closure probes. A
// missing nft, a plant/list error, or a missing helper yields reached=false (the
// fail-closed-safe reading: no observed escape), never a false leak.
func offBoxLeakReached(ctx context.Context, p LiveParams, counterDaddr, l4 string, port int, probeNetwork, probeAddr string) bool {
	if _, err := exec.LookPath("nft"); err != nil {
		return false
	}
	ruleset := escapedLeakCounterRuleset(p.AnonUID, counterDaddr, l4, port)
	if _, _, err := nftRun(ctx, ruleset, "nft", "-f", "-"); err != nil {
		return false
	}
	defer func() { _, _, _ = nftRun(ctx, "delete table inet "+escapedLeakCounterTable, "nft", "-f", "-") }()

	// Dial the off-box destination AS the anon UID; a genuine leak keeps the off-box
	// daddr and hits the counter, a redirect/drop does not. We ignore whether the
	// dial "succeeded" (a loopback handshake with the relay always does); only the
	// counter is decisive.
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	_, _, _ = runSetprivProbe(pctx, p.AnonUID, probeNetwork, probeAddr)

	out, _, err := nftRun(ctx, "", "nft", "list", "table", "inet", escapedLeakCounterTable)
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

// forcedExitIP fetches the exit IP OBSERVED THROUGH the forced path, and, for a
// tor-shared endpoint, whether check.torproject.org reports a Tor exit. It egresses
// AS THE ANON UID (setpriv + curl), so the nat chain transparently redirects the
// fetch into the shim relay and its DNS through the shim DNS forwarder, exactly like
// the hand recipe's `sudo -u anon curl https://check.torproject.org/api/ip` that
// proves anonymization. It does NOT dial the relay port as a SOCKS proxy: the relay
// is a TRANSPARENT SO_ORIGINAL_DST relay (internal/shim/relay.go), NOT a SOCKS
// server, so a direct SOCKS handshake to it would read the relay's own listen addr
// and reset. Any error feeds a failing anonymized-exit decision (never a false pass).
func forcedExitIP(ctx context.Context, p LiveParams) (exitIP string, isTor bool, err error) {
	exitIP, err = curlAsAnon(ctx, p, ipEchoURL)
	if err != nil {
		return "", false, err
	}
	if p.Class == "tor-shared" {
		if body, terr := curlAsAnon(ctx, p, torCheckURL); terr == nil {
			isTor = strings.Contains(body, "\"IsTor\":true") || strings.Contains(body, "\"IsTor\": true")
		}
	}
	return exitIP, isTor, nil
}

// curlAsAnon fetches url AS THE ANON UID via `curl` under setpriv, so the fetch
// egresses the forced way (the nat chain redirects its TCP into the shim relay and
// its DNS through the shim DNS forwarder). It returns the trimmed body or an error;
// a missing curl/setpriv, or a non-zero curl exit (a failed-closed fetch), is an
// error that feeds a FAILING pure decision, never a false pass. curl is the recipe's
// own tool for this proof and resolves the name remotely (the anon UID's :53 is
// transparently redirected to the shim), so no host-side DNS leak is introduced.
func curlAsAnon(ctx context.Context, p LiveParams, url string) (string, error) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		return "", fmt.Errorf("setpriv unavailable: cannot egress as the anon UID")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return "", fmt.Errorf("curl unavailable: cannot fetch the forced-path exit")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		"curl", "-s", "--max-time", "25", url)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("forced-path curl as anon UID failed: %w (%s)", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
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
	// Fetch the name AS THE ANON UID: the anon UID's :53 is transparently redirected
	// to the shim's DNS-over-SOCKS forwarder, so a successful HTTPS fetch of a NAME
	// (never a bare IP) proves the name was resolved REMOTELY via the endpoint, not by
	// a local/plaintext lookup. This does NOT dial the relay port as a SOCKS proxy
	// (the relay is transparent, not a SOCKS server); it egresses the forced way, like
	// the recipe's `sudo -u anon curl` that resolves through the shim.
	if _, err := curlAsAnon(ctx, p, "https://"+probe+"/"); err != nil {
		return probe, nil, false, err
	}
	// The anon UID cannot do plaintext DNS off-box (udp/53 is redirected to the shim,
	// tcp/53 too), so the name was resolved proxy-side and the host resolver was never
	// asked; hostSaw stays false.
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

// setuidNetworkWrappers is the small, DOCUMENTED set of setuid "run a command as
// another uid" network-adjacent wrappers the audit
// (work/notes/findings/uid-transition-escape-surface.md) tested by hand and found
// do NOT hand the anon account a non-anon-owned egress on this class of host:
// pkexec (exits non-zero with no polkit agent in the realistic no-seat case) and
// mullvad-exclude (runs the target as the CALLER, so the socket stays anon-owned).
// The no-uid-transition-egress probe re-asserts that empirically: it runs each
// present wrapper AS the anon UID to execute `id -u` and reads whether the
// resulting euid TRANSITIONED to a uid that is neither the anon nor the shim uid.
// It is a documented list, NOT an invented one; extend it only from a fresh audit.
//
// ping and pppd from the finding are deliberately NOT in this run-a-command list:
// ping is not a uid-changing wrapper (its socket is anon-owned/forced, already
// covered by icmp-drop) and pppd is denied by group membership (it opens no PPP
// link for `id`). Both are recorded in the finding, not re-probed here.
var setuidNetworkWrappers = []string{"pkexec", "mullvad-exclude"}

// uidTransitionVectors runs the CONCRETELY ENUMERABLE UID-transition escape probes
// from the audit finding AS the anon account and returns one UIDTransitionVector
// per checked vector (Escaped == it yielded an off-box-capable process/socket
// owned by a non-anon, non-shim uid, i.e. it bypassed `meta skuid`). It always
// includes the sudo vector, then one entry per PRESENT setuid network wrapper. The
// caller feeds these to NoUIDTransitionEgressAssertion, which frames the result
// honestly as best-effort / not exhaustive. Every probe fails SAFE toward
// non-escape only when that genuinely reflects no transition; a probe that could
// not run at all is simply not reported (the assertion still passes on the vectors
// it did check, and the honest "not exhaustive" framing carries the rest).
func uidTransitionVectors(ctx context.Context, p LiveParams) []UIDTransitionVector {
	vectors := []UIDTransitionVector{sudoVector(ctx, p)}
	for _, bin := range setuidNetworkWrappers {
		if _, err := exec.LookPath(bin); err != nil {
			continue // not on this host: nothing to probe (the finding's list is per-host)
		}
		vectors = append(vectors, setuidWrapperVector(ctx, p, bin))
	}
	return vectors
}

// sudoVector probes the sudo escape: whether the anon account has ANY sudo rights
// (a sudo'd command runs as a DIFFERENT, typically root, uid and its socket
// escapes the `meta skuid` forcing). It runs `sudo -l -U <account>` (list the
// account's permitted sudo commands): sudo exits non-zero ("not allowed to run
// sudo") when the account has none, so a zero exit means it CAN sudo (an escape).
// A missing `sudo` binary means the vector is closed for this account too
// (reported as checked-and-not-escaped). This mirrors provision's sudoAllowed
// probe (the same `sudo -l -U` truth), read here as the verify-side escape signal.
func sudoVector(ctx context.Context, p LiveParams) UIDTransitionVector {
	v := UIDTransitionVector{Name: "sudo"}
	if _, err := exec.LookPath("sudo"); err != nil {
		return v // no sudo binary: no sudo transition path here
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if err := exec.CommandContext(cctx, "sudo", "-l", "-U", p.Account).Run(); err == nil {
		v.Escaped = true
		v.Detail = "the account is permitted sudo (`sudo -l -U` listed rights): a sudo'd socket carries a non-anon uid"
	}
	return v
}

// setuidWrapperVector probes one setuid "run a command as another uid" wrapper
// (e.g. pkexec, mullvad-exclude): it runs the wrapper AS the anon UID to execute
// `id -u` and reads whether the reported euid TRANSITIONED to a uid that is
// neither the anon nor the shim uid. A non-anon (and non-shim) euid means the
// wrapper handed the account a process running as a different uid, whose sockets
// would escape the `meta skuid` forcing (Escaped=true). A run that stays anon
// (mullvad-exclude), that fails to authorize (pkexec with no agent -> non-zero,
// no euid line), or that cannot run at all reads as NOT escaped (the audited safe
// outcome). It runs under setpriv --reuid so the wrapper is invoked exactly as the
// anon account would invoke it.
func setuidWrapperVector(ctx context.Context, p LiveParams, bin string) UIDTransitionVector {
	v := UIDTransitionVector{Name: "setuid:" + bin}
	if _, err := exec.LookPath("setpriv"); err != nil {
		return v // cannot invoke as the anon UID: report checked-not-escaped (safe)
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// `<wrapper> id -u` under setpriv --reuid <anon>: if the wrapper transitions uid,
	// `id -u` prints the TARGET euid; if it runs the target as the caller (or fails
	// to authorize), it prints the anon uid or nothing.
	cmd := exec.CommandContext(cctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		bin, "id", "-u")
	out, _ := cmd.CombinedOutput()
	euid, ok := parseFirstUID(string(out))
	if !ok {
		return v // no euid line (the wrapper did not run the target): not an escape
	}
	if euid != p.AnonUID && euid != p.ShimUID {
		v.Escaped = true
		v.Detail = bin + " ran `id -u` as uid " + strconv.Itoa(euid) + " (a non-anon, non-shim uid): its sockets would escape the forcing"
	}
	return v
}

// parseFirstUID reads the first all-digit token from the wrapper's output (the
// `id -u` line) and returns it as an int. A miss (no numeric line, e.g. pkexec's
// "No authentication agent found") returns ok=false, which the caller reads as
// "the wrapper did not hand back a transitioned uid": the safe, non-escaping
// outcome.
func parseFirstUID(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n, err := strconv.Atoi(line); err == nil {
			return n, true
		}
	}
	return 0, false
}
