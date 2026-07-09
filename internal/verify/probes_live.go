package verify

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/sudoprobe"
	"github.com/wighawag/anonctl/internal/systemd"
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
// the anon UID and reports whether the counter moved. It returns (reached, err):
// a counter plant/read ERROR is propagated (a probe that could not run is not a
// pass), NOT swallowed to reached=false; only a MALFORMED/non-v4 addr reads as a
// clean reached=false (that case is not a probe failure, it is out of scope here).
func clearLANDNSReached(ctx context.Context, p LiveParams, network, addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host).To4() == nil {
		return false, nil // only the v4 LAN-resolver case is probed here
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
// its off-box-form daddr) and are identical for the off-box leak/closure probes.
//
// It returns (reached, err). A COUNTER ERROR (nft missing, a plant/list failure)
// is returned as a non-nil err, NOT swallowed to reached=false: a probe that could
// not run is NOT a pass (the caller surfaces the error as a LOUD failing
// assertion, via escapedLeakProbeAssertion). This is the discipline the two
// closures were missing (the invalid-nft false-green: an unplantable counter read
// as "nothing escaped" => a silent PASS). A clean run returns whether the counter
// moved (a genuine clear escape) with a nil err, so a redirect/drop reads as no
// leak (reached=false) and only a real escape reads as a leak (reached=true).
func offBoxLeakReached(ctx context.Context, p LiveParams, counterDaddr, l4 string, port int, probeNetwork, probeAddr string) (bool, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return false, fmt.Errorf("escaped-leak counter probe cannot run: nft not found: %w", err)
	}
	// A UNIQUELY-NAMED scratch table per probe: `verify.Run` runs the probes
	// concurrently, and several plant a counter, so a shared table name would collide
	// (this defer's delete would tear down a sibling probe's live counter, or the
	// create below would fail on an existing table). Each probe creates + reads +
	// deletes its OWN table, so parallel probes never fight over one name.
	table := uniqueEscapedLeakCounterTable()
	ruleset := escapedLeakCounterRuleset(table, p.AnonUID, counterDaddr, l4, port)
	if _, stderr, err := nftRun(ctx, ruleset, "nft", "-f", "-"); err != nil {
		return false, fmt.Errorf("plant escaped-leak counter: %w (%s)", err, stderr)
	}
	defer func() { _, _, _ = nftRun(ctx, "delete table inet "+table, "nft", "-f", "-") }()

	// Dial the off-box destination AS the anon UID; a genuine leak keeps the off-box
	// daddr and hits the counter, a redirect/drop does not. We ignore whether the
	// dial "succeeded" (a loopback handshake with the relay always does); only the
	// counter is decisive. But a probe that could NOT RUN (setpriv/shim missing) is
	// propagated LOUD: if the dial never happened, a counter that stayed 0 is not
	// evidence of "no leak", it is evidence of "nothing was probed" (a probe that
	// could not run is not a pass).
	//
	// 3s deadline: this probe PASSES by the packet being DROPPED/redirected (the
	// counter never moves), which is knowable FAST, so a long deadline just adds dead
	// wall time. It matches the hand recipe's snappy `ping -W 3` / `curl -m` closure
	// checks (work/notes/findings/manual-per-uid-tor-recipe.md). A genuine clear
	// escape moves the counter on the very first datagram, well inside 3s; the margin
	// covers a slow setpriv/shim exec, not a slow network round-trip (there is none:
	// the whole point is that nothing should egress).
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, _, perr := runSetprivProbe(pctx, p.AnonUID, probeNetwork, probeAddr); perr != nil {
		return false, perr
	}

	out, stderr, err := nftRun(ctx, "", "nft", "list", "table", "inet", table)
	if err != nil {
		return false, fmt.Errorf("read escaped-leak counter: %w (%s)", err, stderr)
	}
	return counterMoved(out), nil
}

// nftRun shells out to nft (optionally with a ruleset on stdin), returning
// stdout/stderr/err. It is the counter-probe's ONLY nft access; it needs root at
// runtime (like `add`/`rm`) and its error is surfaced as a LOUD failing assertion.
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

// INVARIANT (load-bearing UX + correctness contract): NO `anonctl verify` probe in
// this file may trigger an interactive password/polkit prompt. `verify` is a
// leak-test the operator runs unattended (`sudo anonctl verify`); a probe that pops
// a GNOME/CLI auth dialog is a bug, whatever its verdict. The two prompting vectors
// are both closed strictly non-interactively: the pkexec vector QUERIES polkit with
// `pkcheck` (no -u, so it never starts an auth agent and never prompts, see
// pkexecPolicyQueryCommand) INSTEAD of running pkexec, and the sudo vector runs
// `sudo -n -l -U`
// (sudoListCommand, so sudo prints "a password is required" instead of prompting).
// The remaining probes cannot prompt: setpriv (--reuid drops privilege, never
// asks), the shim `-probe` binary, nft, curl, and ping are all non-interactive
// tools invoked without any auth-eliciting flag. A future probe author MUST
// preserve this: any new auth-gated tool has to be invoked in a mode that fails
// unattended rather than prompting (a probe that could not run is honestly
// not-conclusive, never a prompt).
//
// This file is the IMPURE live-probe machinery behind checks_live.go's
// LiveChecks: standing up real connections AS the anon UID (setpriv), fetching the
// forced-path exit IP through the shim relay, and gathering the dns-remote
// evidence. It is compiled into every build (runtime behaviour needing root +
// setpriv + the installed shim probe binary + a live endpoint, failing LOUD when
// it lacks any); the pure assertion decisions it feeds live in verify.go and are
// unit-proven against the fixture. Every probe fails SAFE (an error or empty
// result feeds a FAILING pure decision), never a false pass.

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

// probeShimBinary is the installed static shim binary verify execs (under setpriv)
// as its dialer: `anonctl-shim -probe <network> <addr>`. It is the SAME binary the
// per-account shim units run (internal/systemd.DefaultShimBinaryPath), already
// installed and static, so verify reuses it and needs NO Go toolchain on the
// user's host. It is a package var (not the bare constant) ONLY so the live probe
// suite can point it at a throwaway-built shim; production leaves it at the default.
var probeShimBinary = systemd.DefaultShimBinaryPath

// runSetprivProbe dials network/addr AS the given UID by exec'ing the installed
// static shim binary in `-probe` mode under setpriv (so the connection egresses
// from the anon UID, exercising the nft `meta skuid` rules). It returns whether
// the dial REACHED its target.
//
// A missing `setpriv` or a missing/un-runnable shim probe binary is a LOUD ERROR
// (never a silent reached=false, which the drop assertions would read as a PASS):
// a probe that could not run is not a pass. verify/use require these on the host
// exactly as `add`/`rm` require nft/useradd; the error names the missing tool.
func runSetprivProbe(ctx context.Context, uid int, network, addr string) (reached bool, stderr string, err error) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		return false, "", fmt.Errorf("need setpriv on PATH to run the anon-UID probe (as `add`/`rm` need nft): %w", err)
	}
	if _, err := exec.LookPath(probeShimBinary); err != nil {
		return false, "", fmt.Errorf("need the installed shim probe binary %q to run the anon-UID probe (install anonctl-shim there, or set the shim unit's ExecStart path): %w", probeShimBinary, err)
	}
	cmd := exec.CommandContext(ctx, "setpriv",
		"--reuid", strconv.Itoa(uid), "--clear-groups",
		probeShimBinary, "-probe", network, addr)
	out, runErr := cmd.CombinedOutput()
	s := string(out)
	// The shim probe ALWAYS prints exactly `REACHED` or `DROPPED:<reason>`. If we
	// see neither, the probe binary never ran to completion under the anon UID, so
	// this is an UN-RUNNABLE probe, NOT a dropped connection: fail LOUD (a probe that
	// could not run is not a pass), never a silent reached=false the drop assertions
	// would read as a PASS.
	if !strings.Contains(s, "REACHED") && !strings.Contains(s, "DROPPED") {
		// Distinguish the two ways empty output happens, so the error is HONEST
		// (misdiagnosing a killed-mid-dial probe as "setpriv could not drop" sent past
		// diagnosis down the wrong path). If OUR context deadline fired, exec SIGKILLed
		// the shim before it could print its verdict: the outer window is too tight for
		// this dial, not a privdrop failure. `probeAsAnon` gives the shim a margin over
		// shim.ProbeTimeout so a real full-timeout dial (a silently-dropped SYN, the
		// leak-drop-v6 PASS) always prints before this can trigger; if it still does,
		// name the timeout truthfully.
		if ctx.Err() == context.DeadlineExceeded {
			return false, s, fmt.Errorf("the anon-UID probe timed out before printing a verdict (the shim dial to %s %s outran the probe deadline): %s", network, addr, strings.TrimSpace(s))
		}
		// Otherwise the process itself failed before printing (setpriv could not drop:
		// not root, or the anon UID does not exist; or the shim probe did not execute).
		return false, s, fmt.Errorf("the anon-UID probe could not run (setpriv could not drop to uid %d, or the shim probe did not execute): %v: %s", uid, runErr, strings.TrimSpace(s))
	}
	return strings.Contains(s, "REACHED"), s, nil
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
//
// A MISSING `ping` or `setpriv` is a LOUD error (named), never a silent
// reached=false the icmp-drop assertion would read as a PASS: a probe that could
// not run is not a pass. Only a probe that genuinely RAN and observed no reply
// reads as reached=false (the honest drop).
func pingAsAnon(ctx context.Context, p LiveParams, target string) (reached bool, err error) {
	if _, e := exec.LookPath("setpriv"); e != nil {
		return false, fmt.Errorf("need setpriv on PATH to run the icmp-drop probe as the anon UID: %w", e)
	}
	if _, e := exec.LookPath("ping"); e != nil {
		return false, fmt.Errorf("need ping on PATH to run the icmp-drop probe: %w", e)
	}
	// 3s deadline / -W 2 reply wait: icmp-drop PASSES by the ping getting NO reply (a
	// dropped ICMP echo), which is knowable fast, so a long wait just burns wall time.
	// -W 2 already exceeds any real off-box RTT; the 3s context is a small margin over
	// -W 2 for the setpriv exec, not for a slow network (a dropped ping never answers).
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// -c 1 one packet, -W 2 two-second reply wait, -n numeric. Run under setpriv
	// so the ICMP socket is owned by the anon UID (the nft rules key on meta skuid).
	cmd := exec.CommandContext(pctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		"ping", "-c", "1", "-W", "2", "-n", target)
	out, _ := cmd.CombinedOutput()
	s := string(out)
	// A reply ("1 received" / "bytes from") means ICMP egressed and came back (a
	// leak). A ping that RAN but got no reply prints its own summary line
	// ("packets transmitted"), which is the honest drop => reached=false. If we see
	// NEITHER a reply NOR that summary, ping never ran under the anon UID (setpriv
	// could not drop: not root, or the anon UID does not exist), so this is an
	// UN-RUNNABLE probe: fail LOUD (a probe that could not run is not a pass), never
	// a silent reached=false the icmp-drop assertion would read as a PASS.
	reply := strings.Contains(s, "bytes from") || strings.Contains(s, "1 received") || strings.Contains(s, "1 packets received")
	if !reply && !strings.Contains(s, "packets transmitted") {
		return false, fmt.Errorf("the icmp-drop probe could not run (setpriv could not drop to uid %d, or ping did not execute): %s", p.AnonUID, strings.TrimSpace(s))
	}
	return reply, nil
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
// do NOT hand the anon account a non-anon-owned egress on this class of host. These
// are the RUN-the-wrapper vectors: the probe runs each present wrapper AS the anon
// UID to execute `id -u` and reads whether the resulting euid TRANSITIONED to a uid
// that is neither the anon nor the shim uid. Currently just mullvad-exclude (runs
// the target as the CALLER, so the socket stays anon-owned, and it cannot prompt).
// It is a documented list, NOT an invented one; extend it only from a fresh audit.
//
// pkexec is deliberately NOT in this run-a-command list: it is a polkit-gated
// escalation, so RUNNING it pops a GNOME polkit password dialog and measures the
// OPERATOR's interactive auth, not the account's UNATTENDED capability
// (work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md). It is
// handled separately by pkexecVector, which QUERIES polkit with pkcheck (never runs
// pkexec, never prompts).
//
// ping and pppd from the finding are also deliberately NOT in this run-a-command
// list: ping is not a uid-changing wrapper (its socket is anon-owned/forced,
// already covered by icmp-drop) and pppd is denied by group membership (it opens no
// PPP link for `id`). Both are recorded in the finding, not re-probed here.
var setuidNetworkWrappers = []string{"mullvad-exclude"}

// uidTransitionVectors runs the CONCRETELY ENUMERABLE UID-transition escape probes
// from the audit finding AS the anon account and returns one UIDTransitionVector
// per checked vector (Escaped == it yielded an off-box-capable process/socket
// owned by a non-anon, non-shim uid, i.e. it bypassed `meta skuid`). It always
// includes the sudo vector, the pkexec polkit-policy vector (when pkexec is
// present), then one entry per PRESENT run-the-wrapper setuid network wrapper. The
// caller feeds these to NoUIDTransitionEgressAssertion, which frames the result
// honestly as best-effort / not exhaustive. Every probe fails SAFE toward
// non-escape only when that genuinely reflects no transition; a probe that could
// not run at all is simply not reported (the assertion still passes on the vectors
// it did check, and the honest "not exhaustive" framing carries the rest).
func uidTransitionVectors(ctx context.Context, p LiveParams) []UIDTransitionVector {
	vectors := []UIDTransitionVector{sudoVector(ctx, p)}
	// The pkexec vector is a polkit POLICY QUERY (pkcheck), not a run-the-wrapper
	// probe: when pkexec is present on the host its exec action is relevant, so we
	// query whether the anon account could pkexec-to-root UNATTENDED.
	if _, err := exec.LookPath("pkexec"); err == nil {
		vectors = append(vectors, pkexecVector(ctx, p))
	}
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
// escapes the `meta skuid` forcing). It runs `sudo -n -l -U <account>` (list the
// account's permitted sudo commands, STRICTLY non-interactively so it never
// prompts) and decides from the OUTPUT, NOT the exit
// code: some sudo builds (observed: 1.9.16p2,
// work/notes/findings/e2e-binary-revalidation-2.md) print the not-allowed text yet
// exit 0 for a no-rights account, so an exit-code-only read false-alarms a sudo
// escape (the actual source of the no-uid-transition-egress false-positive). It
// reads stdout+stderr (the negative is commonly on stderr, the listing on stdout),
// classifies via the shared sudoprobe.ParseOutput (the SAME parse provision's
// status uses, not a duplicate), and maps the verdict via sudoVectorFromVerdict.
// A missing `sudo` binary means the vector is closed for this account too
// (reported as checked-and-not-escaped).
func sudoVector(ctx context.Context, p LiveParams) UIDTransitionVector {
	if _, err := exec.LookPath("sudo"); err != nil {
		return UIDTransitionVector{Name: "sudo"} // no sudo binary: no sudo transition path here
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	stdout, stderr := runSudoList(cctx, p.Account)
	return sudoVectorFromVerdict(sudoprobe.ParseOutput(stdout + "\n" + stderr))
}

// sudoListCommand is the PURE construction of the sudo-vector probe's argv: it
// returns `sudo -n -l -U <account>`. The `-n` (non-interactive) is LOAD-BEARING:
// listing ANOTHER user's sudo privileges (`-U <account>`) requires the CALLER to
// be authorized, and on a desktop that authorization goes through a polkit/sudo
// prompt (a GNOME password popup) BEFORE any output is produced. With `-n`, sudo
// NEVER prompts: when auth is required it prints `sudo: a password is required`
// and returns non-interactively (which sudoprobe.ParseOutput reads as the honest
// Unknown, never a false grant/denial); when no auth is needed it lists the
// privileges as before. Keeping the argv construction pure lets the unit suite
// assert the non-interactive contract (the `-n` flag) with NO real sudo and NO
// prompt, while the runSudoListCmd seam actually execs it.
func sudoListCommand(account string) []string {
	return []string{"sudo", "-n", "-l", "-U", account}
}

// runSudoListCmd is the INJECTABLE exec seam for the sudo-vector probe: it execs
// the argv under the deadline and returns its stdout+stderr (the exit code is
// DELIBERATELY ignored: the verdict is read from the OUTPUT via
// sudoprobe.ParseOutput, robust to lenient builds that exit 0 for a no-rights
// account). It is a package var so the unit suite can assert the argv (and script
// the output) WITHOUT a real sudo or any prompt; production points it at the real
// exec. The live probe needs a real sudo on the host at runtime.
var runSudoListCmd = func(ctx context.Context, argv []string) (stdout, stderr string) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	_ = cmd.Run()
	return out.String(), errb.String()
}

// runSudoList runs the sudo-vector probe strictly NON-INTERACTIVELY (`sudo -n -l
// -U <account>`, see sudoListCommand) and returns its stdout+stderr. It is the
// sudoVector's ONLY sudo access.
func runSudoList(ctx context.Context, account string) (stdout, stderr string) {
	return runSudoListCmd(ctx, sudoListCommand(account))
}

// pkexecExecActionID is the polkit action the pkexec vector queries: authorization
// for it means the subject may pkexec (run a program as another user, typically
// root). The vector asks whether the ANON account is authorized for it WITHOUT
// authentication (an unattended escalation), never runs pkexec.
const pkexecExecActionID = "org.freedesktop.policykit.exec"

// pkexecPolicyQueryCommand is the PURE construction of the pkexec UID-transition
// vector's argv: it QUERIES polkit with `pkcheck` instead of RUNNING pkexec, so it
// NEVER pops a password dialog (work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md).
// Running pkexec was the wrong mechanism: polkit finds the auth agent via
// systemd-logind (the login session), not env vars, so --disable-internal-agent + a
// scrubbed env did NOT stop the prompt, and the probe measured the OPERATOR's
// interactive auth, not the account's UNATTENDED capability.
//
// It returns `setpriv --reuid <anon> --clear-groups sh -c 'exec pkcheck
// --action-id org.freedesktop.policykit.exec --process $$'`. The subject must be
// ANON-OWNED, so the query runs UNDER setpriv --reuid <anon>; `--process $$`
// queries the querying process itself, and the `sh -c 'exec pkcheck ...'` wrapper
// makes $$ resolve to the pkcheck process's OWN pid (exec replaces the shell,
// keeping the pid). Crucially there is NO --allow-user-interaction/-u: without it
// pkcheck never starts an authentication agent and never prompts, it just reports
// the policy verdict via its exit code.
//
// Keeping the argv construction pure lets the unit suite assert the
// never-run-pkexec / never-prompt contract (the pkcheck argv, no -u) with NO real
// pkcheck and NO prompt, while the runPkcheck seam actually execs it.
func pkexecPolicyQueryCommand(uid int) []string {
	return []string{
		"setpriv", "--reuid", strconv.Itoa(uid), "--clear-groups",
		"sh", "-c", "exec pkcheck --action-id " + pkexecExecActionID + " --process $$",
	}
}

// runPkcheck is the INJECTABLE exec seam for the pkexec policy-query vector: it
// execs argv under a short deadline and returns pkcheck's EXIT CODE (the verdict is
// read from the exit code, per pkcheck(1)) and whether the query RAN (ran=false
// when pkcheck could not be executed at all, e.g. the binary is missing). It is a
// package var so the unit suite can script the exit code WITHOUT a real pkcheck or
// any prompt; production points it at the real exec. The live vector needs pkcheck
// on the host (it ships in the same polkit package as pkexec).
var runPkcheck = func(ctx context.Context, argv []string) (exitCode int, ran bool) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	err := cmd.Run()
	if err == nil {
		return 0, true
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), true // pkcheck ran and returned a non-zero verdict
	}
	return 0, false // pkcheck could not be executed at all (missing / un-runnable)
}

// pkexecVector probes the pkexec UID-transition escape by QUERYING polkit (pkcheck),
// never by RUNNING pkexec. The real threat is whether the anon account could
// pkexec-to-root UNATTENDED (an automated process running as the anon account
// cannot satisfy a polkit prompt), so the vector asks polkit "is an anon-owned
// subject authorized for the exec action WITHOUT authentication?" and maps the
// pkcheck exit code (pkcheck(1) + the finding):
//
//   - exit 0  => authorized WITHOUT auth => the account can pkexec-to-root
//     UNATTENDED, a real forcing bypass => Escaped=true.
//   - exit 2 (auth required, no -u) / exit 1 (not authorized) / exit 3 (dismissed)
//     => NOT an unattended escape => Escaped=false (and NO prompt: pkcheck without
//     -u never starts an agent).
//   - pkcheck missing / un-runnable => the vector is not conclusively checked
//     (Inconclusive=true): never a false escape and never a false conclusive pass.
//     It does NOT fall back to running pkexec.
//
// It runs the query UNDER setpriv --reuid <anon> so the queried subject is
// anon-owned. A missing setpriv means the anon-owned query cannot be posed, so the
// vector is likewise not conclusively checked.
func pkexecVector(ctx context.Context, p LiveParams) UIDTransitionVector {
	v := UIDTransitionVector{Name: "setuid:pkexec"}
	if _, err := exec.LookPath("setpriv"); err != nil {
		v.Inconclusive = true
		v.Detail = "cannot pose the anon-owned polkit query: setpriv not on PATH"
		return v
	}
	if _, err := exec.LookPath("pkcheck"); err != nil {
		v.Inconclusive = true
		v.Detail = "pkcheck not on PATH: the pkexec exec-action policy was not conclusively queried (no fallback to running pkexec, which would prompt)"
		return v
	}
	exitCode, ran := runPkcheck(ctx, pkexecPolicyQueryCommand(p.AnonUID))
	if !ran {
		v.Inconclusive = true
		v.Detail = "pkcheck could not be run: the pkexec exec-action policy was not conclusively queried"
		return v
	}
	if exitCode == 0 {
		// Authorized with NO authentication: the anon account can pkexec-to-root
		// unattended, a real forcing bypass.
		v.Escaped = true
		v.Detail = "polkit authorizes the anon account for " + pkexecExecActionID + " WITHOUT authentication (pkcheck exit 0): it could pkexec-to-root unattended, bypassing the forcing"
		return v
	}
	// exit 1/2/3: not an unattended escape (auth required / not authorized /
	// dismissed). No prompt was shown. Conclusive no-escape.
	return v
}

// setuidWrapperVector probes one RUN-the-wrapper setuid "run a command as another
// uid" wrapper (e.g. mullvad-exclude): it runs the wrapper AS the anon UID to
// execute `id -u` and reads whether the reported euid TRANSITIONED to a uid that is
// neither the anon nor the shim uid. A non-anon (and non-shim) euid means the
// wrapper handed the account a process running as a different uid, whose sockets
// would escape the `meta skuid` forcing (Escaped=true). A run that stays anon
// (mullvad-exclude) or that cannot run at all reads as NOT escaped (the audited
// safe outcome).
//
// pkexec is NOT probed this way: RUNNING it pops a polkit dialog, so it is handled
// by pkexecVector (a pkcheck policy query) instead. The remaining run-the-wrapper
// wrappers run the target as the caller and cannot prompt. It runs under setpriv
// --reuid so the wrapper is invoked exactly as the anon account would invoke it.
func setuidWrapperVector(ctx context.Context, p LiveParams, bin string) UIDTransitionVector {
	v := UIDTransitionVector{Name: "setuid:" + bin}
	if _, err := exec.LookPath("setpriv"); err != nil {
		return v // cannot invoke as the anon UID: report checked-not-escaped (safe)
	}
	// `<wrapper> id -u` under setpriv --reuid <anon>: if the wrapper transitions uid,
	// `id -u` prints the TARGET euid; if it runs the target as the caller, it prints
	// the anon uid or nothing.
	euid, ok := parseFirstUID(runSetuidWrapper(ctx, setuidWrapperCommand(p.AnonUID, bin)))
	if !ok {
		return v // no euid line (the wrapper did not run the target): not an escape
	}
	if euid != p.AnonUID && euid != p.ShimUID {
		v.Escaped = true
		v.Detail = bin + " ran `id -u` as uid " + strconv.Itoa(euid) + " (a non-anon, non-shim uid): its sockets would escape the forcing"
	}
	return v
}

// setuidWrapperCommand is the PURE construction of one RUN-the-wrapper
// UID-transition probe: it returns `setpriv --reuid <anon> --clear-groups <wrapper>
// id -u`. Keeping it pure lets the unit suite assert the argv with no real wrapper,
// while the runSetuidWrapper seam actually execs it.
func setuidWrapperCommand(uid int, bin string) []string {
	return []string{"setpriv", "--reuid", strconv.Itoa(uid), "--clear-groups", bin, "id", "-u"}
}

// runSetuidWrapper is the INJECTABLE exec seam for the RUN-the-wrapper probe: it
// execs argv under a short deadline and returns the combined output. It is a
// package var so the unit suite can script the wrapper's output WITHOUT a real
// wrapper; production points it at the real exec.
var runSetuidWrapper = func(ctx context.Context, argv []string) string {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	out, _ := cmd.CombinedOutput()
	return string(out)
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
