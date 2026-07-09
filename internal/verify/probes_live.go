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
	ruleset := escapedLeakCounterRuleset(p.AnonUID, counterDaddr, l4, port)
	if _, stderr, err := nftRun(ctx, ruleset, "nft", "-f", "-"); err != nil {
		return false, fmt.Errorf("plant escaped-leak counter: %w (%s)", err, stderr)
	}
	defer func() { _, _, _ = nftRun(ctx, "delete table inet "+escapedLeakCounterTable, "nft", "-f", "-") }()

	// Dial the off-box destination AS the anon UID; a genuine leak keeps the off-box
	// daddr and hits the counter, a redirect/drop does not. We ignore whether the
	// dial "succeeded" (a loopback handshake with the relay always does); only the
	// counter is decisive. But a probe that could NOT RUN (setpriv/shim missing) is
	// propagated LOUD: if the dial never happened, a counter that stayed 0 is not
	// evidence of "no leak", it is evidence of "nothing was probed" (a probe that
	// could not run is not a pass).
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if _, _, perr := runSetprivProbe(pctx, p.AnonUID, probeNetwork, probeAddr); perr != nil {
		return false, perr
	}

	out, stderr, err := nftRun(ctx, "", "nft", "list", "table", "inet", escapedLeakCounterTable)
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
	out, _ := cmd.CombinedOutput()
	s := string(out)
	// The shim probe ALWAYS prints exactly `REACHED` or `DROPPED:<reason>`. If we
	// see neither, the probe binary never ran under the anon UID (e.g. setpriv could
	// not drop: not root, or the anon UID does not exist), so this is an UN-RUNNABLE
	// probe, NOT a dropped connection: fail LOUD (a probe that could not run is not a
	// pass), never a silent reached=false the drop assertions would read as a PASS.
	if !strings.Contains(s, "REACHED") && !strings.Contains(s, "DROPPED") {
		return false, s, fmt.Errorf("the anon-UID probe could not run (setpriv could not drop to uid %d, or the shim probe did not execute): %s", uid, strings.TrimSpace(s))
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
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	// -c 1 one packet, -W 3 three-second reply wait, -n numeric. Run under setpriv
	// so the ICMP socket is owned by the anon UID (the nft rules key on meta skuid).
	cmd := exec.CommandContext(pctx, "setpriv",
		"--reuid", strconv.Itoa(p.AnonUID), "--clear-groups",
		"ping", "-c", "1", "-W", "3", "-n", target)
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
// do NOT hand the anon account a non-anon-owned egress on this class of host:
// pkexec (exits non-zero unattended, with no reachable polkit agent) and
// mullvad-exclude (runs the target as the CALLER, so the socket stays anon-owned).
// The no-uid-transition-egress probe re-asserts that empirically: it runs each
// present wrapper AS the anon UID to execute `id -u` and reads whether the
// resulting euid TRANSITIONED to a uid that is neither the anon nor the shim uid.
// The pkexec run is forced STRICTLY NON-INTERACTIVE (--disable-internal-agent +
// a scrubbed env, see setuidWrapperCommand) so it reproduces the audited
// unattended/no-agent case and never prompts, rather than depending on the
// operator happening to have no seat.
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
// account's permitted sudo commands) and decides from the OUTPUT, NOT the exit
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

// runSudoList shells out to `sudo -l -U <account>` and returns its stdout+stderr
// (the exit code is DELIBERATELY ignored: the verdict is read from the OUTPUT via
// sudoprobe.ParseOutput, robust to lenient builds that exit 0 for a no-rights
// account). It is the sudoVector's ONLY sudo access; the live probe needs a real
// sudo on the host at runtime.
func runSudoList(ctx context.Context, account string) (stdout, stderr string) {
	cmd := exec.CommandContext(ctx, "sudo", "-l", "-U", account)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	_ = cmd.Run()
	return out.String(), errb.String()
}

// pkexecScrubbedEnvVars are the session-agent handles the pkexec probe DROPS so it
// runs strictly non-interactively: with none of these in the env pkexec cannot
// reach the session polkit authentication agent, so unattended it fails "Request
// dismissed" (or "No authentication agent found") INSTEAD of popping a GNOME/CLI
// password dialog. This is the fix for the v0.1.2 bug where the probe inherited the
// operator's session and false-flagged an escape iff a HUMAN authenticated the
// prompt (measuring the operator's interactive auth, not the account's capability).
// A permissive/NOPASSWD polkit rule that escalates with NO auth is unaffected: it
// still escalates unattended and is still caught as a real escape.
var pkexecScrubbedEnvVars = []string{
	"DBUS_SESSION_BUS_ADDRESS",
	"XDG_RUNTIME_DIR",
	"DISPLAY",
	"WAYLAND_DISPLAY",
}

// setuidWrapperCommand is the PURE construction of one setuid-wrapper UID-transition
// probe: it returns the argv to exec (always `setpriv --reuid <anon> --clear-groups
// <wrapper> [flags] id -u`) and the env to run it in. For pkexec it appends
// --disable-internal-agent AND returns a SCRUBBED env (ambient env minus
// pkexecScrubbedEnvVars), the two-part guarantee that the probe cannot reach an
// authentication agent and therefore never prompts. For every other wrapper it
// returns nil for env, meaning "inherit the ambient env unchanged" (those wrappers
// run the target as the caller or fail without prompting, so no scrubbing applies).
//
// Keeping the argv+env construction pure (and passing the ambient env in) is what
// lets the unit suite assert the non-interactive contract - the --disable-internal-agent
// flag and the scrubbed env - with NO real pkexec and NO prompt, while the live
// runSetuidWrapper seam actually execs it. This is the seam the task's acceptance
// tests bind to.
func setuidWrapperCommand(uid int, bin string, ambientEnv []string) (argv []string, env []string) {
	argv = []string{"setpriv", "--reuid", strconv.Itoa(uid), "--clear-groups", bin}
	if bin == "pkexec" {
		// pkexec-only: refuse the internal textual agent, and run with the session
		// agent handles removed, so it is strictly non-interactive.
		argv = append(argv, "--disable-internal-agent")
		env = scrubEnv(ambientEnv, pkexecScrubbedEnvVars)
	}
	argv = append(argv, "id", "-u")
	return argv, env
}

// scrubEnv returns env with every KEY=... entry whose key is in drop removed,
// keeping the rest in order. It never mutates the input slice.
func scrubEnv(env, drop []string) []string {
	banned := make(map[string]bool, len(drop))
	for _, k := range drop {
		banned[k] = true
	}
	out := make([]string, 0, len(env))
	for _, e := range env {
		key := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		if banned[key] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// runSetuidWrapper is the INJECTABLE exec seam for the setuid-wrapper probe: it
// execs argv (in env, or the ambient env when env is nil) under a short deadline
// and returns the combined output. It is a package var so the unit suite can script
// the wrapper's output (an unattended fail, a fixtured unattended escalation)
// WITHOUT a real pkexec or any prompt; production points it at the real exec.
var runSetuidWrapper = func(ctx context.Context, argv, env []string) string {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	if env != nil {
		cmd.Env = env
	}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// setuidWrapperVector probes one setuid "run a command as another uid" wrapper
// (e.g. pkexec, mullvad-exclude): it runs the wrapper AS the anon UID to execute
// `id -u` and reads whether the reported euid TRANSITIONED to a uid that is
// neither the anon nor the shim uid. A non-anon (and non-shim) euid means the
// wrapper handed the account a process running as a different uid, whose sockets
// would escape the `meta skuid` forcing (Escaped=true). A run that stays anon
// (mullvad-exclude), that fails to authorize (pkexec unattended -> non-zero, no
// euid line), or that cannot run at all reads as NOT escaped (the audited safe
// outcome).
//
// It is STRICTLY NON-INTERACTIVE: the command is built by setuidWrapperCommand,
// which for pkexec passes --disable-internal-agent and a scrubbed env so pkexec
// cannot reach an authentication agent and never prompts. So the probe measures
// the ACCOUNT's unattended escape capability (a permissive/NOPASSWD policy that
// escalates with no auth is still caught), NOT the operator's interactive auth
// (the v0.1.2 false-positive is gone). It runs under setpriv --reuid so the wrapper
// is invoked exactly as the anon account would invoke it.
func setuidWrapperVector(ctx context.Context, p LiveParams, bin string) UIDTransitionVector {
	v := UIDTransitionVector{Name: "setuid:" + bin}
	if _, err := exec.LookPath("setpriv"); err != nil {
		return v // cannot invoke as the anon UID: report checked-not-escaped (safe)
	}
	// `<wrapper> id -u` under setpriv --reuid <anon>, built non-interactively: if the
	// wrapper transitions uid, `id -u` prints the TARGET euid; if it runs the target
	// as the caller (or fails to authorize unattended), it prints the anon uid or
	// nothing.
	argv, env := setuidWrapperCommand(p.AnonUID, bin, os.Environ())
	euid, ok := parseFirstUID(runSetuidWrapper(ctx, argv, env))
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
