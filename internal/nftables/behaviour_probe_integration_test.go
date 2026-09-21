//go:build integration
// +build integration

package nftables_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wighawag/anonctl/internal/nftables"
)

// This is the body that executes INSIDE the fresh network namespace. Everything
// here runs against a ruleset that starts empty and dies with the namespace.

// observationTable brackets the forcing filter chain with two observation chains so
// the tests can measure what the forcing table ADJUDICATED, independently of how
// the chain is shaped:
//
//	pre  -> filter priority -50: after nat_out (dstnat, -100), before filter_out (0)
//	post -> filter priority  50: after filter_out
//
// A packet the forcing chain drops is counted by `pre` and never reaches `post`.
// Both chains are policy accept, so they only ever observe.
func observationTable(match string) string {
	return fmt.Sprintf(`table inet anonctl_probe_obs {}
delete table inet anonctl_probe_obs
table inet anonctl_probe_obs {
    chain pre {
        type filter hook output priority -50; policy accept;
        %s counter comment "pre"
    }
    chain post {
        type filter hook output priority 50; policy accept;
        %s counter comment "post"
    }
}
`, match, match)
}

// sentinelTable stands in for "somebody else's rules": it is planted before the
// forcing table is loaded and asserted intact afterwards, so an over-broad load or
// delete is caught inside the namespace as well as outside it.
const sentinelTable = "anonctl_probe_sentinel"

func runScenario(scenario string, res *probeResult) error {
	if err := sh("ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("bring up lo in the namespace: %w", err)
	}
	if err := nftLoad("table inet " + sentinelTable + " {}\n"); err != nil {
		return fmt.Errorf("plant the sentinel: %w", err)
	}

	account := "anonctl-probe"
	ruleset, err := nftables.Generate(nftables.Params{
		Account:      account,
		AnonUID:      anonUID,
		ShimUID:      shimUID,
		RelayPort:    19050,
		DNSPort:      19053,
		EndpointHost: "127.0.0.1",
		EndpointPort: 9050,
	})
	if err != nil {
		return fmt.Errorf("generate the forcing ruleset: %w", err)
	}
	// The forcing table is loaded ALONE: the standing baseline table is deliberately
	// NOT loaded, so it cannot mask a missing terminal drop in the anon scenario.
	if err := nftLoad(ruleset); err != nil {
		return fmt.Errorf("load the forcing ruleset: %w", err)
	}

	switch scenario {
	case "uninvolved":
		err = scenarioUninvolved(res)
	case "anon":
		err = scenarioAnon(res)
	default:
		err = fmt.Errorf("unknown scenario %q", scenario)
	}
	if err != nil {
		return err
	}

	if !tableLoaded(sentinelTable) {
		return fmt.Errorf("the sentinel table was clobbered: the forcing load is not account-scoped")
	}
	return nil
}

// scenarioUninvolved pushes a bulk TCP transfer over loopback as the uid running
// the test (root, which is neither the anon nor the shim uid) and reports whether
// the forcing chain touched any of it.
//
// TWO DETAILS HERE ARE LOAD-BEARING, and both were established by measurement
// rather than guessed, because getting either wrong makes this test a FALSE GREEN
// that passes against the very ruleset it is supposed to reject.
//
//  1. The transfer must be BIG. Small ones never produce packets the kernel cannot
//     attribute, which is exactly why the original bug read as "a Python
//     http.server bug" for a while: 10KB always worked, 600KB stalled at a varying
//     offset. (Even at 10KB the old chain silently dropped the teardown packets --
//     measured: 11 of 121 -- it just was not fatal.)
//
//  2. It must be a RAW TCP write, and the reader must advertise a small window.
//     The first version of this test used net/http and passed against the buggy
//     ruleset: net/http's buffered response writes were emitted inline from the
//     write syscall, where `meta skuid` can still read the socket owner, so no
//     unattributable packet was ever generated. A single large `Write` on a plain
//     conn, drained by a reader with a small SO_RCVBUF, forces most of the data out
//     under flow control -- driven by incoming ACKs in softirq context, where there
//     is no socket owner to read. Measured on loopback (kernel 6.18): net/http
//     produced 0 unattributable packets, while this shape produces 75 of 78.
func scenarioUninvolved(res *probeResult) error {
	sizeKB, _ := strconv.Atoi(os.Getenv("SIZE_KB"))
	attempts, _ := strconv.Atoi(os.Getenv("ATTEMPTS"))
	if sizeKB <= 0 || attempts <= 0 {
		return fmt.Errorf("bad probe parameters: SIZE_KB=%q ATTEMPTS=%q", os.Getenv("SIZE_KB"), os.Getenv("ATTEMPTS"))
	}
	res.Attempts = attempts

	match := fmt.Sprintf("tcp sport %d", loopbackPort)
	if err := nftLoad(observationTable(match)); err != nil {
		return fmt.Errorf("plant the observation chains: %w", err)
	}

	payload := make([]byte, sizeKB*1024)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("build the payload: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", loopbackPort))
	if err != nil {
		return fmt.Errorf("listen on loopback: %w", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetWriteDeadline(time.Now().Add(transferDeadline))
				_, _ = c.Write(payload)
			}(conn)
		}
	}()

	before := retransFail()

	for i := 0; i < attempts; i++ {
		n, err := fetchWithSmallWindow(len(payload))
		if err == nil && n == len(payload) {
			res.Succeeded++
			res.Bytes += n
		}
	}

	res.RetransFailDelta = retransFail() - before
	res.Pre = counter("pre")
	res.Post = counter("post")
	return nil
}

// transferDeadline bounds one transfer. A chain that adjudicates unattributable
// packets does not fail the transfer, it STALLS it: the RTO backs off past 50
// seconds and neither side ever sees an error. So the probe must impose its own
// deadline, or the regression would hang the test suite instead of failing it.
//
// A healthy transfer here takes about 10ms (measured: ten 5MB transfers in 110ms,
// small receive window included), so 5s is a ~500x margin: generous enough not to
// flake on a loaded machine, tight enough that a genuinely broken ruleset fails the
// suite in about a minute and a half instead of stalling it for the full RTO
// backoff.
const transferDeadline = 5 * time.Second

// fetchWithSmallWindow dials the in-namespace server with a deliberately small
// receive buffer (see scenarioUninvolved's note 2) and drains the response.
func fetchWithSmallWindow(want int) (int, error) {
	d := net.Dialer{
		Timeout: transferDeadline,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				// Set before connect so the small window is advertised in the SYN.
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", loopbackPort))
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(transferDeadline)); err != nil {
		return 0, err
	}
	n, err := io.Copy(io.Discard, io.LimitReader(conn, int64(want)))
	return int(n), err
}

// scenarioAnon sends non-53 UDP to an off-box destination AS the anon UID and
// reports whether it survived the forcing chain. It must not: that traffic is never
// redirected into the shim, so the only thing that can stop it is the anon closure
// chain's unconditional terminal drop.
func scenarioAnon(res *probeResult) error {
	// An off-box route so the probe's packets are genuinely "real, non-loopback
	// egress" and reach the output hook with their off-box destination. A dummy
	// device black-holes them, which is what we want: the verdict is read from the
	// counters, not from whether anything answered.
	for _, args := range [][]string{
		{"link", "add", "probe0", "type", "dummy"},
		{"addr", "add", "10.11.12.1/24", "dev", "probe0"},
		{"link", "set", "probe0", "up"},
		{"route", "add", "default", "via", "10.11.12.2", "dev", "probe0"},
		{"neigh", "add", "10.11.12.2", "lladdr", "02:00:00:00:00:02", "dev", "probe0", "nud", "permanent"},
	} {
		if err := sh("ip", args...); err != nil {
			return fmt.Errorf("set up the off-box route (%v): %w", args, err)
		}
	}

	match := fmt.Sprintf("ip daddr %s udp dport 4444", offBoxAddr)
	if err := nftLoad(observationTable(match)); err != nil {
		return fmt.Errorf("plant the observation chains: %w", err)
	}

	// Send AS the anon uid. setpriv takes a numeric uid, so the synthetic account
	// need not exist on the host running the test.
	script := fmt.Sprintf(
		`exec 3<>/dev/udp/%s/4444 && printf 'anonctl-probe' >&3`, offBoxAddr)
	// /dev/udp is a bash builtin; fall back to a tiny Go-free path only if bash is
	// absent, in which case the scenario cannot run and says so.
	bash, err := exec.LookPath("bash")
	if err != nil {
		return fmt.Errorf("need bash for the anon-uid UDP probe (/dev/udp): %w", err)
	}
	// A UDP send to a black-holed route succeeds locally whether or not the packet
	// survives the firewall, so the exit status is NOT the verdict -- the counters
	// are. But it must not be DISCARDED either: a probe that could not run at all
	// would leave both counters at zero, and "no traffic" must never be readable as
	// "the traffic was dropped". That is the same false-green trap verify's
	// escaped-leak counter documents. So the error is kept and surfaced below if
	// nothing was observed.
	var lastErr error
	for i := 0; i < 3; i++ {
		if err := sh("setpriv", "--reuid", strconv.Itoa(anonUID), "--regid", strconv.Itoa(anonUID),
			"--clear-groups", bash, "-c", script); err != nil {
			lastErr = err
		}
	}

	res.Pre = counter("pre")
	res.Post = counter("post")
	if res.Pre <= 0 && lastErr != nil {
		return fmt.Errorf("the anon-uid probe could not run, so its verdict would be meaningless: %w", lastErr)
	}
	return nil
}

// --- small helpers ---------------------------------------------------------

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func nftLoad(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f -: %w (%s)", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func tableLoaded(name string) bool {
	out, err := exec.Command("nft", "list", "tables").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "table inet "+name {
			return true
		}
	}
	return false
}

// counter reads the packet count of the observation rule carrying the given
// comment. A missing counter returns -1 so it can never be mistaken for a genuine
// zero (an unplantable counter reading as "nothing was dropped" would be a silent
// false pass, the same trap verify's escaped-leak counter documents).
func counter(comment string) int {
	out, err := exec.Command("nft", "list", "table", "inet", "anonctl_probe_obs").Output()
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, `comment "`+comment+`"`) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "packets" && i+1 < len(fields) {
				n, err := strconv.Atoi(fields[i+1])
				if err != nil {
					return -1
				}
				return n
			}
		}
	}
	return -1
}

// retransFail reads TcpExtTCPRetransFail: a retransmission the local output path
// REFUSED. This is the counter that rose on the host where the bug was found, while
// the RTO backed off past 50 seconds and the transfer stalled permanently with no
// error on either side. It is read straight from /proc/net/netstat so the test does
// not depend on `nstat` being installed.
func retransFail() int {
	f, err := os.Open("/proc/net/netstat")
	if err != nil {
		return 0
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	var headers []string
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], "TcpExt:") {
			if headers == nil {
				headers = fields
				continue
			}
			for i, h := range headers {
				if h == "TCPRetransFail" && i < len(fields) {
					n, err := strconv.Atoi(fields[i])
					if err != nil {
						return 0
					}
					return n
				}
			}
			headers = nil
		}
	}
	return 0
}
