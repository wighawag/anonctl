package shim

import (
	"net"
	"strings"
	"time"
)

// ProbeTimeout is the dial/write deadline the probe uses. It is short: the probe
// is run AS the anon UID under setpriv by `anonctl verify` to observe whether a
// direct connection REACHED its target or was DROPPED by the fail-closed nft
// rules, and a dropped path must not hang the verify run.
const ProbeTimeout = 3 * time.Second

// Probe dials network/addr with a short timeout and reports whether it REACHED its
// target. It is the dialer `anonctl verify` execs (as `anonctl-shim -probe
// <network> <addr>`, under setpriv, so the dial egresses from the anon UID and
// exercises the real nft `meta skuid` rules). It REPLACES the old runtime-compiled
// probe helper (probes' `go build` at runtime): the shim is already installed and
// static, so verify reuses it and needs no Go toolchain on the user's host.
//
// Polarity mirrors the manual recipe and the retired probe source:
//
//   - TCP: a Dial that ESTABLISHES is REACHED; a refused / timed-out / errored
//     dial (the fail-closed DROP) is not.
//   - UDP: a Dial is connectionless and never proves reachability, so the kernel's
//     `meta skuid` DROP surfaces as an EPERM on the actual sendto. Probe therefore
//     WRITES a datagram and reads whether the kernel let it out (recipe row 5: a
//     dropped UDP write returns "operation not permitted"). A datagram that leaves
//     is REACHED; an EPERM/error on the write is not.
//
// It returns (reached, detail): detail is a short human string (the dial error, or
// "connected"/"datagram sent") the caller may surface. A usage error (missing
// args) returns reached=false with a "usage" detail.
func Probe(network, addr string) (reached bool, detail string) {
	if network == "" || addr == "" {
		return false, "usage: -probe <network> <addr>"
	}
	c, err := (&net.Dialer{Timeout: ProbeTimeout}).Dial(network, addr)
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	if strings.HasPrefix(network, "udp") {
		_ = c.SetWriteDeadline(time.Now().Add(ProbeTimeout))
		if _, werr := c.Write([]byte("x")); werr != nil {
			return false, werr.Error()
		}
		return true, "datagram sent"
	}
	return true, "connected"
}

// ProbeResult renders a Probe outcome as the single-line REACHED/DROPPED token the
// caller (`anonctl verify`'s runSetprivProbe) greps for, mirroring the retired
// probe helper's `REACHED` / `DROPPED:<reason>` output. It is a pure formatter so
// the exact wire string is unit-tested.
func ProbeResult(reached bool, detail string) string {
	if reached {
		return "REACHED"
	}
	return "DROPPED:" + detail
}
