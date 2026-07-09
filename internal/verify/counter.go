package verify

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// This file is the PURE (untagged, root-free) core of the escaped-leak counter
// discipline the transparent-relay probes rely on. The transparent SO_ORIGINAL_DST
// relay makes a loopback TCP handshake with the relay ALWAYS complete (the relay
// accepts, then fail-closed-drops upstream), so "a handshake completed" is NEVER
// "reached the target": the leak/closure probes must instead read whether an
// anon-UID packet ESCAPED the box still carrying an OFF-BOX destination
// (work/notes/findings/manual-per-uid-tor-recipe.md, "The DNS subtlety" + the
// escaped-leak counter). That signal is a throwaway nft counter chain planted at a
// filter priority AFTER the account's nat_out (dstnat, -100): a REDIRECTED packet
// has had its daddr rewritten to the shim loopback port, so it no longer matches
// the off-box daddr and is NOT counted; only a genuine clear escape (a
// non-redirected packet keeping the off-box daddr) increments the counter.
//
// The ruleset TEXT and the counter READING are pure so they are unit-tested with
// no root; the live plant/probe/read wrapper is integration-tagged (needs nft +
// setpriv) in probes_integration.go.

// escapedLeakCounterTable is the fixed throwaway table name the escaped-leak
// counter is planted in. It is a per-verify-run scratch table (create + delete
// around one probe), distinct from any account table, so it never collides with a
// real account's `anonctl_<account>` ruleset.
const escapedLeakCounterTable = "anonctl_verify_escapedleak"

// escapedLeakCounterRuleset renders the throwaway nft counter ruleset that catches
// an anon-UID packet STILL carrying an off-box destination when it reaches the
// filter output hook (i.e. it was NOT redirected into the shim). It is planted at
// filter priority 50 (AFTER the account's nat_out at dstnat/-100), so it observes
// the POST-redirect destination: a redirected packet's daddr is the shim loopback
// port (no match), only a clear escape keeps the off-box daddr (a match, counted).
//
// daddr is the off-box destination the probe dials (a documentation/off-box IP);
// its family selects ip/ip6. l4 is "tcp" or "udp". A port <= 0 counts the daddr on
// any port of that l4 (the closure probes, which care that NO clear TCP escapes to
// the off-box host); a port > 0 pins it (the raw-UDP row, an off-box UDP port).
// The chain policy is accept: the counter only OBSERVES, it never changes forcing.
func escapedLeakCounterRuleset(anonUID int, daddr string, l4 string, port int) string {
	family := "ip"
	if ip := net.ParseIP(daddr); ip != nil && ip.To4() == nil {
		family = "ip6"
	}
	match := fmt.Sprintf("meta skuid %d %s daddr %s %s", anonUID, family, daddr, l4)
	if port > 0 {
		match += " dport " + strconv.Itoa(port)
	}
	return fmt.Sprintf(`table inet %s {
    chain out {
        type filter hook output priority 50; policy accept;
        %s counter
    }
}
`, escapedLeakCounterTable, match)
}

// counterMoved reports whether an nft `counter` line in a `nft list table` dump
// shows a non-zero packet count (`counter packets N ...` with N > 0). A parse miss
// reads as not-moved (no observed leak), the safe outcome: a probe that could not
// read a moved counter never reports a false leak.
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
