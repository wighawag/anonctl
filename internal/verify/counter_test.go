package verify

import (
	"strings"
	"testing"
)

// The escaped-leak counter is the load-bearing trust-anchor primitive: the
// transparent SO_ORIGINAL_DST relay makes a loopback handshake always complete, so
// the leak/closure probes must read whether an anon-UID packet ESCAPED the box
// still carrying an OFF-BOX destination, not whether a handshake completed. These
// unit tests pin the pure core of that primitive (the ruleset text and the counter
// reading) with no root; the live plant/probe/read is integration-tagged.

// TestEscapedLeakCounterRuleset_PlantedAfterNatSoItSeesThePostRedirectDaddr:
// the counter chain MUST sit at a filter priority AFTER the account's nat_out
// (dstnat / -100) so it observes the POST-redirect destination. Priority 50 is
// safely after -100 (the same priority the DNS-hole counter already uses). If it
// ran BEFORE the nat redirect it would count the ORIGINAL (pre-rewrite) daddr and
// every redirected packet would look like a leak (the exact false-fail this task
// closes).
func TestEscapedLeakCounterRuleset_PlantedAfterNatSoItSeesThePostRedirectDaddr(t *testing.T) {
	rs := escapedLeakCounterRuleset(1001, "192.0.2.1", "tcp", 0)
	if !strings.Contains(rs, "priority 50") {
		t.Fatalf("counter chain must run at a filter priority AFTER nat_out (dstnat/-100); got:\n%s", rs)
	}
	if !strings.Contains(rs, "table inet "+escapedLeakCounterTable) {
		t.Fatalf("counter must use the throwaway scratch table %q; got:\n%s", escapedLeakCounterTable, rs)
	}
	if !strings.Contains(rs, "policy accept") {
		t.Fatalf("counter chain must be observe-only (policy accept), never change forcing; got:\n%s", rs)
	}
}

// TestEscapedLeakCounterRuleset_KeysOnTheOffBoxDaddr: the match MUST be keyed on
// the off-box daddr the probe dials (and the anon UID). A redirected packet's
// daddr is rewritten to the shim loopback port, so keying on the off-box daddr
// means only a genuine clear escape is counted; this is what makes the probe
// non-vacuous (it can still FAIL on a real leak).
func TestEscapedLeakCounterRuleset_KeysOnTheOffBoxDaddr(t *testing.T) {
	rs := escapedLeakCounterRuleset(1001, "192.0.2.1", "tcp", 0)
	if !strings.Contains(rs, "meta skuid 1001") {
		t.Fatalf("counter must key on the anon UID; got:\n%s", rs)
	}
	if !strings.Contains(rs, "ip daddr 192.0.2.1") {
		t.Fatalf("counter must key on the off-box daddr; got:\n%s", rs)
	}
	if !strings.Contains(rs, "tcp counter") && !strings.Contains(rs, "tcp  counter") {
		t.Fatalf("a port-omitted counter must match ANY port of the l4 (no dport clause); got:\n%s", rs)
	}
	if strings.Contains(rs, "dport") {
		t.Fatalf("a port <= 0 must NOT pin a dport (it catches any port of the l4); got:\n%s", rs)
	}
}

// TestEscapedLeakCounterRuleset_PinsThePortWhenGiven: the raw-UDP row keys on a
// specific off-box UDP port (recipe row 3's UDP4:...:9999 shape), so a positive
// port pins the dport.
func TestEscapedLeakCounterRuleset_PinsThePortWhenGiven(t *testing.T) {
	rs := escapedLeakCounterRuleset(1001, "1.1.1.1", "udp", 9999)
	if !strings.Contains(rs, "udp dport 9999 counter") {
		t.Fatalf("a positive port must be pinned as the dport; got:\n%s", rs)
	}
}

// TestEscapedLeakCounterRuleset_SelectsFamilyFromTheDaddr: a v6 off-box daddr must
// emit an ip6 match (so the counter is never silently v4-only for a v6 probe).
func TestEscapedLeakCounterRuleset_SelectsFamilyFromTheDaddr(t *testing.T) {
	if rs := escapedLeakCounterRuleset(1001, "192.0.2.1", "tcp", 0); !strings.Contains(rs, "ip daddr") || strings.Contains(rs, "ip6 daddr") {
		t.Fatalf("a v4 daddr must emit an ip match; got:\n%s", rs)
	}
	if rs := escapedLeakCounterRuleset(1001, "2001:db8::1", "tcp", 0); !strings.Contains(rs, "ip6 daddr 2001:db8::1") {
		t.Fatalf("a v6 daddr must emit an ip6 match; got:\n%s", rs)
	}
}

// TestCounterMoved reads the nft-list dump: a non-zero packet count means a clear
// packet escaped (a leak); a zero count (or an unparseable dump) reads as
// not-moved (no observed leak), the fail-closed-safe outcome.
func TestCounterMoved(t *testing.T) {
	moved := `table inet x {
    chain out {
        meta skuid 1001 ip daddr 192.0.2.1 tcp counter packets 3 bytes 180
    }
}`
	if !counterMoved(moved) {
		t.Fatalf("a counter with packets > 0 must read as MOVED (a leak); got not-moved")
	}
	zero := `table inet x {
    chain out {
        meta skuid 1001 ip daddr 192.0.2.1 tcp counter packets 0 bytes 0
    }
}`
	if counterMoved(zero) {
		t.Fatalf("a counter at packets 0 must read as NOT moved (no leak); got moved")
	}
	if counterMoved("garbage with no counter line") {
		t.Fatalf("an unparseable dump must read as NOT moved (safe); got moved")
	}
}
