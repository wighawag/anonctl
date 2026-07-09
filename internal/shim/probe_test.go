package shim

import (
	"net"
	"strings"
	"testing"
)

// TestProbeReachesAListeningTCP proves the probe reports REACHED when a TCP dial
// establishes: this is the "leak" polarity (a direct connection that got through).
// A local listener stands in for an off-box target the fail-closed rules would
// otherwise drop.
func TestProbeReachesAListeningTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	reached, detail := Probe("tcp", ln.Addr().String())
	if !reached {
		t.Fatalf("Probe(tcp, listening addr) = reached=false (%q); want REACHED", detail)
	}
	if got := ProbeResult(reached, detail); got != "REACHED" {
		t.Fatalf("ProbeResult = %q; want REACHED", got)
	}
}

// TestProbeDropsARefusedTCP proves a TCP dial that does NOT establish reports
// DROPPED (the fail-closed PASS polarity): dialing a closed port is refused.
func TestProbeDropsARefusedTCP(t *testing.T) {
	// Bind then immediately close to obtain a very-likely-unused port, then dial it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	reached, detail := Probe("tcp", addr)
	if reached {
		t.Fatalf("Probe(tcp, closed port) = REACHED; want DROPPED")
	}
	if got := ProbeResult(reached, detail); !strings.HasPrefix(got, "DROPPED:") {
		t.Fatalf("ProbeResult = %q; want a DROPPED:<reason>", got)
	}
}

// TestProbeUsageError proves a missing arg is a DROPPED:usage, never a false
// REACHED (a probe that could not run is not a "reached").
func TestProbeUsageError(t *testing.T) {
	reached, detail := Probe("", "")
	if reached {
		t.Fatalf("Probe(empty) = REACHED; want a usage DROPPED")
	}
	if !strings.Contains(detail, "usage") {
		t.Fatalf("Probe(empty) detail = %q; want a usage message", detail)
	}
}
