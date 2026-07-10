package lanexempt_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/lanexempt"
)

// TestParseAcceptsPrivateHostPort proves the happy path: an exact RFC1918
// host:port parses into a /32 host route on the exact port. This is the local-LLM
// case (192.168.1.150:8080) the exemption exists for.
func TestParseAcceptsPrivateHostPort(t *testing.T) {
	e, err := lanexempt.Parse("192.168.1.150:8080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := e.Network.String(); got != "192.168.1.150/32" {
		t.Errorf("a bare IP must normalise to a /32 host route; got %q", got)
	}
	if e.Port != 8080 {
		t.Errorf("Port = %d, want 8080", e.Port)
	}
	if !e.IsV4() {
		t.Errorf("192.168.1.150 must classify as IPv4")
	}
}

// TestParseRejectsPortOmittedLoudly proves the port-omitted form (a bare IP/CIDR,
// no `:port`) is REJECTED loudly, naming the value and telling the user to add
// `:port`. The all-ports form used to open EVERY TCP port except 53, which is a
// deanonymization leak if the exempted host runs any forwarding proxy on some
// other port; the only defensible granularity is "reach exactly this service", so
// a port is now MANDATORY (see docs/adr/0007).
func TestParseRejectsPortOmittedLoudly(t *testing.T) {
	for _, raw := range []string{"10.0.0.5", "192.168.0.0/24", "192.168.1.150", "169.254.1.1"} {
		_, err := lanexempt.Parse(raw)
		if err == nil {
			t.Errorf("Parse(%q) must reject a port-omitted (all-ports) exemption", raw)
			continue
		}
		if !strings.Contains(err.Error(), raw) {
			t.Errorf("Parse(%q) error should name the offending value; got: %v", raw, err)
		}
		if !strings.Contains(err.Error(), ":port") {
			t.Errorf("Parse(%q) error should instruct the user to add :port; got: %v", raw, err)
		}
	}
}

// TestHostPortRendersProbeTarget proves the dialable host:port the verify probe
// needs: an exemption renders its own exact host+port (a port is mandatory, so it
// always carries a concrete port).
func TestHostPortRendersProbeTarget(t *testing.T) {
	withPort, err := lanexempt.Parse("192.168.1.150:8080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := withPort.HostPort(); got != "192.168.1.150:8080" {
		t.Errorf("HostPort = %q, want 192.168.1.150:8080 (the exemption's own port)", got)
	}
}

// TestParseAcceptsEveryPrivateRange proves all four accepted ranges (the three
// RFC1918 blocks + link-local) parse, mirroring netcage's --allow guardrail
// verbatim. A port is now mandatory, so each value carries an explicit `:port`
// (including the whole-block CIDR forms).
func TestParseAcceptsEveryPrivateRange(t *testing.T) {
	for _, raw := range []string{
		"10.1.2.3:22",
		"172.16.5.5:443",
		"192.168.1.150:8080",
		"169.254.1.1:80",  // link-local
		"10.0.0.0/8:8080", // whole private block, CIDR:port
		"172.16.0.0/12:443",
		"192.168.0.0/16:8080",
		"169.254.0.0/16:80",
	} {
		if _, err := lanexempt.Parse(raw); err != nil {
			t.Errorf("Parse(%q) should accept a private destination, got: %v", raw, err)
		}
	}
}

// TestParseRejectsPublicLoudly proves a public IP/CIDR is REJECTED loudly, naming
// the value: a public direct would be a real anonymity leak (story 24). This is
// the load-bearing guardrail.
func TestParseRejectsPublicLoudly(t *testing.T) {
	for _, raw := range []string{
		"8.8.8.8:53",
		"1.1.1.1",
		"93.184.216.34:80",
		"172.32.0.1:80", // just OUTSIDE 172.16.0.0/12
		"11.0.0.0/8",    // public
		"10.0.0.0/7",    // straddles public space (must be refused)
	} {
		_, err := lanexempt.Parse(raw)
		if err == nil {
			t.Errorf("Parse(%q) must reject a public/broad destination", raw)
			continue
		}
		if !strings.Contains(err.Error(), raw) {
			t.Errorf("Parse(%q) error should name the offending value; got: %v", raw, err)
		}
	}
}

// TestParseRejectsHostnames proves a hostname is REJECTED (IP/CIDR literals only):
// a LAN name cannot resolve through the forced path, and a local-resolver hole
// would be another leak (story 24).
func TestParseRejectsHostnames(t *testing.T) {
	for _, raw := range []string{
		"my-llm.local:8080",
		"localhost:8080",
		"router:80",
	} {
		if _, err := lanexempt.Parse(raw); err == nil {
			t.Errorf("Parse(%q) must reject a hostname (IP/CIDR only)", raw)
		}
	}
}

// TestParseRejectsPort53Loudly proves an explicit `:53` exemption is REJECTED
// loudly, naming the value and the reason: a clear-DNS hole to a LAN resolver can
// reveal the local network's public IP (Tails leak-catalogue row 2). DNS must go
// through the anonymizer, never a direct LAN query. This closes hole (1).
func TestParseRejectsPort53Loudly(t *testing.T) {
	for _, raw := range []string{
		"192.168.1.1:53",
		"10.0.0.1:53",
		"172.16.0.53:53",
		"192.168.0.0/24:53", // a whole-subnet :53 is the same clear-DNS hole
	} {
		_, err := lanexempt.Parse(raw)
		if err == nil {
			t.Errorf("Parse(%q) must reject an explicit :53 exemption (a clear-DNS hole)", raw)
			continue
		}
		if !strings.Contains(err.Error(), raw) {
			t.Errorf("Parse(%q) error should name the offending value; got: %v", raw, err)
		}
		if !strings.Contains(err.Error(), "53") || !strings.Contains(strings.ToLower(err.Error()), "dns") {
			t.Errorf("Parse(%q) error should explain the DNS reason; got: %v", raw, err)
		}
	}
}

// TestParseAcceptsNonDNSPorts proves the reject is scoped to 53 ONLY: a nearby
// port (and DoT/853) on an exact-port exemption still parses. The all-ports form
// is gone (port-omitted is rejected), so every accepted value names an exact port.
func TestParseAcceptsNonDNSPorts(t *testing.T) {
	for _, raw := range []string{
		"192.168.1.1:52",
		"192.168.1.1:54",
		"192.168.1.1:853",   // DoT is encrypted DNS, not the clear-DNS leak this guards
		"192.168.0.0/24:80", // whole-subnet with an exact port
	} {
		if _, err := lanexempt.Parse(raw); err != nil {
			t.Errorf("Parse(%q) should accept a non-53 exact-port exemption; got: %v", raw, err)
		}
	}
}

// TestParseAcceptsLoopbackHostPort proves the loopback class: an exact
// 127.0.0.1:port parses into a /32 host route on the exact port and classifies as
// loopback (not LAN). This is the same-host local-model case (a loopback-bound
// service the anon account may reach directly without binding it to 0.0.0.0).
func TestParseAcceptsLoopbackHostPort(t *testing.T) {
	e, err := lanexempt.Parse("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := e.Network.String(); got != "127.0.0.1/32" {
		t.Errorf("a bare loopback IP must normalise to a /32 host route; got %q", got)
	}
	if e.Port != 8080 {
		t.Errorf("Port = %d, want 8080", e.Port)
	}
	if !e.IsLoopback() {
		t.Errorf("127.0.0.1 must classify as loopback")
	}
	if e.IsV4() != true {
		t.Errorf("127.0.0.1 is IPv4")
	}
}

// TestClassDispatchFromSameEntryPoint proves the SINGLE --allow entry point
// dispatches on the typed address: a loopback address is loopback-class, a private
// address is LAN-class, from the SAME Parse call. The user made the class obvious
// by typing 127.0.0.1 vs 192.168.x.x, so no separate flag disambiguates.
func TestClassDispatchFromSameEntryPoint(t *testing.T) {
	lo, err := lanexempt.Parse("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("Parse(loopback): %v", err)
	}
	if !lo.IsLoopback() {
		t.Errorf("127.0.0.1:8080 must route to the loopback branch")
	}
	lan, err := lanexempt.Parse("192.168.1.150:8080")
	if err != nil {
		t.Fatalf("Parse(lan): %v", err)
	}
	if lan.IsLoopback() {
		t.Errorf("192.168.1.150:8080 must route to the LAN branch, not loopback")
	}
}

// TestParseRejectsLoopbackAnonymizerPortsLoudly proves the loopback guardrail is
// STRICTER than the LAN branch: loopback is the anonymizer's OWN control surface,
// so an exemption naming a conventional anonymizer control/SOCKS/DNS port is
// REJECTED loudly, naming the port. Allowing a SOCKS/control port would let the
// anon UID dial the forced path's own upstream directly (defeating closure (b) and
// the <account>@ isolation) or self-deanonymize (9051 Tor control). 53 is clear
// DNS. The account-specific shim relay/DNS/endpoint ports are rejected at the nft
// generate layer (which knows them); the well-known set is rejected here.
func TestParseRejectsLoopbackAnonymizerPortsLoudly(t *testing.T) {
	for _, tc := range []struct{ raw, portStr string }{
		{"127.0.0.1:53", "53"},     // clear DNS
		{"127.0.0.1:9050", "9050"}, // Tor SOCKS
		{"127.0.0.1:9150", "9150"}, // Tor Browser SOCKS
		{"127.0.0.1:9051", "9051"}, // Tor control (self-deanonymization vector)
		{"127.0.0.1:1080", "1080"}, // generic SOCKS
	} {
		_, err := lanexempt.Parse(tc.raw)
		if err == nil {
			t.Errorf("Parse(%q) must reject a loopback anonymizer control/SOCKS/DNS port", tc.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.portStr) {
			t.Errorf("Parse(%q) error should name the offending port %s; got: %v", tc.raw, tc.portStr, err)
		}
	}
}

// TestParseAcceptsLoopbackNonAnonymizerPort proves a non-anonymizer loopback port
// (a local model server) is accepted: the guardrail rejects the control surface,
// not every loopback port.
func TestParseAcceptsLoopbackNonAnonymizerPort(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1:8080",
		"127.0.0.1:11434", // a common local-model port
		"127.0.0.1:3000",
	} {
		if _, err := lanexempt.Parse(raw); err != nil {
			t.Errorf("Parse(%q) should accept a non-anonymizer loopback port; got: %v", raw, err)
		}
	}
}

// TestParseRejectsLoopbackPortOmitted proves loopback has NO all-ports form under
// any circumstance: a port-omitted loopback value is rejected loudly, naming the
// value and telling the user to add :port (loopback is even stricter than LAN,
// which also rejects port-omitted).
func TestParseRejectsLoopbackPortOmitted(t *testing.T) {
	_, err := lanexempt.Parse("127.0.0.1")
	if err == nil {
		t.Fatalf("Parse(127.0.0.1) must reject a port-omitted loopback exemption")
	}
	if !strings.Contains(err.Error(), ":port") {
		t.Errorf("error should instruct the user to add :port; got: %v", err)
	}
}

// TestParseRejectsLoopbackHostname proves a hostname that resolves to loopback
// (localhost) is still rejected: IP/CIDR literals only, so the class is decided
// from the literal the user typed, never a resolver lookup (a local-resolver hole
// would be a leak).
func TestParseRejectsLoopbackHostname(t *testing.T) {
	if _, err := lanexempt.Parse("localhost:8080"); err == nil {
		t.Errorf("Parse(localhost:8080) must reject a hostname (IP/CIDR only)")
	}
}

// TestParseRejectsMalformed proves malformed / empty / bad-port values are
// rejected loudly rather than silently mis-parsed.
func TestParseRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"",                  // empty
		"192.168.1.150:",    // empty port
		"192.168.1.150:abc", // non-numeric port
		"192.168.1.150:0",   // out-of-range port
		"192.168.1.150:70000",
		"192.168.1.999:80", // not an IP
	} {
		if _, err := lanexempt.Parse(raw); err == nil {
			t.Errorf("Parse(%q) must reject a malformed value", raw)
		}
	}
}
