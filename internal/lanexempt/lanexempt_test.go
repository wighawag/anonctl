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

// TestParsePortOmittedMeansAllTCP proves the port-omitted form (a bare IP/CIDR)
// means "all TCP ports on this host" (Port == 0), per the acceptance criterion.
func TestParsePortOmittedMeansAllTCP(t *testing.T) {
	for _, raw := range []string{"10.0.0.5", "192.168.0.0/24"} {
		e, err := lanexempt.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if e.Port != 0 {
			t.Errorf("Parse(%q).Port = %d, want 0 (all TCP ports)", raw, e.Port)
		}
	}
}

// TestParseAcceptsEveryPrivateRange proves all four accepted ranges (the three
// RFC1918 blocks + link-local) parse, mirroring netcage's --allow-direct guardrail
// verbatim.
func TestParseAcceptsEveryPrivateRange(t *testing.T) {
	for _, raw := range []string{
		"10.1.2.3:22",
		"172.16.5.5:443",
		"192.168.1.150:8080",
		"169.254.1.1:80", // link-local
		"10.0.0.0/8",     // whole private block, CIDR
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
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
