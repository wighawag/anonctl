package endpoint_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/endpoint"
)

// fakeProber answers the pure Scan decision from a scripted per-port result, so
// the scan-and-offer enumeration is unit-testable with no real socket probe
// (mirrors netcage detectproxy's Prober seam).
type fakeProber struct {
	results map[int]endpoint.ProbeResult
}

func (p fakeProber) Probe(port int) endpoint.ProbeResult { return p.results[port] }

// Scan-and-offer enumerates the plausible local socks5h endpoints (story 6): it
// walks the canonical ports, keeps only the ports that CONFIRMED SOCKS5 (an open
// port alone is not enough), and offers each as a socks5h candidate with a
// suggested share-class (a Tor-conventional port suggests tor-shared).
func TestScanOffersConfirmedSocks5hCandidates(t *testing.T) {
	prober := fakeProber{results: map[int]endpoint.ProbeResult{
		9050: {Open: true, SOCKS5: true},  // Tor: confirmed
		9150: {Open: true, SOCKS5: false}, // open but not SOCKS5: not offered
		1080: {Open: true, SOCKS5: true},  // generic SOCKS: confirmed
	}}
	offers := endpoint.Scan(prober)

	var got []string
	for _, o := range offers {
		got = append(got, o.URL())
	}
	if len(offers) != 2 {
		t.Fatalf("Scan offered %d candidates (%v), want 2 confirmed (9050, 1080)", len(offers), got)
	}

	byPort := map[string]endpoint.Endpoint{}
	for _, o := range offers {
		byPort[o.Port] = o
	}
	tor, ok := byPort["9050"]
	if !ok {
		t.Fatalf("Scan did not offer the confirmed Tor port 9050 (got %v)", got)
	}
	if !strings.HasPrefix(tor.URL(), "socks5h://") {
		t.Errorf("offered candidate %q must be socks5h://", tor.URL())
	}
	if tor.Class != endpoint.ClassTorShared {
		t.Errorf("port 9050 offer class = %q, want tor-shared (Tor-conventional port)", tor.Class)
	}
	if generic, ok := byPort["1080"]; !ok || generic.Class != endpoint.ClassSocksPeruser {
		t.Errorf("port 1080 offer = %+v, want a socks-peruser candidate", generic)
	}
}

// An open port that does NOT confirm SOCKS5 is never offered (an open port is not
// a proxy); and a fully closed scan offers nothing rather than a false candidate.
func TestScanOffersNothingWhenNoneConfirmed(t *testing.T) {
	prober := fakeProber{results: map[int]endpoint.ProbeResult{
		9050: {Open: true, SOCKS5: false},
		1080: {Open: false},
	}}
	if offers := endpoint.Scan(prober); len(offers) != 0 {
		t.Errorf("Scan offered %d candidates for an unconfirmed scan, want 0", len(offers))
	}
}
