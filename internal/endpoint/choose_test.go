package endpoint_test

import (
	"errors"
	"testing"

	"github.com/wighawag/anonctl/internal/endpoint"
)

// ep is a small helper building a loopback endpoint of a given port/class.
func ep(port string, class endpoint.ShareClass) endpoint.Endpoint {
	return endpoint.Endpoint{Host: "127.0.0.1", Port: port, Class: class}
}

// BuildOffers marks the first Tor offer default and annotates a peruser endpoint
// owned by ANOTHER account as taken; a tor-shared offer is never taken.
func TestBuildOffersMarksDefaultAndTaken(t *testing.T) {
	offers := []endpoint.Endpoint{
		ep("9050", endpoint.ClassTorShared),
		ep("1080", endpoint.ClassSocksPeruser),
	}
	taken := func(e endpoint.Endpoint) string {
		if e.Port == "1080" {
			return "anon-a"
		}
		return ""
	}
	got := endpoint.BuildOffers(offers, "anon-new", taken)

	if !got[0].IsDefault {
		t.Errorf("the Tor offer must be the default")
	}
	if got[0].TakenBy != "" {
		t.Errorf("a tor-shared offer must never be taken, got TakenBy=%q", got[0].TakenBy)
	}
	if got[1].TakenBy != "anon-a" || got[1].Selectable() {
		t.Errorf("the peruser offer owned by anon-a must be taken + not selectable, got %+v", got[1])
	}
}

// A peruser endpoint owned by the SAME account being added is selectable (a self
// re-add is fine).
func TestBuildOffersSelfOwnedPeruserSelectable(t *testing.T) {
	offers := []endpoint.Endpoint{ep("1080", endpoint.ClassSocksPeruser)}
	taken := func(endpoint.Endpoint) string { return "anon-a" } // owner is the same account
	got := endpoint.BuildOffers(offers, "anon-a", taken)
	if !got[0].Selectable() {
		t.Errorf("a peruser endpoint owned by the SAME account must be selectable")
	}
}

// ChooseNonInteractive picks the confirmed Tor default when present.
func TestChooseNonInteractivePicksTor(t *testing.T) {
	offers := endpoint.BuildOffers(
		[]endpoint.Endpoint{ep("1080", endpoint.ClassSocksPeruser), ep("9050", endpoint.ClassTorShared)},
		"anon", func(endpoint.Endpoint) string { return "" },
	)
	chosen, err := endpoint.ChooseNonInteractive(offers)
	if err != nil {
		t.Fatalf("ChooseNonInteractive: %v", err)
	}
	if chosen.Port != "9050" || chosen.Class != endpoint.ClassTorShared {
		t.Errorf("non-interactive choice = %s, want the Tor default 9050", chosen.URL())
	}
}

// ChooseNonInteractive fails CLOSED when nothing confirmed a Tor endpoint (a lone
// peruser is never auto-picked): add must refuse, not configure a dead default.
func TestChooseNonInteractiveFailsClosedWithoutTor(t *testing.T) {
	offers := endpoint.BuildOffers(
		[]endpoint.Endpoint{ep("1080", endpoint.ClassSocksPeruser)},
		"anon", func(endpoint.Endpoint) string { return "" },
	)
	if _, err := endpoint.ChooseNonInteractive(offers); !errors.Is(err, endpoint.ErrNoEndpointConfirmed) {
		t.Errorf("ChooseNonInteractive with no Tor = %v, want ErrNoEndpointConfirmed", err)
	}
	// An empty scan (no candidates at all) also fails closed.
	if _, err := endpoint.ChooseNonInteractive(nil); !errors.Is(err, endpoint.ErrNoEndpointConfirmed) {
		t.Errorf("ChooseNonInteractive on an empty scan = %v, want ErrNoEndpointConfirmed", err)
	}
}

// SelectByIndex resolves a valid 1-based pick, rejects out-of-range, and rejects a
// pick of a taken offer.
func TestSelectByIndex(t *testing.T) {
	offers := endpoint.BuildOffers(
		[]endpoint.Endpoint{ep("9050", endpoint.ClassTorShared), ep("1080", endpoint.ClassSocksPeruser)},
		"anon-new", func(e endpoint.Endpoint) string {
			if e.Port == "1080" {
				return "anon-a"
			}
			return ""
		},
	)
	// Pick 1 (the Tor offer) is selectable.
	if chosen, err := endpoint.SelectByIndex(offers, 1); err != nil || chosen.Port != "9050" {
		t.Errorf("SelectByIndex(1) = %s, %v; want 9050, nil", chosen.URL(), err)
	}
	// Pick 2 (the taken peruser) is refused.
	if _, err := endpoint.SelectByIndex(offers, 2); err == nil {
		t.Errorf("SelectByIndex on a taken offer must error")
	}
	// Out of range.
	if _, err := endpoint.SelectByIndex(offers, 3); err == nil {
		t.Errorf("SelectByIndex out of range must error")
	}
	if _, err := endpoint.SelectByIndex(offers, 0); err == nil {
		t.Errorf("SelectByIndex(0) must error (0 is reserved for default/custom)")
	}
}
