package endpoint

import (
	"errors"
	"fmt"
)

// Choose is the scan-and-offer decision layer over Scan's candidates: it turns a
// list of confirmed offers plus an "already taken by another account" predicate
// into an ordered set of OFFERS an operator can pick from, marks the DEFAULT
// selection (a confirmed Tor endpoint when present), and decides the
// NON-INTERACTIVE outcome (Tor-if-confirmed, else fail-closed). It is PURE: no
// socket, no TTY, no /etc read. The impure edges (the real DialProber scan, the
// terminal prompt, the claim-set read) are the caller's; the choice logic here is
// exhaustively unit-testable.
//
// It is deliberately claim-AWARE only through an injected predicate, so it does
// not import accountconfig (which imports THIS package): the caller folds the
// on-disk claim set into `takenBy` and this stays a pure decision.

// ErrNoEndpointConfirmed is returned by ChooseNonInteractive when no endpoint can
// be chosen without a prompt: the scan confirmed nothing (or only a taken
// peruser), and there is no TTY to ask. add surfaces it as a fail-closed refusal
// ("pass --endpoint ...") rather than silently configuring a dead default.
var ErrNoEndpointConfirmed = errors.New("no socks5h endpoint confirmed and no interactive terminal to choose one")

// Offer is one scan candidate decorated for presentation/selection: the endpoint,
// whether it is the DEFAULT (a confirmed Tor endpoint), and, when it is a
// socks-peruser endpoint already owned by ANOTHER account, that owner (so it is
// shown "in use by <owner>" and is NOT selectable for a second account). A
// tor-shared offer is never "taken" (sharing Tor is safe), so TakenBy is empty for
// it regardless.
type Offer struct {
	Endpoint  Endpoint
	IsDefault bool
	// TakenBy is the OTHER account that already owns this socks-peruser endpoint, or
	// "" when the offer is selectable (unowned, owned by the SAME account, or a
	// share-safe tor-shared endpoint).
	TakenBy string
}

// Selectable reports whether this offer may be chosen for the account being added:
// a share-safe (tor-shared) or unclaimed endpoint is selectable; a socks-peruser
// endpoint already owned by another account is NOT (choosing it would make the two
// accounts cross-identifiable, and the Registry would refuse it anyway).
func (o Offer) Selectable() bool { return o.TakenBy == "" }

// BuildOffers decorates the scan offers for `account`: it marks the FIRST
// tor-shared (Tor) offer as the default, and annotates each socks-peruser offer
// with the other account that owns it (via takenBy), leaving tor-shared offers
// never-taken. takenBy(ep) returns the owning account for a peruser endpoint, or ""
// when the endpoint is unowned or owned by `account` itself (a self re-add is
// selectable). It is pure over the injected predicate.
func BuildOffers(offers []Endpoint, account string, takenBy func(Endpoint) string) []Offer {
	out := make([]Offer, 0, len(offers))
	defaultSet := false
	for _, ep := range offers {
		o := Offer{Endpoint: ep}
		if ep.Class == ClassTorShared && !defaultSet {
			o.IsDefault = true
			defaultSet = true
		}
		if ep.Class == ClassSocksPeruser {
			if owner := takenBy(ep); owner != "" && owner != account {
				o.TakenBy = owner
			}
		}
		out = append(out, o)
	}
	return out
}

// DefaultOffer returns the default offer (the confirmed Tor one) and true, or a
// zero Offer and false when there is none. It is the non-interactive selection and
// the pre-selected interactive default.
func DefaultOffer(offers []Offer) (Offer, bool) {
	for _, o := range offers {
		if o.IsDefault {
			return o, true
		}
	}
	return Offer{}, false
}

// ChooseNonInteractive is the outcome when there is NO terminal to prompt: it
// picks the confirmed Tor default if present, else returns ErrNoEndpointConfirmed
// so add fails CLOSED (never silently configuring a dead endpoint). A taken
// peruser is never auto-picked (only the share-safe Tor default is), so a
// non-interactive add never lands on a colliding endpoint.
func ChooseNonInteractive(offers []Offer) (Endpoint, error) {
	if o, ok := DefaultOffer(offers); ok {
		return o.Endpoint, nil
	}
	return Endpoint{}, ErrNoEndpointConfirmed
}

// SelectByIndex resolves an operator's 1-based menu pick into the chosen endpoint,
// rejecting an out-of-range index or a pick of a taken (non-selectable) offer with
// a clear error. Index 0 is reserved by the caller for "accept the default"/"type
// a custom endpoint"; this validates a concrete numbered pick.
func SelectByIndex(offers []Offer, oneBased int) (Endpoint, error) {
	if oneBased < 1 || oneBased > len(offers) {
		return Endpoint{}, fmt.Errorf("choice %d is out of range (1..%d)", oneBased, len(offers))
	}
	o := offers[oneBased-1]
	if !o.Selectable() {
		return Endpoint{}, fmt.Errorf("%s is already in use by account %q (a socks-peruser endpoint is a single identity; pick another)", o.Endpoint.URL(), o.TakenBy)
	}
	return o.Endpoint, nil
}
