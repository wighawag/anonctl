package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
)

// swapConfigListStore points the claim-set store at a scratch dir (never the real
// /etc/anonctl/accounts) and restores it on cleanup. Returns the store so a test
// can seed sibling configs.
func swapConfigListStore(t *testing.T) accountconfig.Store {
	t.Helper()
	orig := configListStore
	s := accountconfig.Store{BaseDir: t.TempDir()}
	configListStore = s
	t.Cleanup(func() { configListStore = orig })
	return s
}

// writeConfig seeds one sibling account config into the scratch store.
func writeConfig(t *testing.T, s accountconfig.Store, account string, port int, class endpoint.ShareClass) {
	t.Helper()
	if err := s.Write(accountconfig.Config{
		Account:       account,
		AnonUID:       30034,
		ShimUID:       995,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  port,
		EndpointClass: class,
	}); err != nil {
		t.Fatalf("seed config %s: %v", account, err)
	}
}

// claimEndpoint refuses pointing a NEW account at a socks-peruser endpoint an
// existing DIFFERENT account already owns (the cross-identification guard).
func TestClaimEndpointRefusesSecondPeruser(t *testing.T) {
	s := swapConfigListStore(t)
	writeConfig(t, s, "anon-a", 1080, endpoint.ClassSocksPeruser)

	ep, err := endpoint.Parse("socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser)
	if err != nil {
		t.Fatal(err)
	}
	err = claimEndpoint("anon-b", ep)
	if !errors.Is(err, endpoint.ErrPeruserAlreadyClaimed) {
		t.Errorf("claimEndpoint for a second peruser account = %v, want ErrPeruserAlreadyClaimed", err)
	}
}

// A shared tor-shared endpoint is never refused: many accounts share one Tor via
// the per-account `<account>@` isolation.
func TestClaimEndpointAllowsSharedTor(t *testing.T) {
	s := swapConfigListStore(t)
	writeConfig(t, s, "anon-a", 9050, endpoint.ClassTorShared)

	ep := endpoint.Default() // tor-shared 9050
	if err := claimEndpoint("anon-b", ep); err != nil {
		t.Errorf("a shared tor endpoint must never be refused, got %v", err)
	}
}

// The SAME account re-pointing at its own peruser endpoint is idempotent (an
// `update` re-point must not trip on its own persisted claim), because it is
// excluded from the built registry.
func TestClaimEndpointSelfRepointIdempotent(t *testing.T) {
	s := swapConfigListStore(t)
	writeConfig(t, s, "anon-a", 1080, endpoint.ClassSocksPeruser)

	ep, err := endpoint.Parse("socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimEndpoint("anon-a", ep); err != nil {
		t.Errorf("anon-a re-pointing at its own peruser endpoint must be allowed, got %v", err)
	}
}

// A distinct peruser endpoint (different port) is allowed even when another peruser
// endpoint is already claimed: the guard is per-endpoint, not a global one-peruser
// cap.
func TestClaimEndpointDistinctPeruserAllowed(t *testing.T) {
	s := swapConfigListStore(t)
	writeConfig(t, s, "anon-a", 1080, endpoint.ClassSocksPeruser)

	ep, err := endpoint.Parse("socks5h://127.0.0.1:1081", endpoint.ClassSocksPeruser)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimEndpoint("anon-b", ep); err != nil {
		t.Errorf("a DISTINCT peruser endpoint must be allowed, got %v", err)
	}
}

// A corrupt sibling config makes claimEndpoint fail LOUD (the guard must not be
// silently disabled by an unreadable claim set).
func TestClaimEndpointFailsLoudOnCorruptClaimSet(t *testing.T) {
	s := swapConfigListStore(t)
	// A corrupt .json in the config dir: List (and thus claimEndpoint) must error.
	if err := os.WriteFile(filepath.Join(s.BaseDir, "anon-bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ep := endpoint.Default()
	if err := claimEndpoint("anon", ep); err == nil {
		t.Errorf("claimEndpoint with a corrupt claim set = nil, want a loud error")
	}
}
