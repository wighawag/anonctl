package endpoint_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/endpoint"
)

// The default endpoint resolves to the local Tor SocksPort and is classed
// tor-shared: `anonctl add` with no endpoint must anonymize out of the box
// (story 4). It is a socks5h URL, credential-free, on the conventional Tor port.
func TestDefaultEndpointIsLocalTorShared(t *testing.T) {
	ep := endpoint.Default()
	if ep.Host != "127.0.0.1" || ep.Port != "9050" {
		t.Errorf("default endpoint = %s:%s, want 127.0.0.1:9050 (local Tor SocksPort)", ep.Host, ep.Port)
	}
	if ep.Class != endpoint.ClassTorShared {
		t.Errorf("default share-class = %q, want %q (a Tor SocksPort is share-safe)", ep.Class, endpoint.ClassTorShared)
	}
	if !strings.HasPrefix(ep.URL(), "socks5h://") {
		t.Errorf("default URL %q must be socks5h://", ep.URL())
	}
	if ep.Username != "" || ep.Password != "" {
		t.Errorf("default endpoint must be credential-free at rest, got user=%q", ep.Username)
	}
}

// An explicit socks5h endpoint is accepted (story 5): any existing socks5h proxy
// (Mullvad local SOCKS, wireproxy, ssh -D, ...) can back an account. A bare
// host:port is defaulted to the socks5h scheme, mirroring netcage's hygiene.
func TestParseAcceptsExplicitSocks5hEndpoint(t *testing.T) {
	for _, raw := range []string{"socks5h://127.0.0.1:1080", "127.0.0.1:1080"} {
		ep, err := endpoint.Parse(raw, endpoint.ClassSocksPeruser)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", raw, err)
		}
		if ep.Host != "127.0.0.1" || ep.Port != "1080" {
			t.Errorf("Parse(%q) = %s:%s, want 127.0.0.1:1080", raw, ep.Host, ep.Port)
		}
		if ep.Class != endpoint.ClassSocksPeruser {
			t.Errorf("Parse(%q) class = %q, want socks-peruser", raw, ep.Class)
		}
	}
}

// socks5:// (local DNS resolution) LEAKS hostnames to the host resolver, exactly
// the failure anonctl exists to prevent; Parse must refuse it and say socks5h,
// mirroring netcage's ParseProxy.
func TestParseRefusesSocks5LocalDNS(t *testing.T) {
	_, err := endpoint.Parse("socks5://127.0.0.1:9050", endpoint.ClassTorShared)
	if err == nil {
		t.Fatal("Parse accepted socks5:// (local DNS leak); it must require socks5h://")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "socks5h") {
		t.Errorf("rejection %q should mention socks5h", err)
	}
}

// The persisted endpoint is CREDENTIAL-FREE by construction (mirrors netcage's
// config-at-rest hygiene): a user:pass@ endpoint is refused with the sentinel, so
// credentials never land in an anonctl-owned config. The per-account isolation
// username is derived by anonctl, NOT embedded here.
func TestParseRefusesEmbeddedCredentials(t *testing.T) {
	_, err := endpoint.Parse("socks5h://user:pass@127.0.0.1:9050", endpoint.ClassTorShared)
	if !errors.Is(err, endpoint.ErrCredentialedEndpoint) {
		t.Fatalf("Parse of a credentialed endpoint err = %v, want ErrCredentialedEndpoint", err)
	}
}

// Share-class classification returns tor-shared vs socks-peruser for
// representative endpoints (story 7/8). A Tor SocksPort is share-safe (per-account
// SOCKS-auth isolation); a plain socks endpoint is a single identity.
func TestClassifyRepresentativeEndpoints(t *testing.T) {
	cases := []struct {
		raw  string
		want endpoint.ShareClass
	}{
		{"socks5h://127.0.0.1:9050", endpoint.ClassTorShared},    // Tor default
		{"socks5h://127.0.0.1:9150", endpoint.ClassTorShared},    // Tor Browser
		{"socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser}, // generic SOCKS
		{"socks5h://127.0.0.1:1081", endpoint.ClassSocksPeruser}, // wireproxy / ssh -D
	}
	for _, tc := range cases {
		ep, err := endpoint.Parse(tc.raw, endpoint.Classify(tc.raw))
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", tc.raw, err)
		}
		if ep.Class != tc.want {
			t.Errorf("Classify(%q) = %q, want %q", tc.raw, ep.Class, tc.want)
		}
	}
}

// For a tor-shared endpoint the derived per-account isolation username is the
// account name and is DISTINCT per account, so Tor's IsolateSOCKSAuth gives each
// account its own circuit/exit (story 7, grounded in
// work/notes/findings/tor-isolatesocksauth-default.md).
func TestIsolationUsernameDistinctPerAccountForTorShared(t *testing.T) {
	tor := endpoint.Default()
	if got := tor.IsolationUsername("anon"); got != "anon" {
		t.Errorf("IsolationUsername(anon) = %q, want anon", got)
	}
	a := tor.IsolationUsername("anon")
	b := tor.IsolationUsername("anon-work")
	if a == b {
		t.Errorf("isolation usernames must be distinct per account, both = %q", a)
	}
}

// A socks-peruser endpoint has NO per-username isolation, so it derives NO
// isolation username (an empty username): dialling it with an account name would
// be a false promise of isolation. anonctl instead enforces one-account-only.
func TestIsolationUsernameEmptyForSocksPeruser(t *testing.T) {
	ep, err := endpoint.Parse("socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if got := ep.IsolationUsername("anon"); got != "" {
		t.Errorf("socks-peruser IsolationUsername = %q, want empty (no per-username isolation)", got)
	}
}

// Sharing a tor-shared endpoint across accounts is ALLOWED: the <account>@
// username makes each account its own circuit. A Registry that already claims the
// Tor endpoint for `anon` accepts a second account `anon-work` on it.
func TestRegistryAllowsSharingTorShared(t *testing.T) {
	reg := endpoint.NewRegistry()
	tor := endpoint.Default()
	if err := reg.Claim("anon", tor); err != nil {
		t.Fatalf("first claim of tor-shared: %v", err)
	}
	if err := reg.Claim("anon-work", tor); err != nil {
		t.Errorf("second account on a tor-shared endpoint must be allowed, got: %v", err)
	}
}

// Pointing a SECOND account at a socks-peruser endpoint already claimed by
// ANOTHER account is REFUSED loudly (story 8): the two accounts would exit
// identically and become cross-identifiable. The refusal names the conflicting
// account so the operator understands the collision.
func TestRegistryRefusesSharingSocksPeruser(t *testing.T) {
	reg := endpoint.NewRegistry()
	ep, err := endpoint.Parse("socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if err := reg.Claim("anon", ep); err != nil {
		t.Fatalf("first claim of socks-peruser: %v", err)
	}
	err = reg.Claim("anon-work", ep)
	if !errors.Is(err, endpoint.ErrPeruserAlreadyClaimed) {
		t.Fatalf("second account on a socks-peruser endpoint err = %v, want ErrPeruserAlreadyClaimed", err)
	}
	if !strings.Contains(err.Error(), "anon") {
		t.Errorf("refusal %q should name the claiming account", err)
	}
}

// Re-claiming a socks-peruser endpoint for the SAME account is idempotent (a
// reconfigure / re-add of the same account is not a cross-identification), so the
// refusal fires only on a DIFFERENT second account.
func TestRegistrySameAccountReclaimIsAllowed(t *testing.T) {
	reg := endpoint.NewRegistry()
	ep, err := endpoint.Parse("socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if err := reg.Claim("anon", ep); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := reg.Claim("anon", ep); err != nil {
		t.Errorf("same-account re-claim must be idempotent, got: %v", err)
	}
}

// Two DIFFERENT socks-peruser endpoints may each be claimed by one account: the
// refusal is per-ENDPOINT (same host:port), not a global one-socks-account cap.
func TestRegistryDistinctPeruserEndpointsAllowed(t *testing.T) {
	reg := endpoint.NewRegistry()
	a, _ := endpoint.Parse("socks5h://127.0.0.1:1080", endpoint.ClassSocksPeruser)
	b, _ := endpoint.Parse("socks5h://127.0.0.1:1081", endpoint.ClassSocksPeruser)
	if err := reg.Claim("anon", a); err != nil {
		t.Fatalf("claim a: %v", err)
	}
	if err := reg.Claim("anon-work", b); err != nil {
		t.Errorf("a distinct socks-peruser endpoint for another account must be allowed, got: %v", err)
	}
}
