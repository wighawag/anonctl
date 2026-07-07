package accountconfig_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/endpoint"
)

// sample is a valid config for the default `anon` account pointed at the local Tor
// SocksPort, with the recipe's UIDs. Tests mutate a copy for the negative cases.
func sample() accountconfig.Config {
	return accountconfig.Config{
		Account:       "anon",
		AnonUID:       30034,
		ShimUID:       995,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
	}
}

func TestWriteFillsDefaultPortsAndStampsSchema(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	if err := store.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := store.Read("anon")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.SchemaVersion != accountconfig.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, accountconfig.SchemaVersion)
	}
	// A config written without ports gets the recipe's defaults (19050/19053), so a
	// single default account works with no extra input.
	if got.RelayPort != accountconfig.DefaultRelayPort {
		t.Errorf("RelayPort = %d, want default %d", got.RelayPort, accountconfig.DefaultRelayPort)
	}
	if got.DNSPort != accountconfig.DefaultDNSPort {
		t.Errorf("DNSPort = %d, want default %d", got.DNSPort, accountconfig.DefaultDNSPort)
	}
}

func TestRoundTripPreservesEndpoint(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	c := sample()
	c.EndpointHost = "127.0.0.1"
	c.EndpointPort = 1080
	c.EndpointClass = endpoint.ClassSocksPeruser
	if err := store.Write(c); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := store.Read("anon")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	ep := got.Endpoint()
	if ep.Host != "127.0.0.1" || ep.Port != "1080" || ep.Class != endpoint.ClassSocksPeruser {
		t.Errorf("Endpoint() = %+v, want host 127.0.0.1 port 1080 class socks-peruser", ep)
	}
	// A socks-peruser endpoint derives an EMPTY isolation username (no per-username
	// isolation), preserved through the round-trip.
	if u := ep.IsolationUsername("anon"); u != "" {
		t.Errorf("IsolationUsername(socks-peruser) = %q, want empty", u)
	}
}

func TestReadAbsentIsNotFound(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	if _, err := store.Read("anon"); err != accountconfig.ErrNotFound {
		t.Errorf("Read(absent) = %v, want ErrNotFound", err)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	// Removing an absent config is a clean no-op (rm idempotency), not an error.
	if err := store.Remove("anon"); err != nil {
		t.Errorf("Remove(absent) = %v, want nil", err)
	}
	if err := store.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := store.Remove("anon"); err != nil {
		t.Errorf("Remove(present) = %v, want nil", err)
	}
	if _, err := store.Read("anon"); err != accountconfig.ErrNotFound {
		t.Errorf("after Remove, Read = %v, want ErrNotFound", err)
	}
}

func TestWriteRejectsMalformedConfig(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	cases := map[string]func(*accountconfig.Config){
		"empty account":    func(c *accountconfig.Config) { c.Account = "" },
		"zero anon uid":    func(c *accountconfig.Config) { c.AnonUID = 0 },
		"zero shim uid":    func(c *accountconfig.Config) { c.ShimUID = 0 },
		"equal uids":       func(c *accountconfig.Config) { c.ShimUID = c.AnonUID },
		"empty host":       func(c *accountconfig.Config) { c.EndpointHost = "" },
		"zero endpt port":  func(c *accountconfig.Config) { c.EndpointPort = 0 },
		"empty class":      func(c *accountconfig.Config) { c.EndpointClass = "" },
		"endpt port range": func(c *accountconfig.Config) { c.EndpointPort = 70000 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := sample()
			mutate(&c)
			if err := store.Write(c); err == nil {
				t.Errorf("Write(%s) = nil, want a validation error", name)
			}
		})
	}
}

func TestParseRejectsFutureSchema(t *testing.T) {
	// A record from a NEWER anonctl is refused loudly, never half-read.
	data := []byte(`{"schemaVersion": 9999, "account": "anon"}`)
	if _, err := accountconfig.Parse(data); err == nil {
		t.Errorf("Parse(future schema) = nil, want a refusal")
	}
	// A record with no schemaVersion is not an anonctl config.
	if _, err := accountconfig.Parse([]byte(`{"account":"anon"}`)); err == nil {
		t.Errorf("Parse(no schema) = nil, want a refusal")
	}
}

func TestPathRejectsTraversal(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	for _, bad := range []string{"../etc/passwd", "a/b", ".."} {
		if _, err := store.Path(bad); err == nil {
			t.Errorf("Path(%q) = nil, want a traversal refusal", bad)
		}
	}
}

// TestWriteIsRootOnlyAndNeverTouchesRealEtc asserts the config file is written
// 0600 (anonctl-private, unlike the world-readable marker) and that a test Store
// never writes the real /etc/anonctl/accounts (the shared-write isolation
// discipline).
func TestWriteIsRootOnlyAndNeverTouchesRealEtc(t *testing.T) {
	dir := t.TempDir()
	store := accountconfig.Store{BaseDir: dir}
	if err := store.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "anon.json"))
	if err != nil {
		t.Fatalf("stat written config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file mode = %o, want 0600 (root-only, not world-readable)", perm)
	}
	if store.BaseDir == accountconfig.DefaultBaseDir {
		t.Fatal("test Store must not point at the real DefaultBaseDir")
	}
}
