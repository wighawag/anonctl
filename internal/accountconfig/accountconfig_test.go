package accountconfig_test

import (
	"os"
	"path/filepath"
	"strings"
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

// List enumerates every written config (empty on a fresh/missing dir), and is the
// claim-set source the endpoint Registry is built from. A corrupt config is a LOUD
// error, never silently dropped (which would disable the cross-identification guard).
func TestList(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}

	// Missing/empty dir => empty, not an error.
	if got, err := store.List(); err != nil || len(got) != 0 {
		t.Fatalf("List on empty dir = %v, %v; want [], nil", got, err)
	}

	a := sample()
	b := sample()
	b.Account = "anon-work"
	b.EndpointPort = 1080
	b.EndpointClass = endpoint.ClassSocksPeruser
	for _, c := range []accountconfig.Config{a, b} {
		if err := store.Write(c); err != nil {
			t.Fatalf("Write %s: %v", c.Account, err)
		}
	}
	got, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d configs, want 2", len(got))
	}
	accounts := map[string]bool{}
	for _, c := range got {
		accounts[c.Account] = true
	}
	if !accounts["anon"] || !accounts["anon-work"] {
		t.Errorf("List accounts = %v, want anon + anon-work", accounts)
	}
}

// A non-.json file in the config dir is ignored; a CORRUPT .json is a loud error.
func TestListSkipsNonJSONAndFailsLoudOnCorrupt(t *testing.T) {
	base := t.TempDir()
	store := accountconfig.Store{BaseDir: base}
	if err := store.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A stray non-json file must be skipped, not parsed.
	if err := os.WriteFile(filepath.Join(base, "README"), []byte("not a config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.List(); err != nil || len(got) != 1 {
		t.Fatalf("List with a stray file = %v, %v; want 1 config, nil", got, err)
	}
	// A corrupt .json aborts List (the guard must not be silently disabled).
	if err := os.WriteFile(filepath.Join(base, "anon-bad.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); err == nil {
		t.Fatalf("List with a corrupt config = nil error, want a loud error")
	}
}

// BuildRegistryExcluding folds sibling configs into a Registry that refuses a
// SECOND account on a peruser endpoint but excludes the target account (so its own
// re-add is idempotent) and never refuses a shared tor endpoint.
func TestBuildRegistryExcluding(t *testing.T) {
	peruser := sample()
	peruser.Account = "anon-a"
	peruser.EndpointPort = 1080
	peruser.EndpointClass = endpoint.ClassSocksPeruser

	tor := sample()
	tor.Account = "anon-b" // tor-shared 9050

	configs := []accountconfig.Config{peruser, tor}

	// A DIFFERENT new account claiming anon-a's peruser endpoint is REFUSED.
	reg := accountconfig.BuildRegistryExcluding(configs, "anon-new")
	if err := reg.Claim("anon-new", peruser.Endpoint()); err == nil {
		t.Errorf("a second account on anon-a's peruser endpoint must be refused")
	}

	// The SAME account re-claiming its own peruser endpoint is allowed because it is
	// EXCLUDED from the built registry (self-idempotent re-add).
	regSelf := accountconfig.BuildRegistryExcluding(configs, "anon-a")
	if err := regSelf.Claim("anon-a", peruser.Endpoint()); err != nil {
		t.Errorf("anon-a re-claiming its own peruser endpoint must be allowed: %v", err)
	}

	// A new account on the SHARED tor endpoint is never refused.
	regTor := accountconfig.BuildRegistryExcluding(configs, "anon-new")
	if err := regTor.Claim("anon-new", tor.Endpoint()); err != nil {
		t.Errorf("a shared tor-shared endpoint must never be refused: %v", err)
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

// A config with LAN exemptions round-trips the raw exemption values (credential-
// free: just IP/CIDR[:port] strings, no secret), so the operator's --allow-direct
// choices survive to the next verb / reboot and reach both the ruleset and verify.
func TestRoundTripPreservesExemptions(t *testing.T) {
	store := accountconfig.Store{BaseDir: t.TempDir()}
	c := sample()
	c.Exemptions = []string{"192.168.1.150:8080", "10.0.0.0/24"}
	if err := store.Write(c); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := store.Read("anon")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Exemptions) != 2 || got.Exemptions[0] != "192.168.1.150:8080" || got.Exemptions[1] != "10.0.0.0/24" {
		t.Errorf("Exemptions = %v, want the two raw values in order", got.Exemptions)
	}
}

// A config with NO exemptions is byte-compatible with a pre-exemption record:
// omitempty means the `exemptions` key is absent, so existing markers/configs
// still load and the field never appears when unused.
func TestExemptionsOmittedWhenEmpty(t *testing.T) {
	blob, err := sample().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(blob), "exemptions") {
		t.Errorf("marshaled config with no exemptions contains %q; want the key OMITTED (byte-compat)\n%s", "exemptions", blob)
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

// RemoveBaseDirIfEmpty removes the config dir ONLY when no configs remain, used on
// the LAST account's teardown so a fully torn-down host leaves no empty
// /etc/anonctl/accounts dir (the e2e finding, BUG 4). It must be a clean no-op when
// the dir is absent, and must NEVER remove a dir that still holds a survivor
// account's config.
func TestRemoveBaseDirIfEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "accounts")
	store := accountconfig.Store{BaseDir: dir}

	// Absent dir: a clean no-op.
	if err := store.RemoveBaseDirIfEmpty(); err != nil {
		t.Errorf("RemoveBaseDirIfEmpty(absent) = %v, want nil", err)
	}

	// A survivor config keeps the dir.
	if err := store.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := store.RemoveBaseDirIfEmpty(); err != nil {
		t.Fatalf("RemoveBaseDirIfEmpty(non-empty) = %v, want nil", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("RemoveBaseDirIfEmpty removed a non-empty config dir: %v", err)
	}

	// After the last config is gone, the empty dir is removed.
	if err := store.Remove("anon"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := store.RemoveBaseDirIfEmpty(); err != nil {
		t.Fatalf("RemoveBaseDirIfEmpty(empty) = %v, want nil", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("RemoveBaseDirIfEmpty left the empty config dir behind")
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
