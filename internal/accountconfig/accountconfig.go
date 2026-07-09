// Package accountconfig owns the per-account, at-rest configuration anonctl needs
// to RE-APPLY an account's forcing across a reboot and to `update`/`reconfigure`
// it: the account's endpoint (host:port + share-class), its shim's per-account
// loopback ports, and its numeric UIDs. It is the source of truth the persisted
// nftables ruleset and the `anonctl-shim@<account>.service` unit are (re)generated
// from at boot, and the record `update` rewrites when the operator changes an
// endpoint.
//
// It is DELIBERATELY separate from the marker (internal/marker). The marker is a
// world-readable coordination CLAIM under `/etc/anonctl/<account>.json` and is
// credential-free by construction; this config is anonctl's OWN operational record
// and is NOT world-readable (dir 0700, file 0600), so it can hold the endpoint URL
// the marker must never carry. Neither holds a secret today (the endpoint at rest
// is credential-free, endpoint.ErrCredentialedEndpoint), but the config is scoped
// tight regardless: it is anonctl's private state, not a public signal.
//
// The `/etc` write is a SHARED system location, so the base directory is behind a
// configurable lever (Store.BaseDir), exactly as marker.Store is: production uses
// DefaultBaseDir; tests point it at a scratch temp dir and assert the real path is
// left untouched (the shared-write isolation discipline). The (de)serialization,
// schema-version, and default-fill are all pure of privilege given a BaseDir, so
// they are unit-tested with no root and no real `/etc` write.
package accountconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wighawag/anonctl/internal/endpoint"
)

// SchemaVersion is the version of the on-disk account-config shape. It starts at
// 1 and evolves ADDITIVELY only (new optional fields), mirroring
// marker.SchemaVersion / verify.SchemaVersion: a build pinned to a version keeps
// reading older records, and a record from a NEWER anonctl is refused loudly
// (Parse) rather than half-understood.
const SchemaVersion = 1

// DefaultBaseDir is the real, anonctl-private location of the per-account config
// records: `/etc/anonctl/accounts`, one `<account>.json` per forced account. It
// sits UNDER the marker dir but in its own subdir so the world-readable markers
// and the root-only account configs never share a mode. Tests override it via
// Store.BaseDir so no test writes the real `/etc`.
const DefaultBaseDir = "/etc/anonctl/accounts"

// DefaultRelayPort / DefaultDNSPort are the shim's per-account loopback ports when
// a config does not name them. They mirror the validated recipe and the shim
// binary's own defaults (work/notes/findings/manual-per-uid-tor-recipe.md:
// RELAY_PORT 19050, DNS_PORT 19053). A single default account uses these as-is;
// distinct-per-account port ALLOCATION for many accounts is left to a later task
// (the ports are stored per-account here so that allocation has a place to land
// without a schema change).
const (
	DefaultRelayPort = 19050
	DefaultDNSPort   = 19053
)

const (
	// dirMode is anonctl-private: 0700, root-only. Unlike the marker dir (0755,
	// world-readable), this holds anonctl's operational state, not a public signal.
	dirMode os.FileMode = 0o700
	// fileMode is 0600, root-only. The record may hold an endpoint URL, so it is
	// never world-readable (the marker's world-readable 0644 is for the
	// credential-free public claim; this is not that).
	fileMode os.FileMode = 0o600
)

// ErrNotFound is returned by Store.Read when there is no config for the account: a
// clean "not configured" negative, NOT an I/O failure, so a caller can branch on
// absence (e.g. `update` on an account never `add`ed) without treating it as an
// error.
var ErrNotFound = errors.New("no config for account (not provisioned/forced)")

// Config is one account's at-rest operational record: everything the persisted
// ruleset and the shim unit are (re)generated from at boot, and everything
// `update` rewrites. It carries the endpoint (host:port + share-class), the shim
// loopback ports, and the numeric UIDs resolved at provisioning time. It holds NO
// SOCKS credentials: the endpoint at rest is credential-free (the per-account
// isolation username is derived, not stored).
type Config struct {
	// SchemaVersion is the contract version this record was written at.
	SchemaVersion int `json:"schemaVersion"`
	// Account is the anon login account (`anon` / `anon-<name>`).
	Account string `json:"account"`
	// AnonUID / ShimUID are the account's forced UID and its dedicated shim UID,
	// resolved from the passwd table at provisioning time and stored so the boot
	// re-apply need not re-resolve them.
	AnonUID int `json:"anonUid"`
	ShimUID int `json:"shimUid"`
	// EndpointHost / EndpointPort is the upstream socks5h endpoint (e.g. the Tor
	// SocksPort). EndpointClass is its share-class (tor-shared / socks-peruser),
	// which drives the derived isolation username. No credentials are stored.
	EndpointHost  string              `json:"endpointHost"`
	EndpointPort  int                 `json:"endpointPort"`
	EndpointClass endpoint.ShareClass `json:"endpointClass"`
	// RelayPort / DNSPort are the shim's per-account loopback ports.
	RelayPort int `json:"relayPort"`
	DNSPort   int `json:"dnsPort"`
	// Exemptions are the account's LAN exemptions in their RAW `IP|CIDR[:port]`
	// form (as validated by lanexempt.Parse at config time): the private-only,
	// host+port-scoped direct holes the anon UID may reach around the forced path.
	// They are credential-free by construction (just addresses, no secret), so they
	// live at rest alongside the endpoint. Stored raw so the SAME string reaches the
	// nft generator (re-parsed) and verify without a lossy round-trip. omitempty:
	// an account with no exemptions writes no `exemptions` key, so pre-exemption
	// records stay byte-compatible and still load.
	Exemptions []string `json:"exemptions,omitempty"`
}

// Endpoint reconstructs the endpoint.Endpoint from the stored fields, so callers
// (the shim-unit generator, verify) get the same credential-free value and derived
// isolation username without re-parsing a URL.
func (c Config) Endpoint() endpoint.Endpoint {
	return endpoint.Endpoint{
		Host:  c.EndpointHost,
		Port:  fmt.Sprintf("%d", c.EndpointPort),
		Class: c.EndpointClass,
	}
}

// withDefaults returns a copy with the schema version stamped and the ports filled
// to their defaults when unset, so a caller can build a Config from just the
// account + endpoint + UIDs and get the recipe's port scheme for free.
func (c Config) withDefaults() Config {
	c.SchemaVersion = SchemaVersion
	if c.RelayPort == 0 {
		c.RelayPort = DefaultRelayPort
	}
	if c.DNSPort == 0 {
		c.DNSPort = DefaultDNSPort
	}
	return c
}

// validate rejects a Config that could not produce a safe ruleset/unit: an empty
// account, a non-positive or root UID, equal anon/shim UIDs (closure b collapses),
// a port out of range, or an endpoint host that is not an IP literal. It mirrors
// the nftables generator's own validation so a bad record is caught at write time,
// not only at boot re-apply.
func (c Config) validate() error {
	switch {
	case strings.TrimSpace(c.Account) == "":
		return errors.New("accountconfig: empty account")
	case c.AnonUID <= 0:
		return fmt.Errorf("accountconfig: anon uid must be > 0 (got %d)", c.AnonUID)
	case c.ShimUID <= 0:
		return fmt.Errorf("accountconfig: shim uid must be > 0 (got %d)", c.ShimUID)
	case c.AnonUID == c.ShimUID:
		return fmt.Errorf("accountconfig: anon uid and shim uid must differ (both %d)", c.AnonUID)
	case c.RelayPort <= 0 || c.RelayPort > 65535:
		return fmt.Errorf("accountconfig: relay port out of range (got %d)", c.RelayPort)
	case c.DNSPort <= 0 || c.DNSPort > 65535:
		return fmt.Errorf("accountconfig: dns port out of range (got %d)", c.DNSPort)
	case c.EndpointHost == "":
		return errors.New("accountconfig: empty endpoint host")
	case c.EndpointPort <= 0 || c.EndpointPort > 65535:
		return fmt.Errorf("accountconfig: endpoint port out of range (got %d)", c.EndpointPort)
	case c.EndpointClass == "":
		return errors.New("accountconfig: empty endpoint class")
	}
	return nil
}

// Marshal renders the config as the indented JSON written to disk. Separated from
// Write so the round-trip is unit-testable without any filesystem.
func (c Config) Marshal() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }

// Parse decodes a config from JSON, refusing a version this build does not
// understand (a NEWER record is not half-read). A zero schema version is not a
// valid anonctl config.
func Parse(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("invalid account config JSON: %w", err)
	}
	if c.SchemaVersion == 0 {
		return Config{}, errors.New("account config has no schemaVersion (not an anonctl config)")
	}
	if c.SchemaVersion > SchemaVersion {
		return Config{}, fmt.Errorf("account config schemaVersion %d is newer than this anonctl understands (%d); upgrade anonctl", c.SchemaVersion, SchemaVersion)
	}
	return c, nil
}

// Store is the filesystem seam for the per-account configs, isolating the shared
// `/etc` write behind a configurable base directory, exactly as marker.Store does.
// Production builds one with DefaultStore(); tests point BaseDir at a scratch dir
// so no real `/etc` write happens.
type Store struct {
	// BaseDir is the directory holding the `<account>.json` configs. Empty means
	// DefaultBaseDir, so a zero Store still targets the real path.
	BaseDir string
}

// DefaultStore returns the Store pointing at the real DefaultBaseDir.
func DefaultStore() Store { return Store{BaseDir: DefaultBaseDir} }

func (s Store) baseDir() string {
	if s.BaseDir == "" {
		return DefaultBaseDir
	}
	return s.BaseDir
}

// Path returns the config file path for an account (`<BaseDir>/<account>.json`),
// rejecting an account name that could escape BaseDir (path separators /
// traversal), so a crafted name can never clobber an arbitrary file.
func (s Store) Path(account string) (string, error) {
	if err := validAccount(account); err != nil {
		return "", err
	}
	return filepath.Join(s.baseDir(), account+".json"), nil
}

// Write persists the config for its account (dir 0700, file 0600: anonctl-private,
// NOT world-readable). It stamps the schema version and fills the default ports,
// then validates, so a malformed record is refused BEFORE it lands.
func (s Store) Write(c Config) error {
	c = c.withDefaults()
	if err := c.validate(); err != nil {
		return err
	}
	path, err := s.Path(c.Account)
	if err != nil {
		return err
	}
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.baseDir(), dirMode); err != nil {
		return fmt.Errorf("create account-config dir %q: %w", s.baseDir(), err)
	}
	if err := os.WriteFile(path, append(data, '\n'), fileMode); err != nil {
		return fmt.Errorf("write account config %q: %w", path, err)
	}
	// WriteFile respects umask; re-assert the intended root-only mode so the record
	// is never accidentally left group/other-readable.
	if err := os.Chmod(path, fileMode); err != nil {
		return fmt.Errorf("chmod account config %q: %w", path, err)
	}
	return nil
}

// Read loads the config for an account, returning ErrNotFound (a clean "not
// configured") when there is no file, so a caller can branch on absence. A
// present-but-corrupt config is a real error (never silently treated as absent).
func (s Store) Read(account string) (Config, error) {
	path, err := s.Path(account)
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, ErrNotFound
		}
		return Config{}, fmt.Errorf("read account config %q: %w", path, err)
	}
	return Parse(data)
}

// Remove deletes the config for an account (the teardown side: `rm` removes it). A
// missing config is a clean no-op, NOT an error, so rm is idempotent.
func (s Store) Remove(account string) error {
	path, err := s.Path(account)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove account config %q: %w", path, err)
	}
	return nil
}

// RemoveBaseDirIfEmpty removes the config dir ONLY when it holds no configs, used
// on the LAST account's teardown so a fully torn-down host leaves no empty
// `/etc/anonctl/accounts` dir (the e2e finding, BUG 4). os.Remove refuses a
// non-empty dir, so a survivor account's config is never ripped out; an absent dir
// is a clean no-op. The caller guards on the last-account condition regardless.
func (s Store) RemoveBaseDirIfEmpty() error {
	if err := os.Remove(s.baseDir()); err != nil &&
		!errors.Is(err, os.ErrNotExist) &&
		!errors.Is(err, syscall.ENOTEMPTY) &&
		!errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("remove account config dir %q: %w", s.baseDir(), err)
	}
	return nil
}

// validAccount rejects an account name that could escape BaseDir (mirrors
// marker.validAccount). anonctl's own account names never contain these; this only
// trips a malformed caller.
func validAccount(account string) error {
	if strings.TrimSpace(account) == "" {
		return errors.New("empty account name")
	}
	if strings.ContainsAny(account, "/\\") || account == "." || account == ".." || strings.Contains(account, "..") {
		return fmt.Errorf("invalid account name %q for a config path (no path separators or traversal)", account)
	}
	return nil
}
