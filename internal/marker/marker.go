// Package marker owns anonctl's double-anonymization contract: the versioned JSON
// file at `/etc/anonctl/<account>.json` that sibling tools (anon-pi, netcage)
// read to detect "this account is already kernel-anonymized" and skip re-forcing
// a proxy (the Tor-over-Tor guard, stories 28/29). It is a COORDINATION CLAIM,
// not a live security proof: a consumer that needs certainty runs `anonctl
// verify` or its own leak check. anonctl writes the marker only AFTER `verify`
// passes at setup, and removes it on teardown.
//
// The file is the AUTHORITATIVE, dependency-free signal: a consumer reads
// `/etc/anonctl/<account>.json` with no anonctl binary needed. The `anon` /
// `anon-<name>` name PREFIX is a hint only, never authoritative; `anonctl status
// --json` is a convenience reader of the same truth (it reports Marker, it is not
// a second source of it).
//
// The record is DELIBERATELY credential-free: it carries the share-class the
// consumer needs ("forced + which class") but NO endpoint URL or credentials,
// because the file lives world-readable under `/etc` (dir 0755, file 0644). A
// world-readable marker must never hold a secret; the endpoint URL/creds live in
// the account's own (non-world-readable) config, never here.
//
// The `/etc` write is a SHARED/GLOBAL system location, so the base directory is
// behind a configurable lever (Store.BaseDir): production uses DefaultBaseDir
// (`/etc/anonctl`); tests point it at a scratch temp dir and assert the real
// `/etc/anonctl` is left untouched (the shared-write isolation discipline). The
// (de)serialization + schema-version + write path are all pure of privilege given
// a BaseDir, so they are unit-tested with no root and no real `/etc` write.
package marker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wighawag/anonctl/internal/endpoint"
)

// SchemaVersion is the version of the MARKER contract (the on-disk JSON shape a
// sibling tool parses). It starts at 1 and evolves ADDITIVELY only (new optional
// fields), so a consumer pinned to a version keeps working; a breaking change
// bumps it. It mirrors verify.SchemaVersion / detect-proxy's SchemaVersion
// discipline, and is emitted as `schemaVersion` so a machine consumer can guard
// on the shape it understands before trusting the rest.
const SchemaVersion = 1

// DefaultBaseDir is the real, shared, world-readable location of the markers:
// `/etc/anonctl`, holding one `<account>.json` per forced account. It is the
// dependency-free contract path CONTEXT.md documents. Tests override it via
// Store.BaseDir (a scratch dir) so no test ever writes the real `/etc`.
const DefaultBaseDir = "/etc/anonctl"

const (
	// dirMode is the marker DIRECTORY mode: 0755, world-readable + world-traversable
	// so any sibling tool (running as any UID) can reach the marker files. Only root
	// (anonctl) writes it.
	dirMode os.FileMode = 0o755
	// fileMode is the marker FILE mode: 0644, world-READABLE by design (the whole
	// point is a dependency-free signal any UID can read) but writable only by root.
	// It holds no secret (credential-free by construction), so world-readable is safe.
	fileMode os.FileMode = 0o644
)

// ErrNotFound is returned by Store.Read when there is no marker for the account: a
// clean "not forced" negative, NOT an I/O failure. A missing marker means the
// account is not (claimed to be) kernel-anonymized; a consumer treats it as such.
var ErrNotFound = errors.New("no marker for account (not forced)")

// Marker is the double-anonymization coordination record: the versioned,
// credential-free JSON a sibling tool reads to skip re-forcing an
// already-kernel-anonymized account. It carries exactly the fields the contract
// promises and DELIBERATELY EXCLUDES the endpoint URL/credentials (the file is
// world-readable): a consumer needs only "forced + which share-class", which
// EndpointClass provides.
type Marker struct {
	// SchemaVersion is the contract version this record was written at (see
	// SchemaVersion); a consumer guards on it before trusting the rest.
	SchemaVersion int `json:"schemaVersion"`
	// Account is the forced Unix login account (`anon` / `anon-<name>`).
	Account string `json:"account"`
	// UID is the forced account's numeric UID (as a string, matching provision's
	// AccountStatus.UID), so a consumer can correlate the marker with the running
	// account without a second lookup.
	UID string `json:"uid"`
	// EndpointClass is the endpoint's share-class (tor-shared / socks-peruser): the
	// ONE piece of endpoint detail the consumer needs. It is deliberately NOT the
	// endpoint URL/creds (world-readable file).
	EndpointClass endpoint.ShareClass `json:"endpointClass"`
	// CreatedAt is when the marker was written (RFC3339, UTC): the moment `verify`
	// passed and anonctl claimed the account forced.
	CreatedAt string `json:"createdAt"`
	// AnonctlVersion is the anonctl version that wrote the marker, so a consumer /
	// operator can tell which build made the claim.
	AnonctlVersion string `json:"anonctlVersion"`
}

// New builds a Marker for an account at the current SchemaVersion, stamping
// CreatedAt (UTC, RFC3339) from now. It is the single constructor so no caller
// spells the schema version or the timestamp format inline. The endpoint URL/creds
// are intentionally NOT parameters: the marker is credential-free by construction.
func New(account, uid string, class endpoint.ShareClass, anonctlVersion string, now time.Time) Marker {
	return Marker{
		SchemaVersion:  SchemaVersion,
		Account:        account,
		UID:            uid,
		EndpointClass:  class,
		CreatedAt:      now.UTC().Format(time.RFC3339),
		AnonctlVersion: anonctlVersion,
	}
}

// Marshal renders the marker as the indented JSON written to disk (the wire
// contract). It is separated from Write so the (de)serialization round-trip is
// unit-testable without any filesystem.
func (m Marker) Marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// Parse decodes a marker from its JSON bytes, rejecting a version the code does
// not understand. An UNKNOWN (higher) schema version is refused loudly rather than
// silently mis-read: a consumer parsing a future marker with this code learns it
// cannot trust the shape, instead of acting on partially-understood fields.
func Parse(data []byte) (Marker, error) {
	var m Marker
	if err := json.Unmarshal(data, &m); err != nil {
		return Marker{}, fmt.Errorf("invalid marker JSON: %w", err)
	}
	if m.SchemaVersion == 0 {
		return Marker{}, errors.New("marker has no schemaVersion (not an anonctl marker)")
	}
	if m.SchemaVersion > SchemaVersion {
		return Marker{}, fmt.Errorf("marker schemaVersion %d is newer than this anonctl understands (%d); upgrade anonctl", m.SchemaVersion, SchemaVersion)
	}
	return m, nil
}

// Store is the filesystem seam for the markers, isolating the SHARED `/etc` write
// behind a configurable base directory. Production builds one with DefaultStore()
// (BaseDir == DefaultBaseDir == `/etc/anonctl`); tests build one pointing at a
// scratch temp dir so a real `/etc` write never happens and the real location is
// asserted untouched.
type Store struct {
	// BaseDir is the directory holding the `<account>.json` markers. Empty means
	// DefaultBaseDir, so a zero Store is still usable and points at the real path.
	BaseDir string
}

// DefaultStore returns the Store pointing at the real DefaultBaseDir (`/etc/anonctl`).
func DefaultStore() Store { return Store{BaseDir: DefaultBaseDir} }

// baseDir resolves the effective base directory (BaseDir, or DefaultBaseDir when
// empty), so a zero Store still targets the real path.
func (s Store) baseDir() string {
	if s.BaseDir == "" {
		return DefaultBaseDir
	}
	return s.BaseDir
}

// Path returns the marker file path for an account: `<BaseDir>/<account>.json`.
// The account name is validated (no path separators / traversal) so a crafted
// account name can never escape BaseDir and clobber an arbitrary file.
func (s Store) Path(account string) (string, error) {
	if err := validAccount(account); err != nil {
		return "", err
	}
	return filepath.Join(s.baseDir(), account+".json"), nil
}

// Write persists the marker for its account, creating BaseDir if needed (dir
// 0755, file 0644 so the marker is world-readable but root-only-writable). It is
// the WRITE side of the contract; callers must gate it on `verify` passing (the
// marker is a claim written only after the account is proven forced). Write itself
// does not run verify: the gate lives at the call site (WriteVerified) so this
// stays a pure "persist a record" operation the unit tests can exercise directly.
func (s Store) Write(m Marker) error {
	path, err := s.Path(m.Account)
	if err != nil {
		return err
	}
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.baseDir(), dirMode); err != nil {
		return fmt.Errorf("create marker dir %q: %w", s.baseDir(), err)
	}
	if err := os.WriteFile(path, append(data, '\n'), fileMode); err != nil {
		return fmt.Errorf("write marker %q: %w", path, err)
	}
	// WriteFile respects umask, so re-assert the intended world-readable mode: the
	// marker is only useful if any UID can read it.
	if err := os.Chmod(path, fileMode); err != nil {
		return fmt.Errorf("chmod marker %q: %w", path, err)
	}
	return nil
}

// Read loads the marker for an account, returning ErrNotFound (a clean "not
// forced") when there is no marker file, so a caller/CI can branch on absence
// without treating it as an error. A present-but-corrupt marker is a real error
// (it is not silently treated as absent).
func (s Store) Read(account string) (Marker, error) {
	path, err := s.Path(account)
	if err != nil {
		return Marker{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Marker{}, ErrNotFound
		}
		return Marker{}, fmt.Errorf("read marker %q: %w", path, err)
	}
	return Parse(data)
}

// Remove deletes the marker for an account (the teardown side: `anonctl rm`
// removes the claim). A missing marker is a clean no-op, NOT an error, so rm is
// idempotent and a torn-down account leaves no stale claim behind.
func (s Store) Remove(account string) error {
	path, err := s.Path(account)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove marker %q: %w", path, err)
	}
	return nil
}

// WriteVerified is the WRITE-AFTER-VERIFY gate: it persists the marker ONLY when
// verifyPassed is true, so the marker is a claim written strictly after `anonctl
// verify` proves the account forced (the marker is a coordination claim, not a
// live proof, and must never be written for an UNVERIFIED account). A false
// verifyPassed is a loud refusal (ErrVerifyNotPassed), never a silent skip, so a
// caller cannot accidentally claim an account it did not prove.
func (s Store) WriteVerified(m Marker, verifyPassed bool) error {
	if !verifyPassed {
		return ErrVerifyNotPassed
	}
	return s.Write(m)
}

// ErrVerifyNotPassed is returned by WriteVerified when asked to write a marker for
// an account whose `verify` did not pass. The marker is a claim of proven forcing;
// writing it without a passing verify would be a false claim, so it is refused.
var ErrVerifyNotPassed = errors.New("refusing to write marker: verify did not pass (the marker is written only after verify proves the account forced)")

// validAccount rejects an account name that could escape BaseDir. The marker file
// is `<BaseDir>/<account>.json`; a name with a path separator or `..` could
// otherwise write outside `/etc/anonctl`. anonctl's own account names (`anon` /
// `anon-<name>`) never contain these, so this only trips on a malformed caller.
func validAccount(account string) error {
	if strings.TrimSpace(account) == "" {
		return errors.New("empty account name")
	}
	if strings.ContainsAny(account, "/\\") || account == "." || account == ".." || strings.Contains(account, "..") {
		return fmt.Errorf("invalid account name %q for a marker path (no path separators or traversal)", account)
	}
	return nil
}
