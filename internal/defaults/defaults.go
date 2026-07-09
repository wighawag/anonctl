// Package defaults owns anonctl's BOX-WIDE, add-time defaults: the values `add`
// falls back to when the operator names no flag, so a bare `sudo anonctl add
// <name>` can land a ready-to-use account. It is deliberately tiny and generic.
//
// Two defaults, sourced differently on purpose:
//
//   - The DEFAULT HOME is a directory-exists CONVENTION, not a config key: if
//     `/etc/anonctl/default-home/` exists, `add` seeds a fresh account's home from
//     it (see internal/seedhome). Its presence IS the switch; there is nothing to
//     configure. Populate it with a plain `sudo cp -r <src>/. /etc/anonctl/default-home/`.
//     DefaultHomeDir + DefaultHomePresent expose that path and probe.
//
//   - The DEFAULT LAN EXEMPTIONS live in `/etc/anonctl/defaults.json`
//     (`{"allowDirect": ["192.168.1.50:11434"]}`), root-owned. `add` applies them
//     when given no `--allow-direct`. They are STORED RAW and re-validated through
//     lanexempt at the CLI boundary exactly like a flag value, so a default can
//     never be a quieter path to a leak than the flag (a public / :53 default is
//     rejected loudly, never silently punched).
//
// The `/etc` read is a SHARED system location, so the base directory is behind a
// configurable lever (Store.BaseDir), exactly as marker.Store / accountconfig.Store
// are: production uses DefaultBaseDir; tests point it at a scratch temp dir. The
// (de)serialization is pure of privilege given a BaseDir, so it is unit-tested with
// no root and no real `/etc` read.
package defaults

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultBaseDir is the real anonctl config root (`/etc/anonctl`), shared with the
// marker dir. The defaults file and the default-home dir both live directly under
// it. Tests override it via Store.BaseDir so no test reads the real `/etc`.
const DefaultBaseDir = "/etc/anonctl"

// defaultsFile is the box-wide defaults record's name under BaseDir.
const defaultsFile = "defaults.json"

// defaultHomeName is the directory-exists default-home convention's name under
// BaseDir. Its PRESENCE (not any config key) switches on `add`-time home seeding.
const defaultHomeName = "default-home"

// Defaults is the box-wide add-time defaults record. It is intentionally minimal:
// only the values `add` reads when a flag is omitted. It carries NO home path (the
// default home is a directory-exists convention, not a configured path).
type Defaults struct {
	// AllowDirect are the default LAN exemptions in their RAW `IP|CIDR[:port]` form,
	// applied by `add` when no `--allow-direct` flag is given. Stored raw and
	// re-validated through lanexempt at the CLI boundary (a default is Parse-gated
	// exactly like a flag), so a default is never a quieter leak path.
	AllowDirect []string `json:"allowDirect,omitempty"`
}

// Store is the filesystem seam for the box-wide defaults, isolating the shared
// `/etc` read behind a configurable base directory (mirrors marker.Store /
// accountconfig.Store). Production builds one with DefaultStore(); tests point
// BaseDir at a scratch dir.
type Store struct {
	// BaseDir is the anonctl config root holding defaults.json and default-home/.
	// Empty means DefaultBaseDir, so a zero Store still targets the real path.
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

// DefaultHomeDir returns the path of the directory-exists default-home template
// (`<BaseDir>/default-home`). It does NOT check existence; use DefaultHomePresent
// for that.
func (s Store) DefaultHomeDir() string {
	return filepath.Join(s.baseDir(), defaultHomeName)
}

// DefaultHomePresent reports whether the default-home template dir exists AND is a
// directory. A non-directory of that name (a stray file) is treated as ABSENT (not
// an error): the convention is "a default-home DIRECTORY is present", so a file by
// that name simply does not switch seeding on.
func (s Store) DefaultHomePresent() bool {
	info, err := os.Stat(s.DefaultHomeDir())
	return err == nil && info.IsDir()
}

// Read loads the box-wide defaults. A MISSING file is a clean empty Defaults (the
// common case: no defaults configured), NOT an error, so `add` need not special-
// case absence. A present-but-corrupt file IS a loud error (never silently treated
// as empty), so a typo in defaults.json fails visibly rather than dropping a
// configured exemption.
func (s Store) Read() (Defaults, error) {
	path := filepath.Join(s.baseDir(), defaultsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Defaults{}, nil
		}
		return Defaults{}, fmt.Errorf("read defaults %q: %w", path, err)
	}
	var d Defaults
	if err := json.Unmarshal(data, &d); err != nil {
		return Defaults{}, fmt.Errorf("invalid defaults JSON %q: %w", path, err)
	}
	return d, nil
}
