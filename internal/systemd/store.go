package systemd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
)

const (
	// unitMode is the systemd unit-file mode: 0644, world-readable (systemd reads it;
	// it carries no secret) but root-only-writable. Used for both the @-template shim
	// unit and anonctl's early-boot loader unit.
	unitMode os.FileMode = 0o644
	// envMode is 0600: the per-account env file carries the endpoint address (no
	// secret, but anonctl-private), so it is NOT world-readable.
	envMode os.FileMode = 0o600
	// ruleMode is 0600: the per-account nft rule file is anonctl-private state.
	ruleMode os.FileMode = 0o600
	// dirModePrivate is 0700 for the anonctl-private env/rules dirs.
	dirModePrivate os.FileMode = 0o700
	// dirModePublic is 0755 for the systemd unit dir (world-traversable, as systemd
	// expects).
	dirModePublic os.FileMode = 0o755
)

// Store is the filesystem seam for anonctl's persisted systemd + nftables
// artifacts, isolating every SHARED write behind a configurable base dir per
// artifact class (mirrors marker.Store / accountconfig.Store). Production builds
// one with DefaultStore(); tests point each dir at a scratch temp dir so a real
// /etc write never happens and the real locations are asserted untouched.
type Store struct {
	// UnitDir holds the @-template shim unit and anonctl's early-boot loader unit
	// (anonctl-nftables.service); DefaultUnitDir when empty.
	UnitDir string
	// EnvDir holds the per-account EnvironmentFiles (`<account>.env`); DefaultEnvDir
	// when empty.
	EnvDir string
	// RulesDir holds the persisted per-account nft rule files (`<account>.nft`) the
	// drop-in loads at boot; DefaultRulesDir when empty.
	RulesDir string
	// LegacyUnitDir is the pre-0.4 unit dir that MigrateLegacyUnits sweeps;
	// LegacyUnitDir (the package const) when empty. Behind a field so the migration is
	// testable against a scratch dir instead of the host's real /etc/systemd/system.
	LegacyUnitDir string
}

// UnitDirEnv lets an operator repoint the unit dir on a host whose layout does not
// suit DefaultUnitDir. It is a SAFETY VALVE, not the intended path: the default is
// chosen so that neither Debian nor NixOS needs it.
const UnitDirEnv = "ANONCTL_UNIT_DIR"

// knownUnitSearchDirs are the directories systemd actually reads system units from.
// An override outside this set is almost certainly a mistake that would produce
// forcing which never loads at boot, so it is WARNED about loudly rather than
// accepted in silence. (Being absolute is not sufficient: /opt/anonctl/units is a
// perfectly good absolute path that systemd will never look in.)
var knownUnitSearchDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// DefaultStore returns the Store pointing at the real default locations, honouring
// the UnitDirEnv override when it names an absolute path.
//
// A malformed or suspicious override is never silently swallowed: a non-absolute
// value is REFUSED with a warning (a relative unit dir is in no search path), and an
// absolute value outside systemd's known search dirs is honoured but WARNED about,
// because the operator has asked for something that will not be read at boot.
// Silently ignoring either would leave the operator believing units went somewhere
// they did not.
func DefaultStore() Store {
	unitDir := DefaultUnitDir
	if override := strings.TrimSpace(os.Getenv(UnitDirEnv)); override != "" {
		switch {
		case !filepath.IsAbs(override):
			fmt.Fprintf(os.Stderr, "anonctl: ignoring %s=%q: it must be an ABSOLUTE path (a relative unit dir is in no systemd search path); using %s\n", UnitDirEnv, override, unitDir)
		default:
			unitDir = filepath.Clean(override)
			if !isKnownUnitSearchDir(unitDir) {
				fmt.Fprintf(os.Stderr, "anonctl: WARNING: %s=%q is not one of systemd's known unit search directories (%s). Units written there may never be loaded at boot, which would leave accounts unforced after a reboot. Verify with: systemctl show --property=UnitPath\n", UnitDirEnv, unitDir, strings.Join(knownUnitSearchDirs, ", "))
			}
		}
	}
	return Store{UnitDir: unitDir, EnvDir: DefaultEnvDir, RulesDir: DefaultRulesDir, LegacyUnitDir: LegacyUnitDir}
}

// isKnownUnitSearchDir reports whether dir is one of systemd's standard system unit
// search directories.
func isKnownUnitSearchDir(dir string) bool {
	for _, known := range knownUnitSearchDirs {
		if filepath.Clean(known) == dir {
			return true
		}
	}
	return false
}

func (s Store) unitDir() string   { return orDefault(s.UnitDir, DefaultUnitDir) }
func (s Store) envDir() string    { return orDefault(s.EnvDir, DefaultEnvDir) }
func (s Store) rulesDir() string  { return orDefault(s.RulesDir, DefaultRulesDir) }
func (s Store) legacyDir() string { return orDefault(s.LegacyUnitDir, LegacyUnitDir) }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// InstallCommon writes the account-AGNOSTIC persisted artifacts: the @-template
// shim unit file and anonctl's OWN early-boot nftables loader unit
// (`anonctl-nftables.service`). It is idempotent (a plain overwrite of anonctl's
// own files) and touches ONLY anonctl's files, never the host's nftables.service or
// its /etc/nftables.conf. The RulesGlob in the loader is pinned to this Store's
// rules dir so the generated loader and the actual rule-file writes agree.
func (s Store) InstallCommon(tp TemplateParams, lp LoaderParams) error {
	if tp.EnvDir == "" {
		tp.EnvDir = s.envDir()
	}
	if lp.RulesGlob == "" {
		lp.RulesGlob = filepath.Join(s.rulesDir(), "*.nft")
	}
	// Generate BOTH units before writing EITHER, so an unresolved binary path fails
	// the whole install with nothing half-written.
	templateText, err := TemplateUnit(tp)
	if err != nil {
		return err
	}
	loaderText, err := LoaderUnit(lp)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.unitDir(), dirModePublic); err != nil {
		return fmt.Errorf("systemd: create unit dir %q: %w", s.unitDir(), err)
	}
	unitPath := filepath.Join(s.unitDir(), UnitName)
	if err := writeFileMode(unitPath, []byte(templateText), unitMode); err != nil {
		return fmt.Errorf("systemd: write template unit: %w", err)
	}
	loaderPath := filepath.Join(s.unitDir(), LoaderUnitName)
	if err := writeFileMode(loaderPath, []byte(loaderText), unitMode); err != nil {
		// Do not leave the shim template behind without the loader. The loader is what
		// installs the standing baseline default-deny at boot, so "template present, loader
		// absent" is the fail-OPEN combination: a shim would be wired up with no resting
		// deny behind it. Both units land, or neither does.
		_ = os.Remove(unitPath)
		return fmt.Errorf("systemd: write loader unit: %w", err)
	}
	return nil
}

// EnableUnit wires a unit to start at boot by creating anonctl's OWN enablement
// symlink `<UnitDir>/<target>.wants/<linkName>` -> `<UnitDir>/<unitFile>`, which is
// exactly the artifact `systemctl enable` would have produced, in a directory
// anonctl can actually write.
//
// It does NOT shell out to `systemctl enable`, because that command always writes
// into the CONFIG dir for the scope (/etc/systemd/system) regardless of where the
// unit file lives, and that dir is a read-only Nix store symlink on NixOS. systemd
// reads `<target>.wants/` from EVERY directory in the unit load path, so this
// symlink is a genuine, boot-effective Wants= dependency (systemd.unit(5)).
//
// For the @-template, linkName is the INSTANCE (`anonctl-shim@work.service`) while
// unitFile is the TEMPLATE (`anonctl-shim@.service`) -- the same instance-to-template
// mapping systemctl uses. The symlink target must itself live in a unit search path,
// which UnitDir does; it is written ABSOLUTE so it stays valid regardless of how the
// .wants dir is reached. Idempotent: an existing link is replaced.
//
// CAVEAT worth knowing when reading a host by hand: because the symlink is not in
// the config dir, `systemctl is-enabled` reports "disabled" for these units even
// though they are genuinely wired to start at boot. Use IsUnitEnabled, or ask
// systemd for the truth with `systemctl show <target> --property=Wants`.
func (s Store) EnableUnit(unitFile, linkName, target string) error {
	wantsDir := filepath.Join(s.unitDir(), target+".wants")
	if err := os.MkdirAll(wantsDir, dirModePublic); err != nil {
		return fmt.Errorf("systemd: create %q: %w", wantsDir, err)
	}
	linkPath := filepath.Join(wantsDir, linkName)
	targetPath := filepath.Join(s.unitDir(), unitFile)
	if err := os.Remove(linkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("systemd: replace enablement symlink %q: %w", linkPath, err)
	}
	if err := os.Symlink(targetPath, linkPath); err != nil {
		return fmt.Errorf("systemd: create enablement symlink %q -> %q: %w", linkPath, targetPath, err)
	}
	return nil
}

// DisableUnit removes anonctl's enablement symlink, the counterpart of EnableUnit.
// A missing link is a clean no-op (idempotent teardown). The `.wants` dir itself is
// removed only when it is empty, so disabling one account never de-enables another.
func (s Store) DisableUnit(linkName, target string) error {
	wantsDir := filepath.Join(s.unitDir(), target+".wants")
	if err := os.Remove(filepath.Join(wantsDir, linkName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("systemd: remove enablement symlink for %q: %w", linkName, err)
	}
	if err := os.Remove(wantsDir); err != nil && !errors.Is(err, os.ErrNotExist) && !isNotEmpty(err) {
		return fmt.Errorf("systemd: remove %q: %w", wantsDir, err)
	}
	return nil
}

// IsUnitEnabled reports whether anonctl's enablement symlink for linkName exists
// AND points at the unit file in THIS Store's unit dir. It is the honest local
// answer to "will this come back after a reboot", and exists because
// `systemctl is-enabled` cannot see a symlink outside the config dir and would
// report a false "disabled". A link pointing somewhere else counts as NOT enabled:
// that is a stale or foreign definition, not anonctl's.
func (s Store) IsUnitEnabled(unitFile, linkName, target string) (bool, error) {
	linkPath := filepath.Join(s.unitDir(), target+".wants", linkName)
	dest, err := os.Readlink(linkPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("systemd: read enablement symlink %q: %w", linkPath, err)
	}
	if !filepath.IsAbs(dest) {
		dest = filepath.Join(filepath.Dir(linkPath), dest)
	}
	return filepath.Clean(dest) == filepath.Clean(filepath.Join(s.unitDir(), unitFile)), nil
}

// MigrateLegacyUnits removes anonctl's units and enablement symlinks from the
// pre-0.4 unit dir (/etc/systemd/system), returning the paths it removed.
//
// This is MANDATORY, not cosmetic. /etc/systemd/system OUTRANKS the new unit dir in
// systemd's load path, so a leftover copy there SHADOWS the newly installed one:
// the operator would upgrade, see success, and keep running the OLD unit -- which on
// a migrated host is precisely the unit whose hard-coded /usr/sbin/nft fails
// fail-OPEN at boot. Leaving two definitions of the same unit is the one outcome
// this must never produce.
//
// It MIGRATES rather than merely deletes. Every account it finds ENABLED in the
// legacy dir is re-enabled in the current unit dir BEFORE its legacy symlink is
// removed. That matters on a multi-account host: the legacy sweep necessarily
// matches every `anonctl-shim@*.service` link, but the `add` that triggered it only
// re-creates the link for the ONE account being added, so a delete-only sweep would
// silently de-enable every OTHER account. Their shims keep running, so nothing looks
// wrong until the next reboot, when they never come back. Re-enable-then-remove also
// means an interrupted migration never leaves an account enabled in NEITHER dir.
//
// It is a no-op when the legacy dir IS the current unit dir, when the legacy dir does
// not exist, or when it holds no anonctl files (the fresh-install and NixOS cases).
// If anonctl files ARE present but cannot be removed, it fails LOUDLY rather than
// leaving a shadowing copy behind.
func (s Store) MigrateLegacyUnits() ([]string, error) {
	legacy := s.legacyDir()
	same, err := sameDir(legacy, s.unitDir())
	if err != nil {
		return nil, err
	}
	if same {
		return nil, nil
	}
	unitFiles, links, err := s.legacyArtifacts(legacy)
	if err != nil {
		return nil, err
	}
	removed := make([]string, 0, len(unitFiles)+len(links))
	// Enablement symlinks first: adopt each into the current unit dir, THEN drop the
	// legacy one, so no account is ever enabled in neither place.
	for _, link := range links {
		linkName := filepath.Base(link)
		// The target is the `.wants` dir's name minus the suffix, so an adopted link keeps
		// the exact target it was enabled for.
		target := strings.TrimSuffix(filepath.Base(filepath.Dir(link)), ".wants")
		unitFile := UnitName
		if linkName == LoaderUnitName {
			unitFile = LoaderUnitName
		}
		if err := s.EnableUnit(unitFile, linkName, target); err != nil {
			return removed, fmt.Errorf("systemd: adopt legacy enablement %q into %s: %w", link, s.unitDir(), err)
		}
		if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("systemd: remove shadowing legacy enablement symlink %q: %w", link, err)
		}
		removed = append(removed, link)
	}
	// The unit FILES last: they are what actually shadows, and by now every enablement
	// they carried has been adopted.
	for _, path := range unitFiles {
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return removed, fmt.Errorf("systemd: remove shadowing legacy unit file %q (it would override the unit in %s): %w", path, s.unitDir(), err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}

// legacyArtifacts lists anonctl-owned files in the legacy unit dir, split into the
// unit FILES and the enablement SYMLINKS, because the two are handled differently
// (a symlink is adopted before removal; a file is just removed). The shim sweep is a
// glob because every per-account INSTANCE has its own link.
func (s Store) legacyArtifacts(legacy string) (unitFiles, links []string, err error) {
	for _, name := range []string{UnitName, LoaderUnitName} {
		path := filepath.Join(legacy, name)
		if _, serr := os.Lstat(path); serr == nil {
			unitFiles = append(unitFiles, path)
		} else if !errors.Is(serr, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("systemd: inspect legacy unit %q: %w", path, serr)
		}
	}
	for _, pattern := range []string{
		filepath.Join(legacy, ShimWantedBy+".wants", "anonctl-shim@*.service"),
		filepath.Join(legacy, LoaderWantedBy+".wants", LoaderUnitName),
	} {
		matches, gerr := filepath.Glob(pattern)
		if gerr != nil {
			return nil, nil, fmt.Errorf("systemd: scan legacy enablement symlinks %q: %w", pattern, gerr)
		}
		links = append(links, matches...)
	}
	return unitFiles, links, nil
}

// sameDir reports whether two paths are the same directory, resolving symlinks. A
// plain string compare is not enough: if the legacy dir reached the unit dir through
// a symlinked component, the sweep would delete the units just written.
func sameDir(a, b string) (bool, error) {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true, nil
	}
	fa, err := os.Stat(a)
	if err != nil {
		return false, nil // a missing legacy dir is simply nothing to migrate
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, nil
	}
	return os.SameFile(fa, fb), nil
}

// RemoveCommon tears down the SHARED, account-agnostic artifacts InstallCommon
// wrote: the @-template shim unit and anonctl's early-boot loader unit, plus the
// (now empty) anonctl-private env/rules dirs this Store owns. It is used on the
// LAST account's teardown (the caller guards on HasForcedAccounts) so a fully
// torn-down host leaves no anonctl residue (the e2e finding, BUG 4). It is
// idempotent: a missing unit file is a clean no-op. It removes the env/rules dirs
// ONLY when they are empty (os.Remove refuses a non-empty dir), so it can never
// rip out a survivor account's files even if called out of turn.
func (s Store) RemoveCommon() error {
	// Drop the loader's enablement symlink before its unit file, so a torn-down host
	// never keeps a .wants symlink pointing at a unit that no longer exists.
	if err := s.DisableUnit(LoaderUnitName, LoaderWantedBy); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(s.unitDir(), UnitName),
		filepath.Join(s.unitDir(), LoaderUnitName),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("systemd: remove %q: %w", path, err)
		}
	}
	// The shim's `.wants` dir is removed too, but only when empty (DisableUnit's own
	// rule), so a survivor account's enablement is never ripped out.
	shimWants := filepath.Join(s.unitDir(), ShimWantedBy+".wants")
	if err := os.Remove(shimWants); err != nil && !errors.Is(err, os.ErrNotExist) && !isNotEmpty(err) {
		return fmt.Errorf("systemd: remove %q: %w", shimWants, err)
	}
	// Remove the anonctl-private dirs ONLY when empty: os.Remove on a non-empty dir
	// fails (which we tolerate), so a survivor's files are never ripped out. An absent
	// dir is a clean no-op.
	for _, dir := range []string{s.envDir(), s.rulesDir()} {
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) && !isNotEmpty(err) {
			return fmt.Errorf("systemd: remove dir %q: %w", dir, err)
		}
	}
	return nil
}

// isNotEmpty reports whether err is the "directory not empty" error os.Remove
// returns for a non-empty dir, which RemoveCommon deliberately tolerates (it must
// never delete a survivor account's files).
func isNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST)
}

// WriteAccount persists ONE account's per-account artifacts: its EnvironmentFile
// (from the config, parameterising the template instance), its standing baseline
// default-deny rule file (`<account>.baseline.nft`), and its forcing nft rule file
// (`<account>.nft`, the passed ruleset text). All three are anonctl-private (0600),
// and the two `.nft` files are loaded at boot by the loader unit. The baseline is
// generated here from the account's anon UID so it lands as its OWN always-loaded
// artifact, SEPARATE from the forcing table: forcing-absent still means DROPPED. It
// validates the account name (no traversal) before any write.
func (s Store) WriteAccount(c accountconfig.Config, ruleset string) error {
	if err := validAccount(c.Account); err != nil {
		return err
	}
	// Parse the account's persisted raw exemptions so the baseline RETURNs them (the
	// forcing chain accepts the same destinations; the baseline must not drop the
	// un-redirected LAN flow before that accept). A raw value that no longer parses is
	// skipped (it was validated at config time; a corrupt record must not fail the
	// persist), mirroring verify's tolerant re-parse.
	baselineExempt := make([]lanexempt.Exempt, 0, len(c.Exemptions))
	for _, raw := range c.Exemptions {
		e, perr := lanexempt.Parse(raw)
		if perr != nil {
			continue
		}
		baselineExempt = append(baselineExempt, e)
	}
	baseline, err := nftables.GenerateBaseline(c.Account, c.AnonUID, baselineExempt)
	if err != nil {
		return fmt.Errorf("systemd: generate baseline default-deny: %w", err)
	}
	if err := os.MkdirAll(s.envDir(), dirModePrivate); err != nil {
		return fmt.Errorf("systemd: create env dir %q: %w", s.envDir(), err)
	}
	envPath := filepath.Join(s.envDir(), c.Account+".env")
	if err := writeFileMode(envPath, []byte(EnvFile(c)), envMode); err != nil {
		return fmt.Errorf("systemd: write env file: %w", err)
	}
	if err := os.MkdirAll(s.rulesDir(), dirModePrivate); err != nil {
		return fmt.Errorf("systemd: create rules dir %q: %w", s.rulesDir(), err)
	}
	// The baseline is named `<account>.baseline.nft` and the forcing rules
	// `<account>.nft`; both match the loader glob `*.nft`. The baseline loads its own
	// table, the forcing rules load theirs, so the loader restores BOTH at boot.
	baselinePath := filepath.Join(s.rulesDir(), c.Account+".baseline.nft")
	if err := writeFileMode(baselinePath, []byte(baseline), ruleMode); err != nil {
		return fmt.Errorf("systemd: write baseline rule file: %w", err)
	}
	rulePath := filepath.Join(s.rulesDir(), c.Account+".nft")
	if err := writeFileMode(rulePath, []byte(ruleset), ruleMode); err != nil {
		return fmt.Errorf("systemd: write rule file: %w", err)
	}
	return nil
}

// RemoveAccount deletes ONE account's per-account artifacts (env + forcing rule
// file + baseline rule file). A missing file is a clean no-op (rm idempotency),
// never an error. It validates the account name so a crafted name cannot delete an
// arbitrary file.
func (s Store) RemoveAccount(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(s.envDir(), account+".env"),
		filepath.Join(s.rulesDir(), account+".nft"),
		filepath.Join(s.rulesDir(), account+".baseline.nft"),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("systemd: remove %q: %w", path, err)
		}
	}
	return nil
}

// HasForcedAccounts reports whether ANY account still has persisted rule files in
// the rules dir (a forcing `<account>.nft` or a baseline `<account>.baseline.nft`).
// It is how teardown decides whether the shared early-boot loader unit is still
// needed: the loader is disabled only when the LAST account's rule files are gone,
// so a multi-account host keeps loading the survivors at boot. An absent rules dir
// reads as "no accounts" (a clean no-op, never an error).
func (s Store) HasForcedAccounts() (bool, error) {
	entries, err := os.ReadDir(s.rulesDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("systemd: read rules dir %q: %w", s.rulesDir(), err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".nft") {
			return true, nil
		}
	}
	return false, nil
}

// writeFileMode writes data at path and re-asserts mode (WriteFile respects umask,
// so the intended mode is set explicitly, matching marker.Store's discipline).
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// validAccount rejects an account name that could escape a Store dir (mirrors
// marker.validAccount / accountconfig.validAccount).
func validAccount(account string) error {
	if strings.TrimSpace(account) == "" {
		return errors.New("empty account name")
	}
	if strings.ContainsAny(account, "/\\") || account == "." || account == ".." || strings.Contains(account, "..") {
		return fmt.Errorf("invalid account name %q (no path separators or traversal)", account)
	}
	return nil
}

// BakedBinaries returns the absolute BINARY paths the installed units name, so a
// caller can check they still exist.
//
// WHY THIS IS WORTH A FUNCTION. Both units bake absolute paths at install time
// (a unit has no useful inherited $PATH), and they are written ONLY by the install
// path. So when a binary MOVES, nothing re-bakes them: the unit keeps naming a
// path that is gone, and it fails at the next start with 203/EXEC while everything
// looks healthy in the meantime, because a running shim still holds its open
// inode. Two ways that happens in practice, both real:
//
//   - migrating from a hand-installed /usr/local/bin to a packaged binary, which
//     anonctl's own NixOS guide now recommends (measured on telemaque: `verify`
//     passed twice over a template unit naming a deleted shim);
//   - a `/nix/store` path that a later garbage collection removes, which is the
//     hazard the resolver's preferStableAlias exists to avoid but cannot prevent
//     if the operator installed from a store path directly.
//
// It reads the files rather than asking systemd, so it sees what will be loaded at
// the NEXT boot rather than what the running generation happens to have. Paths
// containing a `$` (env-var interpolation) and the rule-file glob are skipped: they
// are not binaries. A missing unit file is not an error here (an account may not be
// installed yet); the caller decides what an empty result means.
func (s Store) BakedBinaries() ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, unit := range []string{filepath.Join(s.unitDir(), UnitName), filepath.Join(s.unitDir(), LoaderUnitName)} {
		body, err := os.ReadFile(unit)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("systemd: read unit %s: %w", unit, err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "ExecStart=") && !strings.HasPrefix(line, "    /") {
				continue
			}
			for _, tok := range strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "ExecStart=")) {
				tok = strings.Trim(tok, "'\"\\;")
				if !strings.HasPrefix(tok, "/") || strings.Contains(tok, "$") || strings.Contains(tok, "*") {
					continue
				}
				if !seen[tok] {
					seen[tok] = true
					out = append(out, tok)
				}
			}
		}
	}
	return out, nil
}
