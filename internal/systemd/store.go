package systemd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wighawag/anonctl/internal/accountconfig"
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
}

// DefaultStore returns the Store pointing at the real default locations.
func DefaultStore() Store {
	return Store{UnitDir: DefaultUnitDir, EnvDir: DefaultEnvDir, RulesDir: DefaultRulesDir}
}

func (s Store) unitDir() string  { return orDefault(s.UnitDir, DefaultUnitDir) }
func (s Store) envDir() string   { return orDefault(s.EnvDir, DefaultEnvDir) }
func (s Store) rulesDir() string { return orDefault(s.RulesDir, DefaultRulesDir) }

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
	if err := os.MkdirAll(s.unitDir(), dirModePublic); err != nil {
		return fmt.Errorf("systemd: create unit dir %q: %w", s.unitDir(), err)
	}
	unitPath := filepath.Join(s.unitDir(), UnitName)
	if err := writeFileMode(unitPath, []byte(TemplateUnit(tp)), unitMode); err != nil {
		return fmt.Errorf("systemd: write template unit: %w", err)
	}
	loaderPath := filepath.Join(s.unitDir(), LoaderUnitName)
	if err := writeFileMode(loaderPath, []byte(LoaderUnit(lp)), unitMode); err != nil {
		return fmt.Errorf("systemd: write loader unit: %w", err)
	}
	return nil
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
	baseline, err := nftables.GenerateBaseline(c.Account, c.AnonUID)
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
