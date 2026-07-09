package systemd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// scratchStore builds a Store whose every write target is under a single temp dir,
// so a test writes NO real /etc file and the real locations are left untouched (the
// shared-write isolation discipline).
func scratchStore(t *testing.T) systemd.Store {
	t.Helper()
	root := t.TempDir()
	return systemd.Store{
		UnitDir:  filepath.Join(root, "systemd"),
		EnvDir:   filepath.Join(root, "shim"),
		RulesDir: filepath.Join(root, "nftables"),
	}
}

func TestInstallTemplateWritesTheUnitAndLoader(t *testing.T) {
	s := scratchStore(t)
	if err := s.InstallCommon(systemd.TemplateParams{}, systemd.LoaderParams{}); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	// The @-template shim unit lands in the unit dir.
	unitPath := filepath.Join(s.UnitDir, systemd.UnitName)
	if _, err := os.Stat(unitPath); err != nil {
		t.Errorf("template unit not written: %v", err)
	}
	// anonctl's OWN early-boot loader unit lands in the unit dir (it REPLACED the
	// nftables.service drop-in): a host unit anonctl does not mutate.
	loaderPath := filepath.Join(s.UnitDir, systemd.LoaderUnitName)
	if _, err := os.Stat(loaderPath); err != nil {
		t.Errorf("loader unit not written: %v", err)
	}
	// The old drop-in must NOT be written anymore (anonctl no longer rides on the
	// host's nftables.service).
	if _, err := os.Stat(filepath.Join(s.UnitDir, "nftables.service.d", "anonctl.conf")); err == nil {
		t.Errorf("the nftables.service drop-in must no longer be written (replaced by the loader unit)")
	}
}

func TestWriteAccountPersistsEnvAndRuleFile(t *testing.T) {
	s := scratchStore(t)
	c := sampleConfig()
	if err := s.WriteAccount(c, "table inet anonctl_anon {}\n"); err != nil {
		t.Fatalf("WriteAccount: %v", err)
	}
	// The per-account env file (parameterises the template instance) lands 0600.
	envPath := filepath.Join(s.EnvDir, "anon.env")
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("env file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("env file mode = %o, want 0600 (anonctl-private)", perm)
	}
	// The per-account nft rule file (loaded at boot by the loader unit) lands too, and
	// carries the account's ruleset text.
	rulePath := filepath.Join(s.RulesDir, "anon.nft")
	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("rule file not written: %v", err)
	}
	if string(data) != "table inet anonctl_anon {}\n" {
		t.Errorf("rule file content = %q, want the passed ruleset", string(data))
	}
	// The standing baseline default-deny lands as its OWN always-loaded artifact
	// (`<account>.baseline.nft`, matching the loader glob), generated from the anon
	// UID: so forcing-absent still means DROPPED at boot.
	baseline, err := os.ReadFile(filepath.Join(s.RulesDir, "anon.baseline.nft"))
	if err != nil {
		t.Fatalf("baseline rule file not written: %v", err)
	}
	if !strings.Contains(string(baseline), "table inet anonctl_baseline_anon {") {
		t.Errorf("baseline file must carry the baseline default-deny table:\n%s", string(baseline))
	}
	if !strings.Contains(string(baseline), "meta skuid 30034 ip daddr != 127.0.0.0/8 drop") {
		t.Errorf("baseline file must drop the anon UID's real egress:\n%s", string(baseline))
	}
}

func TestHasForcedAccountsTracksRuleFiles(t *testing.T) {
	s := scratchStore(t)
	// No rules dir yet => no forced accounts (a clean negative, never an error). This
	// is what teardown uses to disable the shared loader unit only on the LAST account.
	if has, err := s.HasForcedAccounts(); err != nil || has {
		t.Errorf("HasForcedAccounts() on an empty host = (%v, %v), want (false, nil)", has, err)
	}
	if err := s.WriteAccount(sampleConfig(), "table inet anonctl_anon {}\n"); err != nil {
		t.Fatalf("WriteAccount: %v", err)
	}
	if has, err := s.HasForcedAccounts(); err != nil || !has {
		t.Errorf("HasForcedAccounts() with an account = (%v, %v), want (true, nil)", has, err)
	}
	if err := s.RemoveAccount("anon"); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	// After the last account's rule files are gone, the loader is no longer needed.
	if has, err := s.HasForcedAccounts(); err != nil || has {
		t.Errorf("HasForcedAccounts() after the last removal = (%v, %v), want (false, nil)", has, err)
	}
}

func TestRemoveAccountDeletesEnvAndRuleFileIdempotently(t *testing.T) {
	s := scratchStore(t)
	// Removing before writing is a clean no-op (rm idempotency).
	if err := s.RemoveAccount("anon"); err != nil {
		t.Errorf("RemoveAccount(absent) = %v, want nil", err)
	}
	if err := s.WriteAccount(sampleConfig(), "x\n"); err != nil {
		t.Fatalf("WriteAccount: %v", err)
	}
	if err := s.RemoveAccount("anon"); err != nil {
		t.Errorf("RemoveAccount(present) = %v, want nil", err)
	}
	if _, err := os.Stat(filepath.Join(s.EnvDir, "anon.env")); !os.IsNotExist(err) {
		t.Errorf("env file survived RemoveAccount")
	}
	if _, err := os.Stat(filepath.Join(s.RulesDir, "anon.nft")); !os.IsNotExist(err) {
		t.Errorf("rule file survived RemoveAccount")
	}
	if _, err := os.Stat(filepath.Join(s.RulesDir, "anon.baseline.nft")); !os.IsNotExist(err) {
		t.Errorf("baseline rule file survived RemoveAccount")
	}
}

func TestStoreRejectsAccountTraversal(t *testing.T) {
	s := scratchStore(t)
	// A crafted account name can never escape the env/rules dirs.
	if err := s.RemoveAccount("../evil"); err == nil {
		t.Errorf("RemoveAccount(traversal) = nil, want a refusal")
	}
	bad := sampleConfig()
	bad.Account = "../evil"
	if err := s.WriteAccount(bad, "x\n"); err == nil {
		t.Errorf("WriteAccount(traversal) = nil, want a refusal")
	}
}
