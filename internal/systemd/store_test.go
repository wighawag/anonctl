package systemd_test

import (
	"os"
	"path/filepath"
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

func TestInstallTemplateWritesTheUnitAndDropIn(t *testing.T) {
	s := scratchStore(t)
	if err := s.InstallCommon(systemd.TemplateParams{}, systemd.NftablesDropInParams{}); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	// The @-template unit lands in the unit dir.
	unitPath := filepath.Join(s.UnitDir, systemd.UnitName)
	if _, err := os.Stat(unitPath); err != nil {
		t.Errorf("template unit not written: %v", err)
	}
	// The nftables.service drop-in lands under nftables.service.d.
	dropinPath := filepath.Join(s.UnitDir, "nftables.service.d", "anonctl.conf")
	if _, err := os.Stat(dropinPath); err != nil {
		t.Errorf("nftables drop-in not written: %v", err)
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
	// The per-account nft rule file (loaded at boot by the drop-in) lands too, and
	// carries the account's ruleset text.
	rulePath := filepath.Join(s.RulesDir, "anon.nft")
	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("rule file not written: %v", err)
	}
	if string(data) != "table inet anonctl_anon {}\n" {
		t.Errorf("rule file content = %q, want the passed ruleset", string(data))
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
