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

// TestWriteAccountBaselineCarriesExemptionReturn proves WriteAccount threads the
// account's persisted exemptions into the baseline file: the baseline must RETURN an
// exempted destination (so the forcing accept can complete the direct hole), not
// just drop all non-loopback egress. Without this, the persisted baseline loaded at
// boot would drop the split-tunnel hole even though the forcing table opens it.
func TestWriteAccountBaselineCarriesExemptionReturn(t *testing.T) {
	s := scratchStore(t)
	c := sampleConfig()
	c.Exemptions = []string{"192.168.1.150:8080"}
	if err := s.WriteAccount(c, "table inet anonctl_anon {}\n"); err != nil {
		t.Fatalf("WriteAccount: %v", err)
	}
	baseline, err := os.ReadFile(filepath.Join(s.RulesDir, "anon.baseline.nft"))
	if err != nil {
		t.Fatalf("baseline rule file not written: %v", err)
	}
	want := "meta skuid 30034 ip daddr 192.168.1.150 tcp dport 8080 return"
	if !strings.Contains(string(baseline), want) {
		t.Errorf("persisted baseline must RETURN the exempted destination; missing %q:\n%s", want, string(baseline))
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

// RemoveCommon tears down the SHARED, account-agnostic artifacts InstallCommon
// wrote: the @-template shim unit, anonctl's early-boot loader unit, and the (now
// empty) shim/rules dirs. It is used on the LAST account's teardown so a fully
// torn-down host leaves no anonctl residue (the e2e finding, BUG 4). It is a clean
// no-op when the artifacts are already gone (rm idempotency), and it must NEVER
// remove a NON-empty dir (a survivor account's files stay put).
func TestRemoveCommonRemovesSharedUnitsAndEmptyDirs(t *testing.T) {
	s := scratchStore(t)
	if err := s.InstallCommon(systemd.TemplateParams{}, systemd.LoaderParams{}); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	// Create the private dirs too (WriteAccount would; here we just want them empty).
	if err := os.MkdirAll(s.EnvDir, 0o700); err != nil {
		t.Fatalf("mkdir env: %v", err)
	}
	if err := os.MkdirAll(s.RulesDir, 0o700); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := s.RemoveCommon(); err != nil {
		t.Fatalf("RemoveCommon: %v", err)
	}
	// The shared template + loader units are gone.
	if _, err := os.Stat(filepath.Join(s.UnitDir, systemd.UnitName)); !os.IsNotExist(err) {
		t.Errorf("RemoveCommon left the template unit behind")
	}
	if _, err := os.Stat(filepath.Join(s.UnitDir, systemd.LoaderUnitName)); !os.IsNotExist(err) {
		t.Errorf("RemoveCommon left the loader unit behind")
	}
	// The now-empty private dirs are removed too (no empty /etc/anonctl/{shim,nftables}).
	if _, err := os.Stat(s.EnvDir); !os.IsNotExist(err) {
		t.Errorf("RemoveCommon left the empty shim env dir behind")
	}
	if _, err := os.Stat(s.RulesDir); !os.IsNotExist(err) {
		t.Errorf("RemoveCommon left the empty nftables rules dir behind")
	}
}

// RemoveCommon is idempotent (a second call, or a call before InstallCommon ever
// ran, is a clean no-op).
func TestRemoveCommonIdempotent(t *testing.T) {
	s := scratchStore(t)
	if err := s.RemoveCommon(); err != nil {
		t.Errorf("RemoveCommon on a pristine host = %v, want nil", err)
	}
}

// RemoveCommon must NOT delete a NON-empty private dir: it only removes the shared
// units and the dirs it owns WHEN they are empty. A survivor account whose rule
// files still live under the rules dir keeps its dir (this can happen only via a
// misuse, since the caller guards on HasForcedAccounts, but the Store must be safe
// regardless).
func TestRemoveCommonKeepsNonEmptyDirs(t *testing.T) {
	s := scratchStore(t)
	if err := s.WriteAccount(sampleConfig(), "table inet anonctl_anon {}\n"); err != nil {
		t.Fatalf("WriteAccount: %v", err)
	}
	if err := s.RemoveCommon(); err != nil {
		t.Fatalf("RemoveCommon: %v", err)
	}
	if _, err := os.Stat(s.RulesDir); err != nil {
		t.Errorf("RemoveCommon removed a non-empty rules dir (a survivor's files): %v", err)
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
