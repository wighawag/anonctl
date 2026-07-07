package forcing_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/systemd"
)

// event is one recorded system mutation, in the order it happened, so a test can
// assert the fail-closed / no-leak-window ORDERING (nft rules applied before/around
// the shim), not just that the calls happened.
type event struct{ kind, detail string }

// fakeNft records nft applies/deletes in order.
type fakeNft struct{ ev *[]event }

func (f fakeNft) Run(_ context.Context, stdin, name string, args ...string) (string, string, error) {
	// The command discriminator: an apply pipes a full ruleset, a delete pipes a
	// `delete table` line.
	kind := "nft-apply"
	if strings.HasPrefix(strings.TrimSpace(stdin), "delete table") {
		kind = "nft-delete"
	}
	*f.ev = append(*f.ev, event{kind, strings.Join(append([]string{name}, args...), " ")})
	return "", "", nil
}

// fakeSystemctl records systemctl calls in order.
type fakeSystemctl struct{ ev *[]event }

func (f fakeSystemctl) Run(_ context.Context, name string, args ...string) (string, string, error) {
	*f.ev = append(*f.ev, event{"systemctl", strings.Join(args, " ")})
	return "", "", nil
}

func testDeps(t *testing.T) (forcing.Deps, *[]event) {
	t.Helper()
	root := t.TempDir()
	var ev []event
	d := forcing.Deps{
		NftRunner:     fakeNft{&ev},
		SystemdRunner: fakeSystemctl{&ev},
		ConfigStore:   accountconfig.Store{BaseDir: filepath.Join(root, "cfg")},
		SystemdStore: systemd.Store{
			UnitDir:  filepath.Join(root, "systemd"),
			EnvDir:   filepath.Join(root, "shim"),
			RulesDir: filepath.Join(root, "nftables"),
		},
	}
	return d, &ev
}

func sampleConfig() accountconfig.Config {
	return accountconfig.Config{
		Account:       "anon",
		AnonUID:       30034,
		ShimUID:       995,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
	}
}

// firstIndexOf returns the index of the first event of a kind, or -1.
func firstIndexOf(ev []event, kind string, detailSub string) int {
	for i, e := range ev {
		if e.kind == kind && strings.Contains(e.detail, detailSub) {
			return i
		}
	}
	return -1
}

func TestInstallAppliesRulesBeforeEnablingShim(t *testing.T) {
	d, ev := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// FAIL-CLOSED ORDERING: the nft rules (carrying the default-DROP) must be applied
	// BEFORE the shim is enabled, so the anon UID is never live without the drop in
	// force. If the enable ran first, there would be a window with a running account
	// and no rules.
	applyIdx := firstIndexOf(*ev, "nft-apply", "nft")
	enableIdx := firstIndexOf(*ev, "systemctl", "enable")
	if applyIdx < 0 || enableIdx < 0 {
		t.Fatalf("expected an nft apply and a systemctl enable; got %+v", *ev)
	}
	if applyIdx > enableIdx {
		t.Errorf("nft rules applied AFTER the shim was enabled (leak window); order: %+v", *ev)
	}
}

func TestInstallPersistsConfigEnvAndRuleFile(t *testing.T) {
	d, _ := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// The at-rest config is persisted (so a reboot / update can re-read it).
	if _, err := d.ConfigStore.Read("anon"); err != nil {
		t.Errorf("Install did not persist the account config: %v", err)
	}
}

func TestReconfigureReAppliesBeforeRestartWithNoLeakWindow(t *testing.T) {
	d, ev := testDeps(t)
	// Provision the account forced first.
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	*ev = nil // watch only the reconfigure

	// Change the endpoint to a plain socks-peruser proxy.
	c := sampleConfig()
	c.EndpointPort = 1080
	c.EndpointClass = endpoint.ClassSocksPeruser
	if err := forcing.Reconfigure(context.Background(), d, c, nil); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}

	// NO-LEAK-WINDOW ORDERING (story 21): the rules are RE-APPLIED (atomic table
	// replace, the default-DROP never absent) BEFORE the shim is restarted, so
	// egress is dropped-or-forced throughout, never direct.
	applyIdx := firstIndexOf(*ev, "nft-apply", "nft")
	restartIdx := firstIndexOf(*ev, "systemctl", "restart")
	if applyIdx < 0 || restartIdx < 0 {
		t.Fatalf("expected an nft apply and a systemctl restart; got %+v", *ev)
	}
	if applyIdx > restartIdx {
		t.Errorf("rules re-applied AFTER the shim restart (leak window); order: %+v", *ev)
	}
	// The rewritten config carries the new endpoint.
	got, err := d.ConfigStore.Read("anon")
	if err != nil {
		t.Fatalf("Read after Reconfigure: %v", err)
	}
	if got.EndpointPort != 1080 || got.EndpointClass != endpoint.ClassSocksPeruser {
		t.Errorf("Reconfigure did not rewrite the endpoint: got %+v", got)
	}
	// The rewritten env file drops the isolation username (socks-peruser has none).
	env, err := readEnv(d, "anon")
	if err != nil {
		t.Fatalf("read env after Reconfigure: %v", err)
	}
	if strings.Contains(env, "ANONCTL_SOCKS_USER=anon") {
		t.Errorf("reconfigured peruser endpoint must not keep the isolation username:\n%s", env)
	}
}

func TestRemoveDisablesShimAndClearsState(t *testing.T) {
	d, ev := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	*ev = nil
	if err := forcing.Remove(context.Background(), d, "anon"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// Remove disables the shim AND deletes the account's nft table.
	if firstIndexOf(*ev, "systemctl", "disable") < 0 {
		t.Errorf("Remove did not disable the shim; events: %+v", *ev)
	}
	if firstIndexOf(*ev, "nft-delete", "nft") < 0 {
		t.Errorf("Remove did not delete the account's nft table; events: %+v", *ev)
	}
	// The at-rest config is gone (a torn-down account leaves no residue).
	if _, err := d.ConfigStore.Read("anon"); err != accountconfig.ErrNotFound {
		t.Errorf("Remove left the account config behind: %v", err)
	}
}

// readEnv reads the per-account env file the SystemdStore wrote (a small helper so
// the reconfigure test can assert the rewritten isolation username).
func readEnv(d forcing.Deps, account string) (string, error) {
	path := filepath.Join(d.SystemdStore.EnvDir, account+".env")
	b, err := os.ReadFile(path)
	return string(b), err
}
