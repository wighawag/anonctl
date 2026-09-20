package forcing_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
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
	// `delete table` line. The detail carries the piped stdin (the ruleset / delete
	// line), so a test can distinguish the baseline apply from the forcing apply and
	// assert on the exact table names, not just that `nft` ran.
	kind := "nft-apply"
	if strings.HasPrefix(strings.TrimSpace(stdin), "delete table") {
		kind = "nft-delete"
	}
	detail := strings.Join(append([]string{name}, args...), " ") + " | " + strings.TrimSpace(stdin)
	*f.ev = append(*f.ev, event{kind, detail})
	return "", "", nil
}

// fakeSystemctl records systemctl calls in order.
type fakeSystemctl struct{ ev *[]event }

func (f fakeSystemctl) Run(_ context.Context, name string, args ...string) (string, string, error) {
	*f.ev = append(*f.ev, event{"systemctl", strings.Join(args, " ")})
	return "", "", nil
}

// fakeResolver resolves the unit binaries to fixed absolute paths WITHOUT touching
// the host's $PATH, so the orchestration tests neither depend on setpriv/nft being
// installed nor on where they happen to live.
func fakeResolver() systemd.Resolver {
	return systemd.Resolver{
		Look: func(name string) (string, error) { return "/fake/bin/" + name, nil },
		Executable: func() (string, error) {
			return "", errors.New("no executable in test")
		},
	}
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
			// Point the legacy sweep at a scratch dir: the migration must NEVER touch the
			// host's real /etc/systemd/system from a unit test.
			LegacyUnitDir: filepath.Join(root, "legacy-systemd"),
		},
		Resolver: fakeResolver(),
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

// shimLink / loaderLink are anonctl's OWN enablement symlinks -- the artifacts that
// have REPLACED `systemctl enable`, because that command writes into
// /etc/systemd/system whatever the unit dir is, and that dir is read-only on NixOS.
func shimLink(d forcing.Deps, account string) string {
	return filepath.Join(d.SystemdStore.UnitDir, systemd.ShimWantedBy+".wants", systemd.InstanceName(account))
}

func loaderLink(d forcing.Deps) string {
	return filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderWantedBy+".wants", systemd.LoaderUnitName)
}

func TestInstallAppliesRulesBeforeStartingShim(t *testing.T) {
	d, ev := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// FAIL-CLOSED ORDERING: the nft rules (carrying the default-DROP) must be applied
	// BEFORE the shim is started, so the anon UID is never live without the drop in
	// force. If the start ran first, there would be a window with a running account
	// and no rules.
	applyIdx := firstIndexOf(*ev, "nft-apply", "nft")
	startIdx := firstIndexOf(*ev, "systemctl", "start")
	if applyIdx < 0 || startIdx < 0 {
		t.Fatalf("expected an nft apply and a systemctl start; got %+v", *ev)
	}
	if applyIdx > startIdx {
		t.Errorf("nft rules applied AFTER the shim was started (leak window); order: %+v", *ev)
	}
}

// Enablement must be a DURABLE on-disk symlink in anonctl's OWN unit dir, not a
// `systemctl enable` call. This is what makes the forcing survive a reboot on a host
// whose /etc/systemd/system cannot be written.
func TestInstallWritesItsOwnEnablementSymlinksAndNeverCallsSystemctlEnable(t *testing.T) {
	d, ev := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, link := range []string{shimLink(d, "anon"), loaderLink(d)} {
		dest, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("Install did not create the enablement symlink %q: %v", link, err)
		}
		// The symlink target must itself live in a unit search path, or systemd ignores it.
		if filepath.Dir(dest) != d.SystemdStore.UnitDir {
			t.Errorf("enablement symlink %q points outside the unit dir (%q); systemd would ignore it", link, dest)
		}
		if _, err := os.Stat(dest); err != nil {
			t.Errorf("enablement symlink %q dangles: %v", link, err)
		}
	}
	// The shim instance link must point at the TEMPLATE file, the same instance ->
	// template mapping systemctl would have produced.
	if dest, _ := os.Readlink(shimLink(d, "anon")); filepath.Base(dest) != systemd.UnitName {
		t.Errorf("shim instance link should point at the template %q, got %q", systemd.UnitName, dest)
	}
	for _, e := range *ev {
		if e.kind == "systemctl" && strings.Contains(e.detail, "enable") {
			t.Errorf("Install must not call `systemctl enable` (it writes to a read-only dir on NixOS); got %q", e.detail)
		}
	}
}

// The units anonctl writes must carry the RESOLVED absolute binary paths, never the
// FHS guesses that are absent on NixOS. A loader that cannot run nft is fail-OPEN at
// boot: no baseline default-deny, so the anon UID egresses freely.
func TestInstallBakesResolvedBinaryPathsIntoTheUnits(t *testing.T) {
	d, _ := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	loader, err := os.ReadFile(filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderUnitName))
	if err != nil {
		t.Fatalf("read loader unit: %v", err)
	}
	if !strings.Contains(string(loader), "/fake/bin/nft") {
		t.Errorf("loader unit does not carry the resolved nft path:\n%s", loader)
	}
	if strings.Contains(string(loader), "/usr/sbin/nft") {
		t.Errorf("loader unit still hard-codes /usr/sbin/nft (absent on NixOS, fail-OPEN at boot):\n%s", loader)
	}
	unit, err := os.ReadFile(filepath.Join(d.SystemdStore.UnitDir, systemd.UnitName))
	if err != nil {
		t.Fatalf("read template unit: %v", err)
	}
	if strings.Contains(string(unit), "/usr/bin/setpriv") {
		t.Errorf("template unit still hard-codes /usr/bin/setpriv (absent on NixOS):\n%s", unit)
	}
}

// An unresolvable binary must abort the install LOUDLY, rather than writing a unit
// that only fails at the next boot. The live rules are applied before this point, so
// the account is left DROPPED (fail-closed), never leaking.
func TestInstallFailsLoudlyWhenAUnitBinaryCannotBeResolved(t *testing.T) {
	d, ev := testDeps(t)
	d.Resolver = systemd.Resolver{
		Look: func(name string) (string, error) {
			if name == systemd.NftBinaryName {
				return "", errors.New("not found")
			}
			return "/fake/bin/" + name, nil
		},
		Executable: func() (string, error) { return "", errors.New("no executable in test") },
	}
	err := forcing.Install(context.Background(), d, sampleConfig(), nil)
	if err == nil {
		t.Fatal("Install must fail when nft cannot be resolved, not emit a unit that dies at boot")
	}
	if !strings.Contains(err.Error(), systemd.NftBinaryName) {
		t.Errorf("the error must name the binary it could not resolve; got %v", err)
	}
	// Nothing half-written: no unit file may survive a refused generation.
	if _, serr := os.Stat(filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderUnitName)); !os.IsNotExist(serr) {
		t.Error("a failed resolve must not leave a loader unit behind")
	}
	// AND it must have aborted BEFORE mutating any host state. Resolving late would be
	// a fail-OPEN regression: on the `add` path the account already exists by this
	// point, so an abort after the rules were applied but before the units were
	// installed would leave an account that EXISTS with NOTHING enabled -- the next
	// boot loads neither the baseline default-deny nor the forcing, and the anon UID
	// egresses with the host's real IP. Nothing may have been written or applied.
	if _, cerr := d.ConfigStore.Read("anon"); cerr == nil {
		t.Error("a failed resolve must abort BEFORE persisting the account config")
	}
	for _, e := range *ev {
		t.Errorf("a failed resolve must abort before mutating the host; it ran %s %q", e.kind, e.detail)
	}
}

// REGRESSION: a multi-account host upgrading from the legacy layout must keep EVERY
// account enabled, not just the one being added. See
// TestMigrateAdoptsEveryAccountsEnablementNotJustOne for why this is silent.
func TestInstallOnUpgradeKeepsOtherAccountsEnabled(t *testing.T) {
	d, _ := testDeps(t)
	// Seed a 0.3.0-era install with three accounts enabled in the LEGACY dir.
	legacy := d.SystemdStore.LegacyUnitDir
	shimWants := filepath.Join(legacy, systemd.ShimWantedBy+".wants")
	if err := os.MkdirAll(shimWants, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacy, systemd.UnitName), []byte("# stale\n"), 0o644); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	for _, acct := range []string{"anon", "anon-work", "anon-mail"} {
		if err := os.Symlink(filepath.Join(legacy, systemd.UnitName), filepath.Join(shimWants, systemd.InstanceName(acct))); err != nil {
			t.Fatalf("seed link %s: %v", acct, err)
		}
	}
	// Upgrade by adding ONE of them.
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, acct := range []string{"anon", "anon-work", "anon-mail"} {
		if _, err := os.Readlink(shimLink(d, acct)); err != nil {
			t.Errorf("account %q lost its enablement on upgrade: it would not start after a reboot (%v)", acct, err)
		}
	}
	// And the legacy shadowing copies are gone.
	if _, err := os.Lstat(filepath.Join(legacy, systemd.UnitName)); !os.IsNotExist(err) {
		t.Error("upgrade left the shadowing legacy template unit behind")
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
	// The standing baseline default-deny is persisted as its own always-loaded file,
	// so forcing-absent still means DROPPED at boot.
	if _, err := os.Stat(filepath.Join(d.SystemdStore.RulesDir, "anon.baseline.nft")); err != nil {
		t.Errorf("Install did not persist the baseline default-deny file: %v", err)
	}
}

func TestInstallAppliesBaselineBeforeForcingAndEnablesLoader(t *testing.T) {
	d, ev := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// INVERTED INVARIANT ORDERING: the BASELINE default-deny is applied FIRST, before
	// the forcing rules and before the shim, so from the very first moment the account
	// can act its real egress is dropped (never a window with neither present).
	baselineIdx := firstIndexOf(*ev, "nft-apply", "anonctl_baseline_anon")
	forcingIdx := firstIndexOf(*ev, "nft-apply", "anonctl_anon {")
	if baselineIdx < 0 || forcingIdx < 0 {
		t.Fatalf("expected both a baseline apply and a forcing apply; got %+v", *ev)
	}
	if baselineIdx > forcingIdx {
		t.Errorf("baseline default-deny applied AFTER the forcing rules (resting-deny window); order: %+v", *ev)
	}
	// anonctl's OWN early-boot loader unit is enabled (via anonctl's own symlink), so
	// the baseline + forcing load at the next boot independent of the host's
	// nftables.service.
	if _, err := os.Readlink(loaderLink(d)); err != nil {
		t.Errorf("Install did not enable anonctl's own early-boot loader unit: %v", err)
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
	// Remove stops the shim AND deletes the account's forcing table AND its
	// baseline table.
	if firstIndexOf(*ev, "systemctl", "anonctl-shim@anon.service") < 0 {
		t.Errorf("Remove did not stop the shim; events: %+v", *ev)
	}
	// De-enablement is the removal of anonctl's own symlink, so the shim does not come
	// back at the next boot.
	if _, err := os.Lstat(shimLink(d, "anon")); !os.IsNotExist(err) {
		t.Errorf("Remove left the shim enablement symlink behind: it would restart at boot")
	}
	if firstIndexOf(*ev, "nft-delete", "delete table inet anonctl_anon") < 0 {
		t.Errorf("Remove did not delete the account's forcing table; events: %+v", *ev)
	}
	if firstIndexOf(*ev, "nft-delete", "delete table inet anonctl_baseline_anon") < 0 {
		t.Errorf("Remove did not delete the account's baseline table; events: %+v", *ev)
	}
	// This was the LAST account, so anonctl's shared early-boot loader unit is
	// de-enabled (a fully torn-down host leaves no anonctl unit wired to boot).
	if _, err := os.Lstat(loaderLink(d)); !os.IsNotExist(err) {
		t.Errorf("Remove of the last account left the loader enablement symlink behind")
	}
	// The at-rest config is gone (a torn-down account leaves no residue).
	if _, err := d.ConfigStore.Read("anon"); err != accountconfig.ErrNotFound {
		t.Errorf("Remove left the account config behind: %v", err)
	}
	// The baseline file is gone too.
	if _, err := os.Stat(filepath.Join(d.SystemdStore.RulesDir, "anon.baseline.nft")); !os.IsNotExist(err) {
		t.Errorf("Remove left the baseline file behind")
	}
}

func TestRemoveKeepsLoaderWhileAnotherAccountRemains(t *testing.T) {
	d, ev := testDeps(t)
	// Two accounts forced.
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install anon: %v", err)
	}
	second := sampleConfig()
	second.Account = "anon-work"
	second.AnonUID = 41000
	second.ShimUID = 990
	if err := forcing.Install(context.Background(), d, second, nil); err != nil {
		t.Fatalf("Install anon-work: %v", err)
	}
	*ev = nil
	// Remove ONE account; the other survives, so the shared loader must STAY enabled
	// (it still restores the survivor at boot). The loader is disabled only on the
	// LAST account's teardown.
	if err := forcing.Remove(context.Background(), d, "anon"); err != nil {
		t.Fatalf("Remove anon: %v", err)
	}
	if _, err := os.Readlink(loaderLink(d)); err != nil {
		t.Errorf("Remove de-enabled the shared loader while another account remains: %v", err)
	}
	// The SURVIVOR's own enablement must be untouched: removing one account must never
	// stop another from coming back at boot.
	if _, err := os.Readlink(shimLink(d, "anon-work")); err != nil {
		t.Errorf("Remove of one account removed the survivor's enablement symlink: %v", err)
	}
}

// On the LAST account's teardown, Remove ALSO removes the SHARED account-agnostic
// artifacts (the @-template shim unit + the loader unit + the now-empty
// shim/nftables/accounts dirs), so a fully torn-down host leaves no anonctl residue
// (the e2e finding, BUG 4).
func TestRemoveLastAccountRemovesSharedInfraAndDirs(t *testing.T) {
	d, ev := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := forcing.Remove(context.Background(), d, "anon"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// The shared template + loader units are gone, and systemd is reloaded so the
	// removed units are forgotten.
	if _, err := os.Stat(filepath.Join(d.SystemdStore.UnitDir, systemd.UnitName)); !os.IsNotExist(err) {
		t.Errorf("Remove of the last account left the shared template unit behind")
	}
	if _, err := os.Stat(filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderUnitName)); !os.IsNotExist(err) {
		t.Errorf("Remove of the last account left the loader unit behind")
	}
	if firstIndexOf(*ev, "systemctl", "daemon-reload") < 0 {
		t.Errorf("Remove of the last account did not daemon-reload after removing the units; events: %+v", *ev)
	}
	// The now-empty anonctl dirs (shim env + nftables rules + account configs) are
	// removed too: no empty /etc/anonctl/{shim,nftables,accounts} residue.
	for _, dir := range []string{d.SystemdStore.EnvDir, d.SystemdStore.RulesDir} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("Remove of the last account left the empty dir %q behind", dir)
		}
	}
	if _, err := os.Stat(d.ConfigStore.BaseDir); !os.IsNotExist(err) {
		t.Errorf("Remove of the last account left the empty account-config dir behind")
	}
}

// Purging ONE account among several must NOT rip out the shared infra the survivor
// still needs: the template unit, the loader unit, and the shared dirs all survive
// while another account remains (the same last-account guard that keeps the loader).
func TestRemoveKeepsSharedInfraWhileAnotherAccountRemains(t *testing.T) {
	d, _ := testDeps(t)
	if err := forcing.Install(context.Background(), d, sampleConfig(), nil); err != nil {
		t.Fatalf("Install anon: %v", err)
	}
	second := sampleConfig()
	second.Account = "anon-work"
	second.AnonUID = 41000
	second.ShimUID = 990
	if err := forcing.Install(context.Background(), d, second, nil); err != nil {
		t.Fatalf("Install anon-work: %v", err)
	}
	if err := forcing.Remove(context.Background(), d, "anon"); err != nil {
		t.Fatalf("Remove anon: %v", err)
	}
	// The survivor still needs the shared template unit, the loader unit, and the
	// shared dirs (its rule files + env + config live under them).
	if _, err := os.Stat(filepath.Join(d.SystemdStore.UnitDir, systemd.UnitName)); err != nil {
		t.Errorf("Remove ripped out the shared template unit while a survivor remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.SystemdStore.UnitDir, systemd.LoaderUnitName)); err != nil {
		t.Errorf("Remove ripped out the loader unit while a survivor remains: %v", err)
	}
	if _, err := os.Stat(d.SystemdStore.RulesDir); err != nil {
		t.Errorf("Remove ripped out the shared rules dir while a survivor remains: %v", err)
	}
	if _, err := d.ConfigStore.Read("anon-work"); err != nil {
		t.Errorf("Remove of anon destroyed the survivor's config: %v", err)
	}
}

// readEnv reads the per-account env file the SystemdStore wrote (a small helper so
// the reconfigure test can assert the rewritten isolation username).
func readEnv(d forcing.Deps, account string) (string, error) {
	path := filepath.Join(d.SystemdStore.EnvDir, account+".env")
	b, err := os.ReadFile(path)
	return string(b), err
}
