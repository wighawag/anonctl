// Package forcing is the ORCHESTRATION seam that installs, removes, and
// reconfigures an account's forced-egress persistence: it ties together the
// account config (internal/accountconfig, the at-rest record), the kernel rules
// (internal/nftables, generate + apply), and the systemd persistence
// (internal/systemd, the @-template shim unit + anonctl's early-boot loader unit +
// the per-account env/rule files). It is what `add` / `rm` / `update` call after
// the account itself is provisioned.
//
// It is designed around the BOOT INVARIANT and the NO-LEAK-WINDOW property, using
// the INVERTED design: the anon UID's RESTING STATE is a standing per-UID
// default-deny (the baseline), and forcing layers on top to OPEN the shim path. So
// "the anon UID has no anonctl forcing loaded" means DROPPED, not free.
//
//   - Install applies the BASELINE default-deny FIRST (before the forcing rules and
//     before the shim), so from the very first moment the account can act its real
//     egress is dropped, then applies the forcing rules on top and PERSISTS both as
//     their own always-loaded rule files. It also enables anonctl's OWN early-boot
//     loader unit, so at boot the baseline + forcing load INDEPENDENT of the host's
//     nftables.service (which Debian ships disabled). If the forcing fails, the shim
//     is down, or the endpoint is down, the standing baseline still DROPS.
//   - Reconfigure re-applies the forcing rules (which carry the fail-closed
//     default-DROP) as an atomic table replace; the standing baseline is untouched
//     throughout, so the resting deny never lapses.
//   - Reconfigure (update) rewrites the endpoint and RE-APPLIES with no
//     un-anonymized window: the nft rules are re-applied as an ATOMIC table
//     replace (the default-DROP is never absent), THEN the shim env file is
//     rewritten and the shim restarted. Across the whole operation egress is
//     dropped-or-forced, never direct: there is no moment where the old rules are
//     gone and the new ones not yet applied, and the brief shim bounce is covered
//     by the still-applied fail-closed rules.
//
// Every system mutation flows through an injected Runner (nftables.Runner for
// `nft`, systemd.Runner for `systemctl`) and a Store (the file writes), so the
// whole orchestration is unit-testable against fakes with NO root and NO real
// system mutation; the ONE test that touches a real host lives behind the
// `integration` build tag.
package forcing

import (
	"context"
	"fmt"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/systemd"
	"time"
)

// Deps bundles the seams the orchestration mutates through, so a caller (main)
// wires the real runners/stores and a test wires fakes. All are required; a nil
// field is a programming error surfaced at call time.
type Deps struct {
	// NftRunner applies/deletes the live nft ruleset (`nft -f -`).
	NftRunner nftables.Runner
	// SystemdRunner runs `systemctl` (daemon-reload / enable / disable / restart).
	SystemdRunner systemd.Runner
	// ConfigStore persists the per-account at-rest config.
	ConfigStore accountconfig.Store
	// SystemdStore persists the systemd unit / drop-in / per-account env + rule files.
	SystemdStore systemd.Store
	// Resolver turns the binary NAMES baked into the generated units (the shim,
	// setpriv, nft) into absolute paths at install time. The zero value resolves
	// against the real $PATH and the running executable; tests inject fakes.
	Resolver systemd.Resolver
}

// Install turns on forcing for an already-provisioned account: it records the
// config, applies + persists the fail-closed nft rules, installs the common
// systemd artifacts (idempotent), writes the account's env + rule files, and
// enables --now the account's shim instance. After Install the account is forced
// live AND across a reboot (the persisted default-DROP loads early: the boot
// invariant holds).
//
// Ordering is fail-closed by construction: the nft rules (carrying the default-
// DROP) are applied BEFORE the shim is enabled, so from the first moment the anon
// UID exists-under-forcing its egress is dropped-or-redirected, never direct. If
// the shim is not yet up, egress is DROPPED (fail-closed), never leaked.
// shimStartTimeout is how long `add`/`update` wait for the shim to be genuinely
// ACTIVE before giving up. Generous next to a Type=simple unit that is active as
// soon as its exec succeeds, and deliberately longer than the unit's RestartSec
// (2s) so a single transient retry still resolves inside it rather than being
// reported as a failure.
var shimStartTimeout = 10 * time.Second

func Install(ctx context.Context, d Deps, c accountconfig.Config, exemptions []lanexempt.Exempt) error {
	c = normalize(c)
	// RESOLVE BEFORE MUTATING ANYTHING. The three binaries the generated units name
	// (shim, setpriv, nft) are resolved FIRST, so an unresolvable one aborts Install
	// before a single byte of host state changes. Doing this LATE would be a fail-OPEN
	// regression: the account would already exist with live rules applied but NO unit
	// installed and nothing enabled, so the next boot would load neither the baseline
	// default-deny nor the forcing, and the anon UID would egress with the host's real
	// IP. `add` additionally pre-flights this before it creates the account at all (see
	// PreflightUnitBinaries), so reaching a failure here should be near-impossible.
	tp, lp, own, err := prepareUnits(d)
	if err != nil {
		return err
	}
	// GENERATE BEFORE PERSISTING. Generate is pure and validates the whole Params (a
	// zero uid, equal uids, a hostname endpoint, an account name whose nft table name
	// would be ambiguous), so it is the last thing that can REFUSE this install. Doing
	// it after the ledger write left a record on disk for an account that then got no
	// forcing at all - and the ledger is what `list` now reads managed-ness from, so
	// that residue reports as `managed: true, forcing: unforced`, i.e. "anonctl took
	// this account on and has not proven it yet" rather than "this install was
	// refused". A refusal must leave nothing behind.
	ruleset, err := nftables.Generate(nftParams(c, exemptions))
	if err != nil {
		return fmt.Errorf("forcing: generate ruleset: %w", err)
	}
	if err := d.ConfigStore.Write(c); err != nil {
		return fmt.Errorf("forcing: persist account config: %w", err)
	}
	// Apply the live rules (fail-closed default-DROP) FIRST, then persist the rule
	// file the boot drop-in loads, so the running state and the persisted state
	// agree and the account is forced both now and after a reboot.
	// Apply the standing BASELINE default-deny FIRST, so the anon UID's resting state
	// is DROP before either the forcing rules or the shim exist: there is no window
	// where the account can act with neither present. Forcing then layers on top.
	if err := nftables.ApplyBaseline(ctx, d.NftRunner, c.Account, c.AnonUID, exemptions); err != nil {
		return fmt.Errorf("forcing: apply baseline default-deny: %w", err)
	}
	if err := applyRuleset(ctx, d.NftRunner, c, exemptions); err != nil {
		return err
	}
	if err := d.SystemdStore.WriteAccount(c, ruleset); err != nil {
		return fmt.Errorf("forcing: persist per-account systemd files: %w", err)
	}

	// Install the account-agnostic template unit + anonctl's early-boot loader unit
	// (idempotent). SKIPPED when the host owns those two files: they are already there,
	// declared, and anonctl writing its own copy would be a second definition of the
	// same unit that the host's higher-ranked one silently wins over. Everything below
	// this point is unchanged in both modes, because the per-account enablement
	// symlinks are anonctl's either way.
	if !own.HostOwned {
		if err := d.SystemdStore.InstallCommon(tp, lp); err != nil {
			return fmt.Errorf("forcing: install common systemd artifacts: %w", err)
		}
	}
	// ENABLE BEFORE MIGRATING. Both orders leave exactly one definition once the whole
	// sequence completes, but only this one is safe if the sequence is INTERRUPTED: if
	// the migration were to run first and then fail part-way, the legacy enablement
	// symlink could already be gone while the new one had not been created yet, leaving
	// the loader enabled in NEITHER location -- fail-open at the next boot on a host
	// that was previously fine. Enabling first means at every instant at least one
	// enabled, loadable definition exists. Nothing is re-read by systemd until the
	// single daemon-reload below, so ordering these two does not expose a double
	// definition.
	//
	// This replaces `systemctl enable`, which writes into /etc/systemd/system regardless
	// of where the unit file lives and therefore cannot work on a host where that dir is
	// read-only. The loader is enabled but NOT started: `add` already applied the live
	// rules via nft, so it only needs to fire at the next boot.
	if err := d.SystemdStore.EnableUnit(systemd.LoaderUnitName, systemd.LoaderUnitName, systemd.LoaderWantedBy); err != nil {
		return err
	}
	if err := d.SystemdStore.EnableUnit(systemd.UnitName, systemd.InstanceName(c.Account), systemd.ShimWantedBy); err != nil {
		return err
	}
	// Sweep any pre-0.4 units out of /etc/systemd/system. That dir OUTRANKS the current
	// unit dir in systemd's load path, so a leftover copy would shadow what was just
	// written and the host would keep running the OLD definition. The sweep RE-ENABLES
	// every account it finds enabled in the legacy dir, not just this one, so a
	// multi-account upgrade does not silently de-enable the accounts that are not being
	// added right now. Done BEFORE daemon-reload so systemd never sees both at once.
	if _, err := d.SystemdStore.MigrateLegacyUnits(); err != nil {
		return fmt.Errorf("forcing: migrate legacy unit dir: %w", err)
	}
	// Reload AFTER the units, the symlinks and the migration are all in place, so
	// systemd picks up exactly one coherent definition.
	if err := systemd.DaemonReload(ctx, d.SystemdRunner); err != nil {
		return err
	}
	if err := systemd.StartNow(ctx, d.SystemdRunner, c.Account); err != nil {
		return err
	}
	// Same reason as the reconfigure path: a start that is merely RETRYING reports
	// success, so `add` would otherwise finish green over a shim that never came up.
	if err := systemd.WaitUntilActive(ctx, d.SystemdRunner, c.Account, shimStartTimeout); err != nil {
		return err
	}
	return nil
}

// Reconfigure changes an already-forced account's endpoint and re-applies with NO
// un-anonymized window. It rewrites the config, RE-APPLIES the nft rules as an
// atomic table replace (the fail-closed default-DROP is never absent), re-persists
// the rule file, rewrites the shim env file, and restarts the shim instance. The
// nft rules stay applied across the shim restart, so egress is dropped-or-forced
// throughout: there is never a moment of direct, un-anonymized egress during the
// reconfigure (story 21).
func Reconfigure(ctx context.Context, d Deps, c accountconfig.Config, exemptions []lanexempt.Exempt) error {
	c = normalize(c)
	// Resolve the unit binaries BEFORE mutating anything, exactly as Install does: a
	// reconfigure that cannot name the shim must fail while the old, working units are
	// still in place, not half way through.
	tp, lp, own, err := prepareUnits(d)
	if err != nil {
		return err
	}
	if err := d.ConfigStore.Write(c); err != nil {
		return fmt.Errorf("forcing: rewrite account config: %w", err)
	}

	ruleset, gerr := nftables.Generate(nftParams(c, exemptions))
	if gerr != nil {
		return fmt.Errorf("forcing: generate ruleset: %w", gerr)
	}
	// Re-apply the rules FIRST (atomic table replace: the default-DROP is never
	// gone), so the new endpoint's closure (b) is in force before the shim is
	// pointed at it. Persist the new rule file so a reboot re-applies the new state.
	// Re-apply the BASELINE too, so a changed exemption set (an `update --allow`)
	// updates the LIVE baseline's exemption RETURNs, not just the persisted file: the
	// baseline must RETURN the same exempted destinations the forcing chain accepts,
	// or the direct hole is dropped by the stale baseline. It stays a scoped, atomic
	// replace of only the baseline table, so the resting deny never lapses.
	if err := nftables.ApplyBaseline(ctx, d.NftRunner, c.Account, c.AnonUID, exemptions); err != nil {
		return fmt.Errorf("forcing: re-apply baseline default-deny: %w", err)
	}
	if err := applyRuleset(ctx, d.NftRunner, c, exemptions); err != nil {
		return err
	}
	if err := d.SystemdStore.WriteAccount(c, ruleset); err != nil {
		return fmt.Errorf("forcing: re-persist per-account systemd files: %w", err)
	}
	// RE-RESOLVE AND REWRITE THE SHARED UNITS TOO, which this verb did not used to do.
	//
	// The @-template's ExecStart and the loader's `nft` path are baked ABSOLUTE at
	// install time, and only `add` wrote them. So when the binaries MOVE, nothing
	// re-bakes them and the units keep naming a path that no longer exists: the unit
	// fails at the next start with 203/EXEC, and until then everything looks healthy
	// because the RUNNING shim still holds its open inode.
	//
	// That is not hypothetical, and it is a migration anonctl itself now recommends:
	// moving from a hand-installed /usr/local/bin to a packaged binary (docs/nixos.md)
	// leaves exactly this state, and `verify` passed twice over it because the running
	// shim was fine and verify resolves its own probe binary independently. Measured
	// on telemaque.
	//
	// Re-resolving here also costs nothing when nothing moved (the same paths are
	// written back), and it fails LOUD if a binary cannot be resolved at all, which is
	// the same guard `add` applies before it touches the box.
	//
	// NOT when the host owns the units: there is nothing for anonctl to re-bake, because
	// the paths in those files came from the host's own pin and move only when the host
	// rebuilds. prepareUnits has already asserted both files are present and that the
	// binaries they name still exist, which is the same property this re-bake exists to
	// restore -- reported instead of repaired, because repairing would mean writing a
	// file anonctl does not own.
	if !own.HostOwned {
		if err := d.SystemdStore.InstallCommon(tp, lp); err != nil {
			return fmt.Errorf("forcing: rewrite the shared unit files: %w", err)
		}
	}
	// RELOAD BEFORE RESTARTING, or the restart runs the unit systemd still has in
	// memory rather than the one just written. That is not a cosmetic ordering point:
	// measured on a live host, rewriting the template to fix a stale binary path and
	// then restarting WITHOUT a reload restarted the STALE unit, which still named the
	// deleted binary, so the shim failed 203/EXEC and the account lost its forced DNS
	// entirely (fail-closed, so not a leak, but broken). Install already reloads after
	// writing its units for the same reason; this path was missing it.
	if err := systemd.DaemonReload(ctx, d.SystemdRunner); err != nil {
		return err
	}
	// Restart the shim to pick up the rewritten env file (the new endpoint). The
	// still-applied fail-closed rules cover the brief bounce, so no leak window.
	if err := systemd.RestartNow(ctx, d.SystemdRunner, c.Account); err != nil {
		return err
	}
	// AND CONFIRM IT ACTUALLY CAME UP. `systemctl restart` exits 0 for a unit that
	// merely entered its Restart=on-failure backoff, so the exit code proves the job
	// was accepted and nothing more (measured; see WaitUntilActive).
	return systemd.WaitUntilActive(ctx, d.SystemdRunner, c.Account, shimStartTimeout)
}

// Remove turns off forcing for an account: it disables --now the shim instance,
// deletes the live nft forcing table AND the standing baseline default-deny table
// (leaving every other table untouched), removes the per-account systemd files (env
// + forcing + baseline rule files) and the at-rest config, and disables anonctl's
// early-boot loader unit ONLY when this was the LAST account (no rule files remain).
// On that LAST-account teardown it ALSO removes the SHARED account-agnostic
// artifacts (the @-template shim unit + the loader unit + the now-empty
// `/etc/anonctl/{shim,nftables,accounts}` dirs), so a fully torn-down host leaves no
// anonctl residue (the e2e finding, BUG 4). All of that is guarded by the SAME
// last-account check, so purging ONE account among several never rips out the shared
// infra the survivors still need.
// It is idempotent: a not-enabled instance, an absent table's delete, and a missing
// file are all clean no-ops (a torn-down account leaves no residue). The marker
// removal stays in the caller (rm already removes it), so this focuses on the
// forcing artifacts.
func Remove(ctx context.Context, d Deps, account string) error {
	// Stop + de-enable the shim first so it is not left running against rules we are
	// about to delete. Stopping (the runner) and de-enabling (the symlink) are now two
	// steps, because enablement no longer goes through systemctl.
	if err := systemd.StopNow(ctx, d.SystemdRunner, account); err != nil {
		return err
	}
	if err := d.SystemdStore.DisableUnit(systemd.InstanceName(account), systemd.ShimWantedBy); err != nil {
		return err
	}
	// Delete only this account's forcing table AND its baseline table; ignore a
	// not-found (idempotent teardown). A missing table on teardown is not a failure:
	// the account may never have been forced.
	if err := nftables.Delete(ctx, d.NftRunner, account); err != nil {
		_ = err
	}
	if err := nftables.DeleteBaseline(ctx, d.NftRunner, account); err != nil {
		_ = err
	}
	if err := d.SystemdStore.RemoveAccount(account); err != nil {
		return fmt.Errorf("forcing: remove per-account systemd files: %w", err)
	}
	if err := d.ConfigStore.Remove(account); err != nil {
		return fmt.Errorf("forcing: remove account config: %w", err)
	}
	// If this was the LAST forced account (no rule files remain), disable anonctl's
	// shared early-boot loader unit so a fully torn-down host leaves no anonctl unit
	// enabled. While ANY account survives, the loader stays enabled to restore the
	// survivors at boot. A read error here is surfaced; a not-enabled unit's disable
	// is a clean no-op.
	hasAccounts, err := d.SystemdStore.HasForcedAccounts()
	if err != nil {
		return fmt.Errorf("forcing: check remaining forced accounts: %w", err)
	}
	if !hasAccounts {
		if err := d.SystemdStore.DisableUnit(systemd.LoaderUnitName, systemd.LoaderWantedBy); err != nil {
			return err
		}
		// LAST account: also remove the SHARED account-agnostic artifacts (the template
		// shim unit + the loader unit + the now-empty anonctl dirs), then reload systemd
		// so the removed units are forgotten. RemoveCommon only deletes the dirs it owns
		// WHEN empty and RemoveBaseDirIfEmpty the same, so a survivor's files are never
		// touched (belt-and-braces on top of the !hasAccounts guard). A fully torn-down
		// host is left with no anonctl residue (the e2e finding, BUG 4).
		if err := d.SystemdStore.RemoveCommon(); err != nil {
			return fmt.Errorf("forcing: remove shared systemd artifacts: %w", err)
		}
		if err := d.ConfigStore.RemoveBaseDirIfEmpty(); err != nil {
			return fmt.Errorf("forcing: remove empty account-config dir: %w", err)
		}
		if err := systemd.DaemonReload(ctx, d.SystemdRunner); err != nil {
			return err
		}
	}
	return nil
}

// prepareUnits is the BEFORE-ANY-MUTATION unit preflight both Install and
// Reconfigure open with. It decides who owns the two shared unit files and returns
// the generation params for the anonctl-owned case.
//
// The two modes preflight DIFFERENT things, and the difference is the point:
//
//   - anonctl-owned: resolve the three binaries the generated units will name, so an
//     unresolvable one aborts before a single byte of host state changes. Doing this
//     late is a fail-OPEN regression (the account would exist with live rules but no
//     unit installed, so the next boot loads neither the baseline default-deny nor the
//     forcing).
//   - host-owned: do NOT resolve anything. The host's units name the host's own paths,
//     from the same pin as the binary, so requiring a local `setpriv` or a local shim
//     on $PATH would refuse a correctly configured host over text that is discarded.
//     Assert instead that both declared units exist and that the binaries THEY name
//     exist, which is the same fail-closed property, measured where it now lives.
//
// The unit dir's writability is checked in the HOST-OWNED mode only. In the default
// mode nothing changes: InstallCommon creates that directory and fails loudly there
// exactly as it always has. In host-owned mode there is no unit write left to fail,
// so the per-account enablement symlink becomes the only thing that touches it, and
// an account that cannot be enabled is an account that silently does not come back
// after a reboot.
func prepareUnits(d Deps) (systemd.TemplateParams, systemd.LoaderParams, systemd.UnitOwnership, error) {
	none := func(own systemd.UnitOwnership, err error) (systemd.TemplateParams, systemd.LoaderParams, systemd.UnitOwnership, error) {
		return systemd.TemplateParams{}, systemd.LoaderParams{}, own, fmt.Errorf("forcing: %w", err)
	}
	// The SAME preflight `add` runs before it creates the account, so the two cannot
	// disagree about what this host must satisfy.
	own, err := systemd.PreflightUnits(d.SystemdStore, d.Resolver)
	if err != nil {
		return none(own, err)
	}
	if own.HostOwned {
		// Nothing to generate: the host's files are already in place and were just asserted.
		return systemd.TemplateParams{}, systemd.LoaderParams{}, own, nil
	}
	tp, lp, err := systemd.ResolveUnitParams(d.Resolver)
	if err != nil {
		return none(own, err)
	}
	return tp, lp, own, nil
}

// applyRuleset generates and applies the account's nft rules through the injected
// runner. Split out so Install/Reconfigure share the exact same apply path.
func applyRuleset(ctx context.Context, r nftables.Runner, c accountconfig.Config, exemptions []lanexempt.Exempt) error {
	if err := nftables.Apply(ctx, r, nftParams(c, exemptions)); err != nil {
		return fmt.Errorf("forcing: apply ruleset: %w", err)
	}
	return nil
}

// nftParams maps the at-rest account config to the nftables generator's Params, so
// the live rules and the persisted rule file are generated from the SAME config
// (they can never diverge).
func nftParams(c accountconfig.Config, exemptions []lanexempt.Exempt) nftables.Params {
	return nftables.Params{
		Account:      c.Account,
		AnonUID:      c.AnonUID,
		ShimUID:      c.ShimUID,
		RelayPort:    c.RelayPort,
		DNSPort:      c.DNSPort,
		EndpointHost: c.EndpointHost,
		EndpointPort: c.EndpointPort,
		Exemptions:   exemptions,
	}
}

// normalize fills the config's default ports + schema version so a caller can pass
// just the account + endpoint + UIDs. It mirrors accountconfig's own default-fill
// (the Store also fills on Write); doing it here too keeps the nft Params and the
// persisted config consistent even before the Store write.
func normalize(c accountconfig.Config) accountconfig.Config {
	c.SchemaVersion = accountconfig.SchemaVersion
	if c.RelayPort == 0 {
		c.RelayPort = accountconfig.DefaultRelayPort
	}
	if c.DNSPort == 0 {
		c.DNSPort = accountconfig.DefaultDNSPort
	}
	return c
}
