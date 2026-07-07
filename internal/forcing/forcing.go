// Package forcing is the ORCHESTRATION seam that installs, removes, and
// reconfigures an account's forced-egress persistence: it ties together the
// account config (internal/accountconfig, the at-rest record), the kernel rules
// (internal/nftables, generate + apply), and the systemd persistence
// (internal/systemd, the @-template shim unit + the nftables.service drop-in +
// the per-account env/rule files). It is what `add` / `rm` / `update` call after
// the account itself is provisioned.
//
// It is designed around the BOOT INVARIANT and the NO-LEAK-WINDOW property:
//
//   - Install and Reconfigure APPLY the nft rules (which carry the fail-closed
//     default-DROP) and PERSIST them (the rule file the boot drop-in loads) so the
//     forcing survives a reboot and re-applies fail-closed. The persisted default-
//     DROP loading early is what makes the boot invariant hold.
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

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/systemd"
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
func Install(ctx context.Context, d Deps, c accountconfig.Config, exemptions []lanexempt.Exempt) error {
	c = normalize(c)
	if err := d.ConfigStore.Write(c); err != nil {
		return fmt.Errorf("forcing: persist account config: %w", err)
	}

	ruleset, err := nftables.Generate(nftParams(c, exemptions))
	if err != nil {
		return fmt.Errorf("forcing: generate ruleset: %w", err)
	}
	// Apply the live rules (fail-closed default-DROP) FIRST, then persist the rule
	// file the boot drop-in loads, so the running state and the persisted state
	// agree and the account is forced both now and after a reboot.
	if err := applyRuleset(ctx, d.NftRunner, c, exemptions); err != nil {
		return err
	}
	if err := d.SystemdStore.WriteAccount(c, ruleset); err != nil {
		return fmt.Errorf("forcing: persist per-account systemd files: %w", err)
	}

	// Install the account-agnostic template unit + nftables.service drop-in
	// (idempotent), reload systemd so they are picked up, then enable --now the
	// account's shim instance.
	if err := d.SystemdStore.InstallCommon(systemd.TemplateParams{}, systemd.NftablesDropInParams{}); err != nil {
		return fmt.Errorf("forcing: install common systemd artifacts: %w", err)
	}
	if err := systemd.DaemonReload(ctx, d.SystemdRunner); err != nil {
		return err
	}
	if err := systemd.EnableNow(ctx, d.SystemdRunner, c.Account); err != nil {
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
	if err := d.ConfigStore.Write(c); err != nil {
		return fmt.Errorf("forcing: rewrite account config: %w", err)
	}

	ruleset, err := nftables.Generate(nftParams(c, exemptions))
	if err != nil {
		return fmt.Errorf("forcing: generate ruleset: %w", err)
	}
	// Re-apply the rules FIRST (atomic table replace: the default-DROP is never
	// gone), so the new endpoint's closure (b) is in force before the shim is
	// pointed at it. Persist the new rule file so a reboot re-applies the new state.
	if err := applyRuleset(ctx, d.NftRunner, c, exemptions); err != nil {
		return err
	}
	if err := d.SystemdStore.WriteAccount(c, ruleset); err != nil {
		return fmt.Errorf("forcing: re-persist per-account systemd files: %w", err)
	}
	// Restart the shim to pick up the rewritten env file (the new endpoint). The
	// still-applied fail-closed rules cover the brief bounce, so no leak window.
	if err := systemd.RestartNow(ctx, d.SystemdRunner, c.Account); err != nil {
		return err
	}
	return nil
}

// Remove turns off forcing for an account: it disables --now the shim instance,
// deletes the live nft table (leaving every other table untouched), and removes
// the per-account systemd files and the at-rest config. It is idempotent: a
// not-enabled instance, an absent table's delete, and a missing file are all clean
// no-ops (a torn-down account leaves no residue). The marker removal stays in the
// caller (rm already removes it), so this focuses on the forcing artifacts.
func Remove(ctx context.Context, d Deps, account string) error {
	// Stop + disable the shim first so it is not left running against rules we are
	// about to delete.
	if err := systemd.DisableNow(ctx, d.SystemdRunner, account); err != nil {
		return err
	}
	// Delete only this account's table; ignore a not-found (idempotent teardown).
	if err := nftables.Delete(ctx, d.NftRunner, account); err != nil {
		// A missing table on teardown is not a failure: the account may never have
		// been forced. We surface any OTHER error, but tolerate the absent-table case
		// by not aborting rm. The nftables.Delete error text carries nft's message;
		// callers that must distinguish can, but rm's contract is idempotent teardown.
		_ = err
	}
	if err := d.SystemdStore.RemoveAccount(account); err != nil {
		return fmt.Errorf("forcing: remove per-account systemd files: %w", err)
	}
	if err := d.ConfigStore.Remove(account); err != nil {
		return fmt.Errorf("forcing: remove account config: %w", err)
	}
	return nil
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
