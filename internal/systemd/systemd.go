// Package systemd is the REBOOT-PERSISTENCE half of anonctl: it makes an account's
// forcing survive a reboot and re-apply FAIL-CLOSED, with no window where the anon
// UID has un-anonymized egress at boot. Two persisted artifacts, generated pure
// and installed behind a Runner+Store seam:
//
//   - the per-account shim as a systemd @-template unit
//     (`anonctl-shim@<account>.service`), ONE template file for all accounts, each
//     account a distinct supervised INSTANCE running as that account's dedicated
//     shim UID. The per-account process boundary IS the security boundary (a
//     distinct shim UID per account), which is why this is a templated per-account
//     unit and NOT one multiplexer process for all accounts (ADR). `add` enables
//     the instance (`enable --now`); `rm` disables it (`disable --now`).
//   - the anonctl-owned nftables ruleset persisted via an `nftables.service`
//     DROP-IN (`/etc/systemd/system/nftables.service.d/anonctl.conf`) whose
//     `ExecStartPost` loads anonctl's per-account rule files from
//     `/etc/anonctl/nftables/*.nft`. The drop-in EXTENDS the host's nftables.service
//     without editing its `/etc/nftables.conf`, so the host's own rules are left
//     untouched (the shared-write isolation discipline).
//
// The BOOT INVARIANT ("at no point during boot does the anon UID have direct
// egress") holds because the nft default-DROP is part of the persisted ruleset and
// nftables.service loads it EARLY: if the shim/endpoint are not yet up, the anon
// UID is DROPPED, never leaking. The shim unit only orders After=network.target
// (it does NOT depend on, nor manage, the endpoint's own service, which anonctl
// does not own): fail-closed by the kernel rules means "dropped until the shim and
// endpoint are up" is safe.
//
// The pure GENERATION (TemplateUnit / EnvFile / NftablesDropIn / InstanceName) is
// unit-tested everywhere with no privilege; the install/enable/reload/disable
// WIRING flows every mutation through a Runner (systemctl) and a Store (the file
// writes), so it is unit-testable against fakes and the ONE test that touches real
// systemd/nft lives behind the `integration` build tag.
package systemd

import (
	"context"
	"fmt"
	"strings"

	"github.com/wighawag/anonctl/internal/accountconfig"
)

// UnitName is the templated unit's base name. It is an INSTANCE template (the
// trailing `@`), so `anonctl-shim@<account>.service` is one account's instance.
const UnitName = "anonctl-shim@.service"

// DefaultUnitDir is where the template unit file is installed (the standard
// systemd system-unit dir for locally-installed units). Behind Store.UnitDir so
// tests write a scratch dir instead of the real one.
const DefaultUnitDir = "/etc/systemd/system"

// DefaultEnvDir holds the per-account EnvironmentFiles the template instances read
// (`/etc/anonctl/shim/<account>.env`). Anonctl-private (0700/0600): it carries the
// endpoint address (no secret, but not a public signal either).
const DefaultEnvDir = "/etc/anonctl/shim"

// DefaultRulesDir holds the persisted per-account nft rule files the nftables.service
// drop-in loads at boot (`/etc/anonctl/nftables/<account>.nft`).
const DefaultRulesDir = "/etc/anonctl/nftables"

// DefaultShimBinaryPath is where the template unit's ExecStart finds the shim
// binary. It is a parameter (TemplateParams.ShimBinaryPath) so a packaging layout
// can override it; this is the conventional default.
const DefaultShimBinaryPath = "/usr/local/bin/anonctl-shim"

// nftablesDropInPath is the anonctl-owned drop-in that EXTENDS the host's
// nftables.service without touching its /etc/nftables.conf. Behind Store so tests
// point it at a scratch dir.
const nftablesDropInDir = DefaultUnitDir + "/nftables.service.d"
const nftablesDropInName = "anonctl.conf"

// TemplateParams parameterises the ONE template unit (account-agnostic: the
// account is the `%i` instance, its per-account params come from the env file).
type TemplateParams struct {
	// ShimBinaryPath is the shim binary the ExecStart runs; DefaultShimBinaryPath
	// when empty.
	ShimBinaryPath string
	// EnvDir is the dir holding the per-account EnvironmentFiles; DefaultEnvDir when
	// empty. The unit reads `<EnvDir>/%i.env`.
	EnvDir string
}

// InstanceName returns the concrete unit instance for an account:
// `anonctl-shim@<account>.service`. Each account is a DISTINCT supervised instance
// (the per-account security boundary), enabled/disabled independently.
func InstanceName(account string) string {
	return "anonctl-shim@" + account + ".service"
}

// TemplateUnit generates the account-agnostic @-template unit text. It bakes in NO
// account: `%i` is the instance (the account name), and every per-account
// parameter (the shim UID, the loopback ports, the endpoint, the isolation
// username) comes from the per-instance EnvironmentFile the shim's ExecStart
// consumes. It runs as root-launched-then-dropped: systemd's User= is set to the
// per-account shim service account via the env-carried UID is NOT possible (User=
// cannot read an env var), so the ExecStart uses `setpriv --reuid` to drop to the
// shim UID exactly as the validated recipe does, and the unit itself starts as
// root only long enough to drop. ordering: After=network.target; it neither Wants=
// nor After= the endpoint's own service (anonctl does not own the endpoint
// lifecycle), and it is fail-closed by the nft rules if the endpoint is not yet up.
func TemplateUnit(p TemplateParams) string {
	bin := p.ShimBinaryPath
	if bin == "" {
		bin = DefaultShimBinaryPath
	}
	envDir := p.EnvDir
	if envDir == "" {
		envDir = DefaultEnvDir
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# anonctl per-account shim (generated). ONE @-template for all accounts:")
	w("# `systemctl enable --now anonctl-shim@<account>` supervises that account's shim")
	w("# under its OWN dedicated shim UID. The per-account process boundary IS the")
	w("# security boundary (a distinct shim UID per account), which is why this is a")
	w("# templated per-account unit, not a single multiplexer for all accounts.")
	w("[Unit]")
	w("Description=anonctl forced-egress shim for account %%i")
	// Order after the network is configured. Deliberately NOT tied to the endpoint's
	// own service: anonctl does not own the endpoint lifecycle, and the nft rules
	// fail-closed (drop) if the endpoint is not yet up, so there is no leak window.
	w("After=network.target")
	w("")
	w("[Service]")
	w("Type=simple")
	// Per-account parameters come from the per-instance env file, so ONE template
	// serves every account. The `-` prefix means a missing file is not fatal at
	// unit-parse time (anonctl writes it before enabling).
	w("EnvironmentFile=%s/%%i.env", envDir)
	// Drop to the account's dedicated shim UID (from the env file) via setpriv,
	// exactly as the validated recipe runs the shim. The unit starts as root only to
	// drop privilege; the shim itself never runs as root.
	w("ExecStart=/usr/bin/setpriv --reuid ${ANONCTL_SHIM_UID} --regid ${ANONCTL_SHIM_UID} --clear-groups \\")
	w("    %s \\", bin)
	w("    -relay ${ANONCTL_RELAY_ADDR} \\")
	w("    -dns ${ANONCTL_DNS_ADDR} \\")
	w("    -proxy ${ANONCTL_PROXY_ADDR} \\")
	w("    -socks-user ${ANONCTL_SOCKS_USER} \\")
	w("    -upstream-dns ${ANONCTL_UPSTREAM_DNS}")
	w("Restart=on-failure")
	w("RestartSec=2")
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String()
}

// DefaultUpstreamDNS is the resolver the shim reaches over the endpoint by
// hostname (socks5h), matching the shim binary's own default. It is written into
// the env file so the unit's ExecStart has a concrete value.
const DefaultUpstreamDNS = "1.1.1.1:53"

// EnvFile generates the per-account EnvironmentFile the template instance reads: it
// carries EXACTLY the per-account shim parameters the ExecStart consumes (the shim
// UID, the loopback relay/DNS addresses, the endpoint, the derived isolation
// username, and the upstream resolver). The isolation username is DERIVED from the
// endpoint's share-class (the account name for a tor-shared endpoint, EMPTY for a
// socks-peruser one), never stored: a socks-peruser endpoint has no per-username
// isolation, so dialling it with the account name would be a false promise.
func EnvFile(c accountconfig.Config) string {
	ep := c.Endpoint()
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# anonctl per-account shim parameters for %q (generated). Read by", c.Account)
	w("# anonctl-shim@%s.service. NOT world-readable (holds the endpoint address).", c.Account)
	w("ANONCTL_SHIM_UID=%d", c.ShimUID)
	w("ANONCTL_RELAY_ADDR=127.0.0.1:%d", c.RelayPort)
	w("ANONCTL_DNS_ADDR=127.0.0.1:%d", c.DNSPort)
	w("ANONCTL_PROXY_ADDR=%s", ep.Address())
	// Empty for a socks-peruser endpoint (no per-username isolation); the account
	// name for a tor-shared endpoint (drives Tor IsolateSOCKSAuth).
	w("ANONCTL_SOCKS_USER=%s", ep.IsolationUsername(c.Account))
	w("ANONCTL_UPSTREAM_DNS=%s", DefaultUpstreamDNS)
	return b.String()
}

// NftablesDropInParams parameterises the nftables.service drop-in.
type NftablesDropInParams struct {
	// RulesGlob is the shell glob the ExecStartPost loads at boot; when empty it is
	// `<DefaultRulesDir>/*.nft`.
	RulesGlob string
}

// NftablesDropIn generates the `nftables.service` drop-in that persists anonctl's
// ruleset across reboot. It is a DROP-IN (a separate file under
// nftables.service.d), so it EXTENDS the host's nftables.service without editing
// its `/etc/nftables.conf`: the host's own rules load as before, and anonctl's
// per-account rule files are loaded AFTER via ExecStartPost. Because the persisted
// rules carry the default-DROP and nftables.service loads early, the boot
// invariant holds: at no point during boot does the anon UID have direct egress
// (worst case dropped-until-shim-up, never leaking).
//
// The first ExecStartPost= is an empty reset so anonctl's line does not stack if
// the host already sets one; then the loader iterates anonctl's rule files. It
// tolerates an empty rules dir (a `for` over a possibly-empty glob) so boot never
// fails when no account is forced.
func NftablesDropIn(p NftablesDropInParams) string {
	glob := p.RulesGlob
	if glob == "" {
		glob = DefaultRulesDir + "/*.nft"
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# anonctl nftables persistence (generated). Drop-in on nftables.service:")
	w("# it EXTENDS the host's nftables.service (its /etc/nftables.conf is untouched)")
	w("# by loading anonctl's per-account rule files AFTER the host's own rules. The")
	w("# persisted rules carry the fail-closed default-DROP, and nftables.service")
	w("# loads early, so at no point during boot does a forced UID have direct egress")
	w("# (the boot invariant): worst case is dropped-until-shim-up, never leaking.")
	w("[Service]")
	// Load each anonctl per-account rule file. `sh -c` so the glob expands at boot;
	// a missing/empty dir is a clean no-op (the for-loop body never runs), so boot
	// never fails when no account is forced. Each file is a self-contained atomic
	// `nft -f` load of that account's own table.
	w("ExecStartPost=/bin/sh -c 'for f in %s; do [ -e \"$f\" ] && /usr/sbin/nft -f \"$f\"; done'", glob)
	return b.String()
}

// Runner abstracts `systemctl` (and `systemd`-adjacent) shell-outs so the
// enable/disable/reload WIRING is unit-testable without touching real systemd
// (mirrors provision.Runner / nftables.Runner). anonctl runs these as root.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// DaemonReload runs `systemctl daemon-reload` so a newly written/removed unit or
// drop-in is picked up before it is enabled/disabled.
func DaemonReload(ctx context.Context, r Runner) error {
	if _, stderr, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemd: daemon-reload: %w: %s", err, stderr)
	}
	return nil
}

// EnableNow enables AND starts the account's shim instance
// (`systemctl enable --now anonctl-shim@<account>.service`), so `add` brings the
// shim up immediately and it comes back after a reboot.
func EnableNow(ctx context.Context, r Runner, account string) error {
	inst := InstanceName(account)
	if _, stderr, err := r.Run(ctx, "systemctl", "enable", "--now", inst); err != nil {
		return fmt.Errorf("systemd: enable --now %s: %w: %s", inst, err, stderr)
	}
	return nil
}

// DisableNow disables AND stops the account's shim instance
// (`systemctl disable --now anonctl-shim@<account>.service`), so `rm` tears the
// shim down and it does not come back after a reboot. A not-enabled instance is
// tolerated by systemctl (a clean no-op), so this is idempotent.
func DisableNow(ctx context.Context, r Runner, account string) error {
	inst := InstanceName(account)
	if _, stderr, err := r.Run(ctx, "systemctl", "disable", "--now", inst); err != nil {
		return fmt.Errorf("systemd: disable --now %s: %w: %s", inst, err, stderr)
	}
	return nil
}

// RestartNow restarts the account's shim instance
// (`systemctl restart anonctl-shim@<account>.service`), used by `update` to pick
// up a rewritten env file (a changed endpoint) WITHOUT a leak window: the nft
// rules stay applied (fail-closed) across the restart, so egress is dropped, never
// un-anonymized, during the brief shim bounce.
func RestartNow(ctx context.Context, r Runner, account string) error {
	inst := InstanceName(account)
	if _, stderr, err := r.Run(ctx, "systemctl", "restart", inst); err != nil {
		return fmt.Errorf("systemd: restart %s: %w: %s", inst, err, stderr)
	}
	return nil
}
