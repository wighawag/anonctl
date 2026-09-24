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
//   - the anonctl-owned nftables ruleset persisted and loaded at boot by anonctl's
//     OWN early-ordered LOADER unit (`anonctl-nftables.service`), which `nft -f`s
//     anonctl's per-account rule files from `/etc/anonctl/nftables/*.nft`. It is
//     WantedBy=sysinit.target, DefaultDependencies=no, Before=network-pre.target,
//     so it loads BEFORE the network is up and does NOT depend on the host's
//     `nftables.service` (which Debian ships DISABLED). This REPLACES the earlier
//     `nftables.service` drop-in, whose reliance on a host-owned, silently
//     re-disableable unit meant the rules were absent at boot and the anon UID
//     leaked the host's real IP after a reboot (the e2e finding, BUG 1).
//
// The BOOT INVARIANT ("at no point during boot does the anon UID have direct
// egress") holds by INVERSION: each account also has a standing per-UID
// default-deny (internal/nftables.GenerateBaseline) whose resting state is DROP,
// loaded by this same early unit. Forcing (the redirect-into-shim rules) layers on
// top to OPEN the shim path; the ABSENCE of forcing is DROPPED, never free. The
// shim unit only orders After=network.target (it does NOT depend on, nor manage,
// the endpoint's own service, which anonctl does not own): fail-closed by the
// kernel rules means "dropped until the shim and endpoint are up" is safe.
//
// The pure GENERATION (TemplateUnit / EnvFile / LoaderUnit / InstanceName) is
// unit-tested everywhere with no privilege; the install/enable/reload/disable
// WIRING flows every mutation through a Runner (systemctl) and a Store (the file
// writes), so it is unit-testable against fakes and the ONE test that touches real
// systemd/nft lives behind the `integration` build tag.
package systemd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wighawag/anoncore/accountconfig"
	"time"
)

// UnitName is the templated unit's base name. It is an INSTANCE template (the
// trailing `@`), so `anonctl-shim@<account>.service` is one account's instance.
const UnitName = "anonctl-shim@.service"

// DefaultUnitDir is where the template unit file is installed: systemd's own
// load-path table calls it "System units installed by the administrator", which is
// exactly what anonctl is, and it is the natural sibling of the /usr/local/bin
// binary install. It is chosen over /etc/systemd/system because that directory is a
// READ-ONLY Nix store symlink on NixOS, so anonctl could not install itself there at
// all. It is chosen over /run/systemd/system (which IS writable on NixOS) because
// /run is CLEARED AT BOOT: forcing that evaporates on reboot is worse than no
// forcing, since the account still exists and still looks anonymized. This one
// default works on both Debian and NixOS, so nothing here needs a distro check.
// Behind Store.UnitDir so tests write a scratch dir instead of the real one.
const DefaultUnitDir = "/usr/local/lib/systemd/system"

// LegacyUnitDir is where anonctl <= 0.3.0 installed its units. It OUTRANKS
// DefaultUnitDir in systemd's unit load path, so a unit file left behind here would
// SHADOW the one in DefaultUnitDir and silently keep serving the old definition.
// That is why migration (Store.MigrateLegacyUnits) is mandatory rather than
// best-effort: two definitions of the same unit is the one unacceptable outcome.
const LegacyUnitDir = "/etc/systemd/system"

// ShimWantedBy / LoaderWantedBy are the targets whose `.wants/` directories carry
// anonctl's own enablement symlinks. anonctl creates those symlinks ITSELF (see
// Store.EnableUnit) rather than shelling out to `systemctl enable`, because
// `systemctl enable` always writes into the CONFIG dir for the scope
// (/etc/systemd/system) no matter where the unit file lives -- which is read-only on
// NixOS, so the enable would fail even after the unit file moved somewhere writable.
// systemd reads `<target>.wants/` from EVERY directory in the unit load path, so a
// symlink anonctl places in its own unit dir is a real, boot-effective dependency.
const (
	ShimWantedBy   = "multi-user.target"
	LoaderWantedBy = "sysinit.target"
)

// DefaultEnvDir holds the per-account EnvironmentFiles the template instances read
// (`/etc/anonctl/shim/<account>.env`). Anonctl-private (0700/0600): it carries the
// endpoint address (no secret, but not a public signal either).
const DefaultEnvDir = "/etc/anonctl/shim"

// DefaultRulesDir holds the persisted per-account nft rule files anonctl's early
// loader unit loads at boot: both the standing baseline default-deny
// (`<account>.baseline.nft`) and the per-account forcing table (`<account>.nft`).
const DefaultRulesDir = "/etc/anonctl/nftables"

// DefaultShimBinaryPath is the conventional location of the shim binary, used ONLY
// as the last fallback by Resolver.ShimBinary. It is deliberately not trusted
// blindly: install.sh honours $PREFIX, so the shim is frequently NOT here, and on
// NixOS /usr/local/bin does not exist at all.
const DefaultShimBinaryPath = "/usr/local/bin/anonctl-shim"

// ShimBinaryName / SetprivBinaryName / NftBinaryName are the binaries whose
// ABSOLUTE paths get baked into the generated units. They must be resolved at
// install time (Resolver) rather than assumed: a systemd unit has no useful
// inherited $PATH, so ExecStart must be absolute, but the conventional FHS
// locations (/usr/bin/setpriv, /usr/sbin/nft) do not exist on NixOS, where /usr/bin
// holds only `env` and /bin holds only `sh`.
const (
	ShimBinaryName    = "anonctl-shim"
	SetprivBinaryName = "setpriv"
	NftBinaryName     = "nft"
)

// LoaderUnitName is anonctl's OWN early-boot nftables loader unit. It is anonctl's
// unit (not a host unit anonctl mutates), so `add` may enable it without touching
// any host-owned service. It REPLACES the earlier nftables.service drop-in.
const LoaderUnitName = "anonctl-nftables.service"

// TemplateParams parameterises the ONE template unit (account-agnostic: the
// account is the `%i` instance, its per-account params come from the env file).
type TemplateParams struct {
	// ShimBinaryPath is the ABSOLUTE path to the shim binary the ExecStart runs.
	// REQUIRED: TemplateUnit refuses to generate without it, so a unit naming a
	// non-existent binary can never be written. Fill it via Resolver.ShimBinary.
	ShimBinaryPath string
	// SetprivPath is the ABSOLUTE path to setpriv, which the ExecStart uses to drop to
	// the account's shim UID. REQUIRED, for the same reason as ShimBinaryPath: the old
	// hard-coded /usr/bin/setpriv does not exist on NixOS, and a unit carrying it fails
	// 203/EXEC at boot. Fill it via Resolver.Binary(SetprivBinaryName).
	SetprivPath string
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
//
// It returns an ERROR rather than falling back to a conventional path when a
// required binary path is missing. That is deliberate and load-bearing: a unit
// generated with a wrong absolute path fails only at the NEXT BOOT, long after the
// operator saw `add` succeed, so the failure must surface at install time instead.
func TemplateUnit(p TemplateParams) (string, error) {
	if strings.TrimSpace(p.ShimBinaryPath) == "" {
		return "", fmt.Errorf("systemd: refusing to generate %s without a resolved shim binary path", UnitName)
	}
	if strings.TrimSpace(p.SetprivPath) == "" {
		return "", fmt.Errorf("systemd: refusing to generate %s without a resolved %s path", UnitName, SetprivBinaryName)
	}
	bin := p.ShimBinaryPath
	envDir := p.EnvDir
	if envDir == "" {
		envDir = DefaultEnvDir
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# anonctl per-account shim (generated). ONE @-template for all accounts: each")
	w("# account runs as its OWN supervised instance under its OWN dedicated shim UID.")
	w("# The per-account process boundary IS the security boundary (a distinct shim UID")
	w("# per account), which is why this is a templated per-account unit and not a single")
	w("# multiplexer for all accounts.")
	w("#")
	w("# Managed by `anonctl add` / `anonctl rm` -- do not enable this by hand. anonctl")
	w("# writes its OWN enablement symlink into %s.wants/ next to this", ShimWantedBy)
	w("# file, because `systemctl enable` writes into /etc/systemd/system whatever the")
	w("# unit dir is, and that path is read-only on some hosts (NixOS). A consequence:")
	w("# `systemctl is-enabled` will say \"disabled\" even when this IS wired to start at")
	w("# boot. To check for real: systemctl show %s --property=Wants", ShimWantedBy)
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
	// serves every account. There is deliberately NO `-` prefix: a missing env file must
	// be fatal to the START, because an instance that came up without ANONCTL_SHIM_UID,
	// the loopback ports or the endpoint would be a shim running as the wrong uid or
	// pointing nowhere. Failing is fail-closed (the baseline still drops); starting is
	// not. This is now text a HOST may declare, so it must not carry a comment
	// describing a leading dash that is not there.
	w("EnvironmentFile=%s/%%i.env", envDir)
	// Drop to the account's dedicated shim UID (from the env file) via setpriv,
	// exactly as the validated recipe runs the shim. The unit starts as root only to
	// drop privilege; the shim itself never runs as root.
	w("ExecStart=%s --reuid ${ANONCTL_SHIM_UID} --regid ${ANONCTL_SHIM_UID} --clear-groups \\", p.SetprivPath)
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
	w("WantedBy=%s", ShimWantedBy)
	return b.String(), nil
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

// LoaderParams parameterises anonctl's own early-boot nftables loader unit.
type LoaderParams struct {
	// RulesGlob is the shell glob the ExecStart loads at boot; when empty it is
	// `<DefaultRulesDir>/*.nft`.
	RulesGlob string
	// NftPath is the ABSOLUTE path to the nft binary the ExecStart loads the rules
	// with. REQUIRED. This is the most safety-critical of the three resolved paths: the
	// loader is what installs the STANDING BASELINE DEFAULT-DENY at boot, so if it
	// fails, the inversion ADR-0005 relies on never happens and the anon UID egresses
	// FREELY with the host's real IP -- fail-OPEN, and silent. The old hard-coded
	// /usr/sbin/nft does not exist on NixOS, which is exactly that scenario.
	NftPath string
}

// LoaderUnit generates anonctl's OWN early-boot nftables loader unit
// (`anonctl-nftables.service`). It `nft -f`s anonctl's per-account rule files (both
// the standing baseline default-deny and the per-account forcing tables) at boot,
// INDEPENDENT of the host's `nftables.service`. It REPLACES the earlier drop-in on
// nftables.service, whose reliance on a host-owned unit Debian ships disabled meant
// the rules were absent at boot and the anon UID leaked the host's real IP after a
// reboot (the e2e finding, BUG 1). anonctl owns this unit, so `add` enabling it
// mutates no host service; a later `systemctl disable nftables` cannot re-open the
// leak.
//
// It is ordered EARLY so the standing default-deny is present before the anon UID
// could act: WantedBy=sysinit.target (pulled in early), DefaultDependencies=no (not
// held to the normal late boot phase), Before=network-pre.target (loaded before the
// network is configured). The load itself iterates the glob, so a missing/empty
// rules dir is a clean no-op and boot never fails when no account is forced. It is
// a oneshot with RemainAfterExit so systemd tracks it as active after the load.
//
// Like TemplateUnit it refuses to generate without a resolved binary path, because
// this unit failing is fail-OPEN at boot rather than fail-closed.
func LoaderUnit(p LoaderParams) (string, error) {
	if strings.TrimSpace(p.NftPath) == "" {
		return "", fmt.Errorf("systemd: refusing to generate %s without a resolved %s path", LoaderUnitName, NftBinaryName)
	}
	glob := p.RulesGlob
	if glob == "" {
		glob = DefaultRulesDir + "/*.nft"
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# anonctl early-boot nftables loader (generated). anonctl's OWN unit: it does NOT")
	w("# ride on the host's firewall service (which Debian ships disabled, so the rules")
	w("# were absent at boot and the anon UID leaked the host's real IP). It loads")
	w("# anonctl's per-account rule files (the standing baseline default-deny AND the")
	w("# forcing tables) EARLY, before the network is up, so the resting-state DROP is")
	w("# present from the first moment the anon UID could egress (the boot invariant).")
	w("[Unit]")
	w("Description=anonctl early-boot nftables loader (baseline default-deny + forcing)")
	// Run early: not held to the normal late boot phase, and ordered before the
	// network is configured, so the deny is up before any egress is possible.
	w("DefaultDependencies=no")
	w("Before=network-pre.target")
	w("Wants=network-pre.target")
	w("")
	w("[Service]")
	w("Type=oneshot")
	w("RemainAfterExit=yes")
	// Load each anonctl per-account rule file. `sh -c` so the glob expands at boot;
	// a missing/empty dir is a clean no-op (the for-loop body never runs), so boot
	// never fails when no account is forced. Each file is a self-contained atomic
	// `nft -f` load of that account's own table.
	w("ExecStart=/bin/sh -c 'for f in %s; do [ -e \"$f\" ] && %s -f \"$f\"; done'", glob, p.NftPath)
	w("")
	w("[Install]")
	w("WantedBy=%s", LoaderWantedBy)
	return b.String(), nil
}

// Resolver turns a binary NAME into the ABSOLUTE path that gets baked into a
// generated unit. Both lookups are injectable so the resolution rules are
// unit-testable with no root and no dependency on the host's actual $PATH.
type Resolver struct {
	// Look resolves a bare name against $PATH; exec.LookPath when nil.
	Look func(name string) (string, error)
	// Executable reports the running anonctl binary's own path; os.Executable when nil.
	Executable func() (string, error)
}

func (r Resolver) look(name string) (string, error) {
	if r.Look != nil {
		return r.Look(name)
	}
	return exec.LookPath(name)
}

func (r Resolver) executable() (string, error) {
	if r.Executable != nil {
		return r.Executable()
	}
	return os.Executable()
}

// Binary resolves a required helper binary (setpriv, nft) to an absolute path via
// $PATH. It returns a LOUD error naming the binary when it cannot be found, so
// `add` fails at install time rather than emitting a unit that dies at the next
// boot. It never falls back to a conventional FHS path: that is precisely the
// assumption that produced a fail-open loader on NixOS.
//
// NEVER RESOLVE THE SYMLINK. exec.LookPath returns the $PATH entry VERBATIM, and
// that is exactly what must be baked into the unit. On NixOS every tool has two
// absolute paths:
//
//	/run/current-system/sw/bin/nft                      <- STABLE: repointed on every rebuild
//	/nix/store/<hash>-nftables-1.1.6/bin/nft            <- what EvalSymlinks/realpath gives
//
// The store path is correct today and WRONG the moment nftables is updated or the
// system is rebuilt: the old store path is garbage-collected, ExecStart points at a
// file that no longer exists, the loader fails 203/EXEC, and the account is silently
// unjailed with no baseline default-deny -- weeks after the install, with nothing in
// the config having changed. filepath.Abs is safe here (it only Cleans an already
// absolute path); filepath.EvalSymlinks would NOT be. On Debian LookPath yields
// /usr/sbin/nft and the same code works, so this is one code path, not a distro
// branch.
func (r Resolver) Binary(name string) (string, error) {
	path, err := r.look(name)
	if err != nil {
		return "", fmt.Errorf("systemd: cannot resolve %q, which anonctl must bake into a generated unit as an absolute path: %w", name, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("systemd: resolve %q to an absolute path: %w", name, err)
	}
	return abs, nil
}

// preferStableAlias returns a $PATH entry that refers to the SAME FILE as candidate,
// when one exists, and otherwise candidate unchanged.
//
// This exists because os.Executable() RESOLVES symlinks (it reads /proc/self/exe on
// Linux). So when anonctl is itself invoked through a symlink -- which is the normal
// case on NixOS, where /run/current-system/sw/bin/anonctl points into the store --
// the "sibling of the running binary" rule yields a /nix/store/... path. Baking that
// into a unit is the garbage-collection time bomb described on Binary above. If a
// $PATH entry names the same inode, it is the administrator-facing alias and stays
// valid across rebuilds, so prefer it.
//
// It is a general rule, not a NixOS branch: on Debian the sibling and the $PATH entry
// are usually the same path already, so this changes nothing there. Note it compares
// by inode and only ever RETURNS one of the two unresolved paths; it never bakes the
// resolved target.
func (r Resolver) preferStableAlias(candidate string) string {
	onPath, err := r.look(ShimBinaryName)
	if err != nil {
		return candidate
	}
	if abs, aerr := filepath.Abs(onPath); aerr == nil && sameFile(abs, candidate) {
		return abs
	}
	return candidate
}

// sameFile reports whether two paths name the same file, following symlinks. Used
// only for COMPARISON; the resolved path is never returned or baked.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// ShimBinary resolves the shim binary the template unit's ExecStart runs. It tries,
// in order: the SIBLING of the running anonctl executable, then $PATH, then
// DefaultShimBinaryPath if that file actually exists. The sibling rule comes first
// because install.sh installs BOTH binaries into $PREFIX, so the shim sits next to
// the anonctl that is running right now -- which is what makes a non-default PREFIX
// work without the operator hand-editing the unit. The old behaviour (hard-code
// /usr/local/bin/anonctl-shim regardless of PREFIX) is the fallback of last resort,
// and only when the file is really there.
// The sibling candidate is passed through preferStableAlias, because os.Executable
// resolves symlinks and would otherwise hand back a garbage-collectable store path
// on NixOS.
func (r Resolver) ShimBinary() (string, error) {
	if self, err := r.executable(); err == nil && self != "" {
		sibling := filepath.Join(filepath.Dir(self), ShimBinaryName)
		if st, serr := os.Stat(sibling); serr == nil && !st.IsDir() {
			return r.preferStableAlias(sibling), nil
		}
	}
	if path, err := r.look(ShimBinaryName); err == nil {
		if abs, aerr := filepath.Abs(path); aerr == nil {
			return abs, nil
		}
	}
	if st, err := os.Stat(DefaultShimBinaryPath); err == nil && !st.IsDir() {
		return DefaultShimBinaryPath, nil
	}
	return "", fmt.Errorf("systemd: cannot find the %q binary (looked next to the running anonctl, on $PATH, and at %s); install it before forcing an account", ShimBinaryName, DefaultShimBinaryPath)
}

// PreflightUnitBinaries checks that every binary the generated units will name can
// be resolved, WITHOUT producing or writing anything. `add` calls it before it
// creates the UNIX account, so a host missing `nft`, `setpriv` or the shim is
// refused while the box is still UNTOUCHED.
//
// This placement is load-bearing, not defensive tidiness. Discovering the problem
// later -- after the account exists and the live rules are applied but before the
// units are installed -- would leave an account that EXISTS with NO unit enabled, so
// the next boot would load neither the baseline default-deny nor the forcing and the
// anon UID would egress with the host's real IP. Refusing before anything is created
// keeps the failure fail-closed in the only sense that matters: nothing was changed.
func PreflightUnitBinaries(r Resolver) error {
	_, _, err := ResolveUnitParams(r)
	return err
}

// ResolveUnitParams builds the fully-resolved generation params for BOTH units in
// one place, so `add` fails loudly and EARLY -- before it has written any unit -- if
// any of the three binaries cannot be found.
func ResolveUnitParams(r Resolver) (TemplateParams, LoaderParams, error) {
	shim, err := r.ShimBinary()
	if err != nil {
		return TemplateParams{}, LoaderParams{}, err
	}
	setpriv, err := r.Binary(SetprivBinaryName)
	if err != nil {
		return TemplateParams{}, LoaderParams{}, err
	}
	nft, err := r.Binary(NftBinaryName)
	if err != nil {
		return TemplateParams{}, LoaderParams{}, err
	}
	return TemplateParams{ShimBinaryPath: shim, SetprivPath: setpriv}, LoaderParams{NftPath: nft}, nil
}

// Runner abstracts `systemctl` (and `systemd`-adjacent) shell-outs so the
// enable/disable/reload WIRING is unit-testable without touching real systemd
// (mirrors provision.Runner / nftables.Runner). anonctl runs these as root.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// WaitUntilActive blocks until the account's shim instance is genuinely ACTIVE, or
// returns a loud error naming what to look at.
//
// IT EXISTS BECAUSE `systemctl restart` LIES HERE, and that is measured, not
// assumed. The shim unit carries `Restart=on-failure`, and with that directive a
// start that fails immediately (a missing ExecStart binary, 203/EXEC) leaves the
// unit in `activating` for its auto-restart backoff rather than `failed`, so the
// restart JOB is reported as succeeding and `systemctl restart` exits 0. Probed
// directly with a throwaway user unit: without Restart=on-failure the same failure
// exits 1; with it, exit 0 and `is-active` says `activating`.
//
// The consequence was real: `update` printed "re-applied fail-closed, no leak
// window" over a shim that never came up, and the account lost its forced DNS
// until the next verify caught it. A restart is not done when the job is accepted;
// it is done when the service is up, so that is what this checks.
func WaitUntilActive(ctx context.Context, r Runner, account string, within time.Duration) error {
	inst := InstanceName(account)
	deadline := time.Now().Add(within)
	var last string
	for {
		out, _, _ := r.Run(ctx, "systemctl", "is-active", inst)
		last = strings.TrimSpace(out)
		if last == "active" {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("systemd: %s did not become active within %s (state: %q). `systemctl restart` reports success for a unit that is merely RETRYING, so the job was accepted and the service still did not come up. Look at `systemctl status %s` and `journalctl -u %s -n 50`: the usual cause is status=203/EXEC, an ExecStart naming a binary that has moved or been removed",
		inst, within, last, inst, inst)
}

// DaemonReload runs `systemctl daemon-reload` so a newly written/removed unit or
// drop-in is picked up before it is enabled/disabled.
func DaemonReload(ctx context.Context, r Runner) error {
	if _, stderr, err := r.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemd: daemon-reload: %w: %s", err, stderr)
	}
	return nil
}

// StartNow starts the account's shim instance
// (`systemctl start anonctl-shim@<account>.service`), so `add` brings the shim up
// immediately. It is the "--now" half of what used to be `enable --now`; the
// "comes back after a reboot" half is now Store.EnableUnit's symlink, because
// `systemctl enable` cannot write its symlink on a host whose /etc/systemd/system
// is read-only. Starting is separated from enabling so the two halves fail
// independently and legibly.
func StartNow(ctx context.Context, r Runner, account string) error {
	inst := InstanceName(account)
	if _, stderr, err := r.Run(ctx, "systemctl", "start", inst); err != nil {
		return fmt.Errorf("systemd: start %s: %w: %s", inst, err, stderr)
	}
	return nil
}

// StopNow stops the account's shim instance
// (`systemctl stop anonctl-shim@<account>.service`), the teardown counterpart of
// StartNow. Boot-time de-enablement is Store.DisableUnit's symlink removal. Stopping
// an already-stopped instance is a clean no-op, so this stays idempotent.
func StopNow(ctx context.Context, r Runner, account string) error {
	inst := InstanceName(account)
	if _, stderr, err := r.Run(ctx, "systemctl", "stop", inst); err != nil {
		return fmt.Errorf("systemd: stop %s: %w: %s", inst, err, stderr)
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
