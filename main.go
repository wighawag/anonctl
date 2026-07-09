// Command anonctl provisions a dedicated Unix account (`anon` by default,
// `anon-<name>` for named ones) plus its own dedicated shim service account, and
// (in later tasks) forces all of that account's egress through an anonymizer at
// the kernel level, fail-closed. This entry point wires the PURE CLI surface
// (internal/cli: verb dispatch + account-name resolution) to the provisioning
// engine (internal/provision) behind the Runner seam, so the four verbs
// (add/rm/list/status) work end-to-end while verify/update/reconfigure dispatch
// as stubs later tasks fill.
//
// This task delivers the account + shim-UID lifecycle only: NO egress forcing
// (that is the nftables/persistence tasks). Provisioning mutates the system as
// root (the ufw stance), so add/rm require privilege; list/status are read-only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/marker"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/provision"
	"github.com/wighawag/anonctl/internal/systemd"
	"github.com/wighawag/anonctl/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// `anonctl --version` / `anonctl version` prints and exits before any parse.
	if isVersionArg(args) {
		fmt.Println("anonctl " + resolveVersion())
		return 0
	}

	cmd, err := cli.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %v\n", err)
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	// Self-elevation: a root-requiring verb (add/rm/verify/use/update/reconfigure)
	// run WITHOUT root re-execs itself via `sudo <self> <args...>`, so a bare
	// `anonctl verify` prompts for the password inline (no `sudo anonctl` prefix
	// needed) and hands off with the child's exit code. Already-root runs directly
	// (no double-sudo); read verbs (list/status) never elevate; sudo-absent falls
	// through to the verb's own "must be root" error. The re-exec passes the ORIGINAL
	// args unchanged (flags/account/--json), and the notice is on stderr so `--json`
	// stdout stays pure. See elevate.go.
	if handled, code := maybeElevate(cmd.Verb, args); handled {
		return code
	}

	// SIGINT/SIGTERM cancels the context that flows into provisioning, so a
	// long-running useradd is interruptible cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := provision.ExecRunner{}
	switch cmd.Verb {
	case "add":
		return runAdd(ctx, runner, cmd)
	case "rm":
		return runRm(ctx, runner, cmd)
	case "list":
		return runList(ctx, runner, cmd)
	case "status":
		return runStatus(ctx, runner, cmd)
	case "verify":
		return runVerify(ctx, runner, cmd)
	case "use":
		return runUse(ctx, runner, cmd)
	case "update", "reconfigure":
		return runUpdate(ctx, runner, cmd)
	default:
		fmt.Fprintf(os.Stderr, "anonctl: unknown verb %q\n%s\n", cmd.Verb, usage)
		return 2
	}
}

// runAdd provisions the account + its dedicated shim UID, then INSTALLS the forcing
// (the standing baseline default-deny + the nft forcing rules + the persisted
// systemd shim unit + anonctl's own early-boot loader unit), so the account is
// anonymized live AND across a reboot fail-closed - and DROPPED, never free, even if
// the forcing rules never load. It must run as
// root (useradd/nft/systemctl); a non-root run surfaces the underlying command's
// own permission error. Provisioning is idempotent and the forcing install is an
// atomic replace, so re-running `add` cleanly re-applies.
func runAdd(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	res, err := provision.Add(ctx, r, cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: %v\n", err)
		return 1
	}

	// Build the at-rest config from the just-provisioned UIDs and the chosen
	// endpoint (default Tor SocksPort when none named), then install the forcing.
	cfg, err := buildConfig(ctx, r, cmd.Account, cmd.Endpoint, cmd.Exemptions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: %v\n", err)
		return 1
	}
	if err := forcing.Install(ctx, forcingDeps(), cfg, cmd.Exemptions); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: installing forcing: %v\n", err)
		return 1
	}

	if res.Created {
		fmt.Printf("provisioned + forced %s (shim %s, endpoint %s)\n", res.Account, res.Shim, cfg.Endpoint().URL())
	} else {
		fmt.Printf("%s already existed; re-applied forcing (shim %s, endpoint %s)\n", res.Account, res.Shim, cfg.Endpoint().URL())
	}
	fmt.Printf("note: anonctl does NOT manage the endpoint's own service; enable your endpoint (e.g. `systemctl enable --now tor.service`) so it is up at boot\n")
	fmt.Printf("run `%s` to prove the account is anonymized\n", verifyHint(cmd.Account))
	return 0
}

// The rm teardown seams: package vars so the unit tests inject fakes and assert
// the teardown ORDER (the disable-shim call is recorded BEFORE the shim userdel)
// at the runRm seam, mirroring the `use` seams. Production wires the real
// forcing.Remove (which disables --now the shim) and provision.Rm (which userdels).
var (
	// rmForcingRemove disables --now the shim, deletes the account's nft tables +
	// persisted state, and (last account) removes the shared units + empty dirs.
	rmForcingRemove = forcing.Remove
	// rmProvisionRm userdels the login + shim accounts (only under --purge-account).
	rmProvisionRm = provision.Rm
	// rmMarkerStore is the marker Store runRm removes the stale claim through. It is
	// a package var (like the seams above) so the unit tests point it at a scratch
	// t.TempDir() instead of the real `/etc/anonctl` (the shared-write isolation
	// discipline the marker's own tests use via Store.BaseDir). Production wires the
	// real DefaultStore (`/etc/anonctl`).
	rmMarkerStore = marker.DefaultStore()
)

// runRm tears an account's forcing down and, only under --purge-account, deletes
// the account + its shim. A bare rm leaves the home intact. It ALSO removes the
// marker (the double-anonymization claim): teardown must not leave a stale
// `/etc/anonctl/<account>.json` asserting an account is still forced.
//
// ORDER (the fix for the e2e teardown regression, BUG 1): the shim unit is
// disabled --now (rmForcingRemove) BEFORE its account is userdel'd (rmProvisionRm),
// because `userdel` REFUSES ("user is currently used by process") while the shim is
// still running as that UID. Removing forcing first also clears the nft tables and
// persisted state (and, on the last account, the shared units + empty dirs) before
// the accounts go, so the last-account cleanup is reached instead of aborting at
// the userdel. See ADR-0005 (teardown ordering).
//
// PROCEED-AND-REPORT: each step runs even if an earlier one failed, and the first
// error is surfaced with a non-zero exit. A half-torn-down account that silently
// stopped on the first error is worse than a fully-attempted, reported partial.
func runRm(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	var firstErr error
	fail := func(what string, err error) {
		fmt.Fprintf(os.Stderr, "anonctl: rm: %s: %v\n", what, err)
		if firstErr == nil {
			firstErr = err
		}
	}

	// 1. Remove the forcing: disable --now the shim (so nothing runs as the shim UID),
	// delete the account's nft tables, the persisted env/rule files + at-rest config,
	// and (last account) the shared units + empty dirs. This MUST precede the userdel.
	if err := rmForcingRemove(ctx, forcingDeps(), cmd.Account); err != nil {
		fail("removing forcing", err)
	}
	// 2. Delete the accounts (only under --purge-account), now that the shim unit is
	// stopped so `userdel` no longer fails on a live shim UID. A bare rm never userdels.
	res, err := rmProvisionRm(ctx, r, cmd.Account, cmd.PurgeAccount)
	if err != nil {
		fail("removing account", err)
	}
	// 3. Remove the marker (idempotent: a missing marker is a clean no-op), so a
	// torn-down account never leaves a stale "already forced" claim behind.
	if err := rmMarkerStore.Remove(cmd.Account); err != nil {
		fail("removing marker", err)
	}

	if firstErr != nil {
		return 1
	}
	switch {
	case res.AccountRemoved:
		fmt.Printf("removed %s and its shim %s\n", res.Account, res.Shim)
	case cmd.PurgeAccount:
		fmt.Printf("%s did not exist; nothing to remove\n", res.Account)
	default:
		fmt.Printf("removed forcing for %s; account left intact (pass --purge-account to delete it)\n", res.Account)
	}
	return 0
}

// runList enumerates the anon accounts that exist on the box, reading the real
// passwd table (not a maintained index). Read-only: no root needed.
func runList(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	accounts, err := provision.List(ctx, r, provision.ReadPasswd(ctx, r))
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: list: %v\n", err)
		return 1
	}
	if cmd.JSON {
		return emitJSON(accounts)
	}
	if len(accounts) == 0 {
		fmt.Println("no anon accounts")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tUID\tSHIM\tSHIM-UID")
	for _, a := range accounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Account, a.UID, a.Shim, a.ShimUID)
	}
	tw.Flush()
	return 0
}

// runStatus reports one account's state, read from the box. --json emits the
// machine-readable contract; the human form is a short summary. Read-only.
func runStatus(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: status: %v\n", err)
		return 1
	}
	// Read the marker (the same dependency-free truth a sibling tool reads). A
	// missing marker is a clean "not forced", not an error.
	st, err = st.WithMarker(marker.DefaultStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: status: reading marker: %v\n", err)
		return 1
	}
	if cmd.JSON {
		return emitJSON(st)
	}
	if !st.Exists {
		fmt.Printf("%s: not provisioned\n", st.Account)
		return 0
	}
	fmt.Printf("%s: provisioned (uid %s)\n", st.Account, st.UID)
	if st.ShimExists {
		fmt.Printf("  shim %s: present (uid %s)\n", st.Shim, st.ShimUID)
	} else {
		fmt.Printf("  shim %s: MISSING\n", st.Shim)
	}
	// Positively surface the sudo-absence invariant (a UID-transition escape closed
	// at add-time): no sudo is the hardened, expected state; sudo present is a WARN
	// because a sudo'd socket carries a different uid and escapes the forcing. When
	// the account exists but the probe returned no decisive verdict (SudoChecked=false
	// on a lenient/ambiguous `sudo -l -U` output), report UNKNOWN rather than silently
	// omit the line or guess either way.
	if st.SudoChecked {
		if st.SudoAllowed {
			fmt.Printf("  sudo: PRESENT (warning: a uid-transition escape; the account should have no sudo)\n")
		} else {
			fmt.Printf("  sudo: none (no uid-transition escape via sudo)\n")
		}
	} else {
		fmt.Printf("  sudo: UNKNOWN (could not determine sudo rights from `sudo -l -U`; not confirmed absent)\n")
	}
	if st.Forced && st.Marker != nil {
		fmt.Printf("  forced: yes (endpoint class %s, marked %s)\n", st.Marker.EndpointClass, st.Marker.CreatedAt)
	} else {
		fmt.Printf("  forced: no (no marker)\n")
	}
	return 0
}

// runVerify is the trust anchor (story 15-18, 25): it PROVES the account is
// anonymized rather than assuming it, running the named assertion set with NO
// short-circuit, printing each result, and exiting NON-ZERO on any failure (the
// CI-gating contract). `--json` emits the versioned machine report (the contract
// others may consume) on stdout; the human form goes to stdout too so a plain
// `verify` reads clearly. The live probes need root + a live host and are compiled
// only under the `integration` build tag; the DEFAULT binary's verify therefore
// fails-closed (it cannot PROVE anonymization, so it must not exit 0).
//
// It reads the account's UIDs from the box (the same read-only truth `status`
// uses) and the endpoint + shim loopback ports from the PERSISTED account config
// (written by `add`/`update`), so the live probes dial the account's real endpoint
// and shim ports. When there is no persisted config (an account never forced), it
// falls back to the default Tor endpoint + the default ports, which is enough for
// the default build's fail-closed report and for the integration harness (which
// supplies the live params directly).
func runVerify(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	rep := verifyAndMark(ctx, r, cmd)
	if cmd.JSON {
		blob, jerr := rep.JSON()
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "anonctl: verify: %v\n", jerr)
			return 1
		}
		os.Stdout.Write(append(blob, '\n'))
	} else {
		fmt.Print(rep.Human())
	}
	return rep.ExitCode()
}

// verifyAndMark runs the LIVE verify assertion set for the command's account and,
// on a GREEN report, writes the write-after-verify marker (the coordination CLAIM
// an account is forced). It is the shared gate BOTH `verify` and `use` run: `use`
// is a verify-then-shell front door, so it MUST make the identical verify decision
// (same assertions, same marker-on-green side effect) and only differs in what it
// does with the verdict (render + exit vs render + exec-or-refuse). Extracting it
// keeps the two verbs from drifting into two different notions of "anonymized".
//
// A marker-write failure does NOT flip a passing verify to a failure (the account
// IS proven forced); it is surfaced on stderr so the operator can retry.
func verifyAndMark(ctx context.Context, r provision.Runner, cmd *cli.Command) verify.Report {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		// A status read failure yields a single failing assertion so the report is a
		// clean RED (verify could not even read the account), never a silent pass.
		return verify.Report{
			Account:    cmd.Account,
			Assertions: []verify.Assertion{{Name: "account-readable", Ok: false, Err: err}},
		}
	}
	p := verifyParams(accountconfig.DefaultStore(), cmd.Account, st)
	rep := verify.RunVerify(ctx, p)

	// WRITE-AFTER-VERIFY: the marker is a coordination CLAIM written strictly AFTER
	// verify proves the account forced. On a passing report we write it (via the
	// gate, so an unverified account can never be claimed); a failing verify writes
	// nothing and leaves any prior claim to be cleared by `rm`.
	if rep.Ok() {
		m := marker.New(cmd.Account, st.UID, p.Class, resolveVersion(), time.Now())
		if werr := marker.DefaultStore().WriteVerified(m, true); werr != nil {
			fmt.Fprintf(os.Stderr, "anonctl: verify: writing marker: %v\n", werr)
		}
	}
	return rep
}

// verifyParams assembles the LIVE verify params for an account: the endpoint +
// shim loopback ports from the PERSISTED account config (written by add/update)
// when present, else the default Tor endpoint + default ports (an account never
// forced). The UIDs always come from the box (the same read-only truth status
// uses). This is the seam that lets the default build's fail-closed report and the
// integration probes target the account's real endpoint/ports.
func verifyParams(store accountconfig.Store, account string, st provision.AccountStatus) verify.LiveParams {
	ep := endpoint.Default()
	relay, dns := accountconfig.DefaultRelayPort, accountconfig.DefaultDNSPort
	var exempt string
	if cfg, err := store.Read(account); err == nil {
		ep = cfg.Endpoint()
		relay, dns = cfg.RelayPort, cfg.DNSPort
		exempt = firstExemptHostPort(cfg.Exemptions)
	}
	return verify.LiveParams{
		Account:      account,
		Endpoint:     ep.URL(),
		Class:        ep.Class,
		AnonUID:      atoiOr(st.UID, 0),
		ShimUID:      atoiOr(st.ShimUID, 0),
		RelayPort:    relay,
		DNSPort:      dns,
		EndpointHost: ep.Host,
		EndpointPort: atoiOr(ep.Port, 0),
		Exempt:       exempt,
	}
}

// exemptProbePort is the concrete non-53 TCP port the split-tunnel verify probe
// dials for a port-omitted (all-TCP) exemption: it must pick ONE port, and every
// non-53 TCP port on the host is exempted, so any plausible one proves the hole.
// 8080 is the local-service port the feature exists for (a LAN LLM/proxy).
const exemptProbePort = 8080

// firstExemptHostPort renders the FIRST persisted exemption (raw IP|CIDR[:port])
// into the dialable host:port string verify.LiveParams.Exempt expects, so the
// split-tunnel-tight + lan-exemption-not-a-dns-hole assertions fire for an
// exempted account (they run only when Exempt != ""). It verifies ONE exemption as
// the representative proof that exemptions are wired end-to-end; an account with no
// exemptions yields "" (the assertions are cleanly skipped, as today). A raw value
// that no longer parses is skipped (it was validated at config time; a corrupt
// record must not crash verify), falling through to the next.
func firstExemptHostPort(raw []string) string {
	for _, r := range raw {
		e, err := lanexempt.Parse(r)
		if err != nil {
			continue
		}
		return e.HostPort(exemptProbePort)
	}
	return ""
}

// runUse is the verify-then-shell SAFE FRONT DOOR (a maintainer-requested
// convenience): it verifies the resolved account and, ONLY on a GREEN verify,
// execs an interactive login shell as that account (the kernel forcing already in
// effect). On a RED verify it prints the failing assertions and exits non-zero
// WITHOUT starting any shell, so `use` can never hand you an un-anonymized shell.
//
// HONESTY (see the help text + README): `use` is a session-start CONVENIENCE +
// SAFETY gate, NOT the leak protection and NOT enforcement. It is a SNAPSHOT
// (verify at login, not continuous: Tor could die or rules be flushed mid-session)
// and it is BYPASSABLE (`su - <account>` / `sudo -iu <account>` / ssh / cron reach
// the account without ever consulting `use`). The REAL protection is the kernel
// forcing plus the standing per-UID default-deny; `use` just refuses to drop you
// into a setup that is broken RIGHT NOW. A mandatory login-shell/PAM gate is a
// separate idea (`mandatory-anonctl-gated-login`), not this verb.
//
// It requires root because it drops to the account (setpriv). The verify-gate
// decision and the shell exec are behind package seams (useVerifyReport,
// useExecLoginShell, useGeteuid) so the unit tests assert the gate polarity
// without spawning a real shell or needing root; the real setpriv drop is
// exercised under the `integration` tag.
func runUse(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	if useGeteuid() != 0 {
		fmt.Fprintf(os.Stderr, "anonctl: use: must be root to drop into %s (it changes UID via setpriv); re-run with sudo\n", cmd.Account)
		return 1
	}

	rep := useVerifyReport(ctx, r, cmd)
	if !rep.Ok() {
		// RED: print the failing assertions and REFUSE. Do NOT exec a shell (you must
		// never get an un-anonymized shell via `use`).
		fmt.Print(rep.Human())
		fmt.Fprintf(os.Stderr, "anonctl: use: %s did NOT verify as anonymized; refusing to open a shell (fix it, then `%s`)\n", cmd.Account, verifyHint(cmd.Account))
		return rep.ExitCode()
	}

	// GREEN: drop into the account's login shell. exec replaces this process, so on
	// success useExecLoginShell never returns; a returned error means the drop itself
	// failed (e.g. no setpriv, no such account) and is surfaced non-zero.
	fmt.Printf("%s verified anonymized; opening a shell as %s (the kernel forcing is in effect for this session)\n", cmd.Account, cmd.Account)
	if err := useExecLoginShell(ctx, r, cmd.Account); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: use: opening shell as %s: %v\n", cmd.Account, err)
		return 1
	}
	return 0 // unreachable on a real exec (it replaced the process)
}

// The `use` seams: package vars so the unit tests inject fakes (assert the gate
// polarity without a live host or a real shell), mirroring provision's
// WriteLoginEnv seam discipline. Production wires the real verify gate + the real
// setpriv drop.
var (
	// useGeteuid reports the effective UID (os.Geteuid in production); a test can
	// simulate a non-root run.
	useGeteuid = os.Geteuid
	// useVerifyReport runs the verify gate for the account and returns its report
	// (the same gate `verify` runs, marker-on-green included).
	useVerifyReport = verifyAndMark
	// useExecLoginShell drops to the account and execs its interactive login shell.
	// In the DEFAULT build this is a fail-loud stub: the real setpriv drop is
	// compiled only under the `integration` tag (use_exec_integration.go), mirroring
	// verify's build-tag split, so a stray unit path can never spawn a shell.
	useExecLoginShell = execLoginShell
)

// runUpdate is `update`/`reconfigure`: it changes an already-forced account's
// endpoint and RE-APPLIES the rules fail-closed, with no un-anonymized window
// (story 21). It reads the account's persisted config (it must already be
// provisioned + forced), overlays the new endpoint (required for update), and calls
// forcing.Reconfigure, which re-applies the nft rules (atomic table replace, the
// default-DROP never absent) BEFORE restarting the shim, so egress is
// dropped-or-forced throughout. It runs as root (nft/systemctl).
func runUpdate(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	if cmd.Endpoint == "" {
		fmt.Fprintf(os.Stderr, "anonctl: %s: --endpoint is required (the new socks5h endpoint to point the account at)\n", cmd.Verb)
		return 2
	}
	cfg, err := accountconfig.DefaultStore().Read(cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %s is not provisioned/forced (run `anonctl add %s` first): %v\n", cmd.Verb, cmd.Account, accountArg(cmd.Account), err)
		return 1
	}
	ep, err := resolveEndpoint(cmd.Endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %v\n", cmd.Verb, err)
		return 1
	}
	cfg.EndpointHost = ep.Host
	cfg.EndpointPort = atoiOr(ep.Port, 0)
	cfg.EndpointClass = ep.Class
	// Overlay the exemptions the operator passed on THIS update: an update that
	// names --allow-direct sets the account's exemptions, an update that names none
	// leaves the persisted set intact (re-applying the same holes), so a plain
	// endpoint change never silently drops a configured exemption.
	exemptions, err := exemptionsForUpdate(cmd, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %v\n", cmd.Verb, err)
		return 1
	}
	cfg.Exemptions = rawExemptions(exemptions)
	if err := forcing.Reconfigure(ctx, forcingDeps(), cfg, exemptions); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %v\n", cmd.Verb, err)
		return 1
	}
	fmt.Printf("reconfigured %s -> endpoint %s (re-applied fail-closed, no leak window)\n", cfg.Account, cfg.Endpoint().URL())
	fmt.Printf("run `%s` to re-prove the account is anonymized\n", verifyHint(cmd.Account))
	return 0
}

// forcingDeps wires the real runners + stores for the forcing orchestration (the
// production seam; tests build fakes). It is the ONE place the ExecRunners + the
// default Stores are assembled.
func forcingDeps() forcing.Deps {
	return forcing.Deps{
		NftRunner:     nftables.ExecRunner{},
		SystemdRunner: systemd.ExecRunner{},
		ConfigStore:   accountconfig.DefaultStore(),
		SystemdStore:  systemd.DefaultStore(),
	}
}

// buildConfig assembles an account's at-rest config from its just-provisioned UIDs
// (read from the box) and the chosen endpoint (the raw --endpoint value, or the
// default Tor SocksPort when empty). It fails loud if the account's UIDs cannot be
// read (a provisioning that did not land) rather than emit a config that would
// mis-force.
// exemptionsForUpdate resolves which exemptions an update should apply: the ones
// the operator named on THIS invocation when any were given, else the account's
// already-persisted exemptions (re-parsed from their raw form). This keeps a plain
// `update --endpoint` from silently dropping configured holes while letting an
// `update --allow-direct ...` replace the set.
func exemptionsForUpdate(cmd *cli.Command, cfg accountconfig.Config) ([]lanexempt.Exempt, error) {
	if len(cmd.Exemptions) > 0 {
		return cmd.Exemptions, nil
	}
	out := make([]lanexempt.Exempt, 0, len(cfg.Exemptions))
	for _, raw := range cfg.Exemptions {
		e, err := lanexempt.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("persisted exemption %q is invalid: %w", raw, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// rawExemptions renders parsed exemptions back to their raw IP|CIDR[:port] strings
// for persistence in the account config (the credential-free at-rest form the nft
// generator + verify re-parse). It is the inverse of the CLI/config parse.
func rawExemptions(exemptions []lanexempt.Exempt) []string {
	if len(exemptions) == 0 {
		return nil
	}
	raw := make([]string, 0, len(exemptions))
	for _, e := range exemptions {
		raw = append(raw, e.Raw)
	}
	return raw
}

func buildConfig(ctx context.Context, r provision.Runner, account, rawEndpoint string, exemptions []lanexempt.Exempt) (accountconfig.Config, error) {
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		return accountconfig.Config{}, fmt.Errorf("reading provisioned account: %w", err)
	}
	anonUID := atoiOr(st.UID, 0)
	shimUID := atoiOr(st.ShimUID, 0)
	if anonUID <= 0 || shimUID <= 0 {
		return accountconfig.Config{}, fmt.Errorf("account %q is missing its UID (%q) or shim UID (%q); provisioning did not complete", account, st.UID, st.ShimUID)
	}
	ep, err := resolveEndpoint(rawEndpoint)
	if err != nil {
		return accountconfig.Config{}, err
	}
	return accountconfig.Config{
		Account:       account,
		AnonUID:       anonUID,
		ShimUID:       shimUID,
		EndpointHost:  ep.Host,
		EndpointPort:  atoiOr(ep.Port, 0),
		EndpointClass: ep.Class,
		Exemptions:    rawExemptions(exemptions),
	}, nil
}

// resolveEndpoint turns the raw --endpoint value into a validated, credential-free
// endpoint with its share-class. An empty value is the default Tor SocksPort
// (story 4). A named value is parsed with the heuristic class (Classify), which the
// operator's future --endpoint-class override could refine (out of scope here).
func resolveEndpoint(raw string) (endpoint.Endpoint, error) {
	if raw == "" {
		return endpoint.Default(), nil
	}
	ep, err := endpoint.Parse(raw, endpoint.Classify(raw))
	if err != nil {
		return endpoint.Endpoint{}, fmt.Errorf("endpoint: %w", err)
	}
	return ep, nil
}

// accountArg renders an account name as the CLI argument that targets it: the
// default `anon` is a BARE verb (no name), a named `anon-<name>` is `<name>`. So a
// follow-up hint prints the shortest form the operator would type.
func accountArg(account string) string {
	if account == cli.DefaultAccount {
		return ""
	}
	return strings.TrimPrefix(account, cli.DefaultAccount+"-")
}

// verifyHint renders the exact `anonctl verify [<name>]` command an operator would
// type next, with NO trailing space for the default account (whose CLI argument is
// empty): `anonctl verify` for the default, `anonctl verify <name>` for a named one.
// It exists so the follow-up hint never prints a stray `verify ` (the e2e finding,
// BUG 5); callers wrap it in backticks in the message.
func verifyHint(account string) string {
	if arg := accountArg(account); arg != "" {
		return "anonctl verify " + arg
	}
	return "anonctl verify"
}

// atoiOr parses s as an int, returning def on any error (an empty/absent UID for a
// not-yet-provisioned account maps to the default rather than aborting: verify
// still runs its assertions and reports the fail-closed verdict).
func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// emitJSON writes v as indented JSON to stdout (the machine-readable channel), so
// a caller can capture it cleanly. Diagnostics stay on stderr.
func emitJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %v\n", err)
		return 1
	}
	return 0
}

const usage = `usage:
  anonctl add    [--endpoint <socks5h://host:port>] [--allow-direct <IP|CIDR[:port]>]... [<name>]
                                     provision the account + shim UID, install fail-closed forcing that
                                     survives reboot (default endpoint: the local Tor SocksPort) (root)
                                     --allow-direct punches a narrow private-only LAN hole (repeatable;
                                     RFC1918/link-local only, never :53)
  anonctl rm     [--purge-account] [<name>]
                                     remove forcing; --purge-account also deletes the account (root)
  anonctl list   [--json]           list the anon accounts that exist on the box
  anonctl status [<name>] [--json]  show one account's state (machine-readable with --json)
  anonctl verify [<name>] [--json]  prove the account is anonymized (named assertions, non-zero exit on failure)
  anonctl use    [<name>]           verify the account, then open a shell as it ONLY on green (root); refuses
                                     (no shell) if it is not currently anonymized. A session-start SAFETY GATE,
                                     NOT the leak protection: it is a snapshot (verify at login, not continuous)
                                     and bypassable (su/sudo -iu/ssh/cron reach the account anyway). The real
                                     protection is the kernel rules + the standing default-deny; a MANDATORY gate
                                     is the separate mandatory-anonctl-gated-login idea.
  anonctl update|reconfigure --endpoint <socks5h://host:port> [--allow-direct <IP|CIDR[:port]>]... [<name>]
                                     change the account's endpoint and re-apply fail-closed (no leak window) (root)
                                     --allow-direct here REPLACES the account's LAN holes (omit to keep them)
  anonctl --version | version       print the anonctl version

A bare verb targets the default account ` + "`anon`" + `; ` + "`<name>`" + ` targets ` + "`anon-<name>`" + `.
Each account gets its OWN dedicated shim service account (` + "`<account>-shim`" + `), the
only UID allowed to reach the upstream endpoint. anonctl does NOT manage the
endpoint's own service: enable your endpoint (e.g. ` + "`tor.service`" + `) at boot yourself.`
