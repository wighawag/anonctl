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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anoncore/marker"
	"github.com/wighawag/anoncore/provision"
	"github.com/wighawag/anoncore/seedhome"
	"github.com/wighawag/anoncore/ui"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/defaults"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/lanexempt"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/systemd"
	"github.com/wighawag/anonctl/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// errStyle / outStyle are the per-stream color helpers the CLI prints through. They
// colorize ONLY when the stream is an interactive terminal and color is not disabled
// (NO_COLOR), so piped output and the --json path stay byte-plain. Built once at
// startup.
var (
	errStyle = ui.Stderr()
	outStyle = ui.Stdout()
)

// errorf prints a red, `anonctl:`-prefixed error line to stderr (color-gated by the
// stream). It is the single styled error sink the verbs route through, so the red
// `anonctl:` prefix is consistent and one edit changes it everywhere.
func errorf(format string, a ...any) {
	fmt.Fprint(os.Stderr, errStyle.Red("anonctl: ")+errStyle.Red(fmt.Sprintf(format, a...))+"\n")
}

func run(args []string) int {
	// `anonctl --version` / `anonctl version` prints and exits before any parse.
	if isVersionArg(args) {
		fmt.Println("anonctl " + resolveVersion())
		return 0
	}

	cmd, err := cli.Parse(args)
	if err != nil {
		errorf("%v", err)
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
	if handled, code := maybeElevate(cmd.Verb, cmd.Account, args); handled {
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
	case "exec":
		return runExec(ctx, runner, cmd)
	case "seed-home":
		return runSeedHome(ctx, runner, cmd)
	case "update", "reconfigure":
		return runUpdate(ctx, runner, cmd)
	default:
		errorf("unknown verb %q", cmd.Verb)
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
}

// runAdd provisions the account + its dedicated shim UID, then INSTALLS the forcing
// (the standing baseline default-deny + the nft forcing rules + the persisted
// systemd shim unit + anonctl's own early-boot loader unit), so the account is
// anonymized live AND across a reboot fail-closed - and DROPPED, never free, even if
// the forcing rules never load. It must run as
// root (useradd/nft/systemctl); a non-root run surfaces the underlying command's
// own permission error.
//
// `add` is CREATE-ONLY: it refuses an account that already exists, up front, before
// any mutation, so a second `add` never silently re-applies a (possibly different)
// endpoint/config. Changing an existing account's endpoint or exemptions is
// `update`'s job (which re-applies fail-closed with no leak window); recreating is
// `rm` then `add`. This keeps one clear command per intent.
func runAdd(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	// Refuse an existing account BEFORE provisioning or resolving the endpoint, so a
	// rejected re-add mutates nothing (a pure read) and never re-applies config. Point
	// the operator at the verb that DOES change a live account (update) or at rm+add.
	if st, serr := provision.Status(ctx, r, cmd.Account); serr != nil {
		errorf("add: %v", serr)
		return 1
	} else if st.Exists {
		errorf("add: %s already exists; `add` will not modify it. To change its endpoint or LAN exemptions run `%s`; to recreate it run `anonctl rm %s` first",
			cmd.Account, updateHint(cmd.Account), accountArg(cmd.Account))
		return 1
	}

	// CREATE-LAST ORDERING: everything that can fail, be refused, or need an ANSWER
	// (exemption resolution, the interactive endpoint prompt, the cross-identification
	// guard) runs BEFORE provision.Add creates the account. So a Ctrl+C at the prompt,
	// a refused shared endpoint, or an invalid default leaves the box UNTOUCHED (no
	// half-provisioned account to clean up). The account is created only once every
	// question is answered and every guard has passed.

	// Resolve the effective LAN exemptions: the ones the operator named on THIS
	// invocation when any were given, else the box-wide defaults from
	// /etc/anonctl/defaults.json. A default exemption is re-validated through the
	// SAME lanexempt guardrail the CLI flag uses (resolveDefaultExemptions), so a
	// default can never be a quieter path to a leak than the flag.
	exemptions, err := resolveAddExemptions(cmd)
	if err != nil {
		errorf("add: %v", err)
		return 1
	}

	// Resolve the endpoint. With an explicit --endpoint, parse it as-is. With NONE,
	// SCAN the local socks5h ports and choose: default to a confirmed Tor endpoint,
	// prompt interactively when there is a TTY (annotating any peruser endpoint already
	// in use by another account), and fall back fail-closed non-interactively
	// (Tor-if-confirmed, else refuse) rather than blindly configuring a dead 9050. The
	// interactive prompt is CANCELLABLE: a Ctrl+C surfaces immediately (no Enter
	// needed), and because we have not created the account yet, it leaves nothing
	// behind.
	var ep endpoint.Endpoint
	if cmd.Endpoint == "" {
		ep, err = chooseEndpointInteractive(ctx, cmd.Account, "add")
	} else {
		ep, err = resolveEndpoint(cmd.Endpoint)
	}
	if err != nil {
		errorf("add: %v", err)
		return 1
	}

	// CROSS-IDENTIFICATION GUARD: refuse pointing THIS account at a socks-peruser
	// endpoint already claimed by a DIFFERENT account (they would exit identically and
	// become cross-identifiable). A tor-shared endpoint is share-safe and never
	// refused. This runs BEFORE the account is created, so a refusal leaves the box
	// untouched.
	if err := claimEndpoint(cmd.Account, ep); err != nil {
		errorf("add: %v", err)
		return 1
	}

	// All questions answered and all guards passed: NOW create the account + its
	// dedicated shim UID.
	res, err := provision.Add(ctx, r, cmd.Account)
	if err != nil {
		errorf("add: %v", err)
		return 1
	}

	// On FRESH creation only, seed the home from the directory-exists default
	// /etc/anonctl/default-home/ when present (never overwriting: add is create-only,
	// so it uses force=false). A re-add (Created=false) never re-seeds, mirroring the
	// login-env write. Seeding failure is a real add failure (the account did not land
	// as configured), surfaced non-zero.
	if res.Created {
		if n, serr := seedDefaultHome(ctx, r, cmd.Account); serr != nil {
			errorf("add: seeding home: %v", serr)
			return 1
		} else if n > 0 {
			fmt.Printf("seeded %d file(s) into %s's home from %s\n", n, cmd.Account, defaultsStore.DefaultHomeDir())
		}
	}

	// Build the at-rest config from the just-provisioned UIDs and the chosen endpoint,
	// then install the forcing.
	cfg, err := buildConfig(ctx, r, cmd.Account, ep.URL(), exemptions)
	if err != nil {
		errorf("add: %v", err)
		return 1
	}
	if err := forcing.Install(ctx, forcingDeps(), cfg, exemptions); err != nil {
		errorf("add: installing forcing: %v", err)
		return 1
	}

	// The account is always freshly created here: runAdd refuses an existing account
	// up front, so this path is only ever reached for a genuinely new account.
	fmt.Printf("%s %s (shim %s, endpoint %s)\n", outStyle.Green("provisioned + forced"), outStyle.Bold(res.Account), res.Shim, cfg.Endpoint().URL())
	fmt.Printf("%s anonctl does NOT manage the endpoint's own service; enable your endpoint (e.g. `systemctl enable --now tor.service`) so it is up at boot\n", outStyle.Yellow("note:"))

	// Prove it INLINE: run the SAME verify gate `verify`/`use` run (assertions +
	// per-check progress + marker-on-green), so `add` ends with a live proof instead
	// of only a homework instruction. This is warn-and-continue, NOT a hard gate: the
	// forcing is already installed and fail-closed (the account is DROPPED, never free,
	// even with the endpoint down), so an add that provisioned correctly must still
	// exit 0 even when anonymization cannot YET be proven (typically the endpoint is
	// not up at add-time). A RED report is surfaced loudly with the named follow-up so
	// the operator knows to bring the endpoint up and re-run `verify`; it never turns a
	// correct provisioning into a failure. See
	// work/notes/ideas/host-ip-fetch-off-by-default-and-verify-on-add.md.
	rep := addVerifyReport(ctx, r, cmd, verifyProgress(false))
	fmt.Print(colorizeReport(rep.Human()))
	if rep.Ok() {
		fmt.Printf("%s the account is anonymized (proven now); re-run `%s` after any reboot or Tor/kernel/nftables change\n", outStyle.Green("verified:"), outStyle.Cyan(verifyHint(cmd.Account)))
	} else {
		fmt.Printf("%s the account is provisioned + forced (fail-closed: DROPPED, never leaking), but anonymization could NOT be proven yet - commonly the endpoint is not up. Bring your endpoint up, then run `%s` to prove it\n", outStyle.Yellow("note:"), outStyle.Cyan(verifyHint(cmd.Account)))
	}
	return 0
}

// addVerifyReport runs the shared verify gate for `add`'s inline proof. It is a
// package var mirroring useVerifyReport/execVerifyReport so a unit test can drive
// runAdd's tail (the inline verify + its green/red messaging) without a real probe
// run; production wires the real verifyAndMark (assertions + marker-on-green).
var addVerifyReport = verifyAndMark

// The seed-home seams: package vars so the unit tests drive the add/seed-home
// wiring without a real home or a real /etc read. Production wires the real
// seedhome.Seed and the real defaults Store.
var (
	// seedHomeSeed copies a template dir into an account's home (chowning, stripping
	// setuid). Tests replace it to capture the call without touching a real home.
	seedHomeSeed = seedhome.Seed
	// defaultsStore reads the box-wide add-time defaults (default-home presence +
	// default exemptions). Tests point its BaseDir at a scratch dir.
	defaultsStore = defaults.DefaultStore()
)

// seedDefaultHome seeds the account's home from the directory-exists default
// /etc/anonctl/default-home/ when it is present, returning the number of files
// copied (0 when there is no default-home dir: a clean no-op, not an error). It
// resolves the account's home through provision.AccountHome and copies with
// force=false (add never overwrites). It is used ONLY on fresh creation.
func seedDefaultHome(ctx context.Context, r provision.Runner, account string) (int, error) {
	if !defaultsStore.DefaultHomePresent() {
		return 0, nil
	}
	home, err := provision.AccountHome(ctx, r, account)
	if err != nil {
		return 0, err
	}
	res, err := seedHomeSeed(ctx, r, defaultsStore.DefaultHomeDir(), home, account, false)
	if err != nil {
		return 0, err
	}
	return res.Copied, nil
}

// resolveAddExemptions returns the exemptions `add` should apply: the ones named on
// THIS invocation when any were given, else the box-wide defaults from
// defaults.json (re-validated through the same lanexempt guardrail the CLI flag
// uses, so a default is never a quieter leak path). A missing/empty defaults file
// yields no exemptions (the pre-feature behaviour).
func resolveAddExemptions(cmd *cli.Command) ([]lanexempt.Exempt, error) {
	if len(cmd.Exemptions) > 0 {
		return cmd.Exemptions, nil
	}
	d, err := defaultsStore.Read()
	if err != nil {
		return nil, err
	}
	out := make([]lanexempt.Exempt, 0, len(d.Allow))
	for _, raw := range d.Allow {
		e, perr := lanexempt.Parse(raw)
		if perr != nil {
			return nil, fmt.Errorf("default exemption %q in defaults.json is invalid: %w", raw, perr)
		}
		out = append(out, e)
	}
	return out, nil
}

// runSeedHome is the explicit, re-runnable home-seeding verb: it copies a template
// directory (`--from <dir>`, else the directory-exists default
// /etc/anonctl/default-home/) into an EXISTING account's home. A per-file collision
// is a loud error unless `--force`. It copies as root (chown to the account), so it
// self-elevates like the other mutating verbs. It refuses on a non-existent account
// (it seeds a home, it does not create one).
func runSeedHome(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		errorf("seed-home: %v", err)
		return 1
	}
	if !st.Exists {
		errorf("seed-home: %s is not provisioned (run `anonctl add %s` first)", cmd.Account, accountArg(cmd.Account))
		return 1
	}

	template := cmd.SeedFrom
	if template == "" {
		if !defaultsStore.DefaultHomePresent() {
			errorf("seed-home: no --from given and no default home at %s; nothing to seed", defaultsStore.DefaultHomeDir())
			return 1
		}
		template = defaultsStore.DefaultHomeDir()
	}

	home, err := provision.AccountHome(ctx, r, cmd.Account)
	if err != nil {
		errorf("seed-home: %v", err)
		return 1
	}
	res, err := seedHomeSeed(ctx, r, template, home, cmd.Account, cmd.Force)
	if err != nil {
		errorf("seed-home: %v", err)
		return 1
	}
	if len(res.Overwrote) > 0 {
		fmt.Printf("seeded %d file(s) into %s's home from %s (overwrote %d: %s)\n",
			res.Copied, cmd.Account, template, len(res.Overwrote), strings.Join(res.Overwrote, ", "))
	} else {
		fmt.Printf("seeded %d file(s) into %s's home from %s\n", res.Copied, cmd.Account, template)
	}
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
		errorf("rm: %s: %v", what, err)
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
		errorf("list: %v", err)
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
		errorf("status: %v", err)
		return 1
	}
	// Read the marker (the same dependency-free truth a sibling tool reads). A
	// missing marker is a clean "not forced", not an error.
	st, err = st.WithMarker(marker.DefaultStore())
	if err != nil {
		errorf("status: reading marker: %v", err)
		return 1
	}
	if cmd.JSON {
		return emitJSON(st)
	}
	if !st.Exists {
		fmt.Printf("%s: %s\n", outStyle.Bold(st.Account), outStyle.Yellow("not provisioned"))
		return 0
	}
	fmt.Printf("%s: %s (uid %s)\n", outStyle.Bold(st.Account), outStyle.Green("provisioned"), st.UID)
	if st.ShimExists {
		fmt.Printf("  shim %s: %s (uid %s)\n", st.Shim, outStyle.Green("present"), st.ShimUID)
	} else {
		fmt.Printf("  shim %s: %s\n", st.Shim, outStyle.Red("MISSING"))
	}
	// Positively surface the sudo-absence invariant (a UID-transition escape closed
	// at add-time): no sudo is the hardened, expected state; sudo present is a WARN
	// because a sudo'd socket carries a different uid and escapes the forcing. When
	// the account exists but the probe returned no decisive verdict (SudoChecked=false
	// on a lenient/ambiguous `sudo -l -U` output), report UNKNOWN rather than silently
	// omit the line or guess either way.
	if st.SudoChecked {
		if st.SudoAllowed {
			fmt.Printf("  sudo: %s (warning: a uid-transition escape; the account should have no sudo)\n", outStyle.Red("PRESENT"))
		} else {
			fmt.Printf("  sudo: %s (no uid-transition escape via sudo)\n", outStyle.Green("none"))
		}
	} else {
		fmt.Printf("  sudo: %s (could not determine sudo rights from `sudo -l -U`; not confirmed absent)\n", outStyle.Yellow("UNKNOWN"))
	}
	if st.Forced && st.Marker != nil {
		fmt.Printf("  forced: %s (endpoint class %s, marked %s)\n", outStyle.Green("yes"), st.Marker.EndpointClass, st.Marker.CreatedAt)
	} else {
		fmt.Printf("  forced: %s (no marker)\n", outStyle.Yellow("no"))
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
	// Progress is SUPPRESSED under --json (stdout must stay pure JSON a tool parses),
	// and shown in the human path so the operator sees the multi-second probe run is
	// alive instead of a silent wait. It goes to stderr, so the PASS/FAIL result lines
	// stay on stdout exactly as today.
	prog := verifyProgress(cmd.JSON)
	rep := verifyAndMark(ctx, r, cmd, prog)
	if cmd.JSON {
		blob, jerr := rep.JSON()
		if jerr != nil {
			errorf("verify: %v", jerr)
			return 1
		}
		os.Stdout.Write(append(blob, '\n'))
	} else {
		fmt.Print(colorizeReport(rep.Human()))
	}
	return rep.ExitCode()
}

// verifyProgressWriter is where the human-path per-check progress is emitted: it
// is STDERR so the PASS/FAIL result lines (and, under --json, the JSON blob) stay
// pure on stdout. It is a package var so a unit test can drive the progress
// rendering into a buffer with no real terminal, mirroring the repo's seam
// discipline (useExecLoginShell, provision's WriteLoginEnv).
var verifyProgressWriter io.Writer = os.Stderr

// verifyProgress builds the per-check progress hook `verify` and `use` share.
// Under --json it returns a ZERO hook so NO progress is emitted (the machine
// contract on stdout is untouched). Otherwise it streams, to stderr, a
// "  ... <name>" line as each check STARTS and the completed "[PASS]/[FAIL]
// <name>" as it finishes, so the operator watches the lines appear one by one and
// learns which probe is slow. It is plain-text only (no cursor/spinner control
// chars), so it degrades cleanly when stderr is redirected/piped (non-tty) with no
// garbage in the stream.
func verifyProgress(jsonMode bool) verify.Progress {
	if jsonMode {
		return verify.Progress{}
	}
	return verify.Progress{
		Start: func(name string) {
			fmt.Fprintf(verifyProgressWriter, "  ... %s\n", name)
		},
		Done: func(a verify.Assertion) {
			// Color the mark ONLY when progress goes to the real (interactive) stderr, not
			// when a test/redirect has swapped the writer to a buffer/pipe: the progress must
			// degrade to plain `[PASS]`/`[FAIL]` on a non-tty (no escape codes in a captured
			// or piped stream).
			ps := progressStyler()
			mark := ps.Red("FAIL")
			if a.Ok {
				mark = ps.Green("PASS")
			}
			fmt.Fprintf(verifyProgressWriter, "  [%s] %s\n", mark, ps.Bold(a.Name))
		},
	}
}

// progressStyler returns the styler the verify progress hook uses: the colored
// stderr styler ONLY when progress is actually going to the real stderr (an
// interactive terminal, color enabled). When a test or a redirect has swapped
// verifyProgressWriter to a buffer/pipe, it returns a disabled styler so the stream
// stays plain (`[PASS]`/`[FAIL]`, no escape codes). This keeps the human terminal
// colored without ever leaking control chars into a captured/piped progress stream.
func progressStyler() ui.Styler {
	if verifyProgressWriter == os.Stderr {
		return errStyle
	}
	return ui.Styler{}
}

// colorizeReport recolors the plain verify Report.Human() text at the print
// boundary: [PASS] green, [FAIL] red, so the machine/test contract (Human() stays
// plain) is untouched while the human terminal gets color. It is a no-op string
// substitution when color is disabled (the styler returns its input unchanged), so
// piped/redirected output stays byte-identical to before.
func colorizeReport(s string) string {
	s = strings.ReplaceAll(s, "[PASS]", "["+outStyle.Green("PASS")+"]")
	s = strings.ReplaceAll(s, "[FAIL]", "["+outStyle.Red("FAIL")+"]")
	return s
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
//
// prog is the per-check progress hook (built by verifyProgress); it is observation
// only and never changes the verdict or the assertion set. Passing it HERE (the
// shared gate) is what gives `use` the same progress `verify` shows.
func verifyAndMark(ctx context.Context, r provision.Runner, cmd *cli.Command, prog verify.Progress) verify.Report {
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
	p.SkipTorExitCheck = cmd.SkipTorExitCheck
	rep := verify.RunVerifyWith(ctx, p, prog)

	// WRITE-AFTER-VERIFY: the marker is a coordination CLAIM written strictly AFTER
	// verify proves the account forced. On a passing report we write it (via the
	// gate, so an unverified account can never be claimed); a failing verify writes
	// nothing and leaves any prior claim to be cleared by `rm`.
	if rep.Ok() {
		m := marker.New(cmd.Account, st.UID, p.Class, resolveVersion(), time.Now())
		if werr := marker.DefaultStore().WriteVerified(m, true); werr != nil {
			errorf("verify: writing marker: %v", werr)
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

// firstExemptHostPort renders the FIRST persisted exemption (raw IP|CIDR:port)
// into the dialable host:port string verify.LiveParams.Exempt expects, so the
// split-tunnel-tight + lan-exemption-not-a-dns-hole assertions fire for an
// exempted account (they run only when Exempt != ""). It verifies ONE exemption as
// the representative proof that exemptions are wired end-to-end; an account with no
// exemptions yields "" (the assertions are cleanly skipped, as today). A raw value
// that no longer parses is skipped (it was validated at config time; a corrupt
// record must not crash verify), falling through to the next. A port is mandatory,
// so the exemption always renders its own concrete port.
func firstExemptHostPort(raw []string) string {
	for _, r := range raw {
		e, err := lanexempt.Parse(r)
		if err != nil {
			continue
		}
		return e.HostPort()
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
		errorf("use: must be root to drop into %s (it changes UID via setpriv); re-run with sudo", cmd.Account)
		return 1
	}

	// `use` runs the SAME shared verify gate as `verify`, so it gets the same
	// per-check progress for free: the operator sees the multi-second probe run is
	// working before either a shell opens or the refusal prints. `use` has no --json
	// (it execs a shell), so progress is always the human hook (stderr).
	rep := useVerifyReport(ctx, r, cmd, verifyProgress(false))
	if !rep.Ok() {
		// RED: print the failing assertions and REFUSE. Do NOT exec a shell (you must
		// never get an un-anonymized shell via `use`).
		fmt.Print(colorizeReport(rep.Human()))
		errorf("use: %s did NOT verify as anonymized; refusing to open a shell (fix it, then `%s`)", cmd.Account, verifyHint(cmd.Account))
		return rep.ExitCode()
	}

	// GREEN: drop into the account's login shell. exec replaces this process, so on
	// success useExecLoginShell never returns; a returned error means the drop itself
	// failed (e.g. no setpriv, no such account) and is surfaced non-zero.
	fmt.Printf("%s %s; opening a shell as %s (the kernel forcing is in effect for this session)\n", outStyle.Bold(cmd.Account), outStyle.Green("verified anonymized"), cmd.Account)
	if err := useExecLoginShell(ctx, r, cmd.Account); err != nil {
		errorf("use: opening shell as %s: %v", cmd.Account, err)
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
	// (the same gate `verify` runs, marker-on-green included). It takes the shared
	// per-check progress hook so `use`'s gating verify shows the same activity.
	useVerifyReport = verifyAndMark
	// useExecLoginShell drops to the account and execs its interactive login shell.
	// In the DEFAULT build this is a fail-loud stub: the real setpriv drop is
	// compiled only under the `integration` tag (use_exec_integration.go), mirroring
	// verify's build-tag split, so a stray unit path can never spawn a shell.
	useExecLoginShell = execLoginShell
	// execRunProgram drops to the account and RUNS one program with its args
	// forwarded verbatim (the one-shot face of the same enter-primitive
	// useExecLoginShell is the interactive face of). A unit test replaces it to
	// assert the gate polarity + the forwarded program/args without a real drop.
	execRunProgram = execProgram
)

// runExec is `anonctl exec [--as <name>] <program> [args...]`: the SAME verify-then-
// enter SAFETY GATE as `use`, but instead of an interactive login shell it RUNS one
// program in the anonymized account with every arg forwarded VERBATIM. It verifies
// the resolved account and, ONLY on a GREEN verify, execs the program as that
// account (the kernel forcing already in effect). On a RED verify it prints the
// failing assertions and exits non-zero WITHOUT running the program, so `exec` can
// NEVER run a program in the clear (never a non-anonymized run).
//
// `exec` is `use`'s sibling: `use` = drop an interactive shell, `exec` = run one
// program, two faces of the same verify-green-then-enter gate (a future shared
// anoncore enter-primitive hosts exactly this). It inherits use's honesty caveats
// (a snapshot verify at launch, not continuous; the real protection is the kernel
// forcing + default-deny) and its root requirement (it drops UID via setpriv), so it
// self-elevates via sudo exactly like use/verify/add. The gate + drop are behind the
// same package seams (execVerifyReport/execRunProgram/useGeteuid) so unit tests
// assert the gate without a live host or a real drop; the real setpriv run is
// exercised under the `integration` tag.
func runExec(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	if useGeteuid() != 0 {
		errorf("exec: must be root to run %s as %s (it changes UID via setpriv); re-run with sudo", cmd.Program, cmd.Account)
		return 1
	}

	// `exec` runs the SAME shared verify gate as `verify`/`use`, so it gets the same
	// per-check progress: the operator sees the multi-second probe run before either
	// the program starts or the refusal prints. It has no --json (it execs a program),
	// so progress is always the human hook (stderr).
	rep := execVerifyReport(ctx, r, cmd, verifyProgress(false))
	if !rep.Ok() {
		// RED: print the failing assertions and REFUSE. Do NOT run the program (you must
		// never get a non-anonymized run via `exec`).
		fmt.Print(colorizeReport(rep.Human()))
		errorf("exec: %s did NOT verify as anonymized; refusing to run %s (fix it, then `%s`)", cmd.Account, cmd.Program, verifyHint(cmd.Account))
		return rep.ExitCode()
	}

	// GREEN: run the program in the account. exec replaces this process, so on success
	// execRunProgram never returns; a returned error means the drop/run itself failed
	// (e.g. no setpriv, no such account) and is surfaced non-zero, never a clear run.
	fmt.Fprintf(os.Stderr, "%s %s; running %s as %s (the kernel forcing is in effect)\n", outStyle.Bold(cmd.Account), outStyle.Green("verified anonymized"), cmd.Program, cmd.Account)
	if err := execRunProgram(ctx, r, cmd.Account, cmd.Program, cmd.ExecArgs); err != nil {
		errorf("exec: running %s as %s: %v", cmd.Program, cmd.Account, err)
		return 1
	}
	return 0 // unreachable on a real exec (it replaced the process)
}

// execVerifyReport runs the verify gate for `exec` (the SAME gate `verify`/`use`
// run, marker-on-green included). It is a package var mirroring useVerifyReport so a
// unit test injects a green/red report without a live host.
var execVerifyReport = verifyAndMark

// runUpdate is `update`/`reconfigure`: it changes an already-forced account's
// endpoint and RE-APPLIES the rules fail-closed, with no un-anonymized window
// (story 21). It reads the account's persisted config (it must already be
// provisioned + forced), overlays the new endpoint (required for update), and calls
// forcing.Reconfigure, which re-applies the nft rules (atomic table replace, the
// default-DROP never absent) BEFORE restarting the shim, so egress is
// dropped-or-forced throughout. It runs as root (nft/systemctl).
func runUpdate(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	// Read the persisted config FIRST (the account must already be provisioned +
	// forced), so a bare `update` on a non-existent account fails with that, not a
	// confusing endpoint prompt.
	cfg, err := accountconfig.DefaultStore().Read(cmd.Account)
	if err != nil {
		errorf("%s: %s is not provisioned/forced (run `anonctl add %s` first): %v", cmd.Verb, cmd.Account, accountArg(cmd.Account), err)
		return 1
	}
	// Resolve the new endpoint. With --endpoint, use it as typed. WITHOUT it, scan the
	// local socks5h ports and PROMPT (interactive), exactly like `add`, so a bare
	// `update` is usable to re-point an account without hand-typing the URL. Kept
	// fail-closed non-interactively: with no TTY and no --endpoint the chooser refuses
	// (rather than silently pick), so scripts must still name the endpoint.
	endpointArg := cmd.Endpoint
	if endpointArg == "" {
		if !stdinIsTTY() {
			errorf("%s: --endpoint is required non-interactively (the new socks5h endpoint to point the account at); run `anonctl %s %s` on a terminal to scan and choose", cmd.Verb, cmd.Verb, accountArg(cmd.Account))
			return 2
		}
		chosen, cerr := chooseEndpointInteractive(ctx, cmd.Account, cmd.Verb)
		if cerr != nil {
			errorf("%s: %v", cmd.Verb, cerr)
			return 1
		}
		endpointArg = chosen.URL()
	}
	ep, err := resolveEndpoint(endpointArg)
	if err != nil {
		errorf("%s: %v", cmd.Verb, err)
		return 1
	}
	cfg.EndpointHost = ep.Host
	cfg.EndpointPort = atoiOr(ep.Port, 0)
	cfg.EndpointClass = ep.Class
	// CROSS-IDENTIFICATION GUARD (same as add): refuse re-pointing this account at a
	// socks-peruser endpoint another account already owns, BEFORE the atomic
	// re-apply. The account's OWN prior claim is excluded, so re-pointing it at its
	// own endpoint (or a shared tor one) is never refused.
	if err := claimEndpoint(cmd.Account, cfg.Endpoint()); err != nil {
		errorf("%s: %v", cmd.Verb, err)
		return 1
	}
	// Overlay the exemptions the operator passed on THIS update: an update that
	// names --allow sets the account's exemptions, an update that names none
	// leaves the persisted set intact (re-applying the same holes), so a plain
	// endpoint change never silently drops a configured exemption.
	exemptions, err := exemptionsForUpdate(cmd, cfg)
	if err != nil {
		errorf("%s: %v", cmd.Verb, err)
		return 1
	}
	cfg.Exemptions = rawExemptions(exemptions)
	if err := forcing.Reconfigure(ctx, forcingDeps(), cfg, exemptions); err != nil {
		errorf("%s: %v", cmd.Verb, err)
		return 1
	}
	fmt.Printf("%s %s -> endpoint %s (re-applied fail-closed, no leak window)\n", outStyle.Green("reconfigured"), outStyle.Bold(cfg.Account), cfg.Endpoint().URL())
	fmt.Printf("run `%s` to re-prove the account is anonymized\n", outStyle.Cyan(verifyHint(cmd.Account)))
	return 0
}

// configListStore is the store `claimEndpoint` reads the on-disk claim set from
// (every account's persisted endpoint). It is a package var so a unit test points
// its BaseDir at a scratch dir and never touches the real /etc/anonctl/accounts.
var configListStore = accountconfig.DefaultStore()

// claimEndpoint enforces the cross-identification guard for pointing `account` at
// `ep`: it builds the endpoint Registry from every OTHER account's persisted
// endpoint (accountconfig.List, excluding this account so a re-add/re-point is
// idempotent) and Claims `ep`. A socks-peruser endpoint already owned by a
// DIFFERENT account is refused (ErrPeruserAlreadyClaimed, naming the owner); a
// tor-shared endpoint is share-safe and always passes (Tor's `<account>@`
// isolation). A failure to READ the claim set is a loud error (a corrupt sibling
// config must not silently disable the guard), NOT a silent pass.
func claimEndpoint(account string, ep endpoint.Endpoint) error {
	configs, err := configListStore.List()
	if err != nil {
		return fmt.Errorf("checking endpoint sharing: %w", err)
	}
	reg := accountconfig.BuildRegistryExcluding(configs, account)
	return reg.Claim(account, ep)
}

// The scan-and-offer seams: package vars so a unit test drives the endpoint-choice
// flow without a real socket probe or a real terminal. Production wires the real
// DialProber scan, the real stdin TTY check, and reads the real prompt from stdin.
var (
	// endpointScan probes the local socks5h ports and returns the confirmed offers.
	// Tests replace it to inject a scripted candidate set.
	endpointScan = func() []endpoint.Endpoint {
		return endpoint.Scan(endpoint.DialProber{Timeout: 2 * time.Second})
	}
	// stdinIsTTY reports whether add is running interactively (a terminal to prompt
	// at). Non-interactive => no prompt => fail-closed fallback. Tests force either.
	stdinIsTTY = defaultStdinIsTTY
	// promptReader is where the interactive menu pick is read from. Tests inject a
	// scripted reader; production reads os.Stdin.
	promptReader io.Reader = os.Stdin
	// promptWriter is where the interactive menu is rendered (stderr, so it never
	// pollutes any stdout contract). Tests capture it.
	promptWriter io.Writer = os.Stderr
)

// defaultStdinIsTTY reports whether stdin is a character device (a terminal). It
// is the production stdinIsTTY: a piped/redirected stdin (a script, CI) reads as
// NOT a TTY, so add takes the non-interactive fail-closed path.
func defaultStdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// peruserOwners folds the on-disk claim set into a lookup from a peruser endpoint
// key (host:port) to the account that owns it, so BuildOffers can annotate a taken
// endpoint. A tor-shared config contributes nothing (share-safe). A read failure is
// surfaced so the annotation never silently misses a claim.
func peruserOwners() (map[string]string, error) {
	configs, err := configListStore.List()
	if err != nil {
		return nil, fmt.Errorf("reading endpoint claims: %w", err)
	}
	owners := map[string]string{}
	for _, c := range configs {
		ep := c.Endpoint()
		if ep.Class == endpoint.ClassSocksPeruser {
			owners[ep.Address()] = c.Account
		}
	}
	return owners, nil
}

// chooseEndpointInteractive is the no-`--endpoint` resolution shared by `add` and
// `update`/`reconfigure`: scan the local ports, decorate the offers with the default
// (confirmed Tor) selection and the in-use-by-another-account annotation, then either
// PROMPT (interactive) or pick the fail-closed non-interactive outcome
// (Tor-if-confirmed, else refuse). The returned endpoint still flows through
// claimEndpoint before any mutation (the annotation is advisory; the Claim is the
// enforcement). verb names the caller so the non-interactive refusal points at the
// right command to re-run interactively.
func chooseEndpointInteractive(ctx context.Context, account, verb string) (endpoint.Endpoint, error) {
	owners, err := peruserOwners()
	if err != nil {
		return endpoint.Endpoint{}, err
	}
	takenBy := func(ep endpoint.Endpoint) string { return owners[ep.Address()] }
	offers := endpoint.BuildOffers(endpointScan(), account, takenBy)

	if !stdinIsTTY() {
		chosen, cerr := endpoint.ChooseNonInteractive(offers)
		if cerr != nil {
			return endpoint.Endpoint{}, fmt.Errorf("%w (or run `anonctl %s` interactively to choose)", cerr, verb)
		}
		return chosen, nil
	}
	return promptEndpointChoice(ctx, offers)
}

// readLineContext reads one newline-terminated line from r, but returns as soon as
// ctx is cancelled (Ctrl+C / SIGTERM) EVEN IF the blocking read has not yet seen a
// newline. The read runs on a goroutine; whichever of (a line arrives) or (ctx is
// done) happens first wins. On a cancel it returns ctx.Err() with a friendly
// "cancelled" wrapping so the operator sees the interrupt immediately instead of
// having to press Enter to unblock the read. The goroutine may linger on the
// abandoned stdin read until the process exits; that is fine, the process is on its
// way out (a cancelled add returns non-zero right after).
func readLineContext(ctx context.Context, r io.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(r).ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("cancelled: %w", ctx.Err())
	case res := <-ch:
		return res.line, res.err
	}
}

// promptEndpointChoice renders the confirmed offers (evidence only, never labelling
// the provider) and reads the operator's pick: a number selects that offer,
// an empty line accepts the DEFAULT (the confirmed Tor endpoint) when there is one,
// and a `socks5h://host:port` (or bare host:port) types a custom endpoint. A taken
// peruser offer is shown "in use by <account>" and is not selectable. When there is
// no default and the operator just hits enter, it re-prompts once via the custom
// path being required.
func promptEndpointChoice(ctx context.Context, offers []endpoint.Offer) (endpoint.Endpoint, error) {
	def, hasDefault := endpoint.DefaultOffer(offers)
	fmt.Fprintln(promptWriter, "anonctl: no --endpoint given; scanning local socks5h ports (evidence only, provider not labelled):")
	if len(offers) == 0 {
		fmt.Fprintln(promptWriter, "  (no socks5h endpoint confirmed on the common ports)")
	}
	for i, o := range offers {
		line := fmt.Sprintf("  [%d] %s  (%s)", i+1, o.Endpoint.URL(), o.Endpoint.Class)
		if o.IsDefault {
			line += "  [default]"
		}
		if o.TakenBy != "" {
			line += fmt.Sprintf("  IN USE by %q (not selectable)", o.TakenBy)
		}
		fmt.Fprintln(promptWriter, line)
	}
	if hasDefault {
		fmt.Fprintf(promptWriter, "choose a number, type a socks5h://host:port, or press Enter for the default (%s): ", def.Endpoint.URL())
	} else {
		fmt.Fprint(promptWriter, "choose a number or type a socks5h://host:port: ")
	}

	line, rerr := readLineContext(ctx, promptReader)
	if rerr != nil {
		// A cancelled context (Ctrl+C at the prompt) surfaces IMMEDIATELY here, without
		// waiting for the operator to press Enter: the blocking stdin read races the
		// context so the interrupt is observed the moment it arrives, not on the next
		// keystroke. runAdd resolves the endpoint BEFORE creating the account, so a
		// cancel here leaves the box untouched (no half-provisioned account).
		return endpoint.Endpoint{}, rerr
	}
	line = strings.TrimSpace(line)
	switch {
	case line == "" && hasDefault:
		return def.Endpoint, nil
	case line == "":
		return endpoint.Endpoint{}, fmt.Errorf("no endpoint chosen and no default confirmed; re-run with `--endpoint socks5h://host:port`")
	}
	if n, perr := strconv.Atoi(line); perr == nil {
		return endpoint.SelectByIndex(offers, n)
	}
	// A typed value: parse + classify it exactly like an explicit --endpoint.
	return resolveEndpoint(line)
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
// `update --allow ...` replace the set.
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
	// Allocate this account's shim loopback ports from the documented anonctl range,
	// avoiding every OTHER account's already-reserved pair. Without this a second
	// account falls back to the constant defaults (19050/19053) and its shim
	// crash-loops on `bind: address already in use`, so `verify` times out (curl exit
	// 28) with no shim to relay its traffic. Allocation reads the on-disk config set
	// (the reservation LEDGER), excluding THIS account so a name that somehow already
	// has a record does not block its own re-derivation; a full range is a loud
	// failure, never a silent colliding default.
	ports, err := allocatePortsFor(account)
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
		RelayPort:     ports.relay,
		DNSPort:       ports.dns,
		Exemptions:    rawExemptions(exemptions),
	}, nil
}

// allocatePortsFor reads the on-disk config set (via the same configListStore seam
// claimEndpoint uses) and allocates a free relay/DNS pair for account, excluding
// account's own record so a re-derivation never collides with itself. A failure to
// READ the ledger is loud (a corrupt sibling config must not silently disable the
// collision guard, exactly as claimEndpoint treats a read error).
func allocatePortsFor(account string) (portPair, error) {
	configs, err := configListStore.List()
	if err != nil {
		return portPair{}, fmt.Errorf("allocating shim ports: reading account configs: %w", err)
	}
	var others []accountconfig.Config
	for _, c := range configs {
		if c.Account != account {
			others = append(others, c)
		}
	}
	return allocatePortPair(others)
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

// updateHint renders the `update` command that changes an existing account's
// endpoint, in the shortest form the operator would type: `--endpoint` is required
// by update, so the hint carries the placeholder, and the account arg is appended
// only for a named account (mirroring verifyHint / accountArg).
func updateHint(account string) string {
	cmd := "anonctl update --endpoint <socks5h://host:port>"
	if arg := accountArg(account); arg != "" {
		return cmd + " " + arg
	}
	return cmd
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
		errorf("%v", err)
		return 1
	}
	return 0
}

const usage = `usage:
  anonctl add    [--endpoint <socks5h://host:port>] [--allow <IP|CIDR:port>]... [<name>]
                                     provision the account + shim UID, install fail-closed forcing that
                                     survives reboot (default endpoint: the local Tor SocksPort) (root).
                                     CREATE-ONLY: refuses an existing account (use update to change its
                                     endpoint/exemptions, or rm then add to recreate).
                                     --allow punches a narrow direct hole (repeatable; an exact :port is
                                     REQUIRED, never :53): an RFC1918/link-local LAN host, OR a same-host
                                     loopback service 127.0.0.1:<port> (the anonymizer control/SOCKS/DNS
                                     ports 9050/9150/9051/1080 are refused on loopback)
  anonctl rm     [--purge-account] [<name>]
                                     remove forcing; --purge-account also deletes the account (root)
  anonctl seed-home [--from <dir>] [--force] [<name>]
                                     copy a template dir into the account's home (default source:
                                     the directory-exists /etc/anonctl/default-home/); a per-file
                                     collision errors unless --force. Setuid/setgid bits are stripped
                                     on copy. add also seeds from default-home on fresh creation (root)
  anonctl list   [--json]           list the anon accounts that exist on the box
  anonctl status [<name>] [--json]  show one account's state (machine-readable with --json)
  anonctl verify [<name>] [--json] [--skip-tor-exit-check]
                                     prove the account is anonymized (named assertions, non-zero exit on
                                     failure). --skip-tor-exit-check accepts an exit that forced egress but
                                     that check.torproject.org + onionoo did not confirm as a Tor exit (for
                                     a tor-shared endpoint): those registries lag, so a new Tor exit can
                                     read as not-Tor; the exit must still DIFFER from the host.
  anonctl use    [<name>] [--skip-tor-exit-check]
                                     verify the account, then open a shell as it ONLY on green (root); refuses
                                     (no shell) if it is not currently anonymized. A session-start SAFETY GATE,
                                     NOT the leak protection: it is a snapshot (verify at login, not continuous)
                                     and bypassable (su/sudo -iu/ssh/cron reach the account anyway). The real
                                     protection is the kernel rules + the standing default-deny; a MANDATORY gate
                                     is the separate mandatory-anonctl-gated-login idea. Run from your NORMAL
                                     (sudo-capable) account: inside an anon session use cannot re-elevate
                                     (anon has no sudo), so switching accounts means exit first, then re-run.
  anonctl exec   [--as <name>] [--skip-tor-exit-check] <program> [args...]
                                     verify the account, then RUN <program> inside it ONLY on green (root);
                                     refuses (runs nothing) if it is not currently anonymized. use's one-program
                                     sibling: same verify-then-enter gate, but it runs one program instead of
                                     dropping an interactive shell. The account is chosen by --as (default anon,
                                     <name> -> anon-<name>); the FIRST token is the program and EVERYTHING after
                                     it is forwarded VERBATIM (never read as an anonctl flag), so
                                     ` + "`anonctl exec pi -p \"hello world\"`" + ` reaches pi with a single
                                     ` + "`hello world`" + ` arg. Same honesty caveat as use (a snapshot at
                                     launch, not continuous; the real protection is the kernel rules + default-deny).
  anonctl update|reconfigure [--endpoint <socks5h://host:port>] [--allow <IP|CIDR:port>]... [<name>]
                                     change the account's endpoint and re-apply fail-closed (no leak window) (root).
                                     With no --endpoint on a terminal it scans local socks5h ports and prompts
                                     (like add); non-interactively --endpoint is required.
                                     --allow here REPLACES the account's direct holes (omit to keep them)
  anonctl --version | version       print the anonctl version

Box-wide add-time defaults live under ` + "`/etc/anonctl`" + ` (create them yourself; a
fresh install ships neither, so the directory-exists convention stays opt-in):
  - Default home: create ` + "`/etc/anonctl/default-home/`" + ` (e.g.
    ` + "`sudo cp -r <src>/. /etc/anonctl/default-home/`" + `) and its contents seed every
    FRESH account's home. Its PRESENCE is the switch; there is no config key.
  - Default direct exemptions: put them in ` + "`/etc/anonctl/defaults.json`" + `, e.g.
    ` + "`{\"allow\": [\"192.168.1.150:8080\"]}`" + `. A bare ` + "`add`" + ` applies them (a CLI
    ` + "`--allow`" + ` overrides; a default is still validated, never a quieter leak
    path; a port is mandatory). Use ` + "`{\"allow\": []}`" + ` for a valid no-op starting point. This is
    STRICT JSON: NO comments (a malformed defaults.json makes ` + "`add`" + ` fail loud).

A bare verb targets the default account ` + "`anon`" + `; ` + "`<name>`" + ` targets ` + "`anon-<name>`" + `.
Each account gets its OWN dedicated shim service account (` + "`<account>-shim`" + `), the
only UID allowed to reach the upstream endpoint. anonctl does NOT manage the
endpoint's own service: enable your endpoint (e.g. ` + "`tor.service`" + `) at boot yourself.`
