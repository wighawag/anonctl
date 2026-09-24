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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
	"github.com/wighawag/anonctl/internal/nssbypass"
	"github.com/wighawag/anonctl/internal/probe"
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

	// `units print` RETURNS HERE, BEFORE EVERYTHING ELSE, and that placement is the
	// feature rather than an optimisation. It is a PURE function of its flags: it must
	// not self-elevate, must not read or chmod anything under /etc (the mode-assertion
	// chokepoint below writes to the config root when run as root), must not resolve a
	// binary against this host's $PATH, and must emit the same bytes on every host and
	// every run. A Nix derivation that calls it is reproducible only while that is
	// true, so the guarantee is structural: there is no code between Parse and the
	// emitter that could touch the system.
	if cmd.Verb == "units" {
		return runUnits(cmd)
	}

	// A non-fatal note about the account NAME (a read/teardown verb given a name the
	// forcing verbs refuse). It goes to stderr, before anything runs and before any
	// possible self-elevation, so it is visible without polluting a `--json` stdout.
	if cmd.NameWarning != "" {
		fmt.Fprintf(os.Stderr, "%s%s\n", errStyle.Yellow("anonctl: warning: "), cmd.NameWarning)
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

	// ASSERT THE MODES OF THE OPERATOR-PLACED ARTIFACTS under the config root, once,
	// at the single dispatch chokepoint - not in each verb, where the next verb added
	// would forget.
	//
	// `/etc/anonctl` is 0755 so the credential-free marker is readable by any uid, as
	// its contract promises. That traversable root is exactly what removes the
	// incidental protection `default-home/` and `defaults.json` used to get from a
	// 0700 parent: the operator creates them with a plain `cp`/editor, so they carry
	// whatever the umask gave them (typically 0755/0644). Widening the root must widen
	// nothing inside it, and for the two paths anonctl does NOT create, this is where
	// that rule is enforced.
	//
	// Root only (a chmod needs it), best-effort, and a WARNING rather than a failure:
	// being unable to tighten a template is not a reason to refuse to provision an
	// account, but it is absolutely something the operator must be told, because the
	// failure mode is silent disclosure.
	if elevateGeteuid() == 0 {
		if terr := defaultsStore.Tighten(); terr != nil {
			fmt.Fprintf(os.Stderr, "%s%v\n", errStyle.Yellow("anonctl: warning: could not tighten the operator-placed files under /etc/anonctl: "), terr)
			fmt.Fprintf(os.Stderr, "  /etc/anonctl is world-traversable (the marker must be readable by any uid), so anything under it that is not mode-protected is readable by every local user.\n")
		}
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
	case "probe":
		return runProbe(ctx, runner, cmd)
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
// `add` is ADD-ONCE, not create-from-nothing: it refuses an account anonctl ALREADY
// MANAGES, up front, before any mutation, so a second `add` never silently
// re-applies a (possibly different) endpoint/config. Changing a managed account's
// endpoint or exemptions is `update`'s job (which re-applies fail-closed with no
// leak window); re-pointing it is `rm` then `add`. This keeps one clear command per
// intent.
//
// "Already manages" is read from anonctl's OWN LEDGER
// (`/etc/anonctl/accounts/<account>.json`), NOT from the passwd table. An account
// whose passwd entries already exist but that anonctl has no record of is ADOPTED:
// no account is created, the uids are discovered from the box, and the forcing is
// installed against those uids. That is the only way anonctl can run on a host that
// declares its users (NixOS with `users.mutableUsers = false` deletes every
// undeclared account at every activation, so declaring both accounts with pinned
// uids is the supported path there, and it closes the UID-reuse hazard as a bonus).
// See docs/nixos.md.
func runAdd(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	// Refuse an account anonctl ALREADY MANAGES, before provisioning or resolving the
	// endpoint, so a rejected re-add mutates nothing (a pure read) and never re-applies
	// config. Point the operator at the verb that DOES change a live account (update)
	// or at rm+add.
	//
	// The gate reads the LEDGER, because that is what the guard was always about: the
	// thing that must not be silently re-applied is anonctl's own endpoint/exemption
	// record, and a passwd entry says nothing about whether such a record exists. A
	// passwd-entry gate refuses exactly the declarative hosts that need adoption, and
	// refuses them in the worst state available: both accounts exist, nothing jails
	// them, and no anonctl verb will install the forcing (`update` cannot: it targets
	// an account anonctl already manages).
	if _, cerr := configStore.Read(cmd.Account); cerr == nil {
		errorf("add: %s already exists and is managed by anonctl (%s); `add` will not modify it. To change its endpoint or LAN exemptions run `%s`; to re-install its forcing (e.g. after its uid changed) run `%s` first, which leaves the accounts and their homes intact",
			cmd.Account, ledgerPath(cmd.Account), updateHint(cmd.Account), rmHint(cmd.Account))
		return 1
	} else if !errors.Is(cerr, accountconfig.ErrNotFound) {
		// A record that EXISTS but cannot be read (corrupt, unreadable) must never be
		// treated as "absent": that would re-add over an account anonctl already manages,
		// re-applying a config on top of one it could not read. Fail loud instead.
		errorf("add: reading anonctl's record for %s: %v", cmd.Account, cerr)
		return 1
	}

	// ADOPTION vs CREATION, decided from the box. The accounts may already exist
	// without anonctl having any record of them (the declarative host above, or an
	// operator who created them by hand). Then `add` adopts them: provision.Add is a
	// no-op per account that already exists, so nothing is created, the home is left
	// exactly as whoever declared it left it, and the forcing is installed against the
	// uids read from the box further down (buildConfig re-reads them; they are never
	// assumed, because the whole point is that the declaring system chose them).
	st, serr := checkAddPair(ctx, r, cmd.Account)
	if serr != nil {
		errorf("add: %v", serr)
		return 1
	}
	adopting := st.Exists && st.ShimExists
	if adopting {
		if code := vetAdoption(ctx, r, st, "already exist"); code != 0 {
			return code
		}
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

	// The LAST guard before the box is touched: the units this account will depend on
	// at boot must be installable and sound NOW. If they are not, refuse while the host
	// is still untouched. Discovering it after provision.Add would leave an account that
	// EXISTS but whose units were never installed, so the next boot would load neither
	// the baseline default-deny nor the forcing and the anon UID would egress with the
	// host's real IP -- fail-OPEN, and silent.
	//
	// On a host that owns the unit files it asserts the DECLARED units instead of
	// resolving anonctl's own binaries (see systemd.PreflightUnits): both files must be
	// in systemd's search path and the binaries they name must exist.
	unitOwner, err := preflightUnits(forcingDeps().SystemdStore, forcingDeps().Resolver)
	if err != nil {
		errorf("add: %v", err)
		return 1
	}
	if unitOwner.HostOwned {
		fmt.Fprintf(os.Stderr, "anonctl: the host owns anonctl's unit files (%s): they will not be written or rewritten. anonctl still installs this account's own enablement symlink, which is what makes its forcing come back after a reboot.\n", unitOwner.MarkerPath)
		// NAME THE FILES THAT WERE VALIDATED, from the preflight's own result rather than
		// by asking again. In this mode anonctl is vouching for text it did not write, so
		// the operator must be able to see WHICH file it read: with two copies in the
		// search path systemd picks one silently, and "anonctl checked the units" is only a
		// useful statement if it says which ones.
		for _, name := range systemd.SharedUnitNames() {
			if path := unitOwner.Units[name]; path != "" {
				fmt.Fprintf(os.Stderr, "  %s -> %s\n", name, path)
			}
		}
	}

	// THE OTHER LAST GUARD, and the one that is about the account's DNS rather than
	// its packets: refuse a host whose glibc resolves `hosts` OUT OF PROCESS.
	//
	// anonctl's whole mechanism is `meta skuid <anonUID>`, which matches a socket's
	// OWNER. When an nscd-compatible daemon or systemd-resolved does the resolving,
	// the lookup happens in THAT process under THAT uid, so no rule anonctl can write
	// governs it: every name the account visits is resolved by the host's resolver and
	// is attributable to the operator, while the TCP connection exits correctly over
	// the endpoint. That is precisely the correlation an anon account exists to
	// prevent, and it is invisible unless somebody looks for it.
	//
	// It refuses BEFORE provision.Add for the same reason the unit-binary preflight
	// does: refusing later would leave an account that exists, is jailed, and leaks
	// its DNS. anonctl does NOT "fix" the host here, because the remedy belongs to a
	// daemon that serves every uid on the box (forcing its egress is not anonctl's
	// business) and there is no per-uid override of nsswitch.conf or resolv.conf a
	// setup-and-verify manager could install without becoming a runtime wrapper. See
	// docs/adr/0011.
	if code := refuseNSSBypassHost(ctx, cmd); code != 0 {
		return code
	}

	// RE-ASSERT THE PAIR RULE AGAINST THE STATE THAT EXISTS AT MUTATION TIME, and DECIDE
	// FROM THIS READ, not the one above. The earlier read happened before the endpoint
	// prompt, which an operator can sit on for minutes, and on the very host adoption
	// exists for (a declarative one) a concurrent activation creates and deletes
	// accounts. Re-reading shrinks the window in which the pair could change from "the
	// length of the prompt" to the gap before provision.Add's own existence checks; using
	// the re-read's ANSWER is what stops a pair that appeared during the prompt from
	// being adopted with none of the adoption guards ever having run. It is not atomic
	// (nothing here can be), so the post-condition after provisioning reports the
	// residual race rather than pretending it cannot happen.
	st, serr = checkAddPair(ctx, r, cmd.Account)
	if serr != nil {
		errorf("add: %v", serr)
		return 1
	}
	if !adopting && st.Exists && st.ShimExists {
		// The pair APPEARED while this run was waiting. That turns a creation into an
		// adoption, so it must clear the same bar an adoption cleared above (a shared uid is
		// no less dangerous for having been created a minute ago) and must be disclosed, or
		// the run would silently force accounts the operator never saw anonctl consider.
		// Nothing has been mutated yet, so a refusal here is still free.
		if code := vetAdoption(ctx, r, st, "appeared while this run was waiting for an endpoint, so this is now an adoption"); code != 0 {
			return code
		}
		adopting = true
	}

	// All questions answered and all guards passed: NOW create the account + its
	// dedicated shim UID. When adopting, this is a pure no-op (both accounts exist),
	// which is precisely why adoption needs no separate provisioning path: res.Created
	// / res.ShimCreated report which happened, and everything that is scoped to a FRESH
	// account (the home seeding below, and the login-env write inside provision.Add)
	// stays scoped to it. An adopted account's home belongs to whoever declared it.
	res, err := provision.Add(ctx, r, cmd.Account)
	if err != nil {
		errorf("add: %v", err)
		return 1
	}
	if adopting && (res.Created || res.ShimCreated) {
		// The accounts were there when we looked and one of them was not there when we
		// provisioned: the box changed underneath this run (on a declarative host, that is
		// an activation deleting an undeclared account mid-add). anonctl has just CREATED
		// what it meant to adopt, so it says so loudly rather than reporting an adoption
		// that did not happen. It continues: the forcing below is built from the uids read
		// after this point, so it is correct for the accounts that exist NOW, and stopping
		// here would leave those accounts with no forcing at all.
		fmt.Printf("%s %s and/or %s disappeared between this run's checks and creation, so anonctl CREATED the missing account(s) instead of adopting them. On a host that deletes undeclared accounts they will be deleted again at the next activation: declare them (see docs/nixos.md), then run `%s` and `anonctl add %s` again\n",
			outStyle.Red("WARNING:"), cmd.Account, res.Shim, rmHint(cmd.Account), accountArg(cmd.Account))
	}

	// On FRESH creation only, seed the home from the directory-exists default
	// /etc/anonctl/default-home/ when present (never overwriting: `add` has no --force,
	// so it seeds with force=false). An ADOPTED account (Created=false) is never
	// seeded, mirroring the login-env write: its home is whoever declared it's, and
	// anonctl is not entitled to drop files into it. Seeding failure is a real add
	// failure (the account did not land as configured), surfaced non-zero.
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
	if err := addForcingInstall(ctx, forcingDeps(), cfg, exemptions); err != nil {
		errorf("add: installing forcing: %v", err)
		return 1
	}
	warnShadowedUnits()

	// Report which of the two paths actually ran, read from what provisioning DID (not
	// from the earlier prediction), so the line never claims to have created an account
	// it adopted.
	did := "provisioned + forced"
	if !res.Created {
		did = "adopted + forced"
	}
	fmt.Printf("%s %s (shim %s, endpoint %s)\n", outStyle.Green(did), outStyle.Bold(res.Account), res.Shim, cfg.Endpoint().URL())
	if !res.Created {
		fmt.Printf("%s anonctl did NOT create %s (uid %d) or %s (uid %d); whoever declared them owns their lifecycle. The installed rules match those uids, so if either uid ever changes the rules will govern the OLD one: `%s` reports that as its account-identity check, and `anonctl status` shows it too\n",
			outStyle.Yellow("note:"), res.Account, cfg.AnonUID, res.Shim, cfg.ShimUID, verifyHint(cmd.Account))
	}
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

// checkAddPair reads the account pair's state from the box and enforces the rule
// that `add` deals in PAIRS: the login account and its shim must both exist (adopt
// them) or both be absent (create them). Half a pair is refused with an error that
// names BOTH accounts.
//
// Half a pair is provision.go:145's half-provisioned state, and adopting it would
// install forcing naming a uid that does not exist: with no shim account the
// endpoint-reachability exemption names nobody, so the account is fail-CLOSED but
// permanently unusable while anonctl reports it as set up. Creating the missing half
// instead is worse on the host that needs adoption: an account anonctl creates there
// is undeclared, so the next activation deletes it and the half-state returns at
// every boot. So it refuses and lets the operator fix it where the accounts are
// actually defined.
//
// It is called TWICE: once early (before the endpoint prompt, so a refusal costs the
// operator nothing) and once immediately before provisioning (so the rule is applied
// to the state that exists at mutation time, not to a reading from before the
// prompt).
func checkAddPair(ctx context.Context, r provision.Runner, account string) (provision.AccountStatus, error) {
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		return st, err
	}
	if st.Exists == st.ShimExists {
		return st, nil
	}
	present, absent := account, st.Shim
	if !st.Exists {
		present, absent = st.Shim, account
	}
	return st, fmt.Errorf("%s already exists but %s does not, and anonctl has no record of %s: it will not adopt half a pair. The forcing it installs names BOTH uids (the account's, and the shim's as the only uid allowed to reach the endpoint), so adopting %s alone would name a uid that does not exist. Both %s and %s must exist, or neither: on a host that declares its accounts, declare both with pinned uids (see docs/nixos.md) and re-run this; otherwise run `%s` to clear the leftover half and let `add` create both",
		present, absent, account, present, account, st.Shim, purgeHint(account))
}

// vetAdoption runs the checks an ADOPTION must clear and discloses it, returning an
// exit code (0 = proceed). Both places that can decide "this is an adoption" go
// through it: the read before the endpoint prompt, and the re-read at mutation time
// for a pair that appeared in between. Keeping it in one function is what stops the
// second path from silently skipping the guard the first path applies. what names
// how the accounts came to be here, so the disclosure is truthful in both cases.
func vetAdoption(ctx context.Context, r provision.Runner, st provision.AccountStatus, what string) int {
	// The adopted uids must be THIS pair's and nobody else's. anonctl did not allocate
	// them, so the uniqueness `useradd` would have enforced is not guaranteed here: a
	// pair created with `useradd -o -u <uid>`, or a host without uid-uniqueness
	// enforcement, can share a uid with an unrelated account. The rules match `meta
	// skuid`, which knows nothing about names, so forcing such a uid would silently jail
	// that other account too - the UID-reuse hazard, arrived at by adoption instead of
	// by deletion.
	if err := refuseSharedUID(ctx, r, st); err != nil {
		errorf("add: %v", err)
		return 1
	}
	// Disclose it as early as the decision is made (before the endpoint prompt on the
	// ordinary path), so the operator can abort if adopting these particular accounts is
	// not what they meant.
	fmt.Printf("%s %s (uid %s) and %s (uid %s) %s and anonctl has no record of them: adopting them as they are (no account is created, no home is touched)\n",
		outStyle.Bold("adopting:"), st.Account, st.UID, st.Shim, st.ShimUID, what)
	return 0
}

// refuseSharedUID refuses adopting a pair whose uid (or shim uid) is ALSO owned by
// another account in the passwd table.
//
// This guard exists only on the adoption path, because only there does anonctl force
// a uid it did not allocate: `useradd` refuses a duplicate uid unless explicitly
// told otherwise, so an account anonctl created is unique by construction, while an
// account it adopts is only as unique as whoever made it. The nft rules match `meta
// skuid <uid>` and know nothing about names, so forcing a shared uid would redirect
// and default-deny the OTHER account's egress too, silently: the UID-reuse hazard
// docs/nixos.md describes, reached by adoption rather than by deletion.
//
// It asks TWO questions, because neither alone covers the hosts anonctl runs on:
//
//   - a REVERSE lookup (`getent passwd <uid>`) resolves through NSS, so it still
//     answers on a directory backend (LDAP/SSSD/AD, nss-systemd) that does not allow
//     enumeration. It returns only the FIRST match, so it catches the dangerous
//     shape - another account OUTRANKING ours for that uid - but cannot see a
//     duplicate that sorts after us.
//   - an ENUMERATION (`getent passwd`) sees every LOCAL duplicate, including one
//     that sorts after the anon account, which the reverse lookup would miss.
//
// Neither can prove a NEGATIVE on a non-enumerable backend: enumeration there
// returns the local files only, non-empty and incomplete, so "no collision found" is
// not "no collision". That is stated in a note rather than treated as a refusal:
// refusing every directory-backed host for a hazard with no evidence would make
// anonctl unusable on them, and the reverse lookup has already asked the one
// question those backends can answer.
func refuseSharedUID(ctx context.Context, r provision.Runner, st provision.AccountStatus) error {
	lines := provision.ReadPasswd(ctx, r)
	for _, target := range []struct{ account, uid string }{{st.Account, st.UID}, {st.Shim, st.ShimUID}} {
		owners := passwdNamesForUID(lines, target.uid)
		if owner, ok := passwdNameOfUID(ctx, r, target.uid); ok {
			owners = append(owners, owner)
		}
		for _, other := range owners {
			if other == target.account {
				continue
			}
			return fmt.Errorf("%s owns uid %s, but so does %q: anonctl will not adopt an account whose uid is shared. Its rules match `meta skuid %s`, which names a uid and not an account, so forcing it would silently redirect and default-deny %q's egress as well. Give %s a uid of its own (a PINNED, unshared one on a host that declares its accounts) and re-run this",
				target.account, target.uid, other, target.uid, other, target.account)
		}
	}
	if len(lines) == 0 {
		// getent produced NOTHING at all: not even the local files were read, so only the
		// reverse lookups above were answered. Say which question went unanswered rather
		// than implying the uids were cleared.
		fmt.Fprintf(os.Stderr, "%s could not enumerate the passwd table, so anonctl could not check uid %s and uid %s against every account on this host (only against the one each uid resolves to); adopting anyway - re-check with `getent passwd | awk -F: '$3==%s || $3==%s'`\n",
			errStyle.Yellow("note:"), st.UID, st.ShimUID, st.UID, st.ShimUID)
	}
	return nil
}

// passwdNameOfUID resolves a uid back to the account NAME the box's NSS stack
// answers with (`getent passwd <uid>`), reporting false when it resolves to nothing.
// It is the half of the sharing check that survives a backend which refuses
// enumeration, since a direct lookup is answered where a table dump is not. It reads
// only the FIRST match by construction (that is all getent returns), which is why
// the enumeration above is still consulted.
func passwdNameOfUID(ctx context.Context, r provision.Runner, uid string) (string, bool) {
	if strings.TrimSpace(uid) == "" {
		return "", false
	}
	stdout, _, err := r.Run(ctx, "getent", "passwd", strings.TrimSpace(uid))
	if err != nil && strings.TrimSpace(stdout) == "" {
		return "", false
	}
	line := strings.TrimSpace(strings.SplitN(stdout, "\n", 2)[0])
	fields := strings.Split(line, ":")
	if len(fields) < 3 || fields[0] == "" {
		return "", false
	}
	// Guard against a backend answering with a DIFFERENT uid than asked for (a fuzzy or
	// misconfigured resolver): only a line that really carries this uid is evidence.
	if strings.TrimSpace(fields[2]) != strings.TrimSpace(uid) {
		return "", false
	}
	return fields[0], true
}

// passwdNamesForUID returns every account NAME in the passwd lines that owns uid.
// Lines it cannot parse are skipped: a malformed entry is not evidence of sharing,
// and this is a guard, not a passwd validator.
func passwdNamesForUID(lines []string, uid string) []string {
	if strings.TrimSpace(uid) == "" {
		return nil
	}
	var names []string
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if strings.TrimSpace(fields[2]) == strings.TrimSpace(uid) {
			names = append(names, fields[0])
		}
	}
	return names
}

// addVerifyReport runs the shared verify gate for `add`'s inline proof. It is a
// package var mirroring useVerifyReport/execVerifyReport so a unit test can drive
// runAdd's tail (the inline verify + its green/red messaging) without a real probe
// run; production wires the real verifyAndMark (assertions + marker-on-green).
var addVerifyReport = verifyAndMark

// addForcingInstall installs the forcing for an account `add` has just provisioned
// or adopted (rules + persisted state + units + the shim). It is a package var
// mirroring rmForcingRemove so a unit test can drive runAdd end-to-end (the
// adoption path in particular: no account created, the home untouched, the rules
// built from the uids read off the box) without a real nft/systemd host.
var addForcingInstall = forcing.Install

// ledgerPath renders the path of an account's anonctl record for an error message,
// falling back to the account name when the store cannot name it (an invalid
// account name, which the CLI's own parse already rejects). It exists so the
// "already managed" refusal points at the FILE the operator can look at and delete,
// rather than asserting management with no evidence.
func ledgerPath(account string) string {
	if p, err := configStore.Path(account); err == nil {
		return p
	}
	return account
}

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

// The packaged unit DATA files (share/anonctl/units/*.in) are GENERATED by the
// emitter below, never hand-written: they are the same text with each host-varying
// path left as an `@name@` token, so a packager can ship inspectable data with no
// build-time execution (and no cross-compilation problem) while there is still only
// ONE copy of the unit template in this repository. `go generate ./...` refreshes
// them; TestPackagedUnitFilesMatchTheEmitter fails the build if anyone edits them by
// hand or forgets to regenerate after touching the generator.
//
//go:generate sh -c "go run . units print --placeholders --kind shim > 'share/anonctl/units/anonctl-shim@.service.in'"
//go:generate sh -c "go run . units print --placeholders --kind nftables > share/anonctl/units/anonctl-nftables.service.in"

// runUnits implements `anonctl units print`: it writes the text of ONE of anonctl's
// two shared, account-agnostic unit files to stdout, so a host can DECLARE that unit
// in its own configuration instead of depending on a file `anonctl add` wrote into
// /usr/local/lib/systemd/system that no rebuild reproduces and no rollback undoes.
//
// It is single-sourced through the same generator `add` installs through
// (systemd.Export -> TemplateUnit/LoaderUnit), so the text a host declares and the
// text anonctl would have written cannot drift apart across a version. There is no
// second copy of the template anywhere in this repository, including in testdata,
// and a test asserts the byte-identity rather than trusting the comment.
//
// It needs NO root, touches nothing, and prints only the unit to stdout (every
// diagnostic goes to stderr), so `anonctl units print ... > file` in a build is
// exactly the unit and nothing else.
func runUnits(cmd *cli.Command) int {
	kind := systemd.Kind(cmd.UnitKind)
	p := systemd.ExportParams{
		Kind:           kind,
		SetprivPath:    cmd.UnitSetprivPath,
		ShimBinaryPath: cmd.UnitShimPath,
		EnvDir:         cmd.UnitEnvDir,
		NftPath:        cmd.UnitNftPath,
		RulesDir:       cmd.UnitRulesDir,
	}
	var (
		text string
		err  error
	)
	if cmd.UnitPlaceholders {
		text, err = systemd.ExportPlaceholders(kind)
	} else {
		text, err = systemd.Export(p)
	}
	if err != nil {
		errorf("units print: %v", err)
		return 1
	}
	name, err := kind.UnitFileName()
	if err != nil {
		errorf("units print: %v", err)
		return 1
	}
	// The file NAME the host must install this text under goes to STDERR, never stdout:
	// it is essential (anonctl's per-account enablement symlinks name the shim TEMPLATE,
	// so a host that declared the same text under another name would leave them pointing
	// at nothing), and it must not end up inside the unit file when stdout is redirected.
	fmt.Fprintf(os.Stderr, "anonctl: install this text as %s\n", name)
	fmt.Print(text)
	return 0
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
)

// markerStore is the marker Store every verb reads/writes the double-anonymization
// CLAIM through: `verify` writes it on green, `status` reads it, `rm` removes it. It
// is a package var so the unit tests point it at a scratch t.TempDir() instead of
// the real `/etc/anonctl` (the shared-write isolation discipline the marker's own
// tests use via Store.BaseDir). Production wires the real DefaultStore.
var markerStore = marker.DefaultStore()

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
	if err := markerStore.Remove(cmd.Account); err != nil {
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

// readPasswd is the account-table read `list` enumerates from. A package var so a
// unit test can script the passwd table (and therefore the whole listing) without
// depending on which anon accounts happen to exist on the developer's box.
var readPasswd = provision.ReadPasswd

// listSchemaVersion is the version of the `list --json` CONTRACT: the document
// shape a sibling tool parses. It mirrors verify.SchemaVersion / marker's /
// accountconfig's: a consumer guards on it before trusting the rest, it evolves
// ADDITIVELY (new optional fields do not bump it), and a breaking reshape bumps it.
//
// It starts at 2, not 1, and the gap is deliberate documentation: version 1 is the
// unversioned shape 0.6.x emitted (a bare top-level ARRAY of rows carrying
// `forced`, `sudoChecked` and `sudoAllowed` bools that NOTHING on the list path
// ever computed, so every row reported false at every privilege level). Numbering
// this 2 lets a consumer that finds no `schemaVersion` key at all conclude it is
// reading exactly that broken shape, rather than having to guess.
const listSchemaVersion = 2

// listReport is the `list --json` document. It is an OBJECT wrapping the rows
// rather than a bare array, because a bare array has nowhere to carry a schema
// version - which is the whole reason the previous reshape could not be announced
// to consumers.
type listReport struct {
	SchemaVersion int                        `json:"schemaVersion"`
	Accounts      []provision.AccountListing `json:"accounts"`
}

// runList enumerates the anon accounts, from TWO sources: the passwd table (the
// existence source, honest box truth) and anonctl's ledger (the managed-ness
// source, unioned in so an account anonctl records but the box no longer has is
// visible rather than silently absent). Each row's forcing state is read from the
// marker as an explicit TRI-STATE.
//
// Read-only, and it needs no root - but WITHOUT root it will honestly report
// `managed: null` and `forcing: {"state": "unknown"}`, because the ledger is
// root-only by design. That is the point: `list` used to answer those questions
// confidently at every privilege level from fields nothing computed, so an
// unprivileged caller was told "not forced" about accounts that were forced.
func runList(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	rows, err := provision.List(ctx, r, readPasswd(ctx, r))
	if err != nil {
		errorf("list: %v", err)
		return 1
	}
	// Resolve deliberately cannot fail: an unreadable ledger/marker is a STATE of the
	// answer (null / unknown, each with its reason), never a substituted zero value.
	accounts := provision.Resolve(rows, configStore, markerStore)
	if cmd.JSON {
		return emitJSON(listReport{SchemaVersion: listSchemaVersion, Accounts: accounts})
	}
	if len(accounts) == 0 {
		fmt.Println("no anon accounts")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tUID\tSHIM\tSHIM-UID\tMANAGED\tFORCING")
	for _, a := range accounts {
		uid, shimUID := a.UID, a.ShimUID
		if !a.Exists {
			// A ledger-only row: anonctl records the account, the box has no passwd entry.
			uid = outStyle.Red("NO PASSWD ENTRY")
		}
		if shimUID == "" {
			shimUID = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Account, uid, a.Shim, shimUID, renderManaged(a), renderForcing(a.Forcing))
	}
	tw.Flush()
	// An undetermined column is not a blank to be skimmed past: say WHY, once, so an
	// unprivileged operator knows the answer is missing rather than negative.
	if reason := firstUndeterminedReason(accounts); reason != "" {
		fmt.Printf("\n%s some columns could not be determined (%s).\n", outStyle.Yellow("note:"), reason)
		fmt.Printf("  anonctl's ledger is root-only by design; re-run as root for a determined answer.\n")
	}
	fmt.Printf("\nforcing is a CLAIM that `verify` passed at some point, not a live proof; `%s` is the cheap live check.\n",
		outStyle.Cyan("anonctl probe <name>"))
	return 0
}

// renderManaged renders the tri-state managed-ness: yes / no / UNKNOWN, with
// UNKNOWN visually distinct so it is never skimmed as a "no".
func renderManaged(a provision.AccountListing) string {
	switch {
	case a.Managed == nil:
		return outStyle.Yellow("UNKNOWN")
	case *a.Managed:
		return outStyle.Green("yes")
	default:
		return "no"
	}
}

// renderForcing renders the tri-state forcing verdict.
func renderForcing(f provision.Forcing) string {
	switch f.State {
	case provision.StateForced:
		return outStyle.Green("forced")
	case provision.StateUnforced:
		return outStyle.Red("unforced")
	default:
		return outStyle.Yellow("UNKNOWN")
	}
}

// firstUndeterminedReason returns the first reason an answer could not be
// determined, so the human output can explain the UNKNOWN columns instead of
// leaving them to be read as negatives.
func firstUndeterminedReason(accounts []provision.AccountListing) string {
	for _, a := range accounts {
		if a.ManagedReason != "" {
			return a.ManagedReason
		}
		if a.Forcing.State == provision.StateUnknown && a.Forcing.Reason != "" {
			return a.Forcing.Reason
		}
	}
	return ""
}

// statusReport is the `status --json` document: the account state read from the box
// (EMBEDDED, so every existing field name in the contract is unchanged) plus the
// IDENTITY view, which is the one thing the box alone cannot say - whether what is
// on the box still agrees with what anonctl RECORDED. A consumer that gates on the
// old fields is unaffected; one that cares reads `identity.state`.
type statusReport struct {
	// SchemaVersion is the version of the `status --json` CONTRACT, so a sibling tool
	// can guard on the shape it understands before trusting the rest - the same
	// discipline verify, the marker and the account config already follow, applied to
	// the two documents a consumer actually parses. It is ADDITIVE here (the existing
	// field names are unchanged), so a consumer pinned to the old shape is unaffected
	// and gains a version to key on.
	SchemaVersion int `json:"schemaVersion"`
	provision.AccountStatus
	Identity statusIdentity `json:"identity"`
}

// statusSchemaVersion is the version of the `status --json` document.
//
// It is 2. Version 1 was this same document with `forced` as a plain bool - and,
// more importantly, with NO DOCUMENT AT ALL when the marker could not be read (the
// verb exited 1 and printed an error). `forced` is now null when undetermined, and
// there is a `forcing` object carrying the tri-state and its reason, identical in
// shape to the one `list` emits so the two verbs cannot disagree about how they say
// "I could not tell". A consumer that treated a non-zero exit as "not forced" was
// already wrong; one that read `forced` as a bool must now handle null.
const statusSchemaVersion = 2

// statusIdentity is the machine-readable identity verdict: the same classification
// `verify`'s account-identity precondition gates on (verify.AccountIdentity.State),
// plus the uids anonctl RECORDED so a consumer can see both sides of the
// comparison. State is the field to switch on; Detail is the human evidence line
// and is not a contract.
type statusIdentity struct {
	State           string `json:"state"`
	Ok              bool   `json:"ok"`
	Detail          string `json:"detail"`
	HaveRecord      bool   `json:"haveRecord"`
	RecordedUID     int    `json:"recordedUid,omitempty"`
	RecordedShimUID int    `json:"recordedShimUid,omitempty"`
	// RecordError is the underlying read error when the record could not be read and
	// its absence could not be established (state record-unreadable), so a consumer
	// sees "permission denied" or the parse error rather than only the summary.
	RecordError string `json:"recordError,omitempty"`
}

// runStatus reports one account's state, read from the box AND compared against
// anonctl's own record. --json emits the machine-readable contract; the human form
// is a short summary. Read-only.
//
// The comparison is why this verb is not just a passwd dump. An account can be
// GONE, or can exist owning a uid that is no longer the one the installed rules
// govern, and both of those are silent: the rules stay loaded, the marker stays
// written, and `/etc/anonctl` goes on recording the account as jailed. `status`
// names that condition as itself (the SAME decision `verify`'s precondition gates
// on, via verify.AccountIdentity.State, so the two can never disagree) instead of
// reporting a reassuring "provisioned" line about a uid that belongs to nobody.
//
// It stays EXIT-CODE NEUTRAL: `status` reports, `verify` adjudicates (it is the
// non-zero CI gate, and the identity precondition fails there). A drifted account
// is loud in the output, not in the exit status, so existing scripts that only
// check whether `status` ran are not silently broken by this.
func runStatus(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		errorf("status: %v", err)
		return 1
	}
	// Read the marker (the same dependency-free truth a sibling tool reads). A missing
	// marker is a clean "not forced"; an UNREADABLE one is `unknown` WITH ITS REASON,
	// and neither aborts the verb. This used to exit 1 with no document at all, which
	// made the richest verb the one a consumer could get no partial truth from - over a
	// single field, whose usual cause is just running without privilege, while the
	// eight other things `status` had already established went unreported. It was also
	// inconsistent with this verb's own handling of the LEDGER right below, where an
	// unreadable record has always been a named state rather than an absence.
	st = st.WithMarker(markerStore)
	// The identity comparison: the live uids (above) against the uids anonctl recorded
	// when it installed the forcing (the ledger). accountIdentity holds the two apart;
	// State classifies the disagreement.
	id := accountIdentity(configStore, cmd.Account, st)
	state := id.State()
	detail := verify.AccountIdentityAssertion(id).Detail

	if cmd.JSON {
		return emitJSON(statusReport{
			SchemaVersion: statusSchemaVersion,
			AccountStatus: st,
			Identity: statusIdentity{
				State:           string(state),
				Ok:              state.Ok(),
				Detail:          detail,
				HaveRecord:      id.HaveRecord,
				RecordedUID:     id.RecordedUID,
				RecordedShimUID: id.RecordedShimUID,
				RecordError:     errText(id.RecordErr),
			},
		})
	}
	if !st.Exists {
		// THREE different conditions share "no passwd entry", and conflating them is what
		// made this unreadable on a host that deletes undeclared accounts. With no anonctl
		// record it is simply an account that was never added. WITH one, the account was
		// deleted out from under a forcing that is still installed and still governing a
		// uid that is now free: say that, and say which uid. And when the record could not
		// be READ, anonctl cannot tell those two apart, which must not be reported as the
		// harmless one: an unprivileged `status` in exactly the scenario this check exists
		// for (activation deleted the pair) would otherwise print a calm "not provisioned"
		// while rules may still be governing a freed uid.
		switch {
		case id.RecordErr != nil:
			fmt.Printf("%s: %s (no passwd entry, and anonctl's record could not be read, so whether forcing is still installed for it - and which uid that forcing governs - cannot be said from here)\n",
				outStyle.Bold(st.Account), outStyle.Red("UNKNOWN"))
			fmt.Printf("  identity: %s (%s)\n", outStyle.Red("UNKNOWN"), errText(id.RecordErr))
			fmt.Printf("    the record lives under /etc/anonctl/accounts and is root-only, so the usual cause is running without privilege: re-run as root\n")
			return 0
		case id.HaveRecord:
			fmt.Printf("%s: %s (anonctl records it as forced, governing uid %d; there is no passwd entry for it)\n",
				outStyle.Bold(st.Account), outStyle.Red("ACCOUNT MISSING"), id.RecordedUID)
			fmt.Printf("  %s\n", detail)
			return 0
		}
		fmt.Printf("%s: %s\n", outStyle.Bold(st.Account), outStyle.Yellow("not provisioned"))
		if st.ShimExists {
			// A stray shim with no login account is half a pair, which `add` REFUSES. Say so
			// here: `status` is the cheap diagnostic an operator runs first, and it should
			// name what the mutating verb is going to object to rather than report a bare
			// "not provisioned" and let them discover it from a refusal.
			fmt.Printf("  shim %s: %s (uid %s) - half a pair: `anonctl add` refuses this until both accounts exist or neither (`%s` clears it)\n",
				st.Shim, outStyle.Red("PRESENT WITHOUT ITS ACCOUNT"), st.ShimUID, purgeHint(st.Account))
		}
		return 0
	}
	fmt.Printf("%s: %s (uid %s)\n", outStyle.Bold(st.Account), outStyle.Green("provisioned"), st.UID)
	if st.ShimExists {
		fmt.Printf("  shim %s: %s (uid %s)\n", st.Shim, outStyle.Green("present"), st.ShimUID)
	} else {
		fmt.Printf("  shim %s: %s\n", st.Shim, outStyle.Red("MISSING"))
	}
	printStatusIdentity(state, st, id, detail)
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
	// The forcing line is a TRI-STATE, like every other undetermined answer anonctl
	// reports: yes / no / UNKNOWN-with-its-reason. An unprivileged operator must not
	// read "no" off a marker nobody could open.
	switch st.Forcing.State {
	case provision.StateForced:
		if st.Marker != nil {
			fmt.Printf("  forced: %s (endpoint class %s, marked %s)\n", outStyle.Green("yes"), st.Marker.EndpointClass, st.Marker.CreatedAt)
		} else {
			fmt.Printf("  forced: %s\n", outStyle.Green("yes"))
		}
	case provision.StateUnforced:
		fmt.Printf("  forced: %s (no marker)\n", outStyle.Yellow("no"))
	default:
		fmt.Printf("  forced: %s (the marker could not be read, so this is UNDETERMINED - not a \"no\": %s)\n",
			outStyle.Yellow("UNKNOWN"), st.Forcing.Reason)
		fmt.Printf("    the marker lives at %s; re-run as root, or check the mode of /etc/anonctl\n", markerPathHint(st.Account))
	}
	// The boot-freshness hint belongs with the forcing line: a marker is a claim that
	// verify passed at SOME point, and `probe` is what answers "right now".
	if st.Forcing.State == provision.StateForced {
		fmt.Printf("    this is a CLAIM that `verify` passed, not a live proof; `%s` checks the rules are loaded right now\n",
			outStyle.Cyan("anonctl probe "+accountArg(st.Account)))
	}
	return 0
}

// markerPathHint names the marker file for an account, for an error/UNKNOWN line.
// A malformed name (which cannot produce a path) degrades to the directory rather
// than printing nothing.
func markerPathHint(account string) string {
	if p, err := markerStore.Path(account); err == nil {
		return p
	}
	return marker.DefaultBaseDir
}

// probeNftRun is the seam `probe` reads the live ruleset through (`nft list table
// inet anonctl_<account>`). A package var so the unit tests drive every verdict
// path - table loaded, table missing, ruleset unreadable - with no root and no real
// nft. Production wires the real shell-out.
// It returns (ruleset, tableAbsent, err) and CLASSIFIES the failure, which is the
// whole reason it is not a one-liner. `nft list table` exits non-zero both when the
// table does not exist AND when the caller may not read the ruleset, so a gatherer
// that mapped every failure to an error would make "the rules are gone" -
// the post-reboot condition this verb exists to catch - indistinguishable from "you
// are not root", and would tell a root operator to re-run as root.
//
// The classifier is PRIVILEGE, not stderr text: if we are not root we could not
// have read the ruleset whatever nft said, and if we ARE root and nft ran, a
// non-zero exit means the table is not there. Matching nft's English error strings
// would be a translation and version dependency; the euid is neither.
var probeNftRun = func(ctx context.Context, table string) (string, bool, error) {
	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", table)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err == nil {
		return strings.TrimSpace(out.String()), false, nil
	}
	msg := strings.TrimSpace(errb.String())
	if msg == "" {
		msg = err.Error()
	}
	// nft's stderr is multi-line (a netlink note follows the error). Flatten it: this
	// string lands inside a one-line check evidence field, and a raw newline there
	// breaks the report's alignment and any consumer reading it line by line.
	flat := strings.Join(strings.Fields(msg), " ")
	// A failure to even START nft (not installed, not on PATH) is UNDETERMINED: it says
	// nothing about whether the table is loaded.
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return "", false, fmt.Errorf("%s", flat)
	}
	if elevateGeteuid() != 0 {
		return "", false, fmt.Errorf("%s", flat)
	}
	// Root, and nft ran and refused: the table is not loaded.
	return "", true, nil
}

// probeBootID is the seam for the running kernel's boot id, so a test can pin it.
var probeBootID = marker.CurrentBootID

// runProbe answers "is this account jailed RIGHT NOW" cheaply: no network, no Tor
// exit check, no probes run as the account. It is the verb every automated
// consumer needs on every trigger, and it exists HERE rather than in each
// consumer because the two things it has to know - the per-account nft table name
// and which rule actually attributes a uid to the forcing - are anonctl's private
// convention. A consumer grepping anonctl's ruleset is a coupling anonctl did not
// choose and could not refactor away.
//
// It EXITS NON-ZERO when the account is not jailed, including when a check could
// not be determined, so a shell consumer can gate on the exit status alone. That
// is a deliberate divergence from `status`, which is exit-code neutral because it
// reports; probe adjudicates one narrow question, like `verify` does for the broad
// one.
//
// Reading the ruleset needs root (`nft` is privileged). Probe does NOT
// self-elevate: it is built to be called from automation on every trigger, and a
// verb that can pop a sudo password prompt is unusable there. Without root it
// reports rules-unreadable - UNDETERMINED, and therefore not jailed - and says to
// re-run as root, rather than certifying an account from a question it could not
// ask.
func runProbe(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		errorf("probe: %v", err)
		return 1
	}

	in := probe.Input{
		Account:       cmd.Account,
		AccountExists: st.Exists,
		LiveUID:       st.UID,
		TableName:     nftables.TableName(cmd.Account),
	}

	m, merr := markerStore.Read(cmd.Account)
	if merr != nil {
		in.MarkerErr = merr
	} else {
		in.Marker = &m
	}

	// The uid the rules must govern is the account's LIVE uid. Using the live uid (not
	// the marker's) is what makes uid drift show up as "the loaded rules do not govern
	// this account" rather than being papered over by a self-consistent stale pair.
	if uid, convErr := strconv.Atoi(st.UID); convErr == nil {
		in.GoverningRule = nftables.GoverningRule(uid)
	}
	in.Ruleset, in.TableAbsent, in.RulesetErr = probeNftRun(ctx, in.TableName)

	// A missing boot id is not an error: it is additive, and its absence is reported
	// as an UNKNOWN boot state rather than as a failure.
	if bootID, berr := probeBootID(); berr == nil {
		in.CurrentBootID = bootID
	}

	rep := probe.Decide(in)
	if cmd.JSON {
		if code := emitJSON(rep); code != 0 {
			return code
		}
		return probeExit(rep)
	}
	printProbe(rep)
	return probeExit(rep)
}

// probeExit maps the verdict onto the process exit code: 0 jailed, 1 not.
func probeExit(rep probe.Report) int {
	if rep.Jailed {
		return 0
	}
	return 1
}

// printProbe renders the human form: the verdict, then every check (all of them,
// passing and failing, so the report is complete), then the boot line.
func printProbe(rep probe.Report) {
	if rep.Jailed {
		fmt.Printf("%s: %s (uid %s)\n", outStyle.Bold(rep.Account), outStyle.Green("JAILED"), rep.UID)
	} else {
		fmt.Printf("%s: %s (%s)\n", outStyle.Bold(rep.Account), outStyle.Red("NOT JAILED"), rep.FirstFailure())
	}
	for _, c := range rep.Checks {
		mark := outStyle.Red("FAIL")
		if c.Ok {
			mark = outStyle.Green("ok")
		}
		if c.Ok {
			fmt.Printf("  %-16s %s   %s\n", c.Name, mark, c.Detail)
		} else {
			fmt.Printf("  %-16s %s %s: %s\n", c.Name, mark, c.Reason, c.Detail)
		}
	}
	switch rep.Boot.State {
	case probe.BootThisBoot:
		fmt.Printf("  boot             %s   the forcing was PROVEN during this boot\n", outStyle.Green("ok"))
	case probe.BootEarlierBoot:
		fmt.Printf("  boot             %s the marker was written in an EARLIER boot: the rules above are loaded now, but nothing has re-PROVEN them since this machine came up (`%s`)\n",
			outStyle.Yellow("note"), outStyle.Cyan(verifyHint(accountArg(rep.Account))))
	default:
		fmt.Printf("  boot             %s no boot id to compare, so whether the claim was proven in THIS boot is unknown (an unreadable marker, one written by an anonctl older than the bootId field, or a host without /proc/sys/kernel/random/boot_id)\n", outStyle.Yellow("note"))
	}
	if rep.Jailed {
		fmt.Printf("\nprobe proves the rules are LOADED and attributed to this uid. It does not prove the forced path is leak-free: `%s` is that proof.\n",
			outStyle.Cyan(verifyHint(accountArg(rep.Account))))
	}
}

// printStatusIdentity renders the identity line for an account that EXISTS: does
// the box still agree with anonctl's record? Each state gets its own unambiguous
// wording, because the operator's next action differs for each, and the two that
// are dangerous (a uid that drifted out from under the forcing) carry the full
// evidence line rather than a summary - that drift is the failure that leaves an
// account UNFORCED while everything else still says it is jailed.
//
// The "not recorded" state is deliberately printed too, and is not a failure: it is
// what a declared-but-not-yet-added account looks like, and saying so is how the
// operator learns `anonctl add` still has to run.
func printStatusIdentity(state verify.IdentityState, st provision.AccountStatus, id verify.AccountIdentity, detail string) {
	switch state {
	case verify.IdentityOK:
		fmt.Printf("  identity: %s (uid %s and shim uid %s are the uids anonctl's rules and record govern)\n",
			outStyle.Green("ok"), st.UID, st.ShimUID)
	case verify.IdentityUnrecorded:
		fmt.Printf("  identity: %s (anonctl has no record for %s, so there is no recorded uid to compare against; `anonctl add %s` would adopt these accounts as they are)\n",
			outStyle.Yellow("not recorded"), st.Account, accountArg(st.Account))
	case verify.IdentityUIDMismatch:
		fmt.Printf("  identity: %s (%s now owns uid %s, but anonctl's rules and record govern uid %d)\n",
			outStyle.Red("UID MISMATCH"), st.Account, st.UID, id.RecordedUID)
		fmt.Printf("    %s\n", detail)
	case verify.IdentityShimUIDMismatch:
		fmt.Printf("  identity: %s (%s now owns uid %s, but the installed rules govern uid %d)\n",
			outStyle.Red("SHIM UID MISMATCH"), st.Shim, st.ShimUID, id.RecordedShimUID)
		fmt.Printf("    %s\n", detail)
	case verify.IdentityShimMissing:
		// The shim line above already reported the absence; this states its CONSEQUENCE,
		// which is what the operator actually needs (fail-closed, but unusable).
		fmt.Printf("  identity: %s (the shim account does not exist, so the account is fail-CLOSED but cannot reach the endpoint)\n",
			outStyle.Red("INCOMPLETE"))
	case verify.IdentityRecordUnreadable:
		// NOT reported as "ok" and not silently omitted: nothing was compared, so the uids
		// the rules govern are unknown. Carrying the full detail matters here because it
		// names the likely cause (an unprivileged read of a root-only record).
		fmt.Printf("  identity: %s (anonctl's record for %s could not be read, so nothing was compared)\n",
			outStyle.Red("UNKNOWN"), st.Account)
		fmt.Printf("    %s\n", detail)
	}
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
//
// The account-identity PRECONDITION runs FIRST and SHORT-CIRCUITS the run when it
// fails. Every live probe keys on `meta skuid <uid>` and dials AS that uid, so if
// the account was deleted (or recreated under a different uid) the probes still
// run happily and simply answer a question about somebody else's uid: the
// operator would read a scatter of leak assertions whose actual cause, "your
// account is gone", appears in none of them. Reporting the precondition alone is
// what makes that condition unambiguous. See docs/nixos.md.
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
	// The SAME ledger seam `add` gates on and `status` compares against, so all three
	// verbs read one set of records (and a test that points it at a scratch dir
	// redirects every one of them).
	store := configStore
	p := verifyParams(store, cmd.Account, st)
	p.SkipTorExitCheck = cmd.SkipTorExitCheck

	// The precondition goes through the SAME progress hook as every other check, so a
	// short-circuited run is still visibly a run (and `use`'s gating verify still
	// streams activity) rather than a silent one-line verdict.
	if prog.Start != nil {
		prog.Start(verify.AssertAccountIdentity)
	}
	ident := verify.AccountIdentityAssertion(accountIdentity(store, cmd.Account, st))
	if prog.Done != nil {
		prog.Done(ident)
	}
	if !ident.Ok {
		return verify.Report{
			Account:    cmd.Account,
			Endpoint:   p.Endpoint,
			Assertions: []verify.Assertion{ident},
		}
	}

	rep := verify.RunVerifyWith(ctx, p, prog)
	// The precondition is reported as a named assertion on the green path too: a
	// consumer gating on the JSON contract sees that it was actually checked, rather
	// than having to infer it from the absence of a failure.
	rep.Assertions = append([]verify.Assertion{ident}, rep.Assertions...)

	// WRITE-AFTER-VERIFY: the marker is a coordination CLAIM written strictly AFTER
	// verify proves the account forced. On a passing report we write it (via the
	// gate, so an unverified account can never be claimed); a failing verify writes
	// nothing and leaves any prior claim to be cleared by `rm`.
	if rep.Ok() {
		m := marker.New(cmd.Account, st.UID, p.Class, resolveVersion(), time.Now())
		// Stamp the BOOT the proof was made in. The marker is durable and the proof is
		// not: after a reboot the rules are re-loaded by the early-boot loader and NOTHING
		// re-verifies, so a marker written last week reads exactly as green as one written
		// a second ago. Recording the boot id lets a consumer (and `anonctl probe`) tell
		// "proven THIS boot" from "proven some earlier boot".
		//
		// Best-effort by design: a host that cannot produce a boot id gets a marker
		// WITHOUT the field (absent reads as "unknown boot", never as a mismatch). Refusing
		// to record a proof that actually passed, over an optional diagnostic field, would
		// be the wrong trade.
		if bootID, berr := probeBootID(); berr == nil {
			m = m.WithBootID(bootID)
		} else {
			fmt.Fprintf(os.Stderr, "anonctl: note: could not read this host's boot id (%v); the marker is written without one, so `anonctl probe` will report an UNKNOWN boot rather than 'proven this boot'\n", berr)
		}
		if werr := markerStore.WriteVerified(m, true); werr != nil {
			errorf("verify: writing marker: %v", werr)
		}
	}
	return rep
}

// accountIdentity assembles the account-identity precondition's inputs: what the
// BOX says now (provision.Status, the same read-only truth `status` renders) and
// what anonctl RECORDED when it installed the forcing (the uids in the account
// config, which are the uids the loaded nft tables and the shim unit actually
// govern). Holding the two apart is the whole point: verify's job here is to
// notice they disagree.
//
// A missing config is a clean "no record" (an account that was never forced), not
// an error: the precondition then checks existence only and says so.
//
// An UNREADABLE config is emphatically NOT the same thing and must never collapse
// into it. The record is root-only (`/etc/anonctl/accounts`, 0700/0600), so the
// commonest unreadable case is an unprivileged `anonctl status` - a read-only verb
// the docs tell operators needs no privilege. Swallowing that error would hand them
// "no record, nothing to compare" (a PASSING identity line) for an account whose uid
// may have drifted out from under the forcing, i.e. a reassuring green for exactly
// the condition this check exists to surface. It is carried through as RecordErr and
// classified as its own failing state.
func accountIdentity(store accountconfig.Store, account string, st provision.AccountStatus) verify.AccountIdentity {
	id := verify.AccountIdentity{
		Account:    account,
		Shim:       st.Shim,
		Exists:     st.Exists,
		ShimExists: st.ShimExists,
		UID:        atoiOr(st.UID, 0),
		ShimUID:    atoiOr(st.ShimUID, 0),
	}
	cfg, err := store.Read(account)
	switch {
	case err == nil:
		id.HaveRecord = true
		id.RecordedUID = cfg.AnonUID
		id.RecordedShimUID = cfg.ShimUID
	case !errors.Is(err, accountconfig.ErrNotFound):
		id.RecordErr = err
	}
	return id
}

// errText renders an error for a JSON field, or "" when there is none (the field is
// then omitted). It exists so a report carries the error TEXT rather than a Go error
// value, which does not marshal.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
	// A read error falls back to the defaults, which is safe ONLY because the
	// account-identity precondition classifies an unreadable record as its own FAILING
	// state (verify.IdentityRecordUnreadable) and short-circuits the run before any of
	// these params are probed. Without that, a corrupt or unprivileged read would
	// quietly probe the DEFAULT endpoint and ports and report on the wrong thing.
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
	// Through the SAME ledger seam add/status/verify read, so all four verbs agree on
	// one set of records (and a test that redirects it redirects every one of them).
	cfg, err := configStore.Read(cmd.Account)
	if err != nil {
		// An UNREADABLE record is not an absent one, here either: telling the operator to
		// run `add` would send them at a gate that refuses on exactly this error. `rm`
		// deletes by account name without parsing the record, so it is the way out.
		if !errors.Is(err, accountconfig.ErrNotFound) {
			errorf("%s: reading anonctl's record for %s: %v; it exists but could not be read, so %s cannot re-apply it (the record is root-only: re-run as root, or if it is corrupt run `%s` then `anonctl add %s` to rebuild it)",
				cmd.Verb, cmd.Account, err, cmd.Verb, rmHint(cmd.Account), accountArg(cmd.Account))
			return 1
		}
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
	warnShadowedUnits()
	fmt.Printf("%s %s -> endpoint %s (re-applied fail-closed, no leak window)\n", outStyle.Green("reconfigured"), outStyle.Bold(cfg.Account), cfg.Endpoint().URL())
	fmt.Printf("run `%s` to re-prove the account is anonymized\n", outStyle.Cyan(verifyHint(cmd.Account)))
	return 0
}

// preflightUnits is the seam `add` runs its before-anything-is-created unit check
// through. It is a package var for the same reason the NSS-bypass inspector is: the
// real implementation READS THE HOST (the host-owned marker under /etc/anonctl, the
// unit files in systemd's search path, and $PATH for the binaries it would bake), so
// leaving it un-stubbed would make every `add` test in this package pass or fail
// according to whether the developer's box happens to declare anonctl's units or to
// carry setpriv. TestMain neutralises it; the tests that exercise the refusal opt
// back in via swapUnitPreflight, and its real behaviour is tested against scratch
// stores in internal/systemd and internal/forcing.
var preflightUnits = systemd.PreflightUnits

// warnShadowedUnits tells the operator when a unit file anonctl maintains is
// OUTRANKED by another copy of the same unit elsewhere in systemd's search path, so
// the definition that actually loads is not the one anonctl just wrote.
//
// It is worth a warning because the failure is otherwise completely silent:
// measured on systemd 260, two copies of one unit name produce no diagnostic at all,
// the higher-precedence directory simply wins, and anonctl's copy sits next to it
// looking authoritative while `update` dutifully re-bakes a file nothing loads. The
// usual cause is a host that has started declaring these units without telling
// anonctl, which is exactly what the host-owned-units marker is for.
//
// It never deletes the other copy. On a host that declares units, the higher-ranked
// file is very likely the host's own, and deleting a declaration is the worse of the
// two errors: it is undone only by a rebuild, and until then the next boot has no
// unit at all.
func warnShadowedUnits() {
	shadowed, err := forcingDeps().SystemdStore.ShadowedUnits()
	if err != nil || len(shadowed) == 0 {
		return
	}
	for _, s := range shadowed {
		fmt.Fprintf(os.Stderr, "%s%s is defined in TWO places: systemd loads %s, which outranks anonctl's %s. anonctl maintains the copy that is NOT being used, so a re-bake of the binary paths will not reach the running definition.\n",
			errStyle.Yellow("anonctl: warning: "), s.Name, s.Loaded, s.Ours)
	}
	fmt.Fprintf(os.Stderr, "  If the other copy is declared by this host, create %s so anonctl stops writing its own, then delete anonctl's copy. If it is not, delete it and re-run.\n", systemd.DefaultHostOwnedUnitsMarker)
}

// configStore is anonctl's LEDGER of the accounts it manages
// (`/etc/anonctl/accounts/<account>.json`, one record per forced account). It is
// the single reader/writer seam for that set: `add` gates on whether a record
// exists (is this account ALREADY MANAGED?), `claimEndpoint` and the port
// allocator read the whole set as the claim/reservation ledger, `status` reads one
// record to compare the recorded uids against the box, and forcing.Install/Remove
// write and delete through it (see forcingDeps). It is a package var so a unit
// test points its BaseDir at a scratch dir and never touches the real
// /etc/anonctl/accounts.
var configStore = accountconfig.DefaultStore()

// claimEndpoint enforces the cross-identification guard for pointing `account` at
// `ep`: it builds the endpoint Registry from every OTHER account's persisted
// endpoint (accountconfig.List, excluding this account so a re-add/re-point is
// idempotent) and Claims `ep`. A socks-peruser endpoint already owned by a
// DIFFERENT account is refused (ErrPeruserAlreadyClaimed, naming the owner); a
// tor-shared endpoint is share-safe and always passes (Tor's `<account>@`
// isolation). A failure to READ the claim set is a loud error (a corrupt sibling
// config must not silently disable the guard), NOT a silent pass.
func claimEndpoint(account string, ep endpoint.Endpoint) error {
	configs, err := configStore.List()
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
	configs, err := configStore.List()
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
// inspectNSSBypass is the INJECTABLE host-inspection seam behind `add`'s DNS
// confinement gate. It is a package var for the same reason lookPathBinary is one
// in the verify probes: without it the guard reads the REAL /etc of whatever
// machine the suite runs on, so `add`'s tests would pass or fail according to
// whether the developer's box happens to run nsncd (it does on the host this was
// written on, which is how the defect was found). The tests drive both branches
// explicitly; production points it at the real detector.
var inspectNSSBypass = nssbypass.Inspect

// measureHostResolution is the INJECTABLE measurement seam behind the same gate.
// It needs root and nft, so without a seam every `add` test would fall into the
// could-not-measure branch on an unprivileged runner and never exercise the
// refusal at all.
var measureHostResolution = verify.HostResolvesHostsInProcess

// refuseNSSBypassHost is `add`'s DNS-confinement gate: it refuses a host on which
// the account's name resolution would happen in another process under another uid,
// naming the daemon, the evidence and the remedy, and returns the process exit
// code (0 = proceed).
//
// Only a BROAD provider refuses (one that answers arbitrary hostnames: nscd/nsncd,
// systemd-resolved, sssd, winbind). A bounded-namespace provider (avahi for
// `.local`, machined for machine names) is WARNED about and allowed: it cannot
// carry the account's general traffic, and refusing on it would refuse on most
// Linux desktops for a narrow leak. `verify` reports it as a residual either way.
//
// A detector that could not READ something warns rather than passing silently: a
// check that could not run is not a pass, and here that distinction decides
// whether an operator is told their box leaks.
func refuseNSSBypassHost(ctx context.Context, cmd *cli.Command) int {
	providers, err := inspectNSSBypass()
	if err != nil {
		fmt.Printf("%s %v\n", outStyle.Red("WARNING:"), err)
	}
	broad := nssbypass.Broad(providers)
	// THE DETECTOR IS A HINT; THE MEASUREMENT DECIDES. An nscd-compatible socket is
	// reported as a broad provider because glibc consults such a socket before
	// nsswitch.conf, which is the right default reading and is what found the original
	// leak. But the socket's EXISTENCE does not prove the daemon serves hosts: nsncd
	// with NSNCD_IGNORE_HOSTS=true keeps its socket (it still serves passwd/group)
	// while refusing hosts, and that is the remedy anonctl itself recommends. So
	// refusing on the detector alone refuses precisely the operator who has just done
	// what we told them to, with a message telling them to do it again.
	if len(broad) > 0 {
		if inProcess, measured, why := measureHostResolution(ctx); measured && inProcess {
			fmt.Printf("%s %s is configured on this host, but %s, so the forcing can govern this account's DNS. Proceeding\n",
				outStyle.Yellow("note:"), nssbypass.Names(broad), why)
			broad = nil
		} else if !measured {
			// Could not answer it here. Proceed with a loud warning rather than refuse: `add`
			// runs `verify` inline moments later and MEASURES this per-account, so a wrong
			// guess in this direction is caught within seconds and reported red, while a wrong
			// refusal leaves a correctly configured operator with no way forward except a flag
			// that costs them `use`/`exec` and the marker.
			fmt.Printf("%s %s is configured on this host and %s. anonctl is proceeding, and the `verify` run at the end of this add will measure it for real\n",
				outStyle.Yellow("WARNING:"), nssbypass.Names(broad), why)
			broad = nil
		}
	}
	if narrow := nssbypass.Narrow(providers); len(narrow) > 0 {
		fmt.Printf("%s %s resolve a bounded class of names (.local, machine names) in ANOTHER process under another uid, which `meta skuid` cannot govern. Those names will not be anonymized; `verify` reports it as a residual on every run\n",
			outStyle.Yellow("NOTE:"), nssbypass.Names(narrow))
	}
	if len(broad) == 0 {
		return 0
	}
	if cmd.AllowNSSBypass {
		// STATE THE FULL PRICE, not just the red assertion. The flag does not buy a green
		// report, and because `use`/`exec` gate on a green report and the marker is only
		// written after one, it does not buy a working session or a marker either. An
		// operator who learns that from behaviour rather than from this message was misled
		// by it.
		fmt.Printf("%s proceeding past --allow-nss-bypass: %s will resolve this account's names OUT OF PROCESS, so every name it visits is resolved by the host's resolver and is attributable to you. Three consequences this flag does NOT remove:\n"+
			"  1. `anonctl verify` keeps reporting dns-nss-not-bypassed RED for this account, by design (it measures, and the measurement will keep being true)\n"+
			"  2. `anonctl use` and `anonctl exec` therefore REFUSE to open a session for it, since both gate on a green verify; log in with `sudo -iu %s` instead\n"+
			"  3. the world-readable marker is only written after a green verify, so sibling tools (anon-pi, netcage) will not see this account as kernel-anonymized and may anonymize it a second time\n"+
			"Fixing the host (see the remedies above and docs/nixos.md) clears all three.\n",
			outStyle.Yellow("WARNING:"), nssbypass.Names(broad), cmd.Account)
		return 0
	}
	errorf("add: this host resolves hostnames OUTSIDE the account's own processes, so anonctl cannot confine its DNS:\n%s"+
		"anonctl forces egress with `meta skuid <uid>`, which matches a socket's OWNER; a lookup another daemon performs for the account is not governed by any rule anonctl can write, so the account's browsing would be resolved by the host's resolver and attributable to you while its TCP exits over the endpoint.\n"+
		"Fix the host with one of the remedies above and re-run, or pass --allow-nss-bypass to force it (verify will keep reporting dns-nss-not-bypassed RED, which is the honest answer, not a bug). See docs/adr/0011 and docs/nixos.md.",
		nssbypass.Explain(broad))
	return 1
}

func forcingDeps() forcing.Deps {
	return forcing.Deps{
		NftRunner:     nftables.ExecRunner{},
		SystemdRunner: systemd.ExecRunner{},
		ConfigStore:   configStore,
		SystemdStore:  systemd.DefaultStore(),
	}
}

// buildConfig assembles an account's at-rest config from its UIDs, ALWAYS READ FROM
// THE BOX, and the chosen endpoint (the raw --endpoint value, or the default Tor
// SocksPort when empty). Reading rather than assuming is what makes `add` work
// identically for an account it just created and one it ADOPTED: on a host that
// declares its users, the uids are the ones that configuration pinned, and anonctl
// has no other way to learn them. It fails loud if the UIDs cannot be read (a
// provisioning that did not land) rather than emit a config that would mis-force.

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

// allocatePortsFor reads the on-disk config set (via the same configStore seam
// claimEndpoint uses) and allocates a free relay/DNS pair for account, excluding
// account's own record so a re-derivation never collides with itself. A failure to
// READ the ledger is loud (a corrupt sibling config must not silently disable the
// collision guard, exactly as claimEndpoint treats a read error).
func allocatePortsFor(account string) (portPair, error) {
	configs, err := configStore.List()
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
func verifyHint(account string) string { return appendAccountArg("anonctl verify", account) }

// rmHint / purgeHint render the two `rm` forms an error message points at, in the
// shortest form the operator would type: a bare `rm` (tears the forcing, the record
// and the marker down, leaving the accounts and homes intact) and the
// `--purge-account` form (also deletes both accounts). They mirror verifyHint /
// accountArg so the default account never prints a stray trailing space.
func rmHint(account string) string { return appendAccountArg("anonctl rm", account) }

func purgeHint(account string) string {
	return appendAccountArg("anonctl rm --purge-account", account)
}

// appendAccountArg appends the account's CLI argument to a command, or nothing at
// all for the default account (whose argument is empty), so no hint ever ends in a
// dangling space (the e2e finding, BUG 5).
func appendAccountArg(cmd, account string) string {
	if arg := accountArg(account); arg != "" {
		return cmd + " " + arg
	}
	return cmd
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
  anonctl add    [--endpoint <socks5h://host:port>] [--allow <IP|CIDR:port>]... [--allow-nss-bypass] [<name>]
                                     provision the account + shim UID, install fail-closed forcing that
                                     survives reboot (default endpoint: the local Tor SocksPort) (root).
                                     ADD-ONCE: refuses an account anonctl already MANAGES, i.e. one with a
                                     record in /etc/anonctl/accounts (use update to change its endpoint/
                                     exemptions; rm then add to re-install its forcing).
                                     ADOPTS accounts that already exist but anonctl has no record of (a
                                     host that declares its users, see docs/nixos.md): it creates nothing,
                                     leaves the home untouched, and forces the uids it reads off the box.
                                     Both <account> and <account>-shim must exist, or neither: half a pair
                                     is refused, never completed.
                                     --allow punches a narrow direct hole (repeatable; an exact :port is
                                     REQUIRED, never :53): an RFC1918/link-local LAN host, OR a same-host
                                     loopback service 127.0.0.1:<port> (the anonymizer control/SOCKS/DNS
                                     ports 9050/9150/9051/1080 are refused on loopback)
                                     REFUSES a host whose glibc resolves hostnames OUT OF PROCESS (an
                                     nscd/nsncd socket, or nss-resolve/sssd/winbind in nsswitch.conf):
                                     forcing keys on a socket's OWNER, so a lookup another daemon performs
                                     for the account is ungovernable and every name it visits would be
                                     resolved by the host's resolver. --allow-nss-bypass proceeds anyway,
                                     but buys less than it looks: verify still reports dns-nss-not-bypassed
                                     RED by design, so use/exec refuse the account (log in with sudo -iu)
                                     and no marker is written for sibling tools. Fixing the host clears all three.
  anonctl rm     [--purge-account] [<name>]
                                     remove forcing; --purge-account also deletes the account (root)
  anonctl seed-home [--from <dir>] [--force] [<name>]
                                     copy a template dir into the account's home (default source:
                                     the directory-exists /etc/anonctl/default-home/); a per-file
                                     collision errors unless --force. Setuid/setgid bits are stripped
                                     on copy. add also seeds from default-home on fresh creation (root)
  anonctl units print --kind shim|nftables [--setpriv PATH --shim PATH --env-dir DIR]
                                          [--nft PATH --rules-dir DIR] [--placeholders]
                                     print ONE of anonctl's two shared unit files, so a HOST can
                                     DECLARE it in its own configuration instead of depending on a
                                     file add wrote out of band. No root, no account, no host
                                     lookup: a PURE function of these flags, byte-stable across runs
                                     (a Nix derivation calling it is reproducible only if that holds),
                                     so every path is a flag and a missing one is an error, never a
                                     default. --placeholders emits each path as an @name@ token, which
                                     is how share/anonctl/units/*.in are generated.
                                     Then create /etc/anonctl/units.host-owned so add/update stop
                                     writing their own copy and rm never deletes yours. anonctl still
                                     owns the per-account enablement symlinks, which are deliberately
                                     NOT exportable: their names say which account slot is in use.
                                     See docs/nixos.md section 8.
  anonctl list   [--json]           list the anon accounts, from BOTH the passwd table (existence)
                                     and anonctl's ledger (managed-ness, unioned in so an account
                                     anonctl records but the box no longer has is visible). Each row
                                     carries an explicit TRI-STATE forcing verdict and a managed
                                     true/false/null; without root the ledger is unreadable by design,
                                     so those read UNKNOWN/null rather than a confident "no".
                                     --json is versioned (schemaVersion 2)
  anonctl status [<name>] [--json]  show one account's state (machine-readable with --json,
                                     schemaVersion 1)
  anonctl probe  [<name>] [--json]  cheap "is this account jailed RIGHT NOW": no network, no Tor exit
                                     check. Three checks - the marker is present, its uid is the
                                     account's LIVE uid, and the account's nft table is actually loaded
                                     and funnels that uid into the fail-closed chain - each with a named
                                     reason on failure, plus whether the claim was proven during THIS
                                     boot. NON-ZERO EXIT when not jailed (or when a check could not be
                                     determined), so automation can gate on the exit status. Reading the
                                     ruleset needs root; probe never self-elevates (it is built for
                                     unattended callers), it reports the undetermined state instead.
                                     It is the middle ground between the marker (a durable CLAIM that
                                     verify passed at some point, which survives a reboot the rules may
                                     not have) and verify (a live, tens-of-seconds PROOF). It does NOT
                                     replace verify: it proves the rules are loaded and attributed, not
                                     that the forced path is leak-free
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
