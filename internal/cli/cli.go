// Package cli is anonctl's PURE command surface: it parses argv into a Command
// (verb + resolved account + flags) with NO side effects and NO root, so verb
// dispatch and account-name resolution are exhaustively unit-testable without
// touching the system. The impure work (provisioning as root) lives behind the
// Runner seam in internal/provision; this package only decides WHAT to do.
package cli

import (
	"fmt"
	"strings"

	"github.com/wighawag/anonctl/internal/lanexempt"
)

// DefaultAccount is the account a BARE verb (no name) targets. anonctl OWNS this
// generic "anonymized account" naming (distinct from anon-pi's `anon-pi`).
const DefaultAccount = "anon"

// namePrefix is the prefix anonctl puts on a NAMED account: `add work` becomes
// `anon-work`. The user names the suffix; anonctl owns the prefix.
const namePrefix = DefaultAccount + "-"

// Command is a fully-parsed anonctl invocation. It is the pure output of Parse:
// which verb, which resolved account (already `anon` / `anon-<name>`), and the
// verb-relevant flags. It carries no I/O and no privilege.
type Command struct {
	// Verb is one of the recognised verbs (add/rm/list/status/verify/update/
	// reconfigure). Dispatch switches on it.
	Verb string

	// Account is the RESOLVED Unix account name: `anon` for a bare verb,
	// `anon-<name>` for a named one. Empty for verbs that take no account (list).
	Account string

	// JSON requests machine-readable output. Meaningful for status (and list);
	// ignored by the mutating verbs.
	JSON bool

	// PurgeAccount is the explicit opt-in that lets `rm` delete the Unix account
	// (and its home) rather than only removing forcing hooks. A bare `rm` leaves
	// it false, so it never silently deletes a user's home.
	PurgeAccount bool

	// SeedFrom is the template directory `seed-home` copies into the account's home
	// (`--from <dir>`). Empty means the directory-exists default
	// `/etc/anonctl/default-home/`. Meaningful only for `seed-home`.
	SeedFrom string

	// Force lets `seed-home` OVERWRITE a file that already exists in the home
	// (`--force`). Without it, a collision is a loud error. It lives ONLY on
	// `seed-home`: `add` is create-only and never overwrites, so it has no --force.
	Force bool

	// Endpoint is the socks5h endpoint the account is forced through, as typed by
	// the operator (`--endpoint socks5h://host:port` or a bare `host:port`). It is
	// the RAW value; internal/endpoint parses + classifies it. Empty means the
	// default Tor SocksPort for `add`. Meaningful only for the forcing verbs
	// (add/update/reconfigure); ignored by list/status/rm/verify.
	Endpoint string

	// Exemptions are the parsed+validated LAN exemptions the operator asked for via
	// the repeatable `--allow <IP|CIDR:port>` flag (netcage's vocabulary): the
	// private-only, host+port-scoped direct holes the anon UID may reach around the
	// forced path. A port is MANDATORY. Each value is validated through
	// lanexempt.Parse at the CLI boundary (public/hostname/:53/port-omitted rejected
	// LOUDLY), so a bad exemption is a parse error, never a silent leak. Meaningful
	// only for the forcing verbs (add/update/reconfigure); ignored by
	// list/status/rm/verify.
	Exemptions []lanexempt.Exempt

	// Program is the program `exec` runs INSIDE the anonymized account (the first
	// positional after any `--as <name>`). Meaningful only for `exec`; empty for every
	// other verb.
	Program string

	// ExecArgs are the arguments forwarded VERBATIM to Program (everything on the
	// command line after the program token). They are NOT interpreted as anonctl
	// flags: `anonctl exec pi --session x -p "hi there"` forwards `--session x -p
	// "hi there"` to pi untouched, and `"hi there"` stays a single argument. Meaningful
	// only for `exec`.
	ExecArgs []string

	// SkipTorExitCheck relaxes the anonymized-exit assertion's Tor-exit REQUIREMENT
	// for a tor-shared endpoint (`--skip-tor-exit-check`, on verify/use). It never
	// relaxes the load-bearing half (the exit IP must still DIFFER from the host's, so
	// forced egress is proven); it only stops treating an UNCONFIRMED Tor exit as a
	// failure. Its reason for existing: the Tor-exit confirmation consults external
	// registries (check.torproject.org, then onionoo) that LAG the live consensus, so
	// a genuine, brand-new Tor exit can be reported as not-Tor. This flag lets an
	// operator who trusts their Tor proceed past that registry false-negative. It is
	// deliberately narrow and loud (the pass detail announces the check was skipped);
	// it is NOT a way to skip anonymization. Meaningful only for verify/use.
	SkipTorExitCheck bool
}

// verbs is the recognised verb set. `use` is the verify-then-shell safe front
// door (verify the resolved account, then exec its login shell only on green); it
// takes an optional name like the other account-targeting verbs.
var verbs = map[string]bool{
	"add":         true,
	"rm":          true,
	"list":        true,
	"status":      true,
	"verify":      true,
	"update":      true,
	"reconfigure": true,
	"use":         true,
	"exec":        true,
	"seed-home":   true,
}

// takesName reports whether a verb accepts an account name. `list` enumerates ALL
// accounts, so it takes none; every other verb targets one account (bare =
// default `anon`).
func takesName(verb string) bool { return verb != "list" }

// Parse turns argv (WITHOUT the program name) into a Command. It is pure: it
// never touches the system, so it is safe to call and test without root. A bad
// verb, an unexpected flag, or an extra positional is a fail-loud error (a
// non-zero exit at the call site), never a silent misparse.
func Parse(args []string) (*Command, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no verb given")
	}
	verb := args[0]
	if !verbs[verb] {
		return nil, fmt.Errorf("unknown verb %q", verb)
	}
	cmd := &Command{Verb: verb}

	// `exec` has a bespoke grammar (`exec [--as <name>] <program> [args...]`) where
	// everything AFTER the program token is forwarded VERBATIM and must never be read
	// as an anonctl flag. It cannot share the flag-anywhere loop below (which would
	// steal a `--json` or `-p` meant for the program), so it parses in its own
	// function.
	if verb == "exec" {
		return parseExec(cmd, args[1:])
	}

	// Separate flags from the single optional positional (the account name).
	// Flags may appear before OR after the name (`rm --purge-account work` and
	// `rm work --purge-account` both work) so flag order never swallows the name.
	var positionals []string
	// wantEndpointValue is set when `--endpoint` was seen and its value (the next
	// token) is still pending, so `--endpoint socks5h://h:p` (space form) works
	// alongside `--endpoint=socks5h://h:p`. wantExemptValue is the same pending
	// state for the repeatable `--allow` (space form).
	var wantEndpointValue bool
	var wantExemptValue bool
	// wantSeedFromValue is the pending state for `--from <dir>` (space form) on
	// `seed-home`, mirroring the endpoint/exempt pending states.
	var wantSeedFromValue bool
	for _, a := range args[1:] {
		switch {
		case wantEndpointValue:
			cmd.Endpoint = a
			wantEndpointValue = false
		case wantSeedFromValue:
			cmd.SeedFrom = a
			wantSeedFromValue = false
		case wantExemptValue:
			if err := cmd.addExemption(verb, a); err != nil {
				return nil, err
			}
			wantExemptValue = false
		case a == "--json":
			cmd.JSON = true
		case a == "--purge-account":
			cmd.PurgeAccount = true
		case a == "--force":
			cmd.Force = true
		case a == "--skip-tor-exit-check":
			cmd.SkipTorExitCheck = true
		case a == "--from":
			wantSeedFromValue = true
		case strings.HasPrefix(a, "--from="):
			cmd.SeedFrom = strings.TrimPrefix(a, "--from=")
		case a == "--endpoint":
			wantEndpointValue = true
		case strings.HasPrefix(a, "--endpoint="):
			cmd.Endpoint = strings.TrimPrefix(a, "--endpoint=")
		case a == "--allow":
			wantExemptValue = true
		case strings.HasPrefix(a, "--allow="):
			if err := cmd.addExemption(verb, strings.TrimPrefix(a, "--allow=")); err != nil {
				return nil, err
			}
		case strings.HasPrefix(a, "-"):
			return nil, fmt.Errorf("%s: unknown flag %q", verb, a)
		default:
			positionals = append(positionals, a)
		}
	}
	if wantEndpointValue {
		return nil, fmt.Errorf("%s: --endpoint needs a value (socks5h://host:port)", verb)
	}
	if wantExemptValue {
		return nil, fmt.Errorf("%s: --allow needs a value (an RFC1918/link-local IP or CIDR with a mandatory :port)", verb)
	}
	if wantSeedFromValue {
		return nil, fmt.Errorf("%s: --from needs a value (the template directory to seed the home from)", verb)
	}

	if !takesName(verb) {
		if len(positionals) > 0 {
			return nil, fmt.Errorf("%s takes no account name (got %q)", verb, positionals[0])
		}
		return cmd, nil
	}

	switch len(positionals) {
	case 0:
		cmd.Account = DefaultAccount
	case 1:
		cmd.Account = ResolveAccount(positionals[0])
	default:
		return nil, fmt.Errorf("%s takes at most one account name (got %d)", verb, len(positionals))
	}
	return cmd, nil
}

// parseExec parses `exec`'s bespoke grammar: `exec [--as <name>] <program>
// [args...]`. Unlike every other verb, `exec` has TWO positional roles (an account
// selector and a program) plus a verbatim tail, so the shared "one optional
// positional" convention does not extend to it. It deliberately diverges: the
// account is chosen by an explicit `--as <name>` flag (default `anon`, `<name>` ->
// `anon-<name>`, resolved by ResolveAccount exactly like the positional verbs),
// and the FIRST non-flag token is the PROGRAM. Everything from the program token
// onward is captured VERBATIM into Program + ExecArgs and is NEVER interpreted as
// an anonctl flag, so `anonctl exec pi -p "hi there"` reaches pi as-is (a `--json`
// or `-p` after the program is the program's, not anonctl's).
//
// Why a flag, not a positional name: `anonctl exec pi ...` must run the program
// `pi` on the default account, so the first positional has to be the program;
// there is no unambiguous positional slot left for the account name. `--as` names
// it explicitly instead of guessing. `--as` is only honoured BEFORE the program
// token (after it, `--as` is just a forwarded arg), consistent with the verbatim
// tail.
//
// A missing program is a loud usage error (exec must run something). SkipTorExitCheck
// rides `exec` too (its verify gate is the same as use/verify), but ONLY before the
// program token.
func parseExec(cmd *Command, rest []string) (*Command, error) {
	var wantAsValue bool
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if wantAsValue {
			cmd.Account = ResolveAccount(a)
			wantAsValue = false
			continue
		}
		switch {
		case a == "--as":
			wantAsValue = true
		case strings.HasPrefix(a, "--as="):
			cmd.Account = ResolveAccount(strings.TrimPrefix(a, "--as="))
		case a == "--skip-tor-exit-check":
			cmd.SkipTorExitCheck = true
		case strings.HasPrefix(a, "-"):
			return nil, fmt.Errorf("exec: unknown flag %q (exec's own flags must come BEFORE the program; anything after the program is forwarded to it)", a)
		default:
			// The first non-flag token is the PROGRAM. Stop flag parsing here: this token
			// and everything after it are the program + its verbatim args, captured whole.
			cmd.Program = a
			cmd.ExecArgs = append([]string(nil), rest[i+1:]...)
			if cmd.Account == "" {
				cmd.Account = DefaultAccount
			}
			return cmd, nil
		}
	}
	// Reaching here means the loop ended without ever finding a program token.
	if wantAsValue {
		return nil, fmt.Errorf("exec: --as needs a value (the account name, e.g. `--as work` for anon-work)")
	}
	return nil, fmt.Errorf("exec needs a program to run (usage: `anonctl exec [--as <name>] <program> [args...]`)")
}

// addExemption parses one `--allow` value through the lanexempt guardrail and
// appends it to the command. A public/hostname/:53/port-omitted value is rejected
// LOUDLY here (the fail-loud-at-config-time security gate is surfaced at the CLI
// boundary), so an operator can never punch an anonymity leak from the command
// line; the error names the verb + the offending value.
func (c *Command) addExemption(verb, raw string) error {
	e, err := lanexempt.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: --allow: %w", verb, err)
	}
	c.Exemptions = append(c.Exemptions, e)
	return nil
}

// ResolveAccount maps a user-typed name to the actual Unix account name. An empty
// name or the literal `anon` is the default account; any other name `x` becomes
// `anon-x`. A name the user already spelled with anonctl's `anon-` prefix is NOT
// double-prefixed (`anon-work` stays `anon-work`, never `anon-anon-work`).
func ResolveAccount(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == DefaultAccount {
		return DefaultAccount
	}
	if strings.HasPrefix(name, namePrefix) {
		return name
	}
	return namePrefix + name
}

// ShimAccount returns the dedicated shim service-account name for an anon
// account: `anon` -> `anon-shim`, `anon-<name>` -> `anon-<name>-shim`. Each anon
// account gets its OWN shim UID (a separate service account) so that later only
// the shim UID, never the anon UID, may reach the upstream endpoint (story 12/14).
// The `-shim` suffix mirrors the validated manual recipe, which created
// `anon-shim` for `anon`.
func ShimAccount(account string) string { return account + "-shim" }
