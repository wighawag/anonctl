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

	// Endpoint is the socks5h endpoint the account is forced through, as typed by
	// the operator (`--endpoint socks5h://host:port` or a bare `host:port`). It is
	// the RAW value; internal/endpoint parses + classifies it. Empty means the
	// default Tor SocksPort for `add`. Meaningful only for the forcing verbs
	// (add/update/reconfigure); ignored by list/status/rm/verify.
	Endpoint string

	// Exemptions are the parsed+validated LAN exemptions the operator asked for via
	// the repeatable `--allow-direct <IP|CIDR[:port]>` flag (netcage's vocabulary):
	// the private-only, host+port-scoped direct holes the anon UID may reach around
	// the forced path. Each value is validated through lanexempt.Parse at the CLI
	// boundary (public/hostname/:53 rejected LOUDLY), so a bad exemption is a parse
	// error, never a silent leak. Meaningful only for the forcing verbs
	// (add/update/reconfigure); ignored by list/status/rm/verify.
	Exemptions []lanexempt.Exempt
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

	// Separate flags from the single optional positional (the account name).
	// Flags may appear before OR after the name (`rm --purge-account work` and
	// `rm work --purge-account` both work) so flag order never swallows the name.
	var positionals []string
	// wantEndpointValue is set when `--endpoint` was seen and its value (the next
	// token) is still pending, so `--endpoint socks5h://h:p` (space form) works
	// alongside `--endpoint=socks5h://h:p`. wantExemptValue is the same pending
	// state for the repeatable `--allow-direct` (space form).
	var wantEndpointValue bool
	var wantExemptValue bool
	for _, a := range args[1:] {
		switch {
		case wantEndpointValue:
			cmd.Endpoint = a
			wantEndpointValue = false
		case wantExemptValue:
			if err := cmd.addExemption(verb, a); err != nil {
				return nil, err
			}
			wantExemptValue = false
		case a == "--json":
			cmd.JSON = true
		case a == "--purge-account":
			cmd.PurgeAccount = true
		case a == "--endpoint":
			wantEndpointValue = true
		case strings.HasPrefix(a, "--endpoint="):
			cmd.Endpoint = strings.TrimPrefix(a, "--endpoint=")
		case a == "--allow-direct":
			wantExemptValue = true
		case strings.HasPrefix(a, "--allow-direct="):
			if err := cmd.addExemption(verb, strings.TrimPrefix(a, "--allow-direct=")); err != nil {
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
		return nil, fmt.Errorf("%s: --allow-direct needs a value (an RFC1918/link-local IP or CIDR, optionally :port)", verb)
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

// addExemption parses one `--allow-direct` value through the lanexempt guardrail
// and appends it to the command. A public/hostname/:53 value is rejected LOUDLY
// here (the fail-loud-at-config-time security gate is surfaced at the CLI
// boundary), so an operator can never punch an anonymity leak from the command
// line; the error names the verb + the offending value.
func (c *Command) addExemption(verb, raw string) error {
	e, err := lanexempt.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: --allow-direct: %w", verb, err)
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
