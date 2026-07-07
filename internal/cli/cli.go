// Package cli is anonctl's PURE command surface: it parses argv into a Command
// (verb + resolved account + flags) with NO side effects and NO root, so verb
// dispatch and account-name resolution are exhaustively unit-testable without
// touching the system. The impure work (provisioning as root) lives behind the
// Runner seam in internal/provision; this package only decides WHAT to do.
package cli

import (
	"fmt"
	"strings"
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
}

// verbs is the recognised verb set. add/rm/list/status are live in this task;
// verify and update/reconfigure DISPATCH here as stubs (later tasks fill them),
// so the verb surface is end-to-end from the start.
var verbs = map[string]bool{
	"add":         true,
	"rm":          true,
	"list":        true,
	"status":      true,
	"verify":      true,
	"update":      true,
	"reconfigure": true,
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
	for _, a := range args[1:] {
		switch {
		case a == "--json":
			cmd.JSON = true
		case a == "--purge-account":
			cmd.PurgeAccount = true
		case strings.HasPrefix(a, "-"):
			return nil, fmt.Errorf("%s: unknown flag %q", verb, a)
		default:
			positionals = append(positionals, a)
		}
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
