package nftables

import (
	"context"
	"fmt"

	"github.com/wighawag/anonctl/internal/lanexempt"
)

// Runner abstracts the `nft` shell-out so Apply/Delete are unit-testable without
// touching the host's real ruleset (the fake asserts what would be run), exactly
// as provision.Runner abstracts useradd/userdel. It differs by carrying a stdin
// string, because the atomic load is `nft -f -` (the whole ruleset piped in),
// not a positional argument. anonctl runs these as root (the ufw stance); the
// real runner shells out privileged.
type Runner interface {
	Run(ctx context.Context, stdin, name string, args ...string) (stdout, stderr string, err error)
}

// Apply generates the account's fail-closed ruleset and loads it atomically via
// `nft -f -` (the generated text on stdin). The load is idempotent: the ruleset
// create-if-absent then deletes the account's OWN table before defining it fresh,
// so a re-Apply is a clean replace that never appends stale rules and never
// touches another table on the host. A malformed Params fails BEFORE any nft runs
// (Generate validates), so a bad input can never partially apply.
func Apply(ctx context.Context, r Runner, p Params) error {
	ruleset, err := Generate(p)
	if err != nil {
		return err
	}
	if _, stderr, err := r.Run(ctx, ruleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nftables: apply ruleset for account %q: %w: %s", p.Account, err, stderr)
	}
	return nil
}

// ApplyBaseline generates the account's standing per-UID default-deny (baseline)
// ruleset and loads it atomically via `nft -f -`. It is applied FIRST (before the
// forcing rules) at add-time so the anon UID's resting state is DROP from the very
// moment forcing is being installed: there is no window where the account can act
// with neither the baseline nor the forcing present. The load is idempotent (the
// baseline table is create-if-absent, deleted, then defined fresh) and touches only
// the baseline table. The exemptions are threaded through so the baseline RETURNs
// each exempted (un-redirected) LAN destination before its broad drop, letting the
// forcing chain's exemption accept actually complete the direct hole.
func ApplyBaseline(ctx context.Context, r Runner, account string, anonUID int, exemptions []lanexempt.Exempt) error {
	ruleset, err := GenerateBaseline(account, anonUID, exemptions)
	if err != nil {
		return err
	}
	if _, stderr, err := r.Run(ctx, ruleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nftables: apply baseline default-deny for account %q: %w: %s", account, err, stderr)
	}
	return nil
}

// Delete removes ONLY the given account's table (`delete table inet
// anonctl_<account>`), so tearing one account down leaves every other table (and
// the rest of the host's firewall) untouched. It never flushes the whole ruleset.
// Deleting an absent table is nft's own error; callers that want an idempotent
// teardown can ignore a not-found, but Delete itself reports it so a genuine
// failure is not swallowed.
func Delete(ctx context.Context, r Runner, account string) error {
	if account == "" {
		return fmt.Errorf("nftables: delete needs an account")
	}
	cmd := fmt.Sprintf("delete table inet %s", TableName(account))
	if _, stderr, err := r.Run(ctx, cmd, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nftables: delete table for account %q: %w: %s", account, err, stderr)
	}
	return nil
}

// DeleteBaseline removes ONLY the given account's baseline default-deny table
// (`delete table inet anonctl_baseline_<account>`), so teardown removes the resting
// deny alongside the forcing table and leaves every other table untouched. Like
// Delete, an absent table is nft's own error; the idempotent teardown caller
// ignores a not-found.
func DeleteBaseline(ctx context.Context, r Runner, account string) error {
	if account == "" {
		return fmt.Errorf("nftables: delete baseline needs an account")
	}
	cmd := fmt.Sprintf("delete table inet %s", BaselineTableName(account))
	if _, stderr, err := r.Run(ctx, cmd, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nftables: delete baseline table for account %q: %w: %s", account, err, stderr)
	}
	return nil
}
