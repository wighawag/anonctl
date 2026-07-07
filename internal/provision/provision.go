// Package provision owns the account + dedicated-shim-UID lifecycle behind the
// four verbs (add/rm/list/status). Every system-mutating call goes through the
// Runner seam (mirroring netcage's jail.ExecRunner) so the whole thing is
// unit-testable against a fake WITHOUT creating a real Unix user: the default
// `go test ./...` run touches no real account state. Only the `integration`-
// tagged test wires the real ExecRunner and asserts it cleans up after itself.
//
// The account layout mirrors the validated manual recipe
// (work/notes/findings/manual-per-uid-tor-recipe.md): a login account (`anon` /
// `anon-<name>`, a normal --create-home shell user whose egress is later forced)
// and, alongside it, a DISTINCT dedicated shim service account (`<account>-shim`,
// a --system nologin user) that runs the shim and is the ONLY UID later allowed
// to dial the upstream endpoint. This task provisions those accounts; it installs
// NO egress forcing (that is the nftables/persistence tasks).
package provision

import (
	"context"
	"fmt"
	"strings"

	"github.com/wighawag/anonctl/internal/cli"
)

// Runner abstracts command execution so provisioning is unit-testable without a
// real useradd/userdel/getent (the integration test uses the real one). It
// mirrors netcage's jail.Runner: a single Run that returns stdout, stderr, and
// the raw exec error so callers can classify an exit code. anonctl runs its
// mutations as root (the ufw stance), so the real runner shells out privileged.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// AddResult reports what add did. Created is false when the account already
// existed (the idempotent no-op path), true when this call provisioned it.
type AddResult struct {
	Account     string `json:"account"`
	Shim        string `json:"shim"`
	Created     bool   `json:"created"`
	ShimCreated bool   `json:"shimCreated"`
}

// RmResult reports what rm did. AccountRemoved is true only when the explicit
// opt-in deleted the account; a bare rm leaves it false (the home stays intact).
type RmResult struct {
	Account        string `json:"account"`
	Shim           string `json:"shim"`
	AccountRemoved bool   `json:"accountRemoved"`
	ShimRemoved    bool   `json:"shimRemoved"`
}

// AccountStatus is the machine-readable state of one anon account, read from the
// box (the account table), NOT a maintained index. It is the shape `status
// --json` emits. Forcing/marker state is added by the nftables/verify tasks; the
// JSON field names are the durable contract they extend.
type AccountStatus struct {
	Account    string `json:"account"`
	Shim       string `json:"shim"`
	Exists     bool   `json:"exists"`
	ShimExists bool   `json:"shimExists"`
	UID        string `json:"uid,omitempty"`
	ShimUID    string `json:"shimUid,omitempty"`
}

// Add provisions the anon login account and its distinct dedicated shim service
// account, idempotently. Provisioning each account is a no-op if it already
// exists, so re-running add is a clean no-op (AddResult.Created reports which
// path was taken). Every mutation goes through the Runner, so the unit tests
// never create a real user.
func Add(ctx context.Context, r Runner, account string) (AddResult, error) {
	shim := cli.ShimAccount(account)
	res := AddResult{Account: account, Shim: shim}

	created, err := ensureLoginAccount(ctx, r, account)
	if err != nil {
		return res, err
	}
	res.Created = created

	shimCreated, err := ensureShimAccount(ctx, r, shim)
	if err != nil {
		return res, err
	}
	res.ShimCreated = shimCreated
	return res, nil
}

// Rm removes the account's forcing hooks and, ONLY under the explicit
// purgeAccount opt-in, deletes the login account + its shim (and their homes). A
// bare rm (purgeAccount=false) is the safe default: it never calls userdel, so a
// user's home is never silently deleted. Removing forcing hooks is a no-op until
// the nft/persistence tasks land; the safety gate on account deletion is the
// load-bearing behaviour delivered here.
func Rm(ctx context.Context, r Runner, account string, purgeAccount bool) (RmResult, error) {
	shim := cli.ShimAccount(account)
	res := RmResult{Account: account, Shim: shim}

	// Forcing-hook teardown is a no-op until the nft/persistence tasks exist. It is
	// intentionally a distinct step so a later task fills it without touching the
	// account-deletion gate.

	if !purgeAccount {
		return res, nil
	}

	removed, err := removeAccount(ctx, r, account)
	if err != nil {
		return res, err
	}
	res.AccountRemoved = removed

	shimRemoved, err := removeAccount(ctx, r, shim)
	if err != nil {
		return res, err
	}
	res.ShimRemoved = shimRemoved
	return res, nil
}

// List enumerates the anon LOGIN accounts that actually exist on the box. It
// reads the account table (passwd lines) rather than a maintained index, so it
// reflects ground truth. The shim service accounts (`*-shim`) are excluded: they
// are implementation, not accounts an operator manages. passwdLines is injected
// so the enumeration is pure and testable; the CLI shell reads the real table.
func List(ctx context.Context, r Runner, passwdLines []string) ([]AccountStatus, error) {
	var out []AccountStatus
	for _, line := range passwdLines {
		name, uid, ok := parsePasswd(line)
		if !ok || !isAnonLogin(name) {
			continue
		}
		shim := cli.ShimAccount(name)
		shimExists, shimUID, err := accountEntry(ctx, r, shim)
		if err != nil {
			return nil, err
		}
		out = append(out, AccountStatus{
			Account:    name,
			Shim:       shim,
			Exists:     true,
			UID:        uid,
			ShimExists: shimExists,
			ShimUID:    shimUID,
		})
	}
	return out, nil
}

// Status returns the machine-readable state of one account, read from the box. An
// absent account is a queryable negative (Exists=false), not an error, so a
// caller/CI can branch on it.
func Status(ctx context.Context, r Runner, account string) (AccountStatus, error) {
	shim := cli.ShimAccount(account)
	st := AccountStatus{Account: account, Shim: shim}

	exists, uid, err := accountEntry(ctx, r, account)
	if err != nil {
		return st, err
	}
	st.Exists = exists
	st.UID = uid

	shimExists, shimUID, err := accountEntry(ctx, r, shim)
	if err != nil {
		return st, err
	}
	st.ShimExists = shimExists
	st.ShimUID = shimUID
	return st, nil
}

// ensureLoginAccount creates the login account if absent (idempotent). It is a
// normal --create-home shell user: the operator logs into it and its egress is
// forced by a later task. Returns whether it created the account.
func ensureLoginAccount(ctx context.Context, r Runner, account string) (bool, error) {
	exists, _, err := accountEntry(ctx, r, account)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if _, stderr, err := r.Run(ctx, "useradd", "--create-home", "--shell", "/bin/bash", account); err != nil {
		return false, fmt.Errorf("create login account %q: %w: %s", account, err, stderr)
	}
	return true, nil
}

// ensureShimAccount creates the dedicated shim service account if absent
// (idempotent). It is a --system, --no-create-home, nologin user: it never logs
// in, it only runs the shim and (later) is the ONLY UID allowed to dial the
// endpoint. Returns whether it created the account.
func ensureShimAccount(ctx context.Context, r Runner, shim string) (bool, error) {
	exists, _, err := accountEntry(ctx, r, shim)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if _, stderr, err := r.Run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", shim); err != nil {
		return false, fmt.Errorf("create shim account %q: %w: %s", shim, err, stderr)
	}
	return true, nil
}

// removeAccount deletes an account and its home if present (idempotent: an absent
// account is a clean no-op, not an error). Returns whether it removed anything.
func removeAccount(ctx context.Context, r Runner, account string) (bool, error) {
	exists, _, err := accountEntry(ctx, r, account)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if _, stderr, err := r.Run(ctx, "userdel", "--remove", account); err != nil {
		return false, fmt.Errorf("remove account %q: %w: %s", account, err, stderr)
	}
	return true, nil
}

// accountEntry probes whether an account exists via `getent passwd <name>` and,
// if so, returns its numeric UID. getent exits non-zero (with empty stdout) when
// the account is absent, which we treat as "does not exist", NOT an error, so the
// existence probe is a clean boolean.
func accountEntry(ctx context.Context, r Runner, account string) (exists bool, uid string, err error) {
	stdout, _, runErr := r.Run(ctx, "getent", "passwd", account)
	if runErr != nil {
		// getent's exit 2 == not found. Any getent line means present; empty stdout
		// with an error means absent.
		if strings.TrimSpace(stdout) == "" {
			return false, "", nil
		}
	}
	name, uid, ok := parsePasswd(stdout)
	if !ok || name != account {
		return false, "", nil
	}
	return true, uid, nil
}

// parsePasswd extracts the account name and numeric UID from a passwd line
// (`name:x:uid:gid:gecos:home:shell`). It returns ok=false for a blank or
// malformed line.
func parsePasswd(line string) (name, uid string, ok bool) {
	fields := strings.Split(strings.TrimSpace(line), ":")
	if len(fields) < 3 || fields[0] == "" {
		return "", "", false
	}
	return fields[0], fields[2], true
}

// isAnonLogin reports whether a passwd name is an anon LOGIN account (`anon` or
// `anon-<name>`) and NOT one of the `*-shim` service accounts, which are
// implementation, not operator-managed accounts.
func isAnonLogin(name string) bool {
	if strings.HasSuffix(name, "-shim") {
		return false
	}
	return name == cli.DefaultAccount || strings.HasPrefix(name, cli.DefaultAccount+"-")
}
