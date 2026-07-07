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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/marker"
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

	// SudoChecked reports whether the sudo-absence probe actually RAN for this
	// account (it runs only for an existing account; an absent account is not
	// probed). SudoAllowed is meaningful only when SudoChecked is true.
	SudoChecked bool `json:"sudoChecked"`
	// SudoAllowed is the POSITIVE result of the `sudo -l -U <account>` probe: false
	// means the account has no sudo rights (the hardened, expected state), true means
	// the box grants it sudo (a UID-transition escape: a sudo'd socket carries a
	// different uid and bypasses the `meta skuid` forcing). This surfaces the
	// CLOSE-AT-ADD invariant as a checkable fact, not just an absence.
	SudoAllowed bool `json:"sudoAllowed"`

	// Forced reports whether the account has a marker (`/etc/anonctl/<account>.json`):
	// anonctl's own convenience view of the SAME dependency-free truth a sibling
	// tool reads directly. A missing marker is a clean `false` ("not forced"), never
	// an error. The marker FILE is authoritative; this field is a reader of it.
	Forced bool `json:"forced"`
	// Marker is the account's marker record when present (Forced), else nil. It
	// carries the endpoint SHARE-CLASS (story 20) but no endpoint URL/creds.
	Marker *marker.Marker `json:"marker,omitempty"`
}

// WithMarker returns a copy of the status with its marker fields populated from
// the given Store: Forced+Marker when a marker is present, a clean not-forced
// (Forced=false, Marker=nil) when it is absent (marker.ErrNotFound). A real read
// error (a corrupt marker) is returned so it is not silently swallowed. This is
// the READER side of the marker precedence: `status` reports the same file a
// sibling tool reads directly; it is a convenience view, not a second source of
// truth. Kept separate from Status so the account-table read stays free of any
// /etc dependency (and its unit tests need no marker Store).
func (s AccountStatus) WithMarker(store marker.Store) (AccountStatus, error) {
	m, err := store.Read(s.Account)
	if err != nil {
		if errors.Is(err, marker.ErrNotFound) {
			s.Forced = false
			s.Marker = nil
			return s, nil
		}
		return s, err
	}
	s.Forced = true
	s.Marker = &m
	return s, nil
}

// LoginPATH is the minimal login PATH `add` provisions for the anon account. It
// deliberately OMITS the sbin directories (`/usr/local/sbin`, `/usr/sbin`,
// `/sbin`) that carry the setuid network binaries the audit flagged (exim4,
// pppd, mount.nfs live under /usr/sbin and /sbin): a socket one of those opens
// carries a DIFFERENT uid and escapes the `meta skuid` forcing. Shrinking the
// PATH does not REMOVE those binaries (they are system-wide, still reachable by
// absolute path), so this is a partial CLOSE-AT-ADD hardening, not a barrier; the
// residual is documented in the README threat model. See
// work/notes/findings/uid-transition-escape-surface.md.
const LoginPATH = "/usr/local/bin:/usr/bin:/bin"

// WriteLoginEnv writes the account's minimal login environment (its PATH) into a
// shell profile drop-in in the account's home. It is a package-level seam (not a
// hard call) so the unit tests inject a fake that captures the CONTENT without
// touching a real home directory, mirroring the Runner-seam discipline for the
// rest of provisioning. The default implementation writes the real profile via
// the Runner-discovered home; it is replaced only in tests.
var WriteLoginEnv = writeLoginEnv

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

	// Positively probe the sudo-absence invariant, but ONLY for an existing account
	// (probing a non-existent account would be a meaningless "no sudo"). This surfaces
	// the CLOSE-AT-ADD no-sudo hardening as a checkable fact an operator sees in
	// `status`, not just an absence at add-time.
	if exists {
		st.SudoChecked = true
		st.SudoAllowed = sudoAllowed(ctx, r, account)
	}
	return st, nil
}

// sudoAllowed probes whether the account has ANY sudo rights via
// `sudo -l -U <account>` (list the account's permitted sudo commands). sudo exits
// non-zero and prints "not allowed to run sudo" when the account has none; a
// zero-exit listing means it CAN sudo. We read the exit code as the truth (false
// == no sudo, the hardened state), treating a probe that could not run at all
// (sudo absent) as "no sudo path here": if the box has no sudo binary the vector
// is closed for this account too. This is the PROVE side of the sudo vector.
func sudoAllowed(ctx context.Context, r Runner, account string) bool {
	_, _, err := r.Run(ctx, "sudo", "-l", "-U", account)
	return err == nil
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
	// The login account is created with NO --groups: it is never added to sudo/wheel,
	// so it has no sudo path (the CLOSE-AT-ADD no-sudo invariant). A sudo'd socket
	// would carry a different uid and escape the `meta skuid` forcing.
	if _, stderr, err := r.Run(ctx, "useradd", "--create-home", "--shell", "/bin/bash", account); err != nil {
		return false, fmt.Errorf("create login account %q: %w: %s", account, err, stderr)
	}
	// Write the account's minimal login PATH (omitting the sbin setuid-network dirs)
	// only on FRESH creation, so a re-run never clobbers an operator's edited
	// profile. Failing to write the env is a real provisioning error (the hardening
	// did not take effect), surfaced to the caller.
	if err := WriteLoginEnv(ctx, r, account, loginEnvContent()); err != nil {
		return false, fmt.Errorf("write login env for %q: %w", account, err)
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

// loginEnvContent renders the shell profile drop-in that pins the account's
// minimal login PATH. It is a small, self-contained POSIX-sh snippet exporting
// LoginPATH; a login shell reads it (see writeLoginEnv). Kept a pure function so
// the content is asserted in a unit test without any file I/O.
func loginEnvContent() string {
	return "# Managed by anonctl: minimal login PATH for the anon account.\n" +
		"# Omits the sbin dirs carrying setuid network binaries so the account\n" +
		"# cannot gratuitously name a uid-transition escape. See the anonctl README\n" +
		"# threat model. Edit at your own risk.\n" +
		"export PATH=" + LoginPATH + "\n"
}

// homeMode / envFileMode are the intended modes for the created home-scoped env
// file: owned by the account, readable by it. 0644 mirrors a skel .profile.
const envFileMode = 0o644

// writeLoginEnv is the DEFAULT WriteLoginEnv: it writes the minimal-PATH profile
// drop-in into the account's home as `.profile`, then chowns it to the account so
// the login shell (running as the account) reads it. It discovers the home from
// the passwd entry through the Runner (the same seam the rest of provisioning
// uses to read account state). Any real error (no home, write failure) is
// returned so a failed hardening is not silently swallowed. The unit tests
// replace the WriteLoginEnv seam entirely, so this real writer runs only on a
// live host (exercised by the integration test).
func writeLoginEnv(ctx context.Context, r Runner, account, content string) error {
	home, err := accountHome(ctx, r, account)
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".profile")
	if err := os.WriteFile(path, []byte(content), envFileMode); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	// WriteFile respects umask; re-assert the intended mode, then hand the file to
	// the account so its own login shell can read it.
	if err := os.Chmod(path, envFileMode); err != nil {
		return fmt.Errorf("chmod %q: %w", path, err)
	}
	if _, stderr, err := r.Run(ctx, "chown", account+":"+account, path); err != nil {
		return fmt.Errorf("chown %q to %s: %w: %s", path, account, err, stderr)
	}
	return nil
}

// accountHome returns the account's home directory from its passwd entry (field
// 6). It errors if the account has no resolvable home, so writeLoginEnv never
// writes to a wrong/empty path.
func accountHome(ctx context.Context, r Runner, account string) (string, error) {
	stdout, _, _ := r.Run(ctx, "getent", "passwd", account)
	fields := strings.Split(strings.TrimSpace(stdout), ":")
	if len(fields) < 6 || fields[5] == "" {
		return "", fmt.Errorf("account %q has no home directory in passwd", account)
	}
	return fields[5], nil
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
