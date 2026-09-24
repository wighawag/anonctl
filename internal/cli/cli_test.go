package cli_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/cli"
)

// The four real verbs plus the two later-task stubs must parse, and a bare name
// must resolve to the default `anon` account while `<name>` resolves to
// `anon-<name>` (the vocabulary anonctl OWNS). Name resolution is PURE (no root),
// so it is exercised here exhaustively.
func TestParseVerbAndNameResolution(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantVerb    string
		wantAccount string
	}{
		{"bare add -> default anon", []string{"add"}, "add", "anon"},
		{"named add -> anon-<name>", []string{"add", "work"}, "add", "anon-work"},
		{"bare rm -> default anon", []string{"rm"}, "rm", "anon"},
		{"named rm -> anon-<name>", []string{"rm", "work"}, "rm", "anon-work"},
		{"bare status -> default anon", []string{"status"}, "status", "anon"},
		{"named status", []string{"status", "media"}, "status", "anon-media"},
		{"list takes no name", []string{"list"}, "list", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := cli.Parse(tc.args)
			if err != nil {
				t.Fatalf("Parse(%v) error: %v", tc.args, err)
			}
			if cmd.Verb != tc.wantVerb {
				t.Errorf("verb = %q, want %q", cmd.Verb, tc.wantVerb)
			}
			if cmd.Account != tc.wantAccount {
				t.Errorf("account = %q, want %q", cmd.Account, tc.wantAccount)
			}
		})
	}
}

// A leading `anon-` on an explicit name is anonctl's OWN prefix; typing
// `add anon-work` must NOT double-prefix into `anon-anon-work`. The user names
// the SUFFIX, anonctl owns the prefix.
func TestNameAlreadyPrefixed(t *testing.T) {
	cmd, err := cli.Parse([]string{"add", "anon-work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if cmd.Account != "anon-work" {
		t.Errorf("account = %q, want anon-work (no double prefix)", cmd.Account)
	}
}

// The bare default account name may not be passed explicitly as `anon` either;
// it must resolve to the same `anon`, not `anon-anon`.
func TestExplicitDefaultName(t *testing.T) {
	cmd, err := cli.Parse([]string{"status", "anon"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if cmd.Account != "anon" {
		t.Errorf("account = %q, want anon", cmd.Account)
	}
}

// `use` is the verify-then-shell safe front door: it takes an optional name
// (bare = the default `anon`, `<name>` = `anon-<name>`), exactly like the other
// account-targeting verbs, so it must PARSE and resolve the account the same way.
func TestUseVerbAndNameResolution(t *testing.T) {
	cases := []struct {
		args        []string
		wantAccount string
	}{
		{[]string{"use"}, "anon"},
		{[]string{"use", "work"}, "anon-work"},
		{[]string{"use", "anon-media"}, "anon-media"},
	}
	for _, tc := range cases {
		cmd, err := cli.Parse(tc.args)
		if err != nil {
			t.Fatalf("Parse(%v) error: %v", tc.args, err)
		}
		if cmd.Verb != "use" {
			t.Errorf("verb = %q, want use", cmd.Verb)
		}
		if cmd.Account != tc.wantAccount {
			t.Errorf("Parse(%v) account = %q, want %q", tc.args, cmd.Account, tc.wantAccount)
		}
	}

	// `use` takes at most one account name, like the other targeting verbs.
	if _, err := cli.Parse([]string{"use", "a", "b"}); err == nil {
		t.Error("Parse(use a b) = nil error, want a too-many-names error")
	}
}

// `exec` runs a program INSIDE the anonymized account. Its grammar is bespoke
// (`exec [--as <name>] <program> [args...]`): the account is chosen by `--as`
// (default `anon`, `<name>` -> `anon-<name>`), the FIRST non-flag token is the
// program, and everything after it is forwarded VERBATIM. These are the pure-parse
// proofs of that split.
func TestExecParse(t *testing.T) {
	// Bare `exec <program>` targets the default account, no forwarded args.
	bare, err := cli.Parse([]string{"exec", "pi"})
	if err != nil {
		t.Fatalf("Parse(exec pi): %v", err)
	}
	if bare.Verb != "exec" || bare.Account != "anon" || bare.Program != "pi" {
		t.Errorf("exec pi => verb=%q account=%q program=%q, want exec/anon/pi", bare.Verb, bare.Account, bare.Program)
	}
	if len(bare.ExecArgs) != 0 {
		t.Errorf("exec pi ExecArgs = %v, want none", bare.ExecArgs)
	}

	// `--as <name>` selects the named account and resolves it like the other verbs.
	named, err := cli.Parse([]string{"exec", "--as", "work", "pi"})
	if err != nil {
		t.Fatalf("Parse(exec --as work pi): %v", err)
	}
	if named.Account != "anon-work" || named.Program != "pi" {
		t.Errorf("exec --as work pi => account=%q program=%q, want anon-work/pi", named.Account, named.Program)
	}

	// `--as=<name>` (equals form) works too.
	eq, err := cli.Parse([]string{"exec", "--as=media", "pi"})
	if err != nil {
		t.Fatalf("Parse(exec --as=media pi): %v", err)
	}
	if eq.Account != "anon-media" {
		t.Errorf("exec --as=media => account=%q, want anon-media", eq.Account)
	}
}

// The load-bearing property: everything after the program is forwarded VERBATIM and
// NEVER interpreted as an anonctl flag. A `--json`, a `--as`, a `-p`, or a
// `--skip-tor-exit-check` AFTER the program is the program's argument, not anonctl's,
// and an arg with spaces stays a SINGLE element (`-p "hello world"` reaches the
// program as `-p`, `hello world`).
func TestExecArgsForwardedVerbatim(t *testing.T) {
	cmd, err := cli.Parse([]string{"exec", "pi", "-p", "hello world", "--json", "--as", "notme", "--skip-tor-exit-check"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.Account != "anon" {
		t.Errorf("account = %q, want anon (a --as AFTER the program is the program's arg, not anonctl's)", cmd.Account)
	}
	if cmd.JSON {
		t.Error("a --json AFTER the program must NOT set anonctl's JSON flag")
	}
	if cmd.SkipTorExitCheck {
		t.Error("a --skip-tor-exit-check AFTER the program must NOT set anonctl's flag")
	}
	if cmd.Program != "pi" {
		t.Errorf("program = %q, want pi", cmd.Program)
	}
	want := []string{"-p", "hello world", "--json", "--as", "notme", "--skip-tor-exit-check"}
	if len(cmd.ExecArgs) != len(want) {
		t.Fatalf("ExecArgs = %v, want %v", cmd.ExecArgs, want)
	}
	for i := range want {
		if cmd.ExecArgs[i] != want[i] {
			t.Fatalf("ExecArgs = %v, want %v (verbatim, one element per arg)", cmd.ExecArgs, want)
		}
	}
}

// exec's OWN flags are honoured BEFORE the program (a `--skip-tor-exit-check`
// preceding the program is anonctl's verify-gate flag), and `--as` there sets the
// account.
func TestExecOwnFlagsBeforeProgram(t *testing.T) {
	cmd, err := cli.Parse([]string{"exec", "--skip-tor-exit-check", "--as", "work", "pi", "-p", "x"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cmd.SkipTorExitCheck {
		t.Error("--skip-tor-exit-check BEFORE the program must set anonctl's gate flag")
	}
	if cmd.Account != "anon-work" || cmd.Program != "pi" {
		t.Errorf("account/program = %q/%q, want anon-work/pi", cmd.Account, cmd.Program)
	}
	if len(cmd.ExecArgs) != 2 || cmd.ExecArgs[0] != "-p" || cmd.ExecArgs[1] != "x" {
		t.Errorf("ExecArgs = %v, want [-p x]", cmd.ExecArgs)
	}
}

// A bare `exec` with no program is a loud usage error (exec must run something), and
// an `exec --as work` with no program is too. A dangling `--as` (no value) is a loud
// error, and an unknown exec flag BEFORE the program is rejected.
func TestExecMissingProgramAndBadFlags(t *testing.T) {
	if _, err := cli.Parse([]string{"exec"}); err == nil {
		t.Error("bare exec (no program) must be a usage error")
	}
	if _, err := cli.Parse([]string{"exec", "--as", "work"}); err == nil {
		t.Error("exec --as work (no program) must be a usage error")
	}
	if _, err := cli.Parse([]string{"exec", "--as"}); err == nil {
		t.Error("dangling --as (no value) must be a parse error")
	}
	if _, err := cli.Parse([]string{"exec", "--bogus", "pi"}); err == nil {
		t.Error("an unknown exec flag before the program must be rejected")
	}
}

// verify and update/reconfigure are STUBS filled by later tasks, but they must
// still DISPATCH here so the verb surface is end-to-end.
func TestStubVerbsDispatch(t *testing.T) {
	for _, v := range []string{"verify", "update", "reconfigure"} {
		cmd, err := cli.Parse([]string{v})
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", v, err)
		}
		if cmd.Verb != v {
			t.Errorf("verb = %q, want %q", cmd.Verb, v)
		}
	}
}

// An unknown verb is a parse error (fail-loud, non-zero exit), not a silent
// no-op or a misread account name.
func TestUnknownVerb(t *testing.T) {
	if _, err := cli.Parse([]string{"frobnicate"}); err == nil {
		t.Fatal("Parse(frobnicate) = nil error, want an unknown-verb error")
	}
}

// No args at all is a usage error, not a crash.
func TestNoArgs(t *testing.T) {
	if _, err := cli.Parse(nil); err == nil {
		t.Fatal("Parse(nil) = nil error, want a usage error")
	}
}

// `rm` defaults to leaving the account intact; the destructive account removal is
// gated behind an explicit opt-in flag so a bare `rm` never deletes a home.
func TestRmSafetyFlag(t *testing.T) {
	bare, err := cli.Parse([]string{"rm", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if bare.PurgeAccount {
		t.Error("bare `rm` must NOT set PurgeAccount (home stays intact)")
	}

	purge, err := cli.Parse([]string{"rm", "--purge-account", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !purge.PurgeAccount {
		t.Error("`rm --purge-account` must set PurgeAccount")
	}
	if purge.Account != "anon-work" {
		t.Errorf("account = %q, want anon-work (flag order must not swallow the name)", purge.Account)
	}
}

// `seed-home` parses its verb, resolves the account, and reads --from (both forms)
// and --force. Flag order must not swallow the account name.
func TestSeedHomeParse(t *testing.T) {
	bare, err := cli.Parse([]string{"seed-home", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if bare.Verb != "seed-home" || bare.Account != "anon-work" {
		t.Errorf("verb/account = %q/%q, want seed-home/anon-work", bare.Verb, bare.Account)
	}
	if bare.SeedFrom != "" || bare.Force {
		t.Errorf("bare seed-home must have empty SeedFrom and Force=false, got %q / %v", bare.SeedFrom, bare.Force)
	}

	full, err := cli.Parse([]string{"seed-home", "--from", "/tmp/tmpl", "--force", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if full.SeedFrom != "/tmp/tmpl" || !full.Force || full.Account != "anon-work" {
		t.Errorf("parsed = from %q force %v account %q", full.SeedFrom, full.Force, full.Account)
	}

	eq, err := cli.Parse([]string{"seed-home", "--from=/tmp/tmpl"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if eq.SeedFrom != "/tmp/tmpl" || eq.Account != "anon" {
		t.Errorf("--from= form parsed = %q / %q", eq.SeedFrom, eq.Account)
	}
}

// A dangling `--from` with no value is a loud usage error, never a silent misparse.
func TestSeedHomeDanglingFrom(t *testing.T) {
	if _, err := cli.Parse([]string{"seed-home", "--from"}); err == nil {
		t.Fatal("seed-home --from with no value must error")
	}
}

// Each anon account gets its OWN dedicated shim service account, derived by the
// `-shim` suffix so that name resolution is pure and idempotent: `anon` ->
// `anon-shim` (matching the validated recipe), `anon-<name>` -> `anon-<name>-shim`.
func TestShimAccount(t *testing.T) {
	cases := map[string]string{
		"anon":       "anon-shim",
		"anon-work":  "anon-work-shim",
		"anon-media": "anon-media-shim",
	}
	for account, want := range cases {
		if got := cli.ShimAccount(account); got != want {
			t.Errorf("ShimAccount(%q) = %q, want %q", account, got, want)
		}
	}
}

// The forcing verbs accept `--endpoint`, in both the `=value` and the space
// forms, and it must not swallow the account name; a dangling `--endpoint` with no
// value is a loud parse error. Empty endpoint (the default) is left empty (the
// caller substitutes the default Tor SocksPort).
func TestEndpointFlag(t *testing.T) {
	space, err := cli.Parse([]string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if space.Endpoint != "socks5h://127.0.0.1:9050" {
		t.Errorf("Endpoint = %q, want the socks5h URL", space.Endpoint)
	}
	if space.Account != "anon-work" {
		t.Errorf("account = %q, want anon-work (--endpoint value must not swallow the name)", space.Account)
	}

	eq, err := cli.Parse([]string{"update", "--endpoint=socks5h://127.0.0.1:1080", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if eq.Endpoint != "socks5h://127.0.0.1:1080" || eq.Account != "anon-work" {
		t.Errorf("update --endpoint=... work => Endpoint=%q account=%q", eq.Endpoint, eq.Account)
	}

	bare, err := cli.Parse([]string{"add"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if bare.Endpoint != "" {
		t.Errorf("bare add Endpoint = %q, want empty (default applied by the caller)", bare.Endpoint)
	}

	if _, err := cli.Parse([]string{"update", "--endpoint"}); err == nil {
		t.Error("dangling --endpoint (no value) must be a parse error")
	}
}

// The forcing verbs accept a repeatable `--allow` (netcage's vocabulary): each
// value is parsed+validated through lanexempt.Parse at the CLI boundary and
// collected onto cmd.Exemptions, in both the `=value` and the space forms. A
// public/hostname/:53 value is rejected LOUDLY here (the fail-loud config gate),
// and the flag must not swallow the account name. Every value carries an explicit
// port (a port is mandatory).
func TestAllowFlag(t *testing.T) {
	cmd, err := cli.Parse([]string{"add", "--allow", "192.168.1.150:8080", "--allow=10.0.0.0/24:9090", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if cmd.Account != "anon-work" {
		t.Errorf("account = %q, want anon-work (--allow value must not swallow the name)", cmd.Account)
	}
	if len(cmd.Exemptions) != 2 {
		t.Fatalf("Exemptions = %d, want 2 (repeatable flag)", len(cmd.Exemptions))
	}
	if cmd.Exemptions[0].Raw != "192.168.1.150:8080" || cmd.Exemptions[1].Raw != "10.0.0.0/24:9090" {
		t.Errorf("Exemptions raw = %q/%q, want the two values in order", cmd.Exemptions[0].Raw, cmd.Exemptions[1].Raw)
	}

	bare, err := cli.Parse([]string{"add"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(bare.Exemptions) != 0 {
		t.Errorf("bare add Exemptions = %d, want 0 (no exemption unless asked)", len(bare.Exemptions))
	}

	if _, err := cli.Parse([]string{"add", "--allow"}); err == nil {
		t.Error("dangling --allow (no value) must be a parse error")
	}
}

// The guardrail is surfaced at the CLI boundary: a public address, a hostname, the
// un-exemptable clear-DNS port 53, and a PORT-OMITTED (all-ports) value are each
// rejected LOUDLY by Parse (via lanexempt.Parse), so an operator cannot punch an
// anonymity leak from the CLI.
func TestAllowRejectsUnsafeValues(t *testing.T) {
	for _, bad := range []string{
		"8.8.8.8:443",      // public address
		"router.local:80",  // hostname
		"192.168.1.150:53", // un-exemptable clear-DNS port
		"10.0.0.0/7:80",    // too-wide prefix straddling public space
		"192.168.1.150",    // port-omitted (all-ports) is now rejected
		"10.0.0.0/24",      // port-omitted CIDR too
	} {
		if _, err := cli.Parse([]string{"add", "--allow", bad}); err == nil {
			t.Errorf("Parse(--allow %q) = nil error, want a loud reject", bad)
		}
	}
}

// The unified --allow flag DISPATCHES on the typed address class at the SAME CLI
// entry point: a loopback literal (127.0.0.1:port) is accepted and carried like a
// LAN one (no new flag, no new field), while a loopback anonymizer control/SOCKS/DNS
// port is rejected LOUDLY here. This is the loopback-exemption feature's CLI-boundary
// proof that one flag covers both classes.
func TestAllowFlagLoopbackClassDispatch(t *testing.T) {
	// A same-host loopback service on a non-anonymizer port rides the same flag.
	cmd, err := cli.Parse([]string{"add", "--allow", "127.0.0.1:8080", "work"})
	if err != nil {
		t.Fatalf("Parse(--allow 127.0.0.1:8080): %v", err)
	}
	if len(cmd.Exemptions) != 1 || cmd.Exemptions[0].Raw != "127.0.0.1:8080" {
		t.Fatalf("loopback exemption must ride the same Exemptions slice; got %+v", cmd.Exemptions)
	}
	if !cmd.Exemptions[0].IsLoopback() {
		t.Errorf("127.0.0.1:8080 must route to the loopback class from the --allow entry point")
	}

	// A loopback anonymizer control/SOCKS/DNS port is rejected loudly at the boundary.
	for _, bad := range []string{
		"127.0.0.1:53",   // clear DNS
		"127.0.0.1:9050", // Tor SOCKS
		"127.0.0.1:9051", // Tor control (self-deanonymization)
		"127.0.0.1:1080", // generic SOCKS
		"127.0.0.1",      // port-omitted: no all-ports loopback form
	} {
		if _, err := cli.Parse([]string{"add", "--allow", bad}); err == nil {
			t.Errorf("Parse(--allow %q) = nil error, want a loud loopback reject", bad)
		}
	}
}

// `status` and `list` accept `--json` for machine-readable output; the other
// verbs need not.
func TestJSONFlag(t *testing.T) {
	cmd, err := cli.Parse([]string{"status", "--json"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !cmd.JSON {
		t.Error("status --json must set JSON")
	}
	if cmd.Account != "anon" {
		t.Errorf("account = %q, want anon", cmd.Account)
	}

	named, err := cli.Parse([]string{"status", "--json", "media"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !named.JSON || named.Account != "anon-media" {
		t.Errorf("status --json media => JSON=%v account=%q", named.JSON, named.Account)
	}
}

// `verify`/`use` accept `--skip-tor-exit-check` to relax the tor-exit requirement of
// anonymized-exit (the registry-lag escape hatch); it parses as a bool flag and is
// off by default, and the account name still resolves alongside it.
func TestSkipTorExitCheckFlag(t *testing.T) {
	defaultOff, err := cli.Parse([]string{"verify"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if defaultOff.SkipTorExitCheck {
		t.Error("SkipTorExitCheck must default to false")
	}
	set, err := cli.Parse([]string{"verify", "--skip-tor-exit-check", "work"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !set.SkipTorExitCheck {
		t.Error("verify --skip-tor-exit-check must set SkipTorExitCheck")
	}
	if set.Account != "anon-work" {
		t.Errorf("account = %q, want anon-work (the flag must not swallow the name)", set.Account)
	}
	useSet, err := cli.Parse([]string{"use", "--skip-tor-exit-check"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !useSet.SkipTorExitCheck {
		t.Error("use --skip-tor-exit-check must set SkipTorExitCheck")
	}
}

// `--allow-nss-bypass` is add's explicit escape hatch for a host whose glibc
// resolves `hosts` out of process. It parses before OR after the account name (the
// flag-anywhere rule the other add flags follow), and it is OFF unless asked for:
// the default on such a host is a refusal, because a per-UID rule cannot govern a
// lookup another daemon performs.
func TestParseAllowNSSBypass(t *testing.T) {
	for _, args := range [][]string{
		{"add", "--allow-nss-bypass", "work"},
		{"add", "work", "--allow-nss-bypass"},
	} {
		cmd, err := cli.Parse(args)
		if err != nil {
			t.Fatalf("Parse(%v): %v", args, err)
		}
		if !cmd.AllowNSSBypass {
			t.Errorf("Parse(%v) did not set AllowNSSBypass", args)
		}
		if cmd.Account != "anon-work" {
			t.Errorf("Parse(%v) account = %q, want anon-work: the flag must not swallow the name", args, cmd.Account)
		}
	}
	cmd, err := cli.Parse([]string{"add", "work"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cmd.AllowNSSBypass {
		t.Error("AllowNSSBypass must default to FALSE: the safe default is to refuse a host that resolves out of process")
	}
}

// Name resolution REFUSES an account name anonctl cannot name unambiguously in the
// kernel. `add a_b` and `add a-b` would both derive the nft table `anonctl_anon_a_b`
// (nft identifiers cannot contain `-`, so anonctl rewrites `-` to `_`), and since the
// ruleset is loaded as an atomic table REPLACE, adding the second would silently
// replace the first account's forcing. The refusal happens at PARSE time, before any
// verb touches the box.
func TestParseRefusesAnAccountNameThatCollidesInTheNftTableName(t *testing.T) {
	// The verbs that CREATE or RE-APPLY forcing refuse it outright, before any mutation.
	for _, verb := range []string{"add", "update", "reconfigure"} {
		if _, err := cli.Parse([]string{verb, "a_b"}); err == nil {
			t.Errorf("%s a_b: parsed with no error; a verb that installs forcing must refuse an ambiguous name", verb)
		}
	}
	// The legal twin still parses, so the guard rejects the ambiguity and nothing else.
	cmd, err := cli.Parse([]string{"add", "a-b"})
	if err != nil {
		t.Fatalf("add a-b must still parse: %v", err)
	}
	if cmd.Account != "anon-a-b" {
		t.Errorf("Account = %q, want anon-a-b", cmd.Account)
	}
	if cmd.NameWarning != "" {
		t.Errorf("a well-formed name must carry no warning; got %q", cmd.NameWarning)
	}
}

// ...but the READ and TEARDOWN verbs still accept it, WITH A WARNING. An OLDER
// anonctl accepted `a_b` and installed forcing for it, so a blanket refusal would
// leave that account with no `status` to inspect it and - the real trap - no `rm`
// to remove it. A naming rule must not turn an existing account into one the tool
// can no longer tear down.
func TestReadAndTeardownVerbsStillReachAnAccountAnOlderBuildCreated(t *testing.T) {
	for _, verb := range []string{"rm", "status", "probe", "verify", "use", "seed-home"} {
		cmd, err := cli.Parse([]string{verb, "a_b"})
		if err != nil {
			t.Errorf("%s a_b: refused (%v); a read/teardown verb must still reach an account an older anonctl created", verb, err)
			continue
		}
		if cmd.Account != "anon-a_b" {
			t.Errorf("%s a_b: Account = %q, want anon-a_b", verb, cmd.Account)
		}
		if cmd.NameWarning == "" {
			t.Errorf("%s a_b: proceeding on an ambiguous name must WARN; got no warning", verb)
		}
	}
	if _, err := cli.Parse([]string{"exec", "--as", "a_b", "true"}); err != nil {
		t.Errorf("exec --as a_b: refused (%v); exec installs no forcing", err)
	}
}

// The refusal must EXPLAIN ITSELF in nft terms: an operator who is told only
// "invalid account name" learns nothing about why a perfectly ordinary Unix name
// was rejected.
func TestTheNameRefusalExplainsTheNftReason(t *testing.T) {
	_, err := cli.Parse([]string{"add", "a_b"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"nftables", "table", "underscore"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q; got: %v", want, err)
		}
	}
}

// `units` is the only verb that takes NO account name, and that is a privacy
// property rather than a convenience: the unit FILES are account-agnostic, while the
// artifact that names an account (the per-account enablement symlink) is never
// exportable. A `units` grammar that accepted a name would invite a host to declare
// the one artifact whose name says which slot is in use.
func TestUnitsTakesNoAccountName(t *testing.T) {
	if _, err := cli.Parse([]string{"units", "print", "--kind", "shim", "anon-01"}); err == nil {
		t.Fatal("units accepted an account name; the exported units are account-agnostic by construction")
	}
}

// The `units print` grammar: both flag spellings, and a loud refusal for everything
// underspecified. A path that is silently defaulted would produce a unit that fails
// 203/EXEC at the next boot, long after whoever ran this saw it succeed.
func TestUnitsPrintGrammar(t *testing.T) {
	cmd, err := cli.Parse([]string{"units", "print", "--kind=shim", "--setpriv=/p/setpriv", "--shim", "/p/shim", "--env-dir=/etc/anonctl/shim"})
	if err != nil {
		t.Fatalf("units print: %v", err)
	}
	if cmd.Verb != "units" || cmd.UnitsSubcommand != "print" {
		t.Errorf("verb/subcommand = %q/%q, want units/print", cmd.Verb, cmd.UnitsSubcommand)
	}
	if cmd.UnitKind != "shim" || cmd.UnitSetprivPath != "/p/setpriv" || cmd.UnitShimPath != "/p/shim" || cmd.UnitEnvDir != "/etc/anonctl/shim" {
		t.Errorf("flags parsed as %+v", cmd)
	}
	if cmd.Account != "" {
		t.Errorf("units resolved an account %q; it must resolve none", cmd.Account)
	}

	for _, args := range [][]string{
		{"units"},
		{"units", "list"},
		{"units", "--kind", "shim"},
		{"units", "print", "--kind"},
		{"units", "print", "--setpriv", "/p/setpriv"},
		{"units", "print", "--kind", "shim", "--unknown", "x"},
		{"units", "print", "--kind", "shim", "--placeholders", "--nft", "/p/nft"},
	} {
		if _, err := cli.Parse(args); err == nil {
			t.Errorf("cli.Parse(%q) succeeded; it must refuse", args)
		}
	}
}
