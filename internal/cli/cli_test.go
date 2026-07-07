package cli_test

import (
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
