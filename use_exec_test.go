package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestLoginWorkingDirPrefersHome proves the dropped login shell starts in the
// account's HOME when it is a usable absolute path: this is what keeps `anonctl use`
// from leaving the anon session in the operator's own (unwritable) CWD, the split
// environment that made tools like `pi` hit EACCES (a session dir named after the
// caller's path while HOME points at /home/anon).
func TestLoginWorkingDirPrefersHome(t *testing.T) {
	if got := loginWorkingDir("/home/anon"); got != "/home/anon" {
		t.Errorf("loginWorkingDir(/home/anon) = %q, want /home/anon", got)
	}
}

// TestLoginWorkingDirFallsBackToRootNotCaller proves an unusable home (empty or a
// relative path) falls back to `/`, NEVER to the caller's inherited CWD: a login
// must not sit in the operator's home. The important property is "not the caller's
// dir"; `/` is the safe, always-present fallback.
func TestLoginWorkingDirFallsBackToRootNotCaller(t *testing.T) {
	for _, home := range []string{"", "relative/home", "./x", "home/anon"} {
		if got := loginWorkingDir(home); got != "/" {
			t.Errorf("loginWorkingDir(%q) = %q, want the / fallback (never the caller's CWD)", home, got)
		}
	}
}

// TestShellQuoteWrapsAsSingleLiteral proves shellQuote produces a single-quoted
// literal a POSIX shell reads verbatim, including the classic `'\”` escape for an
// embedded quote. This is the pure-string half of the property that lets `exec`
// forward an arg with spaces/metacharacters as ONE argument.
func TestShellQuoteWrapsAsSingleLiteral(t *testing.T) {
	cases := map[string]string{
		"pi":          "'pi'",
		"hello world": "'hello world'",
		"a$b":         "'a$b'",
		"a;b|c":       "'a;b|c'",
		"it's":        `'it'\''s'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestShellQuoteRoundTripsThroughRealShell is the load-bearing proof: the command
// string `exec` hands the login shell (`<program> <args>` with each token
// shellQuote'd) must re-assemble the EXACT argv anonctl was given, with NO re-split
// and NO glob. It builds the same command string execProgram builds, runs it through
// a real `sh -c` that prints each argv element NUL-delimited, and asserts the shell
// saw exactly the original tokens. This is what guarantees `exec pi -p "hello world"`
// reaches the program as `pi`, `-p`, `hello world` (three args), never four.
func TestShellQuoteRoundTripsThroughRealShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH; skipping the real-shell round-trip")
	}
	// A deliberately nasty argv forwarded to the program: spaces, a glob, a shell
	// metacharacter, an embedded quote, and an empty string. If shellQuote is right, the
	// program's `printf '%s\0'` (which folds the format over each operand and emits it
	// NUL-terminated) reproduces each forwarded arg exactly; if the shell re-split or
	// globbed, the count or contents differ. The program is `printf` with a `%s\0`
	// format, matching how execProgram builds `<program> <args>` (program token +
	// quoted args).
	program := "printf"
	format := `%s\0`
	args := []string{"hello world", "a*b", "a;b", "it's", ""}

	// Build the command string exactly as execProgram does: program token, then every
	// arg (here the format plus the forwarded args) shellQuote'd.
	quoted := []string{shellQuote(program), shellQuote(format)}
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	command := strings.Join(quoted, " ")

	out, err := exec.Command(sh, "-lc", command).Output()
	if err != nil {
		t.Fatalf("running %q via sh: %v", command, err)
	}
	// printf '%s\0' <args...> emits each operand NUL-terminated. Split and drop the
	// trailing empty the final NUL produces.
	got := strings.Split(string(out), "\x00")
	if n := len(got); n > 0 && got[n-1] == "" {
		got = got[:n-1]
	}
	if len(got) != len(args) {
		t.Fatalf("program saw %d args %q, want %d %q (re-split or glob happened)", len(got), got, len(args), args)
	}
	for i := range args {
		if got[i] != args[i] {
			t.Errorf("arg[%d] = %q through the shell, want %q (verbatim)", i, got[i], args[i])
		}
	}
}
