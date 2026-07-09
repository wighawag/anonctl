package ui

import (
	"os"
	"strings"
	"testing"
)

// A disabled Styler is a pure pass-through: every method returns its input with no
// escape codes. This is the piped/redirected/--json path, and it must stay
// byte-plain.
func TestDisabledStylerIsPassThrough(t *testing.T) {
	s := Styler{enabled: false}
	for _, got := range []string{s.Red("x"), s.Green("x"), s.Yellow("x"), s.Cyan("x"), s.Bold("x"), s.Dim("x")} {
		if got != "x" {
			t.Errorf("disabled styler altered text: got %q, want %q", got, "x")
		}
		if strings.Contains(got, "\x1b[") {
			t.Errorf("disabled styler emitted an escape code: %q", got)
		}
	}
	if s.Enabled() {
		t.Errorf("Enabled() must be false for a disabled styler")
	}
}

// An enabled Styler wraps text in the matching ANSI code + a reset, so a terminal
// renders color; the original text is still present between the codes.
func TestEnabledStylerWrapsWithReset(t *testing.T) {
	s := Styler{enabled: true}
	got := s.Red("bad")
	if !strings.HasPrefix(got, ansiRed) || !strings.HasSuffix(got, ansiReset) || !strings.Contains(got, "bad") {
		t.Errorf("enabled Red = %q, want %q...bad...%q", got, ansiRed, ansiReset)
	}
	if !s.Enabled() {
		t.Errorf("Enabled() must be true for an enabled styler")
	}
}

// NO_COLOR disables color even on a (simulated) terminal; FORCE_COLOR enables it
// even off a terminal. NO_COLOR wins when both are set (the stricter, do-not-color
// choice). We drive colorEnabled with a non-TTY *os.File (a pipe) so the TTY branch
// is not what flips these; the env precedence is.
func TestColorEnabledEnvPrecedence(t *testing.T) {
	// A pipe is never a terminal, so without env overrides colorEnabled is false.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })

	// clearEnv unsets a var for the test and restores it after (t.Setenv can only set).
	clearEnv := func(t *testing.T, key string) {
		t.Helper()
		prev, had := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unsetenv %s: %v", key, err)
		}
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(key, prev)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}

	t.Run("no env => not a tty => disabled", func(t *testing.T) {
		clearEnv(t, "NO_COLOR")
		clearEnv(t, "FORCE_COLOR")
		if colorEnabled(w) {
			t.Errorf("a pipe with no color env must be disabled")
		}
	})
	t.Run("FORCE_COLOR forces on even off a tty", func(t *testing.T) {
		clearEnv(t, "NO_COLOR")
		t.Setenv("FORCE_COLOR", "1")
		if !colorEnabled(w) {
			t.Errorf("FORCE_COLOR must enable color even on a pipe")
		}
	})
	t.Run("NO_COLOR wins over FORCE_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		t.Setenv("FORCE_COLOR", "1")
		if colorEnabled(w) {
			t.Errorf("NO_COLOR must win over FORCE_COLOR (never color)")
		}
	})
}
