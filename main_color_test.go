package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/ui"
)

// errorf must never leak escape codes when its stream's styler is disabled (a pipe,
// a redirect, NO_COLOR): the `anonctl:` prefix and message stay byte-plain. This is
// the safety contract that keeps redirected logs and the --json path clean. We swap
// errStyle to a disabled styler (the not-a-tty case) and capture os.Stderr.
func TestErrorfPlainWhenColorDisabled(t *testing.T) {
	origErr := errStyle
	errStyle = ui.Styler{} // disabled (zero value)
	t.Cleanup(func() { errStyle = origErr })

	got := captureStderrDuring(t, func() { errorf("add: %v", "boom") })
	if strings.ContainsRune(got, '\x1b') {
		t.Errorf("errorf leaked an escape code with color disabled: %q", got)
	}
	if !strings.Contains(got, "anonctl: add: boom") {
		t.Errorf("errorf message = %q, want it to contain `anonctl: add: boom`", got)
	}
}

// errorf DOES colorize when its styler is enabled (the interactive terminal case):
// the message is wrapped in escape codes. This proves the color path is live, not
// dead, complementing the plain-when-disabled test.
func TestErrorfColorsWhenEnabled(t *testing.T) {
	origErr := errStyle
	errStyle = ui.Styler{}.ForceEnabledForTest()
	t.Cleanup(func() { errStyle = origErr })

	got := captureStderrDuring(t, func() { errorf("boom") })
	if !strings.ContainsRune(got, '\x1b') {
		t.Errorf("errorf must emit escape codes when color is enabled; got %q", got)
	}
	if !strings.Contains(got, "anonctl: ") {
		t.Errorf("errorf must still carry the anonctl: prefix; got %q", got)
	}
}

// colorizeReport is a no-op when its styler is disabled: the plain [PASS]/[FAIL]
// markers survive unchanged, so a piped/redirected verify report is byte-identical
// to the un-colorized Human() text.
func TestColorizeReportPlainWhenColorDisabled(t *testing.T) {
	orig := outStyle
	outStyle = ui.Styler{} // disabled
	t.Cleanup(func() { outStyle = orig })

	in := "verify anon\n[PASS] dns-remote\n[FAIL] leak-drop-v6\n"
	if got := colorizeReport(in); got != in {
		t.Errorf("colorizeReport altered text with color disabled:\n got %q\nwant %q", got, in)
	}
}

// progressStyler returns a DISABLED styler whenever progress is not going to the
// real stderr (the test/redirect case: verifyProgressWriter is a buffer), so the
// progress stream degrades to plain [PASS]/[FAIL] with no control chars.
func TestProgressStylerDisabledOffRealStderr(t *testing.T) {
	origWriter := verifyProgressWriter
	verifyProgressWriter = &bytes.Buffer{} // not os.Stderr
	t.Cleanup(func() { verifyProgressWriter = origWriter })

	if progressStyler().Enabled() {
		t.Errorf("progress styler must be disabled when the writer is not the real stderr")
	}
}
