// Package ui is anonctl's tiny presentation layer: terminal color + small styling
// helpers for the human CLI output. It is deliberately minimal and dependency-light
// (one ANSI palette, TTY + NO_COLOR/FORCE_COLOR detection) so the rest of the CLI
// can call Red/Green/Bold without each site re-deciding whether color is safe.
//
// The load-bearing rule: color is applied at the PRINT boundary, per output stream,
// and ONLY when that stream is an interactive terminal (and NO_COLOR is unset). So
// piped output, redirected logs, and the machine `--json` path stay byte-plain: the
// verify Report.Human() text and the JSON encoder never see an escape code. A caller
// that colorizes stderr progress does not colorize a stdout JSON blob, because it
// asks THIS package per stream (Stdout()/Stderr()) whether that stream is a TTY.
package ui

import (
	"os"

	"golang.org/x/term"
)

// ansi escape codes. Kept private; callers use the styling functions, never the raw
// codes, so a future palette change is one edit here.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

// Styler colorizes strings for ONE output stream. It captures whether that stream
// is an interactive terminal at construction time; when it is not (a pipe, a file,
// NO_COLOR set), every styling method is a no-op that returns its input unchanged,
// so redirected/piped output and the --json path stay byte-plain. This is the type
// callers hold: build one per stream (Stdout()/Stderr()) and style through it.
type Styler struct{ enabled bool }

// Stdout returns a Styler for os.Stdout, colorizing only when stdout is a TTY and
// color is not disabled. Use it for human result output (never for --json, which is
// stdout but must stay plain: callers gate --json before reaching a colorized print,
// and on a pipe enabled is false anyway).
func Stdout() Styler { return Styler{enabled: colorEnabled(os.Stdout)} }

// Stderr returns a Styler for os.Stderr, colorizing only when stderr is a TTY and
// color is not disabled. Use it for errors, notices, and the verify progress stream.
func Stderr() Styler { return Styler{enabled: colorEnabled(os.Stderr)} }

// Enabled reports whether this Styler will actually emit color (its stream is an
// interactive terminal and color is not disabled), so a caller can pick a plain vs
// colored layout without probing the escape output.
func (s Styler) Enabled() bool { return s.enabled }

// ForceEnabledForTest returns a copy of the Styler with color forced ON. It exists
// so tests in OTHER packages can exercise the colored branch deterministically
// without a real terminal or the FORCE_COLOR env dance (the enabled field is
// unexported). Not for production use: production builds stylers via Stdout/Stderr,
// which gate color on the actual stream.
func (s Styler) ForceEnabledForTest() Styler { s.enabled = true; return s }

func (s Styler) wrap(code, text string) string {
	if !s.enabled {
		return text
	}
	return code + text + ansiReset
}

// Red / Green / Yellow / Cyan color text; Bold / Dim weight it. Each is a no-op when
// color is disabled for the stream, returning text unchanged.
func (s Styler) Red(text string) string    { return s.wrap(ansiRed, text) }
func (s Styler) Green(text string) string  { return s.wrap(ansiGreen, text) }
func (s Styler) Yellow(text string) string { return s.wrap(ansiYellow, text) }
func (s Styler) Cyan(text string) string   { return s.wrap(ansiCyan, text) }
func (s Styler) Bold(text string) string   { return s.wrap(ansiBold, text) }
func (s Styler) Dim(text string) string    { return s.wrap(ansiDim, text) }

// colorEnabled decides whether to colorize a given output stream. The precedence
// mirrors the de-facto standard the ecosystem follows:
//   - NO_COLOR set (to anything, even empty) => never color (https://no-color.org).
//   - FORCE_COLOR set (non-empty) => always color, even when not a TTY (CI/tests).
//   - otherwise => color iff the stream is an interactive terminal.
//
// Deciding per stream (not once globally) is what keeps a colorized stderr from
// leaking codes into a piped/redirected stdout, and vice versa.
func colorEnabled(f *os.File) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if v := os.Getenv("FORCE_COLOR"); v != "" {
		return true
	}
	return term.IsTerminal(int(f.Fd()))
}
