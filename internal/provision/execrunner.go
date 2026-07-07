package provision

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// ExecRunner is the real Runner: it shells out with os/exec. It mirrors netcage's
// jail.ExecRunner (a single Run seam every mutation flows through) so the impure
// system calls live in ONE place, and the default `go test ./...` never
// constructs it (the unit tests use a fake). anonctl runs its mutations as root
// (the ufw stance), so these commands (useradd/userdel) require privilege; a
// non-root invocation surfaces the command's own permission error.
type ExecRunner struct{}

// Run executes the command and returns its trimmed stdout and stderr separately,
// plus the raw exec error (e.g. *exec.ExitError) so callers can inspect the exit
// code. Keeping stdout and stderr separate lets accountEntry distinguish getent's
// "not found" (exit 2, empty stdout) from a real failure.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}

// ReadPasswd returns the host's passwd entries (one raw line each) for List to
// enumerate. It reads getent's full table through the Runner, so the enumeration
// still flows through the one seam (and a test can inject a fake). An empty table
// or a getent failure yields no accounts rather than an error, so `list` on a box
// with no anon accounts is a clean empty result.
func ReadPasswd(ctx context.Context, r Runner) []string {
	stdout, _, err := r.Run(ctx, "getent", "passwd")
	if err != nil && stdout == "" {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
