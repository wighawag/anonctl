package systemd

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// ExecRunner is the real Runner: it shells out to `systemctl` with os/exec. It
// mirrors provision.ExecRunner / nftables.ExecRunner (the one impure seam) so the
// default `go test ./...` never constructs it (the unit tests use a fake) and the
// real systemctl shell-out lives in ONE place. anonctl runs these as root; a
// non-root invocation surfaces systemctl's own permission error.
type ExecRunner struct{}

// Run executes the command, returning trimmed stdout/stderr and the raw exec error
// so callers can classify a failure.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}
