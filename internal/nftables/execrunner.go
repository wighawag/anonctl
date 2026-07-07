package nftables

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// ExecRunner is the real Runner: it shells out to `nft` with os/exec, piping the
// ruleset on stdin (the `nft -f -` atomic-load form). It mirrors
// provision.ExecRunner (the one impure seam) so the default `go test ./...` never
// constructs it (the unit tests use a fake) and the real nft shell-out lives in
// ONE place. anonctl runs these as root (the ufw stance); a non-root invocation
// surfaces nft's own permission error.
type ExecRunner struct{}

// Run executes the command with stdin fed from the ruleset string, returning
// trimmed stdout/stderr and the raw exec error so callers can classify a failure.
func (ExecRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}
