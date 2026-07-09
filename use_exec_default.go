//go:build !integration
// +build !integration

package main

import (
	"context"
	"fmt"

	"github.com/wighawag/anonctl/internal/provision"
)

// execLoginShell (default build) is an honest fail-loud stub: actually dropping
// to the account and exec'ing its login shell needs setpriv + root + a live host,
// which per the repo's build-tag discipline (mirroring verify's checks_default vs
// checks_integration) is compiled ONLY under the `integration` tag
// (use_exec_integration.go). This is not a real limitation in practice: the
// DEFAULT binary also cannot run the live verify probes (checks_default), so its
// `use` never reaches a GREEN verdict to drop on. Keeping the real drop off the
// default build guarantees a stray path can never spawn a shell in a unit run.
func execLoginShell(ctx context.Context, r provision.Runner, account string) error {
	return fmt.Errorf("this anonctl binary was built WITHOUT the shell-drop (and without the live-verify probes); rebuild with `-tags integration` on the provisioned host to use `anonctl use`")
}
