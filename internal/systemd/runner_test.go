package systemd_test

import (
	"context"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// fakeRunner records systemctl invocations so the enable/disable/restart WIRING is
// exercised WITHOUT touching real systemd (mirrors provision/nftables fakeRunner).
type fakeRunner struct {
	calls [][]string
	err   error
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return "", "", r.err
}

func (r *fakeRunner) last() string {
	if len(r.calls) == 0 {
		return ""
	}
	return strings.Join(r.calls[len(r.calls)-1], " ")
}

// Starting is now SEPARATE from enabling: `systemctl start` brings the instance up
// now, while "comes back after a reboot" is anonctl's own .wants symlink
// (Store.EnableUnit). The split exists because `systemctl enable` writes into
// /etc/systemd/system whatever the unit dir is, and that dir is read-only on NixOS.
func TestStartNowStartsTheInstanceWithoutEnabling(t *testing.T) {
	r := &fakeRunner{}
	if err := systemd.StartNow(context.Background(), r, "anon"); err != nil {
		t.Fatalf("StartNow: %v", err)
	}
	if got := r.last(); got != "systemctl start anonctl-shim@anon.service" {
		t.Errorf("StartNow ran %q", got)
	}
	// It must NOT shell out to `systemctl enable`, which cannot work on a host whose
	// config dir is read-only.
	for _, call := range r.calls {
		if strings.Contains(strings.Join(call, " "), "enable") {
			t.Errorf("StartNow must not call systemctl enable: %q", call)
		}
	}
}

func TestStopNowStopsTheInstanceWithoutDisabling(t *testing.T) {
	r := &fakeRunner{}
	if err := systemd.StopNow(context.Background(), r, "anon-work"); err != nil {
		t.Fatalf("StopNow: %v", err)
	}
	if got := r.last(); got != "systemctl stop anonctl-shim@anon-work.service" {
		t.Errorf("StopNow ran %q", got)
	}
}

func TestRestartNowRestartsTheInstance(t *testing.T) {
	r := &fakeRunner{}
	if err := systemd.RestartNow(context.Background(), r, "anon"); err != nil {
		t.Fatalf("RestartNow: %v", err)
	}
	// `update` restarts the instance to pick up a rewritten env file (a changed
	// endpoint); the nft rules stay applied across the bounce, so no leak window.
	if got := r.last(); got != "systemctl restart anonctl-shim@anon.service" {
		t.Errorf("RestartNow ran %q", got)
	}
}

func TestDaemonReloadReloadsSystemd(t *testing.T) {
	r := &fakeRunner{}
	if err := systemd.DaemonReload(context.Background(), r); err != nil {
		t.Fatalf("DaemonReload: %v", err)
	}
	if got := r.last(); got != "systemctl daemon-reload" {
		t.Errorf("DaemonReload ran %q", got)
	}
}
