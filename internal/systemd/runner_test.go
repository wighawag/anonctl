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

func TestEnableNowEnablesAndStartsTheInstance(t *testing.T) {
	r := &fakeRunner{}
	if err := systemd.EnableNow(context.Background(), r, "anon"); err != nil {
		t.Fatalf("EnableNow: %v", err)
	}
	// `enable --now` on the per-account instance: it comes up now AND after a reboot.
	if got := r.last(); got != "systemctl enable --now anonctl-shim@anon.service" {
		t.Errorf("EnableNow ran %q", got)
	}
}

func TestDisableNowDisablesAndStopsTheInstance(t *testing.T) {
	r := &fakeRunner{}
	if err := systemd.DisableNow(context.Background(), r, "anon-work"); err != nil {
		t.Fatalf("DisableNow: %v", err)
	}
	if got := r.last(); got != "systemctl disable --now anonctl-shim@anon-work.service" {
		t.Errorf("DisableNow ran %q", got)
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
