package systemd_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// The LOADER unit is anonctl's OWN early-boot nftables loader, REPLACING the
// previous `nftables.service` drop-in. The drop-in rode on the host's
// nftables.service, which Debian ships DISABLED, so at boot the rules were absent
// and the anon UID leaked the host's real IP (BUG 1 of the e2e finding). anonctl
// must not depend on a host-owned unit it can silently re-disable; it owns its own
// loader, ordered EARLY (before the network is up) so the standing baseline
// default-deny is present from the first moment the anon UID could act.

func TestLoaderUnitIsAnonctlOwnedAndEarly(t *testing.T) {
	unit := systemd.LoaderUnit(systemd.LoaderParams{RulesGlob: "/etc/anonctl/nftables/*.nft"})
	// A oneshot that loads the rules once at boot (RemainAfterExit so systemd tracks
	// it as active after the load).
	if !strings.Contains(unit, "Type=oneshot") {
		t.Errorf("loader unit must be a oneshot:\n%s", unit)
	}
	if !strings.Contains(unit, "RemainAfterExit=yes") {
		t.Errorf("loader unit should RemainAfterExit so it stays active after loading:\n%s", unit)
	}
	// It is ordered EARLY: pulled in by sysinit.target and ordered BEFORE the network
	// comes up, with DefaultDependencies=no so it is not held back to the normal
	// late boot phase. This is what closes the boot-window leak: the standing deny is
	// present before the anon UID could egress.
	if !strings.Contains(unit, "DefaultDependencies=no") {
		t.Errorf("loader unit must set DefaultDependencies=no to run early:\n%s", unit)
	}
	if !strings.Contains(unit, "WantedBy=sysinit.target") {
		t.Errorf("loader unit must be WantedBy=sysinit.target (anonctl-owned early enablement):\n%s", unit)
	}
	if !strings.Contains(unit, "Before=network-pre.target") {
		t.Errorf("loader unit must be ordered before the network is up:\n%s", unit)
	}
}

func TestLoaderUnitLoadsAnonctlRulesNotAHostService(t *testing.T) {
	unit := systemd.LoaderUnit(systemd.LoaderParams{RulesGlob: "/etc/anonctl/nftables/*.nft"})
	// It loads anonctl's OWN per-account rule files (both the baseline and the
	// forcing tables) via nft, independent of the host's nftables.service.
	if !strings.Contains(unit, "ExecStart") {
		t.Errorf("loader unit must load the rules via ExecStart:\n%s", unit)
	}
	if !strings.Contains(unit, "/etc/anonctl/nftables/") {
		t.Errorf("loader unit must reference anonctl's rules dir:\n%s", unit)
	}
	if !strings.Contains(unit, "nft") {
		t.Errorf("loader unit must invoke nft:\n%s", unit)
	}
	// It must NOT ride on the host's nftables.service (the leaky old mechanism): no
	// drop-in on, nor a dependency requiring, a host-owned unit that can be disabled.
	if strings.Contains(unit, "nftables.service") {
		t.Errorf("loader unit must be independent of the host's nftables.service:\n%s", unit)
	}
}

func TestLoaderUnitToleratesEmptyRulesDir(t *testing.T) {
	unit := systemd.LoaderUnit(systemd.LoaderParams{})
	// An empty/absent rules dir must be a clean no-op at boot (the `for` over a
	// possibly-empty glob), so boot never fails when no account is forced. It
	// defaults the glob when none is passed.
	if !strings.Contains(unit, systemd.DefaultRulesDir) {
		t.Errorf("loader unit should default the rules glob to the anonctl rules dir:\n%s", unit)
	}
	if !strings.Contains(unit, "for ") {
		t.Errorf("loader unit should iterate the glob so a missing/empty dir is a no-op:\n%s", unit)
	}
}
