---
title: verify must prove boot enablement and loader health, and never ask systemctl is-enabled
slug: verify-boot-enablement-and-loader-health
spec: portable-unit-install-and-enablement
covers: [3, 9, 12]
blockedBy: []
---

## What to build

`anonctl verify` is the trust anchor: it must never report green unless it actually proved green. Two gaps remain after `portable-unit-install-and-enablement` landed, and both are about the BOOT path rather than the live path.

**1. `verify` does not currently assert that the forcing will survive a reboot at all.** It proves the live state (rules applied, shim up, no leak) and the integration suite proves a reboot-EQUIVALENT early-boot simulation, but the running `anonctl verify` on a real host does not check that the units are actually wired to start. An account whose enablement symlink is missing verifies GREEN today and is unforced after the next reboot. That is the "account still exists and looks anonymised" failure the whole design is built to prevent.

**2. A broken loader is fail-OPEN and currently invisible.** `anonctl-nftables.service` is what installs the standing baseline default-deny at boot. If it is in a `failed` state, the next boot has no baseline, and the anon UID egresses freely with the host's real IP. `verify` should catch that while the operator is still looking.

Add assertions that prove, on the live host:

- the shim instance's enablement symlink exists and resolves to the installed template unit (`Store.IsUnitEnabled`);
- the loader's enablement symlink likewise;
- systemd genuinely carries the dependency, not just the symlink on disk: `systemctl show <target> --property=Wants` lists the unit;
- `anonctl-nftables.service` is not in a `failed` state;
- no shadowing copy of either unit exists in `systemd.LegacyUnitDir`.

**Do NOT use `systemctl is-enabled`.** It inspects only the scope's config dir (`/etc/systemd/system`), so it reports `disabled` for anonctl's self-managed symlinks even when they are genuinely wired to boot. Asking it would produce a FALSE NEGATIVE, which in a tool whose verifier is the trust anchor is the same class of bug as `fix-verify-counter-false-green` in `tasks/done/`. The evidence for the `is-enabled` behaviour is in `work/notes/findings/systemd-enablement-target-and-nixos-fhs-gaps.md` §2.

Also surface the true enablement state in `anonctl status`, so an operator reading a host by hand is not misled by `is-enabled` saying `disabled`.

New assertion names must be added to the ADR-0003 JSON contract (`docs/adr/0003-verify-assertion-names-and-json-contract.md`), since that file pins the machine-readable output.

## Acceptance criteria

- [ ] `verify` fails when the shim instance's enablement symlink is absent, even though every live check passes.
- [ ] `verify` fails when a shadowing unit file is present in the legacy unit dir.
- [ ] `verify` fails when `anonctl-nftables.service` is in a `failed` state.
- [ ] No assertion calls `systemctl is-enabled`; a test pins this, with the reason in a comment.
- [ ] The dependency check reads systemd's actual loaded graph (`--property=Wants`), not only the on-disk symlink, so a symlink present but not reloaded is still caught.
- [ ] A missing/unrunnable probe is a LOUD failing assertion naming what it needed, never a silent pass (the existing verify discipline).
- [ ] New assertion names are recorded in ADR-0003.
- [ ] Tests isolate every path they inspect (scratch `Store` dirs) and assert the real `DefaultUnitDir` / `LegacyUnitDir` are untouched.
- [ ] `gofmt` / `go vet` / `go build` / `go test ./...` green.

## Blocked by

Nothing. `portable-unit-install-and-enablement` has landed and provides `Store.IsUnitEnabled`, `ShimWantedBy` / `LoaderWantedBy` and `LegacyUnitDir`.

## Prompt

`anonctl verify` is the tool's trust anchor: it must never report green unless it proved green. After the portable-unit-install work, enablement is no longer done by `systemctl enable`; anonctl writes its own `.wants/` symlinks into its unit dir (`internal/systemd`, `Store.EnableUnit`). Two boot-path gaps remain.

First, `verify` does not assert that an account's forcing will survive a reboot. An account with a missing enablement symlink verifies green today and is unforced after the next boot.

Second, `anonctl-nftables.service` failing is fail-OPEN: it is what loads the standing baseline default-deny at boot, so if it is in a `failed` state the anon UID has free, un-anonymized egress after a reboot, silently.

Add live assertions covering: the shim instance and loader enablement symlinks resolve to the installed units (`Store.IsUnitEnabled`); systemd's loaded graph really carries the dependency (`systemctl show <target> --property=Wants`); the loader unit is not `failed`; and no shadowing copy of either unit survives in `systemd.LegacyUnitDir`. Surface the true enablement state in `anonctl status` too.

CRITICAL: do NOT use `systemctl is-enabled`. It only inspects `/etc/systemd/system`, so it reports `disabled` for anonctl's self-managed symlinks even when they genuinely start at boot; using it would be a false negative in the verifier itself. See `work/notes/findings/systemd-enablement-target-and-nixos-fhs-gaps.md` §2 for the measured behaviour, and ADR-0005's "Portable unit install and enablement" amendment for why enablement works this way.

Record the new assertion names in `docs/adr/0003-verify-assertion-names-and-json-contract.md`. Keep every test isolated to scratch dirs and assert the real unit dirs are untouched. Repo verify: `gofmt -l .`, `go vet ./...`, `go build ./...`, `go test ./...`. Note that two pre-existing `TestPkexecVector_*` failures are environmental (`pkcheck` absent on NixOS) and are not yours.
