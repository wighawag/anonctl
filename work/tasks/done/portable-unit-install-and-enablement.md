---
title: Install units where they can be written, enable them without systemctl, and resolve the binaries they name
slug: portable-unit-install-and-enablement
spec: portable-unit-install-and-enablement
covers: [1, 2, 5, 6, 7, 8, 10, 11, 14]
blockedBy: []
---

## What was built

anonctl could not install itself on NixOS, and the two obvious partial fixes each left the operator with something that looked installed and was not. Three independent blockers, fixed together because fixing only the first produces the worst outcome of the three.

**1. The units moved to `/usr/local/lib/systemd/system`** (`systemd.DefaultUnitDir`). `/etc/systemd/system` is a read-only Nix store symlink on NixOS. The new dir is in the default unit load path on both Debian and NixOS, sits on the root filesystem so it survives reboot and `nixos-rebuild`, and is what systemd's own load-path table calls "System units installed by the administrator". `/run/systemd/system` was rejected despite being writable there: it is cleared at boot, so it would have made the forcing volatile. Nothing does a distro check. `ANONCTL_UNIT_DIR` (absolute paths only) is a safety valve.

**2. anonctl now writes its OWN enablement symlinks** instead of calling `systemctl enable` (`Store.EnableUnit` / `DisableUnit` / `IsUnitEnabled`). This is the change that actually unblocks NixOS and it is not obvious: `systemctl enable` writes its symlink into the scope's CONFIG dir (`/etc/systemd/system`) regardless of where the unit file lives, so moving the unit file does not move its enablement and the enable still fails on a read-only `/etc`. systemd honours `<target>.wants/` in every unit load-path dir, so anonctl creates the symlink itself. `add` became enable-then-`start`, `rm` became `stop`-then-unlink (`systemd.StartNow` / `StopNow` replaced `EnableNow` / `DisableNow` / `EnableLoader` / `DisableLoader`).

One mechanism runs on both distros, so every Debian test run exercises the NixOS path. Accepted cost: `systemctl is-enabled` now reports `disabled` for these units even though they start at boot, because it inspects only the config dir. Documented in the generated unit's own header, CONTEXT.md and ADR-0005.

**3. Every binary named in a generated unit is resolved at install time** (`systemd.Resolver`, `ResolveUnitParams`) and baked in absolute, and `TemplateUnit` / `LoaderUnit` now REFUSE to generate without a resolved path. `/usr/bin/setpriv` and `/usr/sbin/nft` do not exist on NixOS. The setpriv failure is fail-closed (the shim dies, the baseline still drops). The nft failure is **fail-OPEN and silent**: the loader is what installs the standing baseline default-deny at boot, so a loader that cannot run `nft` means the anon UID egresses freely with the host's real IP while the account and its marker look intact. That is the exact failure mode ADR-0005 exists to prevent, so it must surface at `add` time, not at the next boot.

**Migration** (`Store.MigrateLegacyUnits`) is mandatory, not tidiness: `/etc/systemd/system` OUTRANKS the new dir in the load path, so a leftover unit file shadows the new one and the host silently keeps running the old definition, which on an upgraded host is precisely the fail-open one. It ADOPTS each enablement symlink into the new unit dir before removing the legacy copy, sweeps anonctl's unit files, leaves foreign units alone, no-ops on a fresh install, refuses to sweep its own unit dir (resolving symlinks), and fails loud if it cannot remove a shadowing file.

**Two ordering rules are load-bearing, and both were found by review rather than by construction.** They are recorded here because both failures are invisible until a reboot:

- *Resolve before mutating.* Resolution originally ran after the account was created and the live rules applied. Aborting there left an account that EXISTS with no unit installed, so the next boot loaded neither the baseline nor the forcing and the anon UID egressed with the host's real IP. That is strictly WORSE than the pre-0.4 behaviour it replaced, where a missing shim still left an enabled loader and the account was merely dropped. Resolution now runs in `runAdd` before `provision.Add` (`systemd.PreflightUnitBinaries`) and again at the top of `forcing.Install` before any mutation.
- *Enable before migrating, and adopt rather than delete.* The legacy sweep matches every `anonctl-shim@*.service` link, but `add` re-creates only the account being added, so a delete-only sweep silently de-enabled every OTHER account on a multi-account host: shims keep running, nothing looks wrong, and they never start after the next reboot. And migrating before enabling could leave the loader enabled in neither location if interrupted.

**The shim's path is resolved from the real install location** (sibling of the running anonctl, then `$PATH`, then the conventional path if it exists), closing the second FHS assumption: the unit used to hard-code `/usr/local/bin/anonctl-shim` regardless of `$PREFIX`. `install.sh`'s compensating symlink was removed, and it now warns when `nft` or `setpriv` is absent.

## Acceptance criteria

- [x] `DefaultUnitDir` is a path writable on both Debian and NixOS, persistent across reboot, and in systemd's default search path (verified by reading `systemctl show --property=UnitPath` and systemd.unit(5) on a NixOS host).
- [x] Enablement no longer calls `systemctl enable`; a unit test asserts `Install` never issues one.
- [x] Enablement symlinks point at a target inside the unit dir (systemd ignores a target outside the search path) and use the instance-to-template mapping for the `@`-template.
- [x] Enable/disable are idempotent; disabling one account leaves another account enabled.
- [x] `TemplateUnit` / `LoaderUnit` return an error rather than emitting a unit naming an unresolved binary; a failed resolve leaves no half-written unit.
- [x] `Install` aborts loudly, naming the binary, when one cannot be resolved.
- [x] The upgrade path is exercised from a SEEDED legacy layout (multi-account), not only a fresh install, and asserts exactly one definition of each unit survives.
- [x] A multi-account upgrade keeps EVERY account enabled, not just the one being added (`TestMigrateAdoptsEveryAccountsEnablementNotJustOne`, `TestInstallOnUpgradeKeepsOtherAccountsEnabled`).
- [x] A failed binary resolve aborts before ANY host mutation: no config written, no nft applied, no unit left behind.
- [x] Both regression tests were shown to FAIL against the pre-fix behaviour, so they are not tautological.
- [x] `verify`'s anon-UID probe resolves the shim the same way the unit writer does, instead of pinning `/usr/local/bin/anonctl-shim`.
- [x] `ANONCTL_UNIT_DIR` refuses a relative value loudly and warns when given an absolute path outside systemd's known search dirs, instead of silently accepting a dir systemd never reads.
- [x] The migration leaves foreign units and foreign enablement symlinks untouched.
- [x] Tests never touch the real `DefaultUnitDir` or the real legacy dir: `Store.LegacyUnitDir` is a field, and the integration test asserts both point at scratch.
- [x] `gofmt` / `go vet` / `go build` / `go test ./...` green, and `go test -tags integration ./internal/systemd/` green (real `systemd-analyze verify` parses the generated units).
- [ ] **NOT DISCHARGED: a real NixOS host runs `add`, `rm`, `verify`, and the forcing survives an actual reboot.** See below.

## What is NOT discharged

**No part of the live acceptance has been run.** The session that built this had `no_new_privs` set, so `sudo` could not run: no root, no install, no reboot. The spec's acceptance explicitly demands proof by rebooting rather than by reasoning about unit paths, and that proof does not exist yet. What IS established is read-only measurement on a NixOS host plus a user-scope experiment (recorded in `work/notes/findings/systemd-enablement-target-and-nixos-fhs-gaps.md`), and a green unit + integration suite.

Also blocking a live run: `nft` is not on `PATH` on telemaque at all, so that host needs nftables available (e.g. `networking.nftables.enable`) before `anonctl add` can succeed. With this change that now fails loudly at `add` instead of silently at boot, which is the intended behaviour.

Remaining follow-up work is tracked in `work/tasks/ready/verify-boot-enablement-and-loader-health.md`.
