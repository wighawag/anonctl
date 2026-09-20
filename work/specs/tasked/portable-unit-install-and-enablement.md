---
title: Portable unit install and enablement (anonctl must install itself on NixOS without going fail-open)
slug: portable-unit-install-and-enablement
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks.

## Problem Statement

`anonctl add` cannot install anything on NixOS, and the two obvious partial fixes both leave the operator worse off than they look.

An operator on a NixOS host runs `anonctl add work` and it fails: anonctl writes `anonctl-shim@.service` and `anonctl-nftables.service` into `/etc/systemd/system`, which on NixOS is a symlink into the read-only Nix store. `add`, `rm` and `verify` are all unusable. There is no flag or environment variable to point the install elsewhere; `Store.UnitDir` exists but only the integration tests set it.

Two further failures sit behind that one, and neither is visible until the first is fixed (verified in `work/notes/findings/systemd-enablement-target-and-nixos-fhs-gaps.md`):

1. **Relocating the unit files is not enough to enable them.** `systemctl enable` writes its symlink into the config dir (`/etc/systemd/system`) regardless of where the unit file lives. On NixOS that write fails too, so `add` would still not produce a unit that starts at boot.

2. **The generated units name binaries that do not exist on NixOS, and one of those failures is fail-OPEN.** `anonctl-shim@.service` runs `/usr/bin/setpriv` (missing: the shim fails to start, which is fail-closed and merely breaks the account). `anonctl-nftables.service` runs `/usr/sbin/nft` (missing: **no rules load at boot at all**). Because the loader is what installs the standing baseline default-deny, its failure means the inversion ADR-0005 relies on never happens, and the anon UID egresses freely with the host's real IP after every reboot. The account still exists, its config and marker are intact, and nothing warns the operator. That is exactly the silent post-reboot leak ADR-0005 was written to close.

The operator-facing shape of the problem is therefore: **on NixOS anonctl either refuses to install, or — if only the directory is fixed — installs something that looks forced and is not.**

Two smaller FHS assumptions ride along: the shim unit's `ExecStart` hard-codes `/usr/local/bin/anonctl-shim` regardless of `PREFIX` (install.sh admits this in its own comments), and the `use` session hands the account `PATH=/usr/local/bin:/usr/bin:/bin`, which on NixOS contains exactly two commands.

## Solution

anonctl installs its units into a directory that is writable and boot-persistent on both distros, owns its own enablement rather than delegating to a write that may be impossible, and never emits a unit naming a binary it has not resolved.

From the operator's perspective: `anonctl add`, `rm` and `verify` work identically on Debian and NixOS; `verify` passes only when the jail is genuinely installed and fail-closed; an upgrade from an existing install moves itself with no second copy of any unit left behind; and if anonctl cannot resolve a binary it needs, `add` fails loudly at install time rather than at the next boot.

Four changes:

1. **Units move to `/usr/local/lib/systemd/system`.** systemd's own load-path table calls it "System units installed by the administrator", which is exactly what anonctl is, and it is in the default search path on both distros. It is on the root filesystem, so it persists across reboot and across `nixos-rebuild`. `/run/systemd/system` is rejected outright: it is cleared at boot, and volatile forcing is a regression even when every test passes. An operator override (`--unit-dir` / `ANONCTL_UNIT_DIR`) is added on top, but the default is chosen so that nobody needs it.

2. **anonctl creates its own enablement symlinks** in its own unit directory (`<unitdir>/multi-user.target.wants/anonctl-shim@<account>.service` and `<unitdir>/sysinit.target.wants/anonctl-nftables.service`), instead of calling `systemctl enable`. This is a documented systemd mechanism, not a trick: `.wants/` directories are read from every directory in the load path. `--now` behaviour becomes an explicit `systemctl start`, and disable becomes symlink removal plus `systemctl stop`.

3. **Every binary named in a generated unit is resolved at install time and baked in absolute**, with a loud failure if it cannot be found. This closes the fail-open loader. The shim binary is resolved from anonctl's actual install location rather than assumed to be at `/usr/local/bin`.

4. **Migration is mandatory, not best-effort**, because `/etc/systemd/system` outranks the new directory in the load path: a leftover old unit file would shadow the new one, and the operator would keep running the old definition while believing they had upgraded.

## User Stories

1. As a NixOS operator, I want `anonctl add <name>` to complete successfully, so that I can create a forced account on a host whose `/etc/systemd/system` is read-only.
2. As a NixOS operator, I want `anonctl rm <name>` to tear an account down completely, so that no unit, rule file or enablement symlink is left behind.
3. As a NixOS operator, I want `anonctl verify <name>` to pass, so that I know the jail is genuinely installed and fail-closed rather than merely present on disk.
4. As any operator, I want the forcing to still be in place after a reboot, so that an account cannot quietly stop being jailed while still existing and looking anonymised.
5. As a Debian operator on an existing install, I want an upgrade to move my units to the new location and delete the old ones, so that two definitions of the same unit never coexist and shadow each other.
6. As a Debian operator on an existing install, I want my three currently-forced accounts to stay forced across that upgrade, so that the migration is not a window of un-anonymized egress.
7. As an operator, I want `anonctl add` to fail loudly and immediately if it cannot resolve `nft` or `setpriv`, so that I never get a unit that silently fails at the next boot.
8. As a NixOS operator, I want the nftables loader to actually load the baseline default-deny at boot, so that the anon UID's resting state is DROP rather than free egress.
9. As an operator, I want `anonctl verify` to detect that the boot-time loader is broken or not wired in, so that a fail-open boot path is reported rather than passing green.
10. As an operator who installed with a custom `PREFIX`, I want the shim unit to point at where the shim binary actually is, so that the unit works without my editing it by hand.
11. As an operator, I want an explicit `--unit-dir` / `ANONCTL_UNIT_DIR` override, so that a host with an unusual layout is not stuck with a default that does not fit.
12. As an operator, I want `anonctl status` to report the true enablement state, so that I am not misled by `systemctl is-enabled` reporting `disabled` for a unit that is genuinely wired to start at boot.
13. As a NixOS operator, I want a `use` session to have a usable `PATH`, so that the account is actually workable and not just safely jailed.
14. As a maintainer, I want the same enablement code path to run on both distros, so that the NixOS path is exercised by every Debian test run rather than being the untested branch of a security tool.

### Autonomy notes

- **`humanOnly`:** not set. Tasking this is ordinary work.
- **`needsAnswers`:** raised and **RESOLVED at launch**. The open question was whether to use one enablement mechanism or two (self-managed `.wants` symlinks everywhere, versus `systemctl enable` where the config dir is writable and symlinks only where it is not). It was flagged because it changes operator-visible state on a live box: `systemctl is-enabled` reports `disabled` for a self-managed symlink even though the unit genuinely starts at boot. **Decision: ONE mechanism, self-managed symlinks on both distros**, on the grounds that a fail-closed forcing tool must not have a boot-persistence path that is only ever exercised on one distro. The `is-enabled` cost is accepted and documented (in the generated unit's own header, in CONTEXT.md, and in ADR-0005); `Store.IsUnitEnabled` and `systemctl show <target> --property=Wants` are the truthful checks.

## Implementation Decisions

- **`DefaultUnitDir` becomes `/usr/local/lib/systemd/system`.** One constant changes; no distro detection anywhere. `Store.UnitDir` stays the seam, now reachable from the CLI.
- **The enablement symlink's target must itself be in a unit search path** (systemd.unit(5)), which the new unit dir is. For the template, the symlink is named with the INSTANCE and points at the TEMPLATE file, matching what `systemctl enable` would have produced.
- **`TemplateParams` gains resolved `SetprivPath`; `LoaderParams` gains resolved `NftPath`.** Resolution is `exec.LookPath` at install time, and an unresolvable binary is a hard error from `add`. The generated unit keeps absolute paths (a unit has no useful inherited `$PATH`), so the fix is to resolve-then-bake, never to emit a bare name. `/bin/sh` is retained: it exists on both distros.
- **Shim binary resolution order:** explicit flag/env > sibling of the running anonctl executable (`os.Executable`) > `exec.LookPath` > `DefaultShimBinaryPath`. The sibling rule is what makes a custom `PREFIX` work without the operator editing the unit.
- **Migration runs at install time, ordered so the account is never un-forced.** The nft rules stay applied throughout (fail-closed), so a brief unit-file gap cannot leak: write the new units → `daemon-reload` → create the new `.wants` symlinks → remove the OLD enablement symlinks and the OLD unit files from `/etc/systemd/system` → `daemon-reload` → ensure each instance is running. Deliberately **not** `disable --now` (that would stop a running shim for no reason). If old units exist but `/etc/systemd/system` is not writable, fail loudly: that combination means a host changed underneath the install and silently leaving a shadowing copy is the one unacceptable outcome.
- **`verify` must not ask `systemctl is-enabled`.** It reports `disabled` for a self-managed symlink (finding §2) and would be a false negative. The honest assertions are: the `.wants` symlink exists and resolves to the installed unit; `systemctl show <target> --property=Wants` actually lists the unit; and the loader unit is not in a `failed` state. New assertion names go into the ADR-0003 JSON contract.
- **ADR-0005 needs an amendment**, since it records `add` running `enable --now` and `rm` running `disable --now`. The boot invariant itself is unchanged; the mechanism that wires it up is what moves.

## Testing Decisions

- The pure generators (`TemplateUnit`, `LoaderUnit`) are already unit-tested with no privilege; extend them to assert the resolved paths are baked in and that an unresolvable binary is an error rather than a unit containing a missing path.
- Symlink creation/removal is a `Store` concern and should be tested against a scratch dir, per the existing discipline that tests must never touch the real `DefaultUnitDir` (the integration test already asserts this and must keep doing so with the new default).
- **The migration path must be tested from a seeded OLD layout**, not only a fresh install: seed unit files in a scratch "`/etc/systemd/system`", run install, assert the new location has the units, the old location has none, and exactly one definition of each unit exists.
- A shadowing regression test is worth its own case: assert that after migration no file named `anonctl-shim@.service` or `anonctl-nftables.service` remains in the old dir, since the load-path ordering makes a leftover silently authoritative.
- The reboot claim cannot be discharged by unit tests. Per ADR-0005 the integration suite proves it by an early-boot simulation (load the persisted rules with the shim down, assert the anon UID is DROPPED); that remains the automated gate, and a real-host reboot remains the final human gate.

## Out of Scope

- **A Nix flake with a `nixosModule`.** Worth doing so Nix users get a packaged anonctl, but it does not fix the CLI for anyone not using that module, and this spec's whole point is that the CLI must work unaided. Capture separately in `work/notes/ideas/`.
- **An "externally managed units" mode** where the host declares the units and anonctl only instantiates them. This is genuinely the correct shape for NixOS's model and is the right long-term direction, but it is a much bigger change and it splits ownership of the forcing between the host and the tool. It is not needed to unblock NixOS, and doing it under time pressure would be the wrong way to make that split.
- **Rewriting the `use` session's `PATH` properly** (story 13) if it turns out to need endpoint/profile design; the minimal fix (derive from the account's shell profile, or append `/run/current-system/sw/bin` when present) belongs here, anything larger does not.

## Further Notes

- The downstream diagnosis that triggered this concluded "the blocker is purely WHERE the installer writes". That is measurably not the case, and acting on it alone would have produced the worst available outcome: a NixOS install that succeeds, reports nothing wrong, and leaks the host's real IP on every boot. The three-blocker breakdown and its evidence are in `work/notes/findings/systemd-enablement-target-and-nixos-fhs-gaps.md`.
- `nft` is not currently on `PATH` on telemaque at all, so that host needs nftables available (e.g. `networking.nftables.enable`) before any of this can be end-to-end verified. This is a host prerequisite, not an anonctl bug, but it will be the first thing that stops a test run.
- Acceptance requires root and a reboot on both a NixOS host and the Debian box. Neither was available from the session that wrote this spec (`no_new_privs` was set, so `sudo` could not run), so **no part of the acceptance has been discharged yet** — the measurements here are read-only observations plus a user-scope experiment, not a proven install.
