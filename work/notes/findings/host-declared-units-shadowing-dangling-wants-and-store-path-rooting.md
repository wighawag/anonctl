---
title: two copies of a unit shadow silently, a dangling .wants symlink still creates the dependency, and a declared store path is GC-rooted
slug: host-declared-units-shadowing-dangling-wants-and-store-path-rooting
source: 'Direct measurement on telemaque (NixOS 26.05pre-git, kernel 6.18.49, systemd 260.2) 2026-09-24, while designing host-owned units (ADR-0012). All three measured read-only or in systemd USER scope with throwaway units under ~/.config/systemd/user and ~/.local/share/systemd/user, which were removed afterwards; no system unit, account or ruleset was touched. Commands and their exact output are reproduced below. Claim 3 additionally read a real system unit (sshd.service) and its `nix-store --query --references` output.'
---

Three pieces of ground truth the host-owned-units design rests on. Each was measured rather than reasoned from the manual, because all three are load-bearing in a direction where being wrong is silent: they decide whether anonctl's per-account enablement symlinks keep working when the host owns the unit FILES, whether a second definition of a unit announces itself, and whether a `/nix/store` path in a declared `ExecStart` is durable.

## 1. A `.wants` symlink resolves by unit NAME, so a DANGLING target still creates the dependency

This is what lets anonctl keep the per-account enablement symlinks in its own unit dir while the host owns the unit files. The symlink then points at `<anonctl unit dir>/anonctl-shim@.service`, a path that holds no file in that mode.

Measured in user scope, with `$HI` = `~/.config/systemd/user` (the higher-precedence dir, standing in for `/etc/systemd/system`) and `$LO` = `~/.local/share/systemd/user` (the lower one, standing in for `/usr/local/lib/systemd/system`). The template unit was placed ONLY in `$HI`; the `.wants` symlink was placed in `$LO` and pointed at a file in `$LO` that does not exist:

```
$ ls -l $LO/measure-hostown.target.wants/
lrwxrwxrwx  measure-tpl@inst.service -> /home/wighawag/.local/share/systemd/user/measure-tpl@.service   # target ABSENT

$ systemctl --user show measure-hostown.target -p Wants
Wants=measure-tpl@inst.service

$ systemctl --user show measure-tpl@inst.service -p LoadState -p FragmentPath -p UnitFileState
LoadState=loaded
FragmentPath=/home/wighawag/.config/systemd/user/measure-tpl@.service
UnitFileState=static

$ systemctl --user start measure-hostown.target
$ systemctl --user show measure-tpl@inst.service -p ActiveState --value
active
```

The dependency is real, the fragment is loaded from the OTHER directory, and starting the target starts the instance. The symlink's target is decoration; its NAME is the dependency.

(First attempt reported `failed` because the throwaway unit's `ExecStart=/bin/true` does not exist on NixOS -- `/bin` holds only `sh`. That is finding 2 of `nixos-account-conventions-break-anonctl-provisioning.md` reproducing itself in a test fixture, not a systemd behaviour.)

## 2. Two copies of one unit name shadow SILENTLY

```
$ printf '[Unit]\nDescription=LOWER copy\n...' > $LO/measure-tpl@.service   # now BOTH dirs have it
$ systemctl --user daemon-reload
$ systemctl --user show measure-tpl@inst.service -p FragmentPath -p Description
Description=measure tpl for inst
FragmentPath=/home/wighawag/.config/systemd/user/measure-tpl@.service
```

The higher-precedence copy wins; the Description confirms it is the `$HI` one. There is **no warning, no journal entry and no diagnostic of any kind** that a second definition exists. `daemon-reload` is silent about it.

This is why anonctl reports shadowing itself (`Store.ShadowedUnits`, printed by `add`/`update`) rather than trusting systemd to mention it, and why the pre-0.4 legacy sweep exists at all. It is also why that sweep must be SKIPPED once a host owns the units: `/etc/systemd/system` is both where pre-0.4 residue sits and where a declarative host puts what it declares, and the two are indistinguishable by path.

## 3. A `/nix/store` path in a DECLARED unit is rooted by the system closure

anonctl's own resolver must never bake a store path (`nixos-fhs` finding; ADR-0005), because nothing tracks that reference and the next garbage collection removes the file. A path a HOST declares is the opposite case, and the difference is mechanical: the unit text is itself a store file, and Nix computes a store path's references by scanning its contents.

Measured against a real system unit on this box:

```
$ readlink -f /etc/systemd/system/sshd.service
/nix/store/qh6aq6ajwxg3wvf7ghvsaj0z6lh5nqqm-unit-sshd.service/sshd.service

$ grep -o '^ExecStart=[^ ]*' /nix/store/qh6aq6...-unit-sshd.service/sshd.service
ExecStart=/nix/store/qilxjlbdj0rvrz8isfmnfb9cp91fbvv1-openssh-10.5p1/bin/sshd

$ nix-store --query --references /nix/store/qh6aq6...-unit-sshd.service/sshd.service | grep -c openssh
1
```

The unit's reference set contains the package its `ExecStart` names, so while the generation exists the binary cannot be collected, and a rollback moves both together. That is what makes a declared store path MORE coherent than the stable alias `/run/current-system/sw/bin/...`, which the next rebuild repoints under a unit nobody edited.

Consequence for `verify`: `volatileBakedPaths` must keep NOT flagging `/nix/store`. Flagging it would condemn the configuration `docs/nixos.md` section 8 recommends, exactly as flagging `/run/current-system/sw/bin` would. The list is for locations the SYSTEM empties (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`), which a store path is not.

## 4. Corroborating detail measured at the same time

- `systemctl show` REFUSES a bare template name: `systemctl show 'anonctl-shim@.service' -p FragmentPath` answers `Unit name anonctl-shim@.service is neither a valid invocation ID nor unit name`. An INSTANCE (`anonctl-shim@anon-01.service`) answers normally. So "is the template really there" cannot be asked of systemd directly, which is why anonctl resolves unit files by walking the search path itself.
- This host's system `UnitPath` (`systemctl show --property=UnitPath`) contains `/etc/systemd/system`, `/run/systemd/system`, `/usr/local/lib/systemd/system`, the systemd package's own `lib/systemd/system`, and `/usr/lib/systemd/system`. There is no NixOS-specific extra directory: `systemd.units` and `systemd.packages` both render into `/etc/systemd/system`, so the standard precedence list anonctl searches is complete on this distro.
- `systemd-analyze verify` accepts both units as emitted by `anonctl units print` (exit 0; the only diagnostic printed concerned an unrelated host unit, `cups.socket`).
