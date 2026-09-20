---
title: systemd writes enablement symlinks to /etc/systemd/system regardless of where the unit lives, and NixOS ships almost no FHS binaries
slug: systemd-enablement-target-and-nixos-fhs-gaps
source: 'Direct measurement on telemaque (NixOS 26.05pre-git, systemd 260.2) 2026-09-20. Read-only proof: `ls -ld /etc/systemd/system`, `readlink -f`, and a `touch` that returned EROFS. Unit search path from `systemctl show --property=UnitPath`. Enablement-target behaviour proven by a live user-scope experiment (unit placed in ~/.local/share/systemd/user, `systemctl --user enable` observed creating the symlink under ~/.config/systemd/user/default.target.wants/), and a second experiment placing a hand-made .wants symlink ONLY in the non-config search dir, then reading `systemctl --user show default.target --property=Wants` and `is-enabled`. Corroborated against systemd.unit(5) as shipped on the box (UNIT FILE LOAD PATH table; the ".wants/" paragraph; the "After running systemctl enable, a symlink /etc/systemd/system/multi-user.target.wants/foo.service ... will be created" example). FHS gaps measured by direct existence tests on /usr/bin/setpriv, /usr/sbin/nft, /bin/sh, /bin/bash, /usr/local/bin.'
---

Ground truth about **systemd's enablement mechanism** and **NixOS's filesystem layout**, gathered because anonctl could not install itself on NixOS. It corrects a downstream diagnosis which concluded the blocker was "purely WHERE the installer writes". It is not: there are three independent blockers, and the most dangerous one is fail-OPEN.

## 1. Enablement symlinks go to the CONFIG dir, never to the unit's own directory

`systemctl enable` does not create its symlink next to the unit file. It creates it in the **config directory for the scope**, which for system scope is `/etc/systemd/system`. Moving a unit file elsewhere does not move its enablement symlink.

Proven in user scope, where the same split exists (config dir `~/.config/systemd/user`, non-config search dir `~/.local/share/systemd/user`):

```
$ # unit file placed ONLY in ~/.local/share/systemd/user/anonctl-probe.service
$ systemctl --user enable anonctl-probe.service
Created symlink '/home/wighawag/.config/systemd/user/default.target.wants/anonctl-probe.service'
  → '/home/wighawag/.local/share/systemd/user/anonctl-probe.service'
```

The symlink landed in the **config** dir. systemd.unit(5) states the same for system scope: "After running `systemctl enable`, a symlink `/etc/systemd/system/multi-user.target.wants/foo.service` linking to the actual unit will be created."

**Consequence:** on NixOS, `systemctl enable` fails for ANY unit, wherever its file lives, because `/etc/systemd/system` is a read-only Nix store symlink:

```
$ readlink -f /etc/systemd/system
/nix/store/f59dwpjbqhcdn7612c7hzn0qx4pvz2zh-system-units
$ touch /etc/systemd/system/.probe
touch: cannot touch '/etc/systemd/system/.probe': Read-only file system
```

That directory also holds the 14 `*.wants/` dirs the enablement symlinks would have to be written into. So relocating a unit file to a writable directory is **necessary but not sufficient**: the enable step still fails.

## 2. A hand-made `.wants/` symlink in ANY search dir is honoured, but `is-enabled` cannot see it

systemd reads `<target>.wants/` directories from **every** directory in the unit load path, not only the config dir. A tool can therefore create its own enablement symlink in its own unit directory and get a real, boot-effective dependency without touching `/etc`.

Proven, with the symlink present ONLY in the non-config search dir and no config-dir symlink existing at all:

```
$ systemctl --user show default.target --property=Wants | tr ' ' '\n' | grep -c anonctl-probe
1                     # the dependency is REAL
$ systemctl --user is-enabled anonctl-probe.service
disabled              # but is-enabled does not see it
```

So the dependency is genuine and will pull the unit in at boot, while **`systemctl is-enabled` reports `disabled`**, because `is-enabled` inspects only the config dir. Any check that asks `is-enabled` whether forcing survives a reboot would return a false negative. The honest probe is `systemctl show <target> --property=Wants`, which reflects the loaded dependency graph.

systemd.unit(5) confirms the constraint on such a symlink: its **target** "must be in one of the unit search paths". `/usr/local/lib/systemd/system` is, on both distros.

## 3. `/usr/local/lib/systemd/system` is in the load path on NixOS and is the documented home for this case

From `systemctl show --property=UnitPath` on telemaque, and from the systemd.unit(5) load-path table, which labels it:

| Path | systemd's own description |
| --- | --- |
| `/etc/systemd/system` | "System units created by the administrator" |
| `/usr/local/lib/systemd/system` | **"System units installed by the administrator"** |
| `/usr/lib/systemd/system` | "System units installed by the distribution package manager" |

Two properties matter beyond its presence:

- **It ranks BELOW `/etc/systemd/system` in the load path.** A leftover unit file in `/etc` therefore **shadows** one in `/usr/local/lib`. Any migration that leaves the old copy behind silently keeps serving the old definition.
- **It does not exist yet on NixOS, and neither does `/usr/local` at all.** Root can create it: `/` is `rw` (`/dev/nvme0n1p3`), only `/nix/store` is `ro`. NixOS does not manage `/usr/local`, so it persists across reboots and across `nixos-rebuild`.

## 4. NixOS ships almost no FHS binaries, and two are baked into anonctl's generated units

Measured on telemaque:

```
/usr/bin/setpriv       MISSING
/usr/sbin/nft          MISSING
/usr/local/bin         MISSING
/bin/bash              MISSING
/bin/sh                EXISTS
/usr/bin/env           EXISTS
```

`/usr` contains exactly one entry (`bin`), and `/usr/bin` contains exactly one entry (`env`). `/bin` contains exactly one entry (`sh`). The real tools live in the store, reachable through `/run/current-system/sw/bin` (e.g. `setpriv` → `/nix/store/kql2l4…-util-linux-2.42.2-bin/bin/setpriv`).

This breaks two generated units, and the second failure is the dangerous one:

- **`anonctl-shim@.service`** has `ExecStart=/usr/bin/setpriv …`. On NixOS the shim cannot start (`203/EXEC`). This is fail-CLOSED: the baseline default-deny still drops the anon UID, so the account loses connectivity but does not leak.
- **`anonctl-nftables.service`** has `ExecStart=/bin/sh -c 'for f in …; do [ -e "$f" ] && /usr/sbin/nft -f "$f"; done'`. On NixOS `/usr/sbin/nft` does not exist, so the loop's `nft` invocation fails and **no rules are loaded at boot at all** — not the forcing table and, critically, **not the standing baseline default-deny**. Per ADR-0005 the boot invariant depends on that baseline being present: "an anon UID with no anonctl forcing loaded is DROPPED, not free". If the loader never runs, that inversion never happens and the anon UID egresses **freely, with the host's real IP**.

The second case is therefore **fail-OPEN at boot on NixOS**, and it is the precise failure mode ADR-0005 was written to close after the Debian `nftables.service` incident. It is also silent: the account exists, its config and marker are intact, and only the failed loader unit records anything.

Note the Go code is NOT affected by this: `nft`, `systemctl` and `getent` are invoked by bare name through `$PATH`, and `use_exec.go` already resolves `setpriv` with `exec.LookPath`. The hard-coded absolute paths exist only in the **generated unit text**, where they are in fact required (a unit has no useful inherited `$PATH`, so `ExecStart` must be absolute). The fix is therefore to RESOLVE the path at install time and bake the resolved absolute path into the unit, not to drop to a bare name.

## 5. Smaller FHS assumptions in the `use` session

`use_exec.go` hands the dropped session a fixed `PATH=/usr/local/bin:/usr/bin:/bin`. On NixOS those three directories contain, in total, `env` and `sh`. The session is technically created but has essentially no usable command set. Separately, the `getent`-fallback shell is `/bin/bash`, which does not exist on NixOS. Neither is a security hole (both fail closed), but both make the account unusable rather than unsafe.
