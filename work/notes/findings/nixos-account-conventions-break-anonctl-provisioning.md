---
title: NixOS deletes undeclared accounts at activation and creates no user-private group, so anonctl's account model does not hold there
slug: nixos-account-conventions-break-anonctl-provisioning
source: 'Direct measurement on telemaque (NixOS 26.05pre-git) 2026-09-21, during the live acceptance run for the portable-unit-install work. Account deletion observed by rebooting with a real forced account present and then reading `getent passwd`, `getent passwd <uid>`, `ls -ld /home/<account>`, `ps -o uid,user` on the running shim, and the boot journal (`NixOS Activation` timestamp vs the anonctl loader timestamp). The mutableUsers setting read from ~/dev/github/wighawag/my-boxes/hosts/telemaque (users.mutableUsers = false, with an in-file rationale dated 2026-09-15). The group and shell conventions read from /etc/default/useradd (GROUP=100), /etc/shells, and existence tests on /bin/bash, /usr/sbin/nologin, /sbin/nologin, /bin/false. The chown failure is the verbatim error from `anonctl add` on that host. anoncore call sites read from provision/provision.go @ v0.1.0 (lines 298, 323, 383).'
---

Three NixOS account-management behaviours that anonctl (and its `anoncore` dependency) currently assume away. The first is the serious one: it is not a provisioning inconvenience, it is a **fail-open hazard with a UID-reuse edge**, and it cannot be fixed inside anonctl.

## 1. `users.mutableUsers = false` deletes anonctl's accounts at every activation

NixOS's `update-users-groups.pl` treats the Nix configuration as the authoritative user database. With `users.mutableUsers = false`, any account NOT declared in the configuration is **removed on every activation**, which means every boot and every `nixos-rebuild switch`.

anonctl creates its accounts out of band (`useradd` via `anoncore/provision`), so they are by definition undeclared. Observed on telemaque after a reboot with a forced account in place:

```
getent passwd anon-livetest        -> rc=2 (gone)
getent passwd anon-livetest-shim   -> rc=2 (gone)
getent passwd 1002 992             -> nothing: both UIDs now UNALLOCATED
ls -ld /home/anon-livetest         -> drwx------ 2 1002 users   (orphaned to a bare uid)
ps -o pid,uid,user  <shim pid>     -> 2669  992  992            (running as a uid with no passwd entry)
```

The boot ordering makes the shape of it plain:

```
13:29:41  NixOS Activation ...              <- deletes both accounts
13:29:42  anonctl-nftables.service Finished <- faithfully restores forcing for uid 1002 / 992
```

anonctl did its job correctly and restored the jail for accounts that had been deleted one second earlier.

**Why this is a hazard, not just breakage.** The surviving artifacts (the nft tables, the shim unit, the home directory, `/etc/anonctl/accounts/<account>.json`) all reference UIDs that are now free for reallocation.

- **UID reuse jails a stranger.** The next account NixOS creates can be handed uid 1002 and will silently inherit anonctl's forcing: every TCP connection redirected into a shim it knows nothing about, and its resting state a default-deny it cannot see. Nothing warns anyone.
- **Recreation unjails the real account.** Recreate the anon account and it may receive a DIFFERENT uid. The old rules then match nobody, the new account is completely unforced, and `/etc/anonctl` still records it as jailed. That is the exact "the account still exists and still looks anonymised" failure the whole project exists to prevent, arrived at from a direction nothing in the design anticipated.
- **`anonctl rm` cannot clean it up**, because the account it wants to tear down no longer exists, so the orphaned tables outlive the teardown.

**This cannot be fixed inside anonctl.** Either the accounts are declared in the Nix configuration (which splits ownership of the UID allocation and the shim account, the very things the per-account security boundary rests on), or the host sets `users.mutableUsers = true`. What anonctl CAN and SHOULD do is DETECT it: `verify` currently probes by stored UID and never checks that the account still exists or still owns that UID, so on such a host it reports a confusing scatter of leak assertions instead of the one true finding, "your account is gone".

Note the downstream assumption this overturns. The original NixOS diagnosis in my-boxes reasoned that anonctl's model "fits `users.mutableUsers = true`, which is what lets `anonctl add` create accounts out of band in the first place". telemaque sets it to `false`, deliberately and with a recorded rationale, so on that box the out-of-band model does not hold at all.

## 2. `useradd` creates no user-private group (`GROUP=100`)

`/etc/default/useradd` on NixOS carries `GROUP=100`, so a new account lands in the shared `users` group and no group named after the account is ever created:

```
anon-livetest:x:1002:100::/home/anon-livetest:/bin/bash
uid=1002(anon-livetest) gid=100(users) groups=100(users)
getent group anon-livetest -> nothing
```

`anoncore/provision/provision.go:383` runs `chown <account>:<account>`, which assumes the Debian/Ubuntu `USERGROUPS_ENAB yes` convention. On NixOS this is a hard failure that aborts `anonctl add` midway, leaving a half-provisioned account (login account created, shim account not, no forcing installed):

```
anonctl: add: write login env for "anon-livetest": chown "/home/anon-livetest/.profile"
  to anon-livetest: exit status 1: chown: invalid group: 'anon-livetest:anon-livetest'
```

The portable form is a TRAILING COLON, `chown <account>: <path>`, which coreutils defines as "that user is made the owner and the group is changed to that user's login group" -- the per-user group on Debian, `users` on NixOS, with no branching.

## 3. The hard-coded login shells do not exist

`anoncore` creates the login account with `--shell /bin/bash` (provision.go:298) and the shim account with `--shell /usr/sbin/nologin` (provision.go:323). Measured on telemaque:

```
/bin/bash          MISSING        /usr/sbin/nologin  MISSING
/sbin/nologin      MISSING        /bin/false         MISSING
/bin/sh            EXISTS (it is bash)
```

`useradd` warns and proceeds, so the account is created with a login shell that is not there. The real binaries are `/run/current-system/sw/bin/{bash,nologin}`.

`/etc/shells` lists the STABLE alias (`/run/current-system/sw/bin/bash`) while `type bash` in an interactive shell resolves to `/nix/store/<hash>-bash-interactive-5.3p9/bin/bash`. Persisting the latter into the passwd shell field would be the same garbage-collection time bomb documented for unit `ExecStart` paths in `systemd-enablement-target-and-nixos-fhs-gaps.md`: correct until the next update, then pointing at a collected store path. Resolve with `exec.LookPath` and use the result verbatim.
