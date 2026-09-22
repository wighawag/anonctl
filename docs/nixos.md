# anonctl on NixOS

This is the operator's guide for running anonctl on NixOS, and specifically on a NixOS host with `users.mutableUsers = false`. It stands alone: you should not need to read anything else to get a working, verified account on this distro.

Read section 1 before you run anything. On this distro the default configuration silently destroys anonctl's security model, and the failure mode is fail-OPEN.

## Contents

- [1. Read this first: `users.mutableUsers = false` deletes anonctl's accounts](#1-read-this-first-usersmutableusers--false-deletes-anonctls-accounts)
- [2. The supported path: declare both accounts, then let `add` adopt them](#2-the-supported-path-declare-both-accounts-then-let-add-adopt-them)
- [3. The alternative (`users.mutableUsers = true`) and what it actually costs](#3-the-alternative-usersmutableusers--true-and-what-it-actually-costs)
- [4. Choosing an account NAME is a privacy decision](#4-choosing-an-account-name-is-a-privacy-decision)
- [5. NixOS-specific operational gotchas](#5-nixos-specific-operational-gotchas)
- [6. nsncd resolves your account's names for it, and `add` refuses until you deal with it](#6-nsncd-resolves-your-accounts-names-for-it-and-add-refuses-until-you-deal-with-it)
- [7. Verify it actually worked on this host](#7-verify-it-actually-worked-on-this-host)

## 1. Read this first: `users.mutableUsers = false` deletes anonctl's accounts

NixOS's `update-users-groups.pl` treats your Nix configuration as the authoritative user database. With `users.mutableUsers = false`, any account that is NOT declared in the configuration is **removed on every activation**, which means every `nixos-rebuild switch` and **every boot**.

anonctl creates its two accounts out of band, with `useradd` (via `anoncore/provision`). They are therefore **undeclared by construction**, and NixOS deletes them. This is not a provisioning inconvenience you can work around by re-running `anonctl add`; it is a fail-open hazard with a UID-reuse edge, and it cannot be fixed inside anonctl.

Measured on a real host (NixOS 26.05pre-git) after a single reboot with a forced, verified account in place:

```
getent passwd anon-livetest        -> rc=2 (gone)
getent passwd anon-livetest-shim   -> rc=2 (gone)
getent passwd 1002 992             -> nothing: both UIDs now UNALLOCATED
ls -ld /home/anon-livetest         -> drwx------ 2 1002 users   (orphaned to a bare uid)
ps -o pid,uid,user  <shim pid>     -> 2669  992  992            (running as a uid with no passwd entry)
```

The boot ordering from the same journal makes the shape of it plain:

```
13:29:41  NixOS Activation ...              <- deletes both accounts
13:29:42  anonctl-nftables.service Finished <- faithfully restores forcing for uid 1002 / 992
```

anonctl did its job correctly and restored the jail one second after the accounts it was jailing had been deleted.

### Why this is a hazard, not just breakage

Everything anonctl installed survives the deletion: the nft tables, the shim unit, the home directory, and `/etc/anonctl/accounts/<account>.json`. All of it references UIDs that are now free.

- **UID reuse jails a stranger.** anonctl's accounts were never declared, so they are not in `/var/lib/nixos/uid-map` (NixOS records and re-uses uids only for accounts it declared). Their uids are ordinary free space, so a later activation can hand uid 1002 to an unrelated account, which then silently inherits anonctl's forcing: every TCP connection redirected into a shim it knows nothing about, and its resting state a default-deny it cannot see. Nothing warns anyone.
- **Recreation unjails the real account.** Re-create the anon account and it may receive a DIFFERENT uid. The old rules then match nobody, the new account is completely unforced, and `/etc/anonctl` still records it as jailed. That is the exact "the account still exists and still looks anonymised" failure anonctl exists to prevent, arrived at from a direction nothing in the design anticipated.
- **`anonctl rm` cannot clean it up**, because the account it wants to tear down no longer exists, so the orphaned tables outlive the teardown.

`anonctl verify` detects the condition explicitly: its first assertion, `account-identity`, checks that both accounts still exist and still own the uids anonctl recorded, and reports that alone when they do not (see [section 7](#7-verify-it-actually-worked-on-this-host)).

You have two ways out, and they are not equivalent. [Declare the accounts](#2-the-supported-path-declare-both-accounts-then-let-add-adopt-them) is the supported one. [Setting `users.mutableUsers = true`](#3-the-alternative-usersmutableusers--true-and-what-it-actually-costs) has a real and non-obvious cost elsewhere on the box.

## 2. The supported path: declare both accounts, then let `add` adopt them

Declare **both** the login account and its `-shim` service account in your NixOS configuration, with **pinned uids**, rebuild, and only then run `anonctl add`.

`anonctl add` **adopts** accounts that already exist: it gates on whether anonctl already has a RECORD for the account (`/etc/anonctl/accounts/<account>.json`), not on whether a passwd entry exists, so accounts NixOS created are not mistaken for an account anonctl already set up. On the adoption path it creates nothing, leaves the home exactly as your configuration made it, writes no login environment into it, reads both uids off the box (never assumes them: your configuration chose them) and installs the forcing, the shim unit and the nft tables against those uids. A SECOND `anonctl add` on the same account is then refused, because by that point anonctl does have a record for it; change its endpoint with `anonctl update`, or run `anonctl rm <account>` (a bare `rm` leaves the accounts and homes intact) and `add` again to re-install the forcing.

The order is load-bearing, for a reason that is easy to get wrong: NixOS **will not change the uid of an account that already exists**. If `anonctl add` creates the account first and you declare a different uid afterwards, activation keeps the existing uid and prints only `warning: not applying UID change of user 'anon-a' (1002 -> 1500)`, which scrolls past in a rebuild log. So:

1. Choose the account name. **Read [section 4](#4-choosing-an-account-name-is-a-privacy-decision) first**: the name is permanent, world-readable, and no secret-management tool can hide it afterwards.
2. Add the declarations below to your configuration.
3. `sudo nixos-rebuild switch`.
4. `sudo anonctl add anon-a`.

If the accounts already exist because you ran `anonctl add` before declaring them, either pin the uids they already have (`getent passwd anon-a anon-a-shim`) or delete the accounts (`sudo anonctl rm --purge-account anon-a`) and start from step 2.

### The declarations

```nix
{ pkgs, ... }:

{
  users.mutableUsers = false;

  # A dedicated group per account. NixOS's useradd sets GROUP=100, so an account
  # anonctl creates out of band lands in the shared `users` group with no group of
  # its own (see section 5). Declaring the accounts is also how you get that group
  # back, which keeps the anon account out of `users` alongside your real one.
  users.groups."anon-a" = { };
  users.groups."anon-a-shim" = { };

  # The LOGIN account: the one whose egress anonctl forces, and the one you enter.
  users.users."anon-a" = {
    isNormalUser = true;
    # PINNED. This is the security-load-bearing line: anonctl's nft rules match
    # `meta skuid <uid>`, so an unpinned uid can drift and leave the rules
    # governing a uid that is no longer this account's. NixOS requires >= 1000 for
    # isNormalUser, and auto-allocates normal uids upward from 1000, so pick high.
    uid = 8801;
    group = "anon-a";
    home = "/home/anon-a";
    createHome = true;
    homeMode = "700";
    # Renders to /run/current-system/sw/bin/bash, the STABLE alias, never a
    # garbage-collectable /nix/store path (see section 5).
    shell = pkgs.bashInteractive;
    # No password. You enter the account with `anonctl use` or `sudo -iu anon-a`,
    # both of which change uid without one. A password would be one more thing to
    # manage and would not make the account more private.
    hashedPassword = null;
  };

  # The SHIM service account: the dedicated uid the per-account SOCKS relay runs
  # as, and the ONLY uid permitted to dial the upstream endpoint. It never logs in.
  users.users."anon-a-shim" = {
    isSystemUser = true;
    # PINNED, inside NixOS's system range (400-999). NixOS auto-allocates system
    # uids DOWNWARD from 999, so pick low to stay clear of that. Declared uids are
    # excluded from auto-allocation, so this can never be handed to anything else.
    uid = 412;
    group = "anon-a-shim";
    home = "/var/empty";
    createHome = false;
    # Renders to /run/current-system/sw/bin/nologin. NixOS has no /usr/sbin/nologin.
    shell = pkgs.shadow;
  };
}
```

`users.enforceIdUniqueness` is on by default, so a uid you pick that collides with another declared account fails the **build**, not the boot. `anonctl add` checks the same thing from its side before adopting (it resolves each uid back through NSS and scans the passwd table, and refuses naming the other account), because a shared uid would put that account behind anonctl's forcing too: `meta skuid` matches a uid, not a name. One residual worth knowing on a **directory-joined** host (LDAP/SSSD/AD, or `nss-systemd`): a backend configured with `enumerate = false` answers `getent passwd` with the local files only, so anonctl's reverse lookup is the only half of that check that reaches the directory, and it sees only the first match for a uid. If your uids come from a directory, pin anon uids in a range the directory does not allocate from.

The gids are deliberately left unpinned: nftables matches on `meta skuid` only, so the uid is the thing that must not move. Pin them too if you want fully reproducible group ownership of the home directory.

### Declare BOTH accounts, not just the login account

Declaring only `anon-a` does not work, and `anonctl add` will tell you so rather than paper over it: it refuses a half-declared pair, naming both accounts, and touches nothing.

```
anonctl: add: anon-a already exists but anon-a-shim does not, and anonctl has no record of anon-a: it will not
adopt half a pair ...
```

The refusal is deliberate, and it is the one place anonctl declines to be helpful. Creating the missing shim itself (with `useradd --system`, which is what it does on a host where out-of-band creation is fine) would produce an **undeclared** account on this distro, so the next activation deletes it, and every boot leaves you with exactly the half-provisioned residue `provision.go:145` describes: a login account that exists, no shim, and forcing that names a uid nothing runs as. The account is fail-CLOSED in that state (the baseline default-deny still drops it, so it does not leak) but it is unusable, and it is unusable again after every single rebuild. A missing half on this host means your configuration is wrong, so that is where it has to be fixed.

If you hit the refusal with a leftover half that is NOT declared (an interrupted `anonctl add` from before, say), clear it with `sudo anonctl rm --purge-account anon-a` and start from the declarations.

### Pinning the uids is what closes the UID-reuse hazard

Declaring the accounts stops them from being deleted. **Pinning the uids** is the separate half that stops the two consequences of deletion from ever arising:

- a pinned uid is never auto-allocated to anything else, so no stranger can be handed the uid anonctl's rules govern;
- a pinned uid cannot change under the account, so the rules and the account can never drift apart into the "still recorded as jailed, actually unforced" state.

An unpinned declared account (`uid` omitted) is safe from deletion but still gets an allocated uid, and NixOS's revive-from-`uid-map` behaviour is best-effort, not a guarantee. Pin them.

## 3. The alternative (`users.mutableUsers = true`) and what it actually costs

Flipping `users.mutableUsers = true` does fix anonctl: accounts created out of band survive, and `anonctl add` works exactly as it does on Debian. You should know what else that setting changes before you reach for it, because on a box that manages passwords declaratively the cost is significant and completely non-obvious.

**On NixOS, a declarative password is applied to an account that ALREADY exists only when `mutableUsers` is false.** This is the `/etc/shadow` rewrite in `update-users-groups.pl`, which for every account already present in `/etc/shadow` does exactly this:

```perl
$sp_pwdp = "!" if !$spec->{mutableUsers};
$sp_pwdp = $u->{hashedPassword} if defined $u->{hashedPassword} && !$spec->{mutableUsers}; # FIXME
```

With `mutableUsers = true`, neither line runs, and the hash already in `/etc/shadow` is carried through verbatim. Your declared `hashedPassword` is ignored for that account.

Three things make this worse than it first reads:

- **It is silent, and it looks like it works.** A NEW account (one not yet in `/etc/shadow`) does get its declarative hash, from a later loop that has no `mutableUsers` gate. So the declarative password is applied exactly once, on creation, and is never enforced again. It works the day you set it up and quietly stops being authoritative afterwards.
- **`hashedPasswordFile` is not an escape hatch.** The script reads that file into the very same field (`$u->{hashedPassword} = read_file($u->{hashedPasswordFile})`) before reaching the gate above, so a sops-nix-managed password file passes through the identical `!$spec->{mutableUsers}` condition. If you manage root's password through sops via `hashedPasswordFile`, setting `mutableUsers = true` makes that file advisory: rotating the secret no longer rotates the password, and a password set locally with `passwd` is never overwritten by a rebuild.
- **Upstream marks the line `# FIXME`.** This is acknowledged-fragile behaviour, not a contract to build on.

So the trade is: `mutableUsers = true` buys you out-of-band account creation for anonctl, and pays for it by making declarative password management box-wide advisory rather than enforced. **Declare the accounts instead** ([section 2](#2-the-supported-path-declare-both-accounts-then-let-add-adopt-them)). It is more configuration, it is confined to the accounts anonctl manages, and it changes nothing about the rest of the host.

## 4. Choosing an account NAME is a privacy decision

anonctl exists to keep an identity from being linked to you. The account NAME is the one part of it that is not protected at all, and on NixOS it is written to more places than on any other distro.

`anon-<name>` and `anon-<name>-shim` appear in plaintext in:

- **`/etc/passwd`**, which is mode 0644 and readable by every user and every process on the box;
- **`/home/anon-<name>`**, whose directory name is visible to anyone who can list `/home`, even though the home itself is 0700;
- **the unit name `anonctl-shim@anon-<name>.service`**, which any unprivileged `systemctl list-units` prints;
- on NixOS additionally, **`/nix/store/<hash>-users-groups.json`**, which is world-readable like everything else in the store, and which persists for every past system generation until a garbage collection removes it;
- and **the git history of your configuration repository**, along with every remote you have pushed it to.

**Therefore the account name MUST NOT describe the identity's purpose.** `anon-journalist`, `anon-client-acme`, `anon-jobhunt` all defeat the tool for any observer who can read a file every process on the box can read.

**No secret-management tool can fix this.** NixOS evaluates user declarations at **build** time: the names are serialised into `users-groups.json` in the Nix store while the configuration is being built. sops-nix and every comparable tool decrypt at **activation** time, after the build has already happened. An encrypted value can therefore never become an account name, and even if it could, the result would land in a world-readable store path. This is a structural property of the evaluation order, not a gap in any particular tool.

### What to do instead

**Use opaque slot names.** `anon-a`, `anon-b`, `anon-01`, `anon-02`. They say nothing. Keep the purpose-to-slot mapping (`anon-b is the one for X`) in your own secret store: a password manager entry, or a sops file you decrypt by hand and never render into the Nix store. anonctl never needs to know what a slot is for.

**Declare a POOL of slots in a single commit.** Declare, say, `anon-a` through `anon-f` at once, rather than adding one each time you need an identity. Two separate observers are defeated by this:

- **your git history**, which otherwise reads as a dated timeline of exactly when each identity was created, correlatable with anything else that happened on those dates;
- **the live `/etc/passwd`**, which otherwise says how many identities you currently have and, combined with `/home` timestamps, when each came into use.

A pool declared in one commit reveals only that you use anonctl and a slot count you chose. Run `anonctl add` on a slot when you need it and leave the rest declared-but-unforced; an undeclared-to-anonctl slot is just an ordinary unused account.

## 5. NixOS-specific operational gotchas

These are measured on NixOS, not inferred. anonctl already handles each one; they are listed because they will bite any script, unit or automation you write around an anon account yourself.

### `useradd` creates no user-private group

`/etc/default/useradd` on NixOS carries `GROUP=100`, so an account created out of band lands in the shared `users` group and **no group named after the account is ever created**:

```
anon-livetest:x:1002:100::/home/anon-livetest:/bin/bash
uid=1002(anon-livetest) gid=100(users) groups=100(users)
getent group anon-livetest -> nothing
```

Anything that assumes the Debian/Ubuntu `USERGROUPS_ENAB yes` convention breaks here. `chown anon-a:anon-a` fails outright with `chown: invalid group: 'anon-a:anon-a'`, which is what used to abort `anonctl add` midway on this distro.

The portable form is a **trailing colon and no group name**: `chown anon-a: <path>`. coreutils defines that as "that user is made the owner and the group is changed to that user's login group", which is the per-user group on Debian and whatever the account actually has on NixOS, with no branching and no distro check. anoncore uses this form (`account.ChownOperand`); use it in your own scripts too.

Declaring a dedicated group as [section 2](#the-declarations) does restores the per-account group, which is worth having on its own: it keeps the anon account out of the shared `users` group alongside your real account.

### The conventional login shells do not exist

Measured:

```
/bin/bash          MISSING        /usr/sbin/nologin  MISSING
/sbin/nologin      MISSING        /bin/false         MISSING
/bin/sh            EXISTS (it is bash)
```

The real binaries are `/run/current-system/sw/bin/{bash,nologin}`. `useradd` **warns and proceeds** when given a shell that does not exist, so a hard-coded conventional path yields an account whose login shell is simply not there. anoncore v0.2.0 resolves both shells up front and refuses before touching the box (`provision.PreflightShells`), so you get a clean refusal rather than a half-made account.

In your Nix configuration, use `pkgs.bashInteractive` and `pkgs.shadow` rather than literal paths. NixOS renders those through `utils.toShellPath` into `/run/current-system/sw/bin/bash` and `/run/current-system/sw/bin/nologin`, the stable aliases.

Do **not** put a store path in the shell field. `/etc/shells` lists the stable alias, but `type bash` in an interactive shell resolves to something like `/nix/store/<hash>-bash-interactive-5.3p9/bin/bash`, and that path is garbage-collected on the next rebuild.

### A unit `ExecStart` must never bake a `/nix/store` path

This one is fail-OPEN, so it matters more than the other two.

anonctl's generated units need absolute `ExecStart` paths (a systemd unit has no useful inherited `$PATH`, and on NixOS the manager's own PATH contains no coreutils at all), so `nft` and `setpriv` are resolved at install time and baked in. The correct value is the stable alias, `/run/current-system/sw/bin/nft`. A `/nix/store/<hash>-nftables-1.1.6/bin/nft` is **correct today and gone after the next `nixos-rebuild`**, because the store path is garbage-collected.

There are two routes by which the wrong path can get baked, and only one of them is obvious:

- resolving symlinks (`realpath`, `filepath.EvalSymlinks`) returns the store path. anonctl never does this, by decision (ADR-0005).
- **`exec.LookPath` returns the `$PATH` entry verbatim.** If a store path sits earlier in your `$PATH` than `/run/current-system/sw/bin`, the lookup hands back a store path having resolved no symlink at all. Measured in an ordinary session on such a host: `which bash` printed `/nix/store/yisa2lg79zcvgk4ck4yr6r0lz6j63hs3-bash-interactive-5.3p9/bin/bash`. A `nix develop` shell, a direnv environment, or anything that prepends a store path to `$PATH` is enough to trigger it.

When it happens, the loader unit fails `203/EXEC` at the next boot, weeks after the install, with nothing in your configuration having changed. For `anonctl-nftables.service` specifically that means **no rules are loaded at boot at all**, not the forcing table and, critically, not the standing baseline default-deny. The boot invariant depends on that baseline, so without it the anon UID egresses **freely, with the host's real IP**. It is also silent: the account exists, its config and marker are intact, and only the failed unit records anything.

**What to do:** run `anonctl add` and `anonctl update` from a plain root shell, never from inside a `nix develop` or direnv environment, and check the result:

```sh
grep -h '^ExecStart' /usr/local/lib/systemd/system/anonctl-*.service
```

Every path must be under `/run/current-system/sw/bin` (or a real, non-store install prefix). If any path starts with `/nix/store/`, re-run `sudo anonctl update <account>` from a clean shell.

### `/usr/local/bin` is not on `PATH` here, so the installer's default is invisible

The installer puts both binaries in `/usr/local/bin`, which is the right choice on most distributions and is **not on `PATH` on NixOS**, for the operator or for `sudo`. So a perfectly good install produces:

```
$ sudo anonctl verify anon-01
sudo: anonctl: command not found
```

Nothing is broken: call it by absolute path (`sudo /usr/local/bin/anonctl ...`), or install with a `PREFIX` that is on `PATH`. anonctl itself is unaffected either way, because it resolves the shim as its own sibling and writes that absolute path into the unit, so the units keep working regardless of your `PATH`.

The better answer on this distro is to stop hand-installing altogether: a binary in `/usr/local/bin` is undeclared state that no rebuild reproduces and no rollback undoes, which on a box that pins its uids and declares its users is exactly the drift you are otherwise avoiding. Package it (`buildGoModule`, both binaries, `CGO_ENABLED = 0` to match the release) and put it in `environment.systemPackages`; anonctl's lookup then lands on `/run/current-system/sw/bin`, which is a stable alias rather than a garbage-collectable store path, so it satisfies the `ExecStart` rule above by construction.

### `systemctl is-enabled` lies about anonctl's units here

`/etc/systemd/system` is a read-only Nix store symlink on NixOS, and `systemctl enable` always writes its symlink into that directory no matter where the unit file lives. anonctl therefore installs its units into `/usr/local/lib/systemd/system` (systemd's documented home for "system units installed by the administrator", and in the unit load path on NixOS) and writes its own `.wants/` symlinks there.

systemd honours `.wants/` in **every** load-path directory, so the dependency is real and boot-effective; this has been confirmed across an actual reboot on NixOS. But `systemctl is-enabled` inspects only the config directory, so it reports `disabled` for units that are genuinely wired to boot. Do not use it as your check. The truthful probe is `systemctl show <target> --property=Wants`, used in [section 7](#7-verify-it-actually-worked-on-this-host).

## 6. nsncd resolves your account's names for it, and `add` refuses until you deal with it

NixOS enables an nscd-compatible daemon by default, and since 23.05 that daemon is **nsncd**. glibc asks an nscd socket for the `hosts` database **before** it looks at `/etc/nsswitch.conf` at all, so on a stock NixOS host every `getaddrinfo` your anon account makes is executed inside nsncd's process, under uid `nscd`.

That defeats anonctl completely for DNS. The forcing is `meta skuid <anonUID>`, which matches a socket's **owner**: a lookup another daemon performs on the account's behalf is not governed by any rule anonctl can write. The result is an account whose TCP exits correctly over Tor while every hostname it visits is resolved by your host's resolver and is attributable to you. This was measured, not theorised (`work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md`), and it is why `anonctl add` refuses such a host outright.

You have three honest options.

**Tell nsncd to ignore hosts (recommended, and measured on this box).** nsncd takes `NSNCD_IGNORE_<DATABASE>` environment variables, so it can be told to stop answering the `hosts` database while still serving `passwd`/`group`, which is what NixOS wants it for:

```nix
systemd.services.nscd.environment.NSNCD_IGNORE_HOSTS = "true";
```

The load-bearing question is what glibc does when nsncd refuses: it **falls back to in-process resolution** rather than failing. That was measured here rather than assumed, with a differential that can only come out one way: two nsncd instances, one default and one with the variable set, each reached through a mount namespace whose own `/etc/resolv.conf` points at a dead server. The default instance **resolved** a tailnet name (it answered using the host's real resolver, which is the bypass in miniature); the ignoring instance **failed** (glibc resolved it in-process and hit the dead server). In-process is what `meta skuid` can govern, so that is the fix.

Consequence worth knowing: nsncd exists so foreign-libc binaries (`nix-ld`, `steam-run`, FHS environments) can use this glibc's NSS plugins. With hosts ignored, those binaries resolve with their own libc, so they keep `files` and `dns` but lose `mdns`/`mymachines`. Native programs are unaffected, and nsncd is non-caching, so no cache is lost.

**Or swap nsncd for glibc's nscd with the hosts cache off.** `services.nscd.enableNsncd = false` plus `enable-cache hosts no` in `services.nscd.config`. The glibc `nscd` binary does still exist in nixpkgs (checked here: 2.42), but this is a bigger change than one environment variable, for the same effect.

**Or accept it explicitly.** `anonctl add --allow-nss-bypass <name>` proceeds. Do this only if you know the account will never use NSS (a program pointed straight at the shim's DNS port). Know what it does and does not buy, because it is less than the name suggests:

| after `--allow-nss-bypass` | state |
| --- | --- |
| the forcing (nft rules, shim, boot persistence) | installed and working |
| `anonctl verify` | `dns-nss-not-bypassed` stays RED, every run, by design |
| `anonctl use` / `anonctl exec` | REFUSE the account, because both gate on a green verify |
| entering the account | `sudo -iu <account>`, which is the documented day-to-day path anyway |
| the world-readable marker | not written (it needs a green verify), so anon-pi/netcage will not see this account as kernel-anonymized and may anonymize it again |

That combination is deliberate. Your consent is a reason for anonctl to let you **proceed**; it is not a reason for anonctl to start certifying the box, to itself or to another tool. Fixing the host clears all four rows at once.

**Do not** try to solve it by forcing nsncd's egress through the shim. It serves every uid on the machine, so capturing it would route your whole host's name resolution through one account's Tor circuit.

### While you are here: check that the account's DNS actually works

On this host the two problems are easy to confuse, and they compound: a Tailscale box additionally drops the shim's **answers**, because conntrack un-NATs the reply to the nameserver's address (`100.100.100.100`, inside `100.64.0.0/10`) and tailscaled's `ts-input` chain drops packets from that range arriving on `lo`. The account then has no working DNS at all, and the nsncd bypass is the only reason it appears to resolve anything.

`anonctl verify` reports this as `dns-forced-path-answers`, separately from the bypass, and names the culprit when the nameserver is inside Tailscale's range. The fix is on the host side, because the rule doing the dropping is tailscaled's and is correct on its own terms: anonctl will not edit another tool's ruleset.

What makes it go away is a **loopback** system nameserver. The problem is entirely about the address the answer is un-NATed to: from `127.0.0.53` or `127.0.0.1` the reply is an ordinary loopback packet that no anti-spoofing rule looks at, and the account's redirect (`udp dport 53` to the shim's loopback port) is then loopback-to-loopback throughout. A stub resolver in front of MagicDNS, or a local forwarder pointing at `100.100.100.100`, both do it. Note that the account's own queries never reach that stub: they are redirected into the shim before they get there. The stub is for the rest of the box.

> **The obvious version of that fix trades one bypass for the other, so check it.** Enabling `services.resolved` on NixOS also adds `resolve [!UNAVAIL=return]` to `system.nssDatabases.hosts` (`nixos/modules/system/boot/resolved.nix`, `mkOrder 501`), and `nss-resolve` hands `getaddrinfo` to systemd-resolved over varlink, under uid `systemd-resolve`. That is the SAME out-of-process resolution nsncd was doing, so you would fix `dns-forced-path-answers` and keep `dns-nss-not-bypassed` red. You want the stub LISTENER without the NSS module: drop that entry with a `lib.mkForce` on `system.nssDatabases.hosts` and keep `dns`, so glibc queries `127.0.0.53` on the account's own socket, which the forcing governs correctly. Re-run `anonctl verify` after any such change; that is what it is for.

> **anonctl drops the account's clear DNS at the baseline because of this.** A loopback nameserver makes an UNFORCED query look exactly like a forced one to the standing default-deny (both have a loopback destination, and the baseline returns loopback because that is forcing's own redirect target). Off-box nameservers were caught by the baseline's broad drop; loopback ones would not have been, so "forcing absent means dropped, not free" would have stopped holding for DNS on precisely the hosts this page tells you to configure. The baseline now drops the account's `:53` outright, which cannot touch forced traffic because forcing rewrites the port at `dstnat` before the baseline's chain runs. You do not have to do anything about this; it is here because it is the reason the recommendation above is safe.

The general rule behind all of this, worth stating once: **a loopback system nameserver keeps the whole exchange on `lo`**, so no input filter keyed on a source address (tailscaled's or anyone else's) ever sees the account's DNS. An off-box nameserver makes the un-NATed answer visible to every such filter on the box, and whether it survives is then somebody else's policy decision, re-made on every update of that other tool.

## 7. Verify it actually worked on this host

Run this after `anonctl add`, and again **after a reboot**. On this distro the reboot is not a formality: activation is when accounts are deleted, so a green report before the first reboot proves nothing about whether the configuration is right.

Substitute your own account name for `anon-a` throughout.

### 7.1 The account still exists and still owns its pinned uid

```sh
sudo anonctl status anon-a
sudo anonctl verify anon-a
```

`status` makes the same comparison and prints it as its `identity:` line, so it is the cheap check you can run without waiting for the probes. **Run it with `sudo`**: the record it compares against lives under `/etc/anonctl/accounts` and is root-only, so an unprivileged run cannot read it. It says so rather than guessing (`identity: UNKNOWN ...`, `"state":"record-unreadable"`, `"ok":false`), because reporting an unreadable record as "nothing to compare" would print a reassuring line for an account whose uid may have drifted. The rest of `status` still works without root. It distinguishes the shapes that matter: `ACCOUNT MISSING` (anonctl records the account as forced and there is no passwd entry: the activation deleted it), `UID MISMATCH` (it exists under a uid that is not the one the loaded rules govern, so it is UNFORCED while `/etc/anonctl` still records it as jailed), `not recorded` (the accounts exist but `anonctl add` has not adopted them yet), and `ok`. Under `--json` the same verdict is `identity.state`, so a host-check script can gate on it.

`verify`'s first assertion is `account-identity`, and it is a precondition: it checks that both accounts exist and still own the uids anonctl recorded, and when that fails it reports **that assertion alone** and stops. So on a host where NixOS deleted the accounts you get one unambiguous line naming the deletion and the orphaned uid, not a scatter of leak assertions about a uid that is nobody's. The same assertion catches the recreated-under-a-different-uid case, which is the one that leaves the account completely unforced while `/etc/anonctl` still records it as jailed.

Cross-check it independently, since the whole point of this section is not to take a tool's word for it:

```sh
# Both accounts must be present, with the uids you pinned in section 2.
getent passwd anon-a anon-a-shim

# The uids anonctl's installed rules and unit actually govern. anonUid and
# shimUid must equal what the line above printed.
sudo cat /etc/anonctl/accounts/anon-a.json
```

### 7.2 The tables are loaded

```sh
sudo nft list table inet anonctl_anon_a
sudo nft list table inet anonctl_baseline_anon_a
```

Both must exist. The baseline table is the one that matters most: it is the standing default-deny that makes "no forcing loaded" mean *dropped*, not *free*. If it is missing, re-read the `ExecStart` check in [section 5](#a-unit-execstart-must-never-bake-a-nixstore-path), because a dead loader unit is the usual cause and it is fail-open.

(The table name replaces `-` with `_`, so account `anon-a` gives `anonctl_anon_a`.)

### 7.3 No loaded table governs a uid that is no longer the account's

This is the check that catches an orphaned table from a deleted account, including one belonging to an account you have since forgotten about:

```sh
sudo nft list ruleset \
  | grep -oE 'meta skuid [0-9]+' | awk '{print $3}' | sort -un \
  | while read -r uid; do
      name=$(getent passwd "$uid" | cut -d: -f1)
      printf '%s -> %s\n' "$uid" "${name:-NO SUCH UID (orphaned rules governing a free uid)}"
    done
```

Every uid printed must resolve to one of your anon accounts or its shim. A `NO SUCH UID` line is an orphaned table: the rules are governing a uid that is free to be handed to an unrelated account. Clear it with `sudo anonctl rm --purge-account <account>` if you still know which account it was, or `sudo nft delete table inet <name>` for the table directly, and then fix the declaration so it does not recur.

### 7.4 The forcing is actually wired to boot

`systemctl is-enabled` will say `disabled` and be wrong (see [section 5](#systemctl-is-enabled-lies-about-anonctls-units-here)). Ask the loaded dependency graph instead:

```sh
systemctl show sysinit.target --property=Wants | tr ' ' '\n' | grep anonctl
systemctl show multi-user.target --property=Wants | tr ' ' '\n' | grep anonctl
```

You want `anonctl-nftables.service` under `sysinit.target` and `anonctl-shim@anon-a.service` under `multi-user.target`.

### 7.5 Reboot, then run 7.1 through 7.4 again

This is the only test that exercises what section 1 is about, because the deletion happens during activation at boot. A configuration that survives `nixos-rebuild switch` will usually survive a reboot too, but "usually" is not the standard anonctl holds itself to, and the failure it is guarding against is silent.

## Related reading

- [`docs/adr/0010-add-gates-on-the-ledger-and-adopts-existing-accounts.md`](adr/0010-add-gates-on-the-ledger-and-adopts-existing-accounts.md): why `add` gates on anonctl's own record rather than the passwd table, what adoption does and does not touch, and why half a pair is refused rather than completed.
- [`docs/adr/0003-verify-assertion-names-and-json-contract.md`](adr/0003-verify-assertion-names-and-json-contract.md): the `account-identity` precondition and the `--json` contract.
- [`docs/adr/0011-dns-confinement-is-measured-and-nss-bypass-is-refused.md`](adr/0011-dns-confinement-is-measured-and-nss-bypass-is-refused.md): why nsncd defeats per-UID DNS forcing, why anonctl refuses rather than works around it, and why the DNS assertions measure instead of inferring.
- [`docs/adr/0005-reboot-persistence-and-boot-invariant.md`](adr/0005-reboot-persistence-and-boot-invariant.md): the boot invariant and why a store path in `ExecStart` is fail-open.
- `work/notes/findings/nixos-account-conventions-break-anonctl-provisioning.md`, `work/notes/findings/systemd-enablement-target-and-nixos-fhs-gaps.md`, `work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md` and `work/notes/observations/resolved-unit-binaries-can-bake-a-nix-store-path-from-path.md`: the raw measurements this guide is built from.
