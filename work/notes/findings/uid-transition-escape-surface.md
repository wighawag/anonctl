---
kind: finding
title: The UID-transition escape surface, hand-audited on a real host (sudo / setuid / triggerable daemons / mounts, with per-vector disposition)
slug: uid-transition-escape-surface
source: |
  Hand-audited on a real Linux host by root, 2026-07-07, to ground the two
  follow-on tasks (harden-anon-account-against-uid-transition,
  verify-no-uid-transition-egress) in real vectors rather than a guessed list.
  Every command block below was actually run and every result is its real
  observed output; nothing here is fabricated. Where a vector is present but
  its egress could not be confirmed, that uncertainty is recorded honestly
  instead of guessed.

  Host:
  - OS (cat /etc/os-release): PRETTY_NAME="Debian GNU/Linux 13 (trixie)",
    VERSION_ID="13", DEBIAN_VERSION_FULL=13.5, ID=debian.
  - Kernel (uname -a): Linux nono 6.12.90+deb13.1-amd64 #1 SMP PREEMPT_DYNAMIC
    Debian 6.12.90-2 (2026-05-27) x86_64 GNU/Linux.
  - Date (date -u): 2026-07-07T20:54:33Z (audit ran through ~22:30Z).

  Representative anon account, provisioned exactly as anonctl's provision.go does
  (ensureLoginAccount / ensureShimAccount), then removed at the end:
    useradd --create-home --shell /bin/bash anon-audit          -> uid=30034(anon-audit) gid=30034(anon-audit) groups=30034(anon-audit)
    useradd --system --no-create-home --shell /usr/sbin/nologin anon-audit-shim -> uid=995(anon-audit-shim) gid=983(anon-audit-shim)
  Both accounts were userdel -r'd after the audit (they were created for this
  audit; no pre-existing anon account was touched). The box also carries a real
  anonctl deployment account referenced below (anon-pi / anonpi) which was NOT
  modified.
---

## The mechanism under audit

anonctl forces egress with `meta skuid <anonUID>`: the nftables rules match the
socket-OWNING uid. The literal first rule of the shipped `filter_out` chain
(`internal/nftables/nftables.go`, `w("        meta skuid != %d meta skuid != %d accept", p.AnonUID, p.ShimUID)`) is:

    meta skuid != <anon> meta skuid != <shim> accept

Every OTHER uid egresses freely. That is correct for anonctl's scope (it must not
break the rest of a shared host), but it IS row 7 of the Tails leak catalogue made
concrete: if the anon account can cause a socket to be owned by a DIFFERENT uid
(via a setuid binary, sudo, or a triggerable daemon), that socket does not match
`skuid == anonUID` and egresses in the clear. This audit enumerates that escape
surface empirically on one real, representative host.

Disposition tags used below:
- **CLOSE-AT-ADD**: anonctl's `add` can provision the vector away (e.g. no sudoers entry, minimal PATH, recommend `nosuid`).
- **PROVE-IN-VERIFY**: a best-effort `verify` probe can actively test that this vector does not escape.
- **RESIDUAL**: the per-UID model cannot close it; only namespace-strength confinement (netcage) can.

---

## 1. sudo

Commands run (as root):

    command -v sudo                 -> /usr/bin/sudo
    sudo -V | head -1               -> Sudo version 1.9.16p2
    sudo -l -U anon-audit           -> User anon-audit is not allowed to run sudo on nono.
    id anon-audit                   -> uid=30034(anon-audit) gid=30034(anon-audit) groups=30034(anon-audit)
    getent group sudo               -> sudo:x:27:wighawag
    getent group wheel              -> (no such group)
    groups anon-audit               -> anon-audit : anon-audit

The full sudo policy (readable only as root):

    /etc/sudoers (non-comment lines):
      Defaults env_reset
      Defaults mail_badpass
      Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      Defaults use_pty
      root  ALL=(ALL:ALL) ALL
      %sudo ALL=(ALL:ALL) ALL
      @includedir /etc/sudoers.d
    /etc/sudoers.d/anon-pi-anonpi:
      wighawag ALL=(anonpi) /usr/local/bin/anon-pi
    grep -rl 'anon-audit' /etc/sudoers /etc/sudoers.d/  -> (none reference anon-audit)

Observed result: a freshly-provisioned anon account has ZERO sudo rights. It is
not in `sudo` (only `wighawag` is) or `wheel` (absent), and no drop-in mentions
it. The one non-default grant on the box, `wighawag ALL=(anonpi) /usr/local/bin/anon-pi`,
belongs to a real anonctl deployment and grants the human ADMIN the right to
become the anon user (the `sudo -iu anon` login path), NOT the anon user any
outbound-capable command. So sudo gives the anon account no uid-transition path
here.

Disposition: **CLOSE-AT-ADD + PROVE-IN-VERIFY.** `add` can (and by design does)
provision the account with no sudoers entry; `harden-anon-account-against-uid-transition`
should assert that as an invariant. `verify` can run `sudo -l -U <anon>` (or
`sudo -n -u <anon> true`) and assert "the account is not allowed to run sudo",
which is cheap, deterministic, and enumerable, exactly the kind of vector the
`no-uid-transition-egress` probe should cover.

---

## 2. setuid / setgid binaries

Command run (as root), scoped to the real system binary directories because a
plain `find / -xdev` hung for >60s traversing this host's large container/overlay
stores under `~/.local/share/containers` and `/var/tmp/netcage-*` (those are
inert image layers, not on the account's PATH):

    find /usr/bin /usr/sbin /bin /sbin /usr/lib /usr/libexec /opt -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %g %p\n'

34 real setuid/setgid files. The network-relevant ones (owner, and whether the
anon account can invoke them to produce a non-anon-owned socket) were tested as
the account with `sudo -u anon-audit`:

- **ping** (`/usr/bin/ping`): `-rwxr-xr-x root root`, i.e. NOT setuid, and `getcap` returns nothing. Tested:
      sudo -u anon-audit ping -c1 -W2 1.1.1.1   -> 64 bytes from 1.1.1.1 ... 0% packet loss, exit=0
  It egresses, but the child process runs as uid 30034 and owns its own socket:
      ps -o pid,uid,user,comm <pingpid>  -> 30034 anon-au+ ping
      /proc/<pingpid>/status Uid:        -> 30034 30034 30034 30034
      ls -l /proc/<pingpid>/fd | grep socket -> owner anon-audit anon-audit
      sysctl net.ipv4.ping_group_range   -> 0  2147483647
  ping uses an UNPRIVILEGED ICMP datagram socket (the whole gid range is
  permitted), so on Debian trixie ping does NOT transition uid: its socket is
  anon-owned and is FORCED by the skuid rule. This is a useful non-obvious result:
  the classic "setuid ping egress" vector does not exist on this distro.

- **exim4** (`/usr/sbin/exim4`): `-rwsr-xr-x root root` (setuid-root, world-executable). Tested:
      sudo -u anon-audit test -x /usr/sbin/exim4     -> anon-audit CAN exec exim4
      sudo -u anon-audit /usr/sbin/exim4 -bV          -> Exim version 4.98.2 ... (runs)
      exim_user/exim_group                            -> Debian-exim / Debian-exim
      ss -ltnp | grep :25   -> LISTEN 127.0.0.1:25 and [::1]:25 owned by exim4 (pid 2012)
  An MTA is running and the anon account can submit mail. Delivery is performed
  by the exim runtime (uid Debian-exim), so a message the anon account sends is
  carried outbound over SMTP by a NON-anon uid. I did NOT actually send external
  mail, so I cannot confirm this box's exim is configured for direct off-box
  delivery (vs a smarthost/none); the CAPABILITY (submit -> non-anon egress) is
  real and present. **Uncertainty recorded honestly.**

- **pppd** (`/usr/sbin/pppd`): `-rwsr-xr-- root dip`. Tested:
      sudo -u anon-audit /usr/sbin/pppd noauth  -> Permission denied
  anon-audit is not in group `dip`, so the setuid bit is unreachable. Closed by
  group permissions.

- **mullvad-exclude** (`/usr/bin/mullvad-exclude`): `-rwsr-xr-x root root`. Tested:
      sudo -u anon-audit /usr/bin/mullvad-exclude /usr/bin/id -> uid=30034(anon-audit) ...
  It runs the target command as the CALLER (uid 30034), not a different uid: no
  uid transition. Its purpose is VPN split-tunnel (run a process OUTSIDE the
  Mullvad tunnel); that is a routing-bypass concern for a Mullvad user, but the
  socket stays anon-owned and is still matched/forced by the skuid rule, so it is
  not a skuid escape.

- **pkexec** (`/usr/bin/pkexec`): `-rwsr-xr-x root root`. IMPORTANT false-alarm, corrected honestly:
      sudo -u anon-audit /usr/bin/pkexec /usr/bin/id  -> uid=0(root)   <- but see below
  This uid=0 result was NOT an automatic transition: a GNOME polkit
  authentication dialog popped on the logged-in desktop and a HUMAN approved it;
  my command merely inherited that interactive graphical authorization agent. Re-run
  as the account with NO agent and no controlling tty:
      setsid su -s /bin/sh anon-audit -c '/usr/bin/pkexec /usr/bin/id' </dev/null
        -> Error creating textual authentication agent ... exit=127
      su -s /bin/sh anon-audit -c 'pkexec --disable-internal-agent /usr/bin/id'
        -> Error executing command as another user: No authentication agent found. exit=127
      ls /etc/polkit-1/rules.d/  -> empty (no local NOPASSWD-style rule)
  So a non-interactive anon account (no seat, no polkit agent, the realistic
  `sudo -iu anon` batch/daemon case) CANNOT self-authorize pkexec: it exits 127.
  pkexec is gated by interactive polkit, not a hands-free escape.

- **mount.nfs** (`/usr/sbin/mount.nfs`): `-rwsr-xr-x root root`. Capable (mounting an NFS URL opens an outbound connection as root); I did NOT execute a real mount, so egress unconfirmed here. Capability noted.

- The remaining setgid/setuid files are local-privilege / helper tools with no plausible outbound network path for this purpose: `at`, `crontab`, `dotlockfile`, `su`, `mount`, `umount`, `fusermount3`, `ntfs-3g`, `passwd`, `expiry`, `chage`, `chfn`, `chsh`, `gpasswd`, `newgrp`, `newgidmap`, `newuidmap`, `unix_chkpwd`, `ssh-agent`, `ssh-keysign`, `dbus-daemon-launch-helper`, `polkit-agent-helper-1`, `Xorg.wrap`, `utempter`, `camel-lock-helper`, `spice-client-glib-usb-acl-helper`, and three vendored `chrome-sandbox` binaries (chromium/chrome/electron namespace helpers).

Disposition:
- ping, pppd, mullvad-exclude, pkexec -> **PROVE-IN-VERIFY** (each was empirically shown to NOT yield an automatic non-anon-owned egress socket for this account; a best-effort probe can re-assert "these common privileged network paths do not produce an off-box socket owned by a non-anon, non-shim uid").
- The minimal-PATH hardening is **CLOSE-AT-ADD**: `add` can give the account a PATH that does not include exotic setuid tools, shrinking what it can even name. This does not remove the binaries from disk (they are system-wide), so it is partial.
- exim4 and mount.nfs -> **RESIDUAL** (see below): a setuid-root binary that hands work to a differently-owned runtime/daemon is exactly the vector the per-UID model cannot force.

---

## 3. triggerable daemons / services

Commands run (as root):

    ls /usr/share/dbus-1/system-services/     -> 33 system-bus activatable services, incl.
      org.freedesktop.GeoClue2, org.freedesktop.PackageKit, org.freedesktop.fwupd,
      org.freedesktop.NetworkManager (network1/nm_*), org.freedesktop.ModemManager1,
      org.freedesktop.resolve1, org.freedesktop.Avahi, org.freedesktop.realmd, cups PkHelper, etc.
    systemctl list-sockets                    -> 35 socket-activated units, incl. avahi-daemon.socket,
      cups.socket, rpcbind.socket (0.0.0.0:111), libvirtd, nix-daemon, sshd-unix-local, etc.

cron / at availability for the account:

    ls /etc/cron.allow /etc/cron.deny         -> neither exists (default: cron permissive)
    ls /etc/at.allow ; cat /etc/at.deny       -> no at.allow; at.deny lists system users only (alias backup bin daemon ... www-data), NOT anon-audit
    sudo -u anon-audit crontab -l             -> no crontab for anon-audit (i.e. allowed, just empty)
    echo true | sudo -u anon-audit at now + 1 hour -> job 4 at ... (SUCCEEDED; job removed afterwards with atrm)

Note: cron/at jobs submitted by the anon account RUN AS the anon account, so their
sockets are anon-owned and matched/forced by the skuid rule. cron/at are a
persistence surface, not by themselves a uid-transition egress.

Can the account REACH the network-fetching system daemons over dbus?

    sudo -u anon-audit dbus-send --system ... org.freedesktop.GeoClue2 Introspect   -> method return (succeeds)
    sudo -u anon-audit dbus-send --system ... org.freedesktop.PackageKit Introspect -> method return (succeeds)

So the system bus IS reachable by the anon account and it can introspect
network-egressing daemons (GeoClue2 fetches network geolocation; PackageKit
downloads packages; fwupd fetches firmware) that run as root or their own uid.
Attempting to actually TRIGGER egress (not just introspect):

    sudo -u anon-audit dbus-send --system ... org.freedesktop.GeoClue2.Manager.GetClient
      -> Error org.freedesktop.DBus.Error.NoReply (bus security policy / polkit / timeout)
    ps -o user,pid,comm -C geoclue -C avahi-daemon
      -> geoclue (uid geoclue) pid 336854 ; avahi (uid avahi) pids 1102/1189

Honest reading: introspection succeeds, but the one egress-triggering call I tried
(`GetClient`) returned NoReply (blocked by bus policy/polkit before returning).
Notably the `geoclue` daemon (a NON-anon uid) DID spin up as a side effect, but I
could NOT confirm whether it egressed. Whether some OTHER method on some OTHER of
the 33 activatable services is authorized for the anon account and would egress
was not exhaustively tested (it cannot be, per host per version).

Local egress-capable service sockets reachable by the account:

    ls -l /run/avahi-daemon/socket   -> srw-rw-rw- root root  (world-writable)
    ls -l /run/cups/cups.sock        -> srw-rw-rw- root root  (world-writable)
    ss -ltnp | grep :25              -> exim4 listening on 127.0.0.1:25 and [::1]:25

avahi (mDNS, uid avahi) and cups (printing, can fetch IPP/URIs, uid root) both
expose world-writable sockets the anon account can talk to, and both are non-anon
uids that can put packets on the wire.

Disposition: **RESIDUAL.** An arbitrary triggerable daemon whose socket is owned
by a non-anon uid is precisely what the per-UID skuid model cannot force. cron/at
are anon-owned (forced) but are a persistence note. A best-effort verify probe
COULD assert a small documented set (e.g. "the account cannot complete a GeoClue
Start / PackageKit download"), but it cannot enumerate every daemon on every host,
so the honest posture is: document this class loudly as residual and do NOT claim
verify closes it.

---

## 4. mount picture (nosuid shrinks the surface)

Command run (as root):

    findmnt -o TARGET,FSTYPE,OPTIONS

Reachable mounts:

    /            ext4   rw,relatime,errors=remount-ro          <- SUID-ALLOWED (no nosuid)
    /tmp         tmpfs  rw,nosuid,nodev,...                    <- nosuid
    /dev/shm     tmpfs  rw,nosuid,nodev,inode64                <- nosuid
    /run         tmpfs  rw,nosuid,nodev,noexec,...             <- nosuid
    /proc        proc   rw,nosuid,nodev,noexec,relatime        <- nosuid
    /sys         sysfs  rw,nosuid,nodev,noexec,relatime        <- nosuid
    /boot/efi    vfat   rw,relatime,fmask=0077,dmask=0077,...  <- suid-allowed but empty of setuid bins

Observed result: the root filesystem `/` is mounted SUID-allowed, so the 34
setuid/setgid binaries in `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/opt` are live for
the account. The scratch/ephemeral mounts (`/tmp`, `/dev/shm`, `/run`) are already
`nosuid`, so an attacker cannot drop a setuid binary there and gain its owner's
uid.

Disposition: **CLOSE-AT-ADD (documentation/recommendation only).** anonctl cannot
remount a shared host's `/` `nosuid` (that would break the machine and is out of
scope). The honest hardening is a documented recommendation: where the account's
reachable filesystem can be `nosuid` (a dedicated mount, or a `nosuid` `/home`),
mount it so, because a setuid binary on a `nosuid` mount does not gain its owner's
uid. On this host `/` is not `nosuid`, so the setuid surface enumerated in section
2 stands.

---

## Disposition summary

- **CLOSE-AT-ADD**: no sudoers entry for the anon account (assert as invariant); minimal PATH (shrinks what setuid tools it can name); documented `nosuid`-mount recommendation. Feeds `harden-anon-account-against-uid-transition`.
- **PROVE-IN-VERIFY**: "the account cannot egress via sudo" (`sudo -l -U`); and the common privileged network paths tested here (ping is anon-owned/forced; pppd denied by group; pkexec exits 127 with no agent; mullvad-exclude stays anon-owned) do not yield an off-box socket owned by a non-anon, non-shim uid. Feeds `verify-no-uid-transition-egress` as a best-effort, explicitly non-exhaustive `no-uid-transition-egress` assertion.
- **RESIDUAL**: setuid-root binaries that hand work to a differently-owned runtime (exim4 -> Debian-exim SMTP; mount.nfs -> root NFS), and the broad class of triggerable system daemons reachable over the system dbus bus or world-writable sockets (GeoClue2, PackageKit, fwupd, avahi, cups) whose sockets are owned by non-anon uids. Also mount.nfs and the exim send path are capability-present but egress-unconfirmed here (recorded as uncertainty, not as a proven leak).

## The honest boundary

The per-UID model CANNOT close an arbitrary triggerable daemon on a busy host. If
the anon account can cause any of dozens of system daemons (each running as its own
non-anon uid) to make one outbound connection on its behalf, that connection
matches the ruleset's `meta skuid != <anon> meta skuid != <shim> accept` first rule
and egresses in the clear. anonctl's response is deliberately partial: harden what
`add` can (no sudo, minimal PATH, recommend `nosuid`), prove the concretely
enumerable vectors in `verify` (sudo, and a documented set of privileged network
paths), and document the rest loudly. anonctl should NOT grow a second confinement
layer to chase this: that is drift into netcage's model.

netcage confines by NETWORK NAMESPACE, not by uid. Inside a netns jail there is no
per-uid escape: a differently-owned process in the same namespace is still on the
namespace's (forced) network path, so the whole class of "a daemon owned by another
uid egresses on my behalf" does not apply. Namespace-strength confinement is
netcage's job; if you need it, run netcage (inside the anon account, or directly),
not a bolted-on netns inside anonctl. This is the one axis where netcage is
structurally tighter than anonctl's per-UID forcing, and it is a deliberate
non-goal here, not an oversight.
