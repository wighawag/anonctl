---
title: Empirically audit the UID-transition escape surface on a real host (grounds the hardening + verify tasks)
slug: empirical-uid-transition-escape-audit
prd: per-uid-kernel-anonymized-egress
humanOnly: true
blockedBy: []
covers: [30]
---

## What to build

Row 7 of the Tails leak catalogue (`work/notes/findings/tails-network-filter-lessons.md`) is anonctl's sharpest structural edge: because forcing is `meta skuid <anonUID>`, any socket the anon account can cause to be owned by a DIFFERENT uid (setuid, sudo, a triggerable daemon) matches the ruleset's `meta skuid != <anon> meta skuid != <shim> accept` first filter rule and egresses in the CLEAR. This task GATHERS the real escape surface on a representative host so the two follow-on tasks (`harden-anon-account-against-uid-transition`, `verify-no-uid-transition-egress`) are grounded in real vectors, not a guessed list.

This is HUMAN-run (like the original manual-per-uid-recipe-validation): it inspects a real, freshly-provisioned anon account on a real machine. It writes NO production code.

On a real Linux host with a freshly-provisioned anon account, enumerate and record what actually transitions UID and can egress:

- **sudo:** is `sudo` installed and does the anon account have ANY sudoers entry (even a limited one)? Can it run anything via sudo that reaches the network?
- **setuid binaries:** enumerate setuid/setgid binaries on the anon account's PATH and on all filesystems reachable by the account (`find / -perm -4000 -o -perm -2000` from the account's vantage); flag any that can make an outbound connection (ping is setuid on some distros; `mount`, `su`, etc.).
- **triggerable daemons / services:** dbus-activatable services, socket-activated units, cron, a local HTTP/print/scan/avahi daemon, anything the anon account can cause to make an outbound connection on its behalf whose socket is owned by a non-anon uid.
- **mounts:** which reachable mounts are `nosuid` vs not (a setuid binary on a `nosuid` mount does not gain its owner's uid, so `nosuid` mounts shrink the surface).

## Acceptance criteria

- [x] A `work/notes/findings/uid-transition-escape-surface.md` is written with a `source:` line (hand-audited on a real host: OS + kernel + date), recording: the sudo situation, the reachable setuid/setgid binaries and which can egress, the triggerable daemons/services, and the nosuid-vs-suid mount picture.
- [x] For each vector found, a note on whether anonctl can close it at `add`-time (feeds `harden-anon-account-against-uid-transition`), prove-absent in `verify` (feeds `verify-no-uid-transition-egress`), or must be documented as residual.
- [x] The finding is HONEST about the boundary: it names what the per-UID model cannot close (an arbitrary triggerable daemon on a busy host) and points at netcage's netns model for namespace-strength confinement.

## Blocked by

- None, can start immediately (human-run host audit).

## Prompt

> Goal: hand-audit the real UID-transition escape surface for an anonctl anon account, and record it as a finding so the hardening and verify tasks are grounded in reality, not a guess. Row 7 of `work/notes/findings/tails-network-filter-lessons.md`. This is HUMAN-run (inspects a real host), like `manual-per-uid-recipe-validation`; it writes NO production code, only a finding.
>
> Context: anonctl forces egress by `meta skuid <anonUID>` (see the shipped `internal/nftables/nftables.go` filter chain, whose FIRST rule `meta skuid != <anon> meta skuid != <shim> accept` is the escape: every other uid egresses freely). The design pass in `work/notes/ideas/uid-transition-escape-investigation.md` settled the response (harden at add-time + a best-effort verify probe + document the residual; reject a netns second layer as drift into netcage). This audit produces the empirical input those decisions need.
>
> Do NOT fabricate: every entry in the finding must come from a command actually run on a real host with a real provisioned anon account. If a vector is present but you cannot determine whether it egresses, record that honestly.
>
> "Done" = `work/notes/findings/uid-transition-escape-surface.md` exists with a real `source:`, the enumerated vectors, and the per-vector close-at-add / prove-in-verify / document-residual disposition. This unblocks `harden-anon-account-against-uid-transition` and `verify-no-uid-transition-egress`.
