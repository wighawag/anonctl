---
kind: idea
title: Mandatory anonctl-gated login - make the anon account reachable ONLY through a verify-gated path (login shell / PAM)
slug: mandatory-anonctl-gated-login
status: proposed
---

## The idea

`anonctl use [<name>]` (task `anonctl-use-verify-then-shell`) is an OPT-IN safe front door: it runs verify and only then shells you in. But it is bypassable - `su - anon`, `sudo -iu anon`, an SSH login, or a cron job reach the account WITHOUT going through `use`, so a user can still enter the account on a broken (un-anonymized) setup. This idea makes the gate MANDATORY: the anon account is reachable ONLY through a verify-gated path, so there is no way to get an interactive session on the account unless anonctl has confirmed it is anonymized.

Candidate mechanisms (each with real footguns - this is why it is an idea, not a task):

1. **Set the account's login SHELL to an anonctl wrapper.** Provision the anon account with `--shell /usr/local/bin/anonctl-login` (instead of `/bin/bash`); that wrapper runs verify and, on green, execs the real shell, else refuses. Then `su - anon` / `sudo -iu anon` / SSH all hit the wrapper. Footgun: a shell that refuses can LOCK the operator out of the account (and out of fixing it) if verify is broken (exactly the state we are in with BUG 2 right now); needs a documented root escape hatch (root can still `useradd`-style fix it / change the shell back). Also a non-login `su anon -c '<cmd>'` may skip a login shell, so scope which entry paths this actually covers.
2. **A PAM hook** (`pam_exec` in the account's PAM stack, or a session module) that runs verify at session open and denies the session on red. More thorough than a login shell (covers more entry paths), but PAM misconfiguration is a classic way to lock a box, and it touches host-owned PAM config - the opposite of anonctl's "own only our own artifacts" posture so far.
3. **A restricted-entry design** (e.g. the account has no direct login at all; the only way in is `anonctl use`, enforced by the shell wrapper AND no password / locked account for direct auth). Strongest, most invasive.

## Why an idea, not a task (yet)

- **Lock-out risk is real and current.** Any of these can make the account (and its fix path) unreachable when verify is broken - and verify IS broken right now (BUG 2). This should not even be designed until `fix-verify-probes-transparent-relay` lands and verify reliably certifies a healthy account, else the mandatory gate would brick the account on a false-fail.
- **It touches host-owned config** (PAM, or the login path) - a departure from anonctl's "own only our own artifacts (our nft table, our units, our /etc/anonctl)" discipline. That boundary decision needs a human call and probably its own ADR.
- **The escape hatch is mandatory.** Whatever mechanism, root MUST retain a way to enter/fix the account when verify is (wrongly or rightly) red, or a bad verify permanently bricks the account. Design that first.
- **Scope of "entry paths" is fiddly:** interactive login, `su -`, `su -c`, `sudo -iu`, `sudo -u ... cmd`, SSH (pubkey/password), cron, systemd `User=` services, at-jobs. A login-shell wrapper covers some; PAM covers more; none trivially covers all. Enumerate what each mechanism actually gates before committing.

## Relationship to the shipped model

This is the ENFORCEMENT layer above two things that already exist / are being built:
- the standing per-UID default-deny (`fix-boot-invariant-nftables-not-enabled`) makes "not forced = dropped" true at the KERNEL level - so even a bypassed login lands in an account whose egress is denied-or-forced, never free. That is the real leak protection.
- `anonctl use` makes verify-then-shell the ergonomic default.

So this idea's value is narrow but real: it removes the "user entered the account on a setup that is broken RIGHT NOW and wastes a session / is confused about their state" case, by making the verify gate unavoidable. It does NOT add leak protection beyond the default-deny (a bypassed entry still lands in a denied/forced account). Weigh that modest benefit against the lock-out risk and the host-config departure before tasking. Prerequisite: verify must be reliable first (`fix-verify-probes-transparent-relay`).
