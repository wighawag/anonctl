---
title: anonctl use [<name>] - verify-then-shell safe front door (refuse to shell in if not anonymized)
slug: anonctl-use-verify-then-shell
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

A new verb `anonctl use [<name>]` (bare = the default `anon` account): run `verify` for the account and, ONLY if it passes green, `exec` an interactive login shell as that account. If verify fails, refuse loudly with the failing assertions and do NOT shell in. This is the ergonomic safe front door: you get an anonymized shell or a clear error, never a silently-broken session.

- **Gate on verify:** reuse the existing verify path (`runVerify` returns an exit code; 0 = green). `use` runs it for the resolved account; on non-zero it prints the failing assertions and exits non-zero WITHOUT starting a shell.
- **Exec the account shell on green:** drop to the account and start its login shell (e.g. `setpriv --reuid/--regid/--init-groups` then the account's shell as a login shell, or `sudo -iu <account>` / `su - <account>` semantics - pick one, run as root). `exec` (replace the process) so the user is now IN the anon account's shell with the kernel forcing already in effect. On shell exit, `use` is done.
- **Honest scope (put this in the help text + docs, do NOT over-claim):** `use` is a CONVENIENCE + SAFETY gate at session start, NOT an enforcement and NOT what prevents leaks. Two things it deliberately does NOT do:
  - It is a SNAPSHOT: verify green at login does not guarantee forcing stays up for the whole session (Tor could die, someone could flush rules). The KERNEL rules are the protection; the standing per-UID default-deny (task `fix-boot-invariant-nftables-not-enabled`) is what makes "not forced = dropped". `use` just refuses to hand you a shell on a setup that is broken RIGHT NOW.
  - It is NOT mandatory: `su - <account>` / `sudo -iu <account>` / an SSH login / cron still reach the account and bypass `use`. Making the account usable ONLY through anonctl is a separate, invasive login-shell/PAM change tracked as the idea `mandatory-anonctl-gated-login`.

## Acceptance criteria

- [ ] `anonctl use [<name>]` resolves the account (bare = `anon`, `<name>` = `anon-<name>`), runs verify, and on GREEN execs an interactive login shell as that account with forcing in effect.
- [ ] On a RED verify, `use` prints the failing assertion(s) and exits non-zero WITHOUT starting any shell (you cannot get an un-anonymized shell via `use`).
- [ ] `use` requires root (it drops to the account); it fails loud if not root, like the other mutating-adjacent verbs.
- [ ] The help text + README state honestly that `use` is a session-start safety gate, NOT an enforcement (a snapshot, and bypassable by `su`/`sudo -iu`); the real protection is the kernel rules + the standing default-deny, and the mandatory-gate option is the `mandatory-anonctl-gated-login` idea.
- [ ] Tests cover the new behaviour: the verb dispatch + account resolution (unit); the verify-gate decision (green => would-exec, red => refuse-no-shell) behind an injectable exec seam so the unit test does NOT actually spawn a shell; the real drop-to-shell behind the `integration` tag, isolated.

## Blocked by

- None, can start immediately. (Pairs with `fix-verify-probes-transparent-relay`: `use` is only trustworthy once verify actually certifies a healthy account - note that in the done-record, but `use` can be built and unit-tested against the verify seam regardless.)

## Prompt

> Goal: add `anonctl use [<name>]` - a verify-then-shell safe front door that refuses to shell you into an account that is not currently anonymized. Maintainer request. It reuses the existing verify gate and execs the account's login shell only on green.
>
> FIRST, read `main.go` (the verb dispatch, `runVerify` which returns an exit code, `runStatus`, how root is required), `internal/cli/cli.go` (`Parse` + account resolution - add `use` as a verb taking an optional name), and `internal/provision` (the account layout, the shim UID). The account's egress is already forced by the kernel once `add` ran; `use` just gates entry on verify and drops you in.
>
> Domain vocabulary + HONESTY: `use` is a session-start CONVENIENCE + SAFETY gate, NOT enforcement and NOT the leak protection. It is a snapshot (verify at login, not continuous) and it is bypassable (`su`/`sudo -iu`/ssh/cron reach the account too). The REAL protection is the kernel forcing + the standing per-UID default-deny. Say this in the help + README; do not let `use` read as "the thing that keeps you safe". The mandatory-gate (login-shell/PAM) version is a separate idea (`mandatory-anonctl-gated-login`), not this task.
>
> Where to look / seams: verb dispatch + account resolution (unit-testable); the verify-gate decision behind an injectable exec seam (a fake in unit tests so it does NOT spawn a real shell - assert "green => exec attempted with the right account", "red => no exec, non-zero exit, failing assertions printed"); the real setpriv/su drop behind the `integration` tag, isolated. "Done" = `anonctl use` gives an anonymized shell on green and refuses (no shell) on red, with the honest scope in the docs. RECORD the shell-drop mechanism choice (setpriv vs su -) per the task-template guidance.
