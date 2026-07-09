---
title: anonctl should self-elevate via sudo re-exec (CLI password prompt) instead of requiring a manual `sudo` prefix
slug: self-elevate-via-sudo-reexec
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

Root-requiring verbs (`add`, `rm`, `update`/`reconfigure`, `verify`, `use`) currently make the operator type `sudo anonctl ...`; running them without root just errors ("must be root ... re-run with sudo"). Make anonctl ask for the password ITSELF, in the CLI, so a bare `anonctl verify` works.

The RIGHT mechanism (NOT pkexec - that pops the GNOME polkit GUI dialog we deliberately avoid, see `work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md`): **re-exec via `sudo`.** `sudo` on a TTY prompts for the password INLINE in the terminal (it only uses a GUI askpass when there is no tty), which is exactly the CLI prompt the operator wants.

- **On a root-requiring verb, if `os.Geteuid() != 0`:** re-exec the SAME command through sudo - `sudo <self> <original-args...>` - preserving argv, then hand off (exec-replace the process, or run + propagate the exit code). sudo prompts on the tty; on success the elevated anonctl runs the verb.
- **No double-sudo:** if already root (euid 0, e.g. the operator DID type `sudo anonctl`), do NOT re-exec - run directly. The re-exec is only the not-root path.
- **Only for verbs that need root:** `list` and `status` are read-only (status needs no root for its read; if a specific field needs root, degrade gracefully, do not force elevation for a read verb). `--version`/`version` never elevate. Elevate for add/rm/update/verify/use.
- **Predictable + honest:** print a short line to stderr before re-exec (e.g. `anonctl: <verb> needs root; re-running via sudo...`) so it is not a surprise that a password is being asked. Resolve `sudo` on PATH; if sudo is absent, fall back to today's clear "must be root" error (do NOT try pkexec).
- **Preserve the contract:** the re-exec must pass ALL original args (flags, account name, `--json`, `--endpoint`, `--allow-direct`, etc.) unchanged, and propagate the child's exit code exactly (so `verify` still exits non-zero on a failing assertion, CI-gating intact). `--json` output must remain clean (the "re-running via sudo" notice goes to STDERR, never stdout).
- **Guard against a re-exec loop:** ensure the re-exec cannot recurse (it only fires when euid != 0, and after sudo the child is euid 0, so it will not re-fire - but add a belt-and-suspenders guard, e.g. an env sentinel like ANONCTL_ELEVATED=1, so a misconfigured sudo can never infinite-loop).

## Acceptance criteria

- [ ] A bare `anonctl verify` (non-root) re-execs via `sudo anonctl verify`, sudo prompts for the password IN THE TERMINAL (not a GUI dialog), and on success the verb runs; the child's exit code is propagated exactly.
- [ ] `sudo anonctl verify` (already root) runs directly with NO re-exec (no double-sudo).
- [ ] All original args are preserved across the re-exec (flags, account, --json, --endpoint, --allow-direct); `--json` stdout stays pure JSON (the sudo notice is on stderr).
- [ ] `list`/`status` do not force elevation (read verbs); `--version` never elevates; add/rm/update/verify/use do.
- [ ] If `sudo` is not on PATH, anonctl falls back to the current clear "must be root" error (never pkexec, never a GUI prompt).
- [ ] A re-exec loop is impossible (an ANONCTL_ELEVATED=1-style sentinel or equivalent guard); a test asserts the guard.
- [ ] Tests: not-root + root-requiring verb => a `sudo <self> <args>` re-exec is attempted (assert argv via the injectable exec seam, no real sudo); already-root => no re-exec; read verbs / --version => no re-exec; exit-code propagation; the loop guard.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: let a bare `anonctl verify` (and add/rm/update/use) ask for the password in the CLI itself, instead of requiring the operator to type `sudo anonctl`. The right mechanism is re-exec via `sudo` (which prompts inline on a tty), NOT pkexec (which pops the GNOME dialog we avoid). Maintainer request.
>
> FIRST, read `main.go`: the verb dispatch, the root checks (`os.Geteuid`/the "must be root" errors in runVerify/runAdd/runRm/use), and the `--json` handling (the sudo notice must not pollute --json stdout). Note the pkexec finding (`work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md`) for WHY not pkexec.
>
> Implement: at dispatch, for a root-requiring verb when euid != 0, print a stderr notice and re-exec `sudo <self-path> <original os.Args[1:]>` (find self via /proc/self/exe or os.Executable), propagating the child exit code exactly; guard against recursion with an env sentinel (e.g. ANONCTL_ELEVATED=1) so it can never loop. Already-root => run directly. Read verbs (list/status) and version never elevate. sudo-missing => the current clear "must be root" error, never pkexec.
>
> Where to test: behind an injectable exec/geteuid seam - assert not-root+verify => `sudo <self> verify` argv (no real sudo, no prompt in tests), already-root => direct, read verbs/version => no re-exec, exit-code propagation, and the loop guard. "Done" = `anonctl verify` prompts for the password in the terminal and runs; `sudo anonctl verify` still works with no double-prompt; --json stays clean; no possible re-exec loop.
