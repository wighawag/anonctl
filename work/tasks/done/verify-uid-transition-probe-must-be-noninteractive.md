---
title: verify's UID-transition probe must be non-interactive - pkexec pops a polkit prompt and false-flags on operator auth
slug: verify-uid-transition-probe-must-be-noninteractive
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [30]
---

## What to build

Real-host v0.1.2 result: `sudo anonctl verify` PASSES 8/9 assertions (the whole fail-closed core), but `no-uid-transition-egress` FALSE-FAILS on `setuid:pkexec`. Root cause: the probe runs `setpriv --reuid <anon> pkexec id -u` inheriting the operator's session, so **pkexec pops a GNOME polkit password dialog**. The maintainer confirmed the behaviour empirically: when they AUTHENTICATED the prompt, the probe read euid 0 and reported ESCAPED; when they REFUSED it, pkexec did NOT escalate. So the "escape" the probe measured was the OPERATOR's interactive authentication, NOT a property of the anon account.

That is the wrong thing to measure. A `verify` leak-test must answer "can the anon account escape forcing UNATTENDED (without a human authorizing)?", because an automated/background process running as the anon account cannot satisfy a polkit prompt. A probe that (a) triggers an interactive password dialog during `verify` and (b) reports a leak IFF a human happens to authenticate it is both a UX bug (verify should never prompt) and a CORRECTNESS bug (it false-flags a host where the account has no unattended escape).

FIX: make the UID-transition probes strictly NON-INTERACTIVE, so they measure unattended escape capability and never prompt.

- For **pkexec** specifically: invoke it so it CANNOT reach an authentication agent - `pkexec --disable-internal-agent <cmd>` AND run it in an environment with no session polkit agent reachable (clear `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`, `DISPLAY`, `WAYLAND_DISPLAY` in the probe's env). Confirmed behaviour: `env -u DBUS_SESSION_BUS_ADDRESS pkexec --disable-internal-agent <cmd>` fails with "Request dismissed" WITHOUT prompting. So the probe runs pkexec unattended: if it still escalates (a NOPASSWD/allow-any polkit policy), that is a REAL unattended escape (Escaped=true, correctly flagged); if it cannot authenticate unattended (the normal case, including the maintainer's host), it did NOT escape (Escaped=false, no prompt, no false flag).
- **Generalise the principle** to the whole `no-uid-transition-egress` probe set: NO probe may block on or trigger interactive authentication. Run each uid-transition wrapper in a scrubbed, non-interactive env (no agent, no tty-stealing). The sudo vector already reads `sudo -l -U` output (non-interactive) - keep it that way; ensure nothing in the vector set can pop a prompt.
- **Honesty preserved:** if a probe genuinely cannot determine escape unattended, it is Unknown/not-conclusive per the existing best-effort framing, never a guess. A real unattended escape (a permissive polkit rule that lets the anon account pkexec-to-root with no auth) MUST still be caught and flagged - do not neuter the detection, just stop measuring the operator's interactive auth.

## Acceptance criteria

- [ ] `sudo anonctl verify` NEVER triggers an interactive password/polkit prompt (GUI or CLI) for any UID-transition probe; the pkexec probe runs with `--disable-internal-agent` and a scrubbed env (no DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR / DISPLAY / WAYLAND_DISPLAY) so it fails unattended instead of prompting.
- [ ] On a host where pkexec requires interactive auth (the normal desktop case), `no-uid-transition-egress` reports the pkexec vector as NOT escaped (no false flag), because unattended pkexec cannot escalate.
- [ ] A genuinely permissive policy (pkexec-to-root with NO authentication, e.g. a NOPASSWD-style polkit rule) is STILL caught as a real escape (Escaped=true) - the detection is not neutered, only the operator-auth false-positive is removed.
- [ ] No UID-transition probe blocks on or triggers interactive authentication; each runs non-interactively in a scrubbed env.
- [ ] Unit tests cover: the pkexec probe is invoked with the non-interactive flag + scrubbed env (assert the exec'd argv/env via the injectable seam), an unattended-fail reads as not-escaped, and a (fixtured) unattended-escalation reads as escaped. No real pkexec / no prompt in the unit suite.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make `anonctl verify`'s no-uid-transition-egress probe strictly NON-INTERACTIVE, so it measures whether the anon account can escape forcing UNATTENDED and never pops a polkit prompt. Real-host bug (v0.1.2): the pkexec probe inherits the operator's session, pops a GNOME password dialog, and reports ESCAPED iff the operator authenticates it - measuring the operator's interactive auth, not the account's capability. Confirmed: refusing the prompt = no escalation.
>
> FIRST, read `internal/verify/probes_live.go`: `setuidWrapperVector` (runs `setpriv --reuid <anon> <wrapper> id -u` and reads the euid) and `setuidNetworkWrappers` (= pkexec, mullvad-exclude) and `uidTransitionVectors`. The bug is that pkexec here can reach the session polkit agent. Note the audit finding `work/notes/findings/uid-transition-escape-surface.md` already observed pkexec is a no-escape in the unattended/no-agent case - the probe must reproduce THAT, not the interactive case.
>
> Fix: for pkexec, exec `pkexec --disable-internal-agent id -u` with a scrubbed env (drop DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR, DISPLAY, WAYLAND_DISPLAY) so it fails "Request dismissed" unattended instead of prompting. Generalise: no uid-transition probe may trigger interactive auth; run each in a scrubbed non-interactive env. Keep detection of a REAL unattended escape (a permissive/NOPASSWD polkit rule that escalates with no auth) - only remove the operator-auth false-positive. Preserve the best-effort/Unknown honesty framing.
>
> Where to test: the pkexec exec (argv + env scrubbing) is behind the injectable exec seam - unit-test that it passes --disable-internal-agent and the scrubbed env, that an unattended-fail is not-escaped, and a fixtured unattended-escalation is escaped. No real pkexec / no prompt in unit tests. The live behaviour (no prompt on a real `sudo anonctl verify`) is the real-host confirmation. "Done" = verify never prompts, the pkexec false-flag is gone on a normal desktop, and a genuine unattended escape is still caught.
