---
kind: finding
title: verify's pkexec UID-transition probe must query polkit with pkcheck (non-interactive), not RUN pkexec - env-scrub does not stop the prompt
slug: pkexec-probe-must-use-pkcheck-not-run-pkexec
source: |
  Spiked on a real Linux desktop (the anonctl maintainer's host, a GNOME session
  with a registered polkit agent), 2026-07-09, after v0.1.3 and v0.1.4 STILL
  popped a GNOME polkit password dialog during `sudo anonctl verify` and the
  no-uid-transition-egress assertion still false-FAILED on setuid:pkexec when the
  operator authenticated. Every command below was run on that host; the mechanism
  claims are from the pkexec(1)/pkcheck(1) man pages + observed behaviour.
---

## What was wrong (why the v0.1.3 pkexec fix did not work)

The probe (`internal/verify/probes_live.go` setuidWrapperVector) RUNS pkexec:
`setpriv --reuid <anon> pkexec --disable-internal-agent id -u`, reads the euid,
and calls it an escape if the euid transitioned to a non-anon/non-shim uid.

v0.1.3 tried to make it non-interactive with `--disable-internal-agent` + scrubbing
`DBUS_SESSION_BUS_ADDRESS`/`XDG_RUNTIME_DIR`/`DISPLAY`/`WAYLAND_DISPLAY` from the env.
That did NOT stop the GUI prompt, because it targets the wrong mechanism:

- **polkit finds the authentication agent via `systemd-logind` (the caller's login SESSION), not via env vars.** The maintainer has a graphical logind session (`loginctl list-sessions` shows a seat0 user session). So even with the session-bus env scrubbed, pkexec asks polkitd, which locates the registered GNOME agent through the session and pops the dialog.
- **`--disable-internal-agent` only disables pkexec's OWN fallback textual agent**, not the session's registered agent. So it changes nothing about the GUI prompt.
- **`setpriv --reuid` changes the uid but does NOT leave the login session** (session membership is by cgroup/logind, not uid), so the agent is still found.

Confirmed empirically: `systemd-run --scope -- pkexec --disable-internal-agent id -u` still prompted (and escalated to uid 0 on auth). So neither env-scrub, nor --disable-internal-agent, nor a fresh transient scope suppresses the dialog.

Corollary: the assertion was also measuring the WRONG THING - it reported ESCAPED iff the OPERATOR authenticated the prompt, i.e. it measured the human's interactive auth, not the anon account's UNATTENDED capability. An automated process running as the anon account cannot satisfy a polkit prompt, so the real question is "can it escalate WITHOUT auth?".

## The correct mechanism: pkcheck (query the policy, never run pkexec)

`pkcheck` is polkit's non-interactive policy query. WITHOUT `--allow-user-interaction`/`-u` it NEVER starts an authentication agent and NEVER prompts (verified: ran it repeatedly, zero dialogs). Its exit code is exactly the signal the probe needs:

- **exit 0**: the subject is authorized for the action WITHOUT authentication. For `org.freedesktop.policykit.exec` that means the account could pkexec-to-root UNATTENDED - a REAL forcing bypass. -> Escaped=true.
- **exit 2**: "Authorization requires authentication and -u wasn't passed" (auth required, no interaction). -> NOT an unattended escape. -> Escaped=false. NO PROMPT.
- exit 1: not authorized; exit 3: dialog dismissed. Both -> not an unattended escape (no prompt).

Observed on the host: `pkcheck --action-id org.freedesktop.policykit.exec --process <pid>` -> "Authorization requires authentication and -u wasn't passed." exit=2, no dialog. That is the correct NO-unattended-escape reading for a normal desktop.

The right probe: run `pkcheck --action-id org.freedesktop.policykit.exec --process <pid>,<start>,<uid>` for an anon-owned subject (e.g. under `setpriv --reuid <anon>` so the querying process is anon-owned, then `--process $$`), map exit 0 -> escaped, non-zero -> not-escaped, never RUN pkexec, never start an agent, never prompt. pkcheck ships in the same polkit package as pkexec (Debian `polkitd`), so it is present whenever the pkexec vector is relevant.

## Note on the v0.1.4 `sudo -n` change

Separately, v0.1.4 added `-n` to the sudo probes (`sudo -n -l -U`). That was NOT the source of THIS popup (this is pkexec), but it was still a correct hardening: `sudo -l -U <other-user>` can genuinely prompt on some configs, and `-n` is the right non-interactive form. Keep it. The popup the maintainer saw across v0.1.3/v0.1.4 was always pkexec; the sudo fix closed a different latent prompt.

## Disposition

Fix the pkexec vector to use pkcheck (task `verify-pkexec-probe-uses-pkcheck`). Revert the ineffective env-scrub/--disable-internal-agent machinery for pkexec (it does nothing useful and implies a false guarantee). Keep the "no verify probe prompts" invariant - pkcheck satisfies it correctly where the run-pkexec approach could not.
