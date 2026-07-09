---
title: verify's pkexec probe must query polkit with pkcheck (non-interactive), not RUN pkexec - the real prompt fix
slug: verify-pkexec-probe-uses-pkcheck
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [30]
---

## What to build

Implement the fix the spike found (`work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md`): the pkexec UID-transition probe RUNS pkexec, which pops a GNOME polkit password dialog on a desktop and false-flags when the operator authenticates. The v0.1.3 `--disable-internal-agent` + env-scrub did NOT work, because polkit finds the auth agent via systemd-logind (the login session), not env vars. Confirmed on a real host: pkexec still prompts + escalates on auth regardless of the scrub.

FIX: do NOT run pkexec. Query polkit non-interactively with `pkcheck` for the exec action, so the probe measures whether the anon account could pkexec-to-root UNATTENDED (the real threat), never starting an auth agent, never prompting.

- Replace the pkexec branch of the setuid-wrapper probe: instead of `setpriv --reuid <anon> pkexec ... id -u`, run `pkcheck --action-id org.freedesktop.policykit.exec --process <pid>,<start>,<uid>` for an ANON-OWNED subject. The simple robust way: run `pkcheck` UNDER `setpriv --reuid <anon>` and pass `--process $$` (self), so the queried subject is anon-owned. Do NOT pass `--allow-user-interaction`/`-u` (that is what would start an agent + prompt).
- Map the exit code (from the finding + pkcheck(1)):
  - **exit 0** => authorized WITHOUT auth => the anon account can pkexec-to-root unattended => `Escaped=true` (a real forcing bypass, correctly flagged).
  - **exit 2** (auth required, no interaction) / **exit 1** (not authorized) / **exit 3** (dismissed) => NOT an unattended escape => `Escaped=false`, NO prompt.
  - pkcheck missing / un-runnable => the vector is not conclusively checked (consistent with best-effort framing), NOT a false escape and NOT a false pass.
- **Remove the ineffective machinery:** delete `--disable-internal-agent` + the `pkexecScrubbedEnvVars` scrub for pkexec (they do nothing useful and imply a false guarantee). Keep the general non-interactive INVARIANT comment; pkcheck satisfies it correctly.
- **Keep the other vectors as-is:** sudo already uses `sudo -n` (v0.1.4, correct); mullvad-exclude runs the target as the caller (no agent). Only the pkexec vector changes to the pkcheck query.
- **pkcheck availability:** it ships in the same polkit package as pkexec (Debian polkitd), so it is present whenever pkexec is. If pkexec is present but pkcheck is not (unusual), report the vector as not-conclusively-checked (do not fall back to RUNNING pkexec).

## Acceptance criteria

- [ ] `sudo anonctl verify` does NOT pop any polkit/password dialog for the pkexec vector (nor any other); the pkexec vector runs `pkcheck` (no -u), never `pkexec`.
- [ ] On a normal desktop where pkexec-to-root requires authentication, `no-uid-transition-egress` reports the pkexec vector as NOT escaped (pkcheck exit 2) - the v0.1.3/v0.1.4 false-FAIL is gone.
- [ ] A host whose polkit policy allows the exec action WITHOUT auth (pkcheck exit 0) is STILL flagged as a real unattended escape (Escaped=true) - detection preserved.
- [ ] pkcheck missing/un-runnable => the vector is not-conclusively-checked, never a false escape or false pass.
- [ ] The dead `--disable-internal-agent` + pkexecScrubbedEnvVars machinery is removed; the "no verify probe prompts for interactive auth" invariant still holds (now correctly, via pkcheck).
- [ ] Unit tests: the pkexec vector builds the pkcheck query (assert the argv via the injectable exec seam), exit 0 => escaped, exit 2/1/3 => not escaped, pkcheck-missing => not-conclusive. No real pkexec/pkcheck, no prompt in the unit suite.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: stop `sudo anonctl verify` popping a polkit password dialog (it still does on v0.1.4) and stop the pkexec vector false-flagging. The v0.1.3 fix (--disable-internal-agent + env scrub) was the WRONG mechanism: polkit finds the agent via systemd-logind, not env, so pkexec still prompts. The correct fix is to QUERY polkit with pkcheck instead of RUNNING pkexec. Source: `work/notes/findings/pkexec-probe-must-use-pkcheck-not-run-pkexec.md` (the spike, with observed exit codes).
>
> FIRST, read that finding (the mechanism + the pkcheck exit-code mapping), then `internal/verify/probes_live.go`: setuidWrapperVector / setuidWrapperCommand / pkexecScrubbedEnvVars (the pkexec branch to replace) and how UIDTransitionVector.Escaped is set + fed to NoUIDTransitionEgressAssertion.
>
> Replace the pkexec branch: run `pkcheck --action-id org.freedesktop.policykit.exec --process $$` UNDER `setpriv --reuid <anon>` (anon-owned subject), no --allow-user-interaction. Map exit 0 => Escaped=true (unattended escalation allowed = real bypass), exit 2/1/3 => Escaped=false (auth required = no unattended escape, no prompt), pkcheck-missing => not-conclusive. Remove the dead --disable-internal-agent + env-scrub. Keep sudo (-n) and mullvad-exclude unchanged.
>
> Where to test: the pkcheck exec (argv + setpriv wrap) behind the injectable seam - unit-test the argv, the exit-0=>escaped / exit-2=>not-escaped / missing=>not-conclusive mapping. No real pkexec/pkcheck, no prompt in the unit suite. The live no-prompt + correct-verdict behaviour is the real-host confirmation. "Done" = verify never prompts, the pkexec vector reads not-escaped on a normal desktop (via pkcheck exit 2), and a genuine no-auth exec policy is still caught (exit 0).
