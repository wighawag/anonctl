---
title: Harden the sudo-absence probe - do not trust `sudo -l -U` exit code alone (a lenient sudo build false-alarms)
slug: harden-sudo-absence-probe
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [30]
---

## What to build

Close the robustness gap noted in the second real-host re-validation (`work/notes/findings/e2e-binary-revalidation-2.md`): `internal/provision.sudoAllowed` decides whether an account has sudo rights from the `sudo -l -U <account>` EXIT CODE alone:

```go
func sudoAllowed(ctx context.Context, r Runner, account string) bool {
	_, _, err := r.Run(ctx, "sudo", "-l", "-U", account)
	return err == nil
}
```

On some sudo builds (observed: sudo 1.9.16p2 in a container sandbox) `sudo -l -U <no-rights-user>` exits 0 even when the account has NO sudo rights, so anonctl reads `SudoAllowed = true` (a false "can sudo"). Knock-on: `verify`'s `no-uid-transition-egress` and `status` report a sudo escape that is not real.

This FAILS SAFE (a false ALARM, loud, not a silent false-green), so it is NOT a security hole and was correctly out of scope for the two run-2 fixes. But it is a real correctness gap that will confuse operators on affected sudo builds, worth a small hardening.

FIX: decide sudo-absence from the OUTPUT, not the exit code alone. `sudo -l -U <account>` prints a clear negative ("User <account> is not allowed to run sudo on <host>." / "not allowed to run sudo") when the account has none, and lists permitted commands when it does. Parse for the not-allowed signal (and/or the presence of a "may run the following commands" list), so a lenient exit-0-on-no-rights build is read correctly. Keep it conservative: if the output is genuinely ambiguous or the probe could not run, prefer reporting UNKNOWN / not-checked over a false "has sudo" (do not swing to a false-negative that hides a real sudo path) - i.e. surface the ambiguity rather than guess either way.

## Acceptance criteria

- [ ] `sudoAllowed` (or its replacement) decides sudo-absence from the `sudo -l -U` OUTPUT (the "not allowed to run sudo" text / the permitted-commands listing), not the exit code alone, so a lenient sudo build that exits 0 for a no-rights account is read as NO sudo.
- [ ] A genuine sudo grant (a real permitted-commands listing) is still read as `SudoAllowed = true`.
- [ ] An ambiguous / unparseable / could-not-run result is surfaced as UNKNOWN / not-checked rather than a false "has sudo" (and never as a false "no sudo" that would hide a real escape).
- [ ] Unit tests cover: the not-allowed output (=> no sudo) incl. the exit-0 lenient case, a real grant (=> has sudo), and an ambiguous/empty output (=> unknown/not-checked); driven through the injected Runner with fixture `sudo -l -U` outputs (no real sudo).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make anonctl's sudo-absence detection robust to sudo builds where `sudo -l -U <no-rights-user>` exits 0. Source: `work/notes/findings/e2e-binary-revalidation-2.md` (the honest observation: sudoAllowed trusts the exit code alone, so a lenient sudo 1.9.16p2 reads a false "can sudo"). This is a correctness/robustness fix, not a security hole (it fails safe as a false alarm today).
>
> FIRST, read `internal/provision/provision.go` `sudoAllowed` (returns err==nil), and how `SudoChecked`/`SudoAllowed` feed `status` (main.go runStatus) and verify's `no-uid-transition-egress`. Read the audit finding `work/notes/findings/uid-transition-escape-surface.md` for the real `sudo -l -U` output shapes observed.
>
> Fix: parse the `sudo -l -U <account>` OUTPUT for the not-allowed signal ("not allowed to run sudo") and/or the permitted-commands listing, instead of trusting the exit code. Be conservative on ambiguity: surface UNKNOWN/not-checked rather than guess "has sudo" (a false alarm) OR "no sudo" (which would hide a real escape - worse). The SudoChecked/SudoAllowed pair already models "was it probed"; extend it if you need a third UNKNOWN state, or document how ambiguity maps onto the existing pair.
>
> Where to look / seams: it is all behind the provision Runner seam, so unit-test with fixture `sudo -l -U` outputs (the lenient exit-0 case, a real grant, the not-allowed text, an ambiguous blob) - no real sudo. "Done" = a lenient sudo build no longer false-alarms, a real grant is still caught, and ambiguity is surfaced not guessed. RECORD any non-obvious in-scope decision (the parse signals, the UNKNOWN mapping) per the task-template guidance.
