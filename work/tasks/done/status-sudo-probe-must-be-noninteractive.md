---
title: provision sudoRights (used by `anonctl status`) must use `sudo -n` too - it can still pop a prompt
slug: status-sudo-probe-must-be-noninteractive
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [30]
---

## What to build

Close the sibling of the verify sudo-vector fix (`work/notes/observations/provision-sudo-probe-missing-n.md`): `internal/provision/provision.go` `sudoRights` (used by the `status`/provision side to report the sudo-absence invariant) runs `sudo -l -U <account>` WITHOUT `-n`:

```go
func sudoRights(ctx context.Context, r Runner, account string) sudoprobe.Verdict {
	stdout, stderr, _ := r.Run(ctx, "sudo", "-l", "-U", account)
	return sudoprobe.ParseOutput(stdout + "\n" + stderr)
}
```

Listing ANOTHER user's sudo privileges (`-U <account>`) requires the caller to be authorized, so on a desktop this can trigger a polkit/sudo password prompt exactly like the verify vector did (the v0.1.3/v0.1.4 GNOME popup). `anonctl status` (and any code path that calls sudoRights) can therefore still pop a dialog even after the verify fix.

FIX (mirror the verify fix, `sudoListCommand` in probes_live.go): run `sudo -n -l -U <account>`. The `-n` makes sudo print "a password is required" and return non-interactively instead of prompting when auth would be needed. `sudoprobe.ParseOutput` already maps that (neither "not allowed" nor "may run") to Unknown - the honest not-conclusive verdict, which SudoChecked/SudoAllowed already models (Unknown => SudoChecked=false). So a `-n`-blocked probe is surfaced as "not conclusively checked", never a false "has sudo" or false "no sudo".

## Acceptance criteria

- [ ] `sudoRights` runs `sudo -n -l -U <account>` (non-interactive); `anonctl status` (and add's sudo-absence surfacing) no longer pops a password/polkit prompt.
- [ ] The verdict still reads from the OUTPUT via `sudoprobe.ParseOutput`: a real grant => Granted, a "not allowed" => Denied, a `-n` auth-blocked "a password is required" => Unknown (which maps to SudoChecked=false, i.e. not conclusively checked), never a false has/no-sudo.
- [ ] No regression to the status/add sudo reporting: a genuinely no-sudo account still reports no sudo; a real grant still reports the warning.
- [ ] Unit test: `sudoRights` (via the injected Runner) issues `sudo -n -l -U <account>`; the password-required output maps to Unknown/not-checked. No real sudo / no prompt in the unit suite.
- [ ] The "no anonctl subcommand's sudo probe prompts for interactive auth" property now holds for BOTH verify (done) and status/provision (this task).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make `anonctl status`'s sudo-absence probe non-interactive, the sibling of the just-fixed verify sudo vector. `internal/provision/provision.go` `sudoRights` runs `sudo -l -U <account>` without `-n`, so it can pop a polkit/sudo prompt on a desktop. Source: `work/notes/observations/provision-sudo-probe-missing-n.md`.
>
> FIRST, read `internal/provision/provision.go` `sudoRights` (the `sudo -l -U`, no -n) and how SudoChecked/SudoAllowed map the Verdict (Unknown => SudoChecked=false), and mirror the verify fix `internal/verify/probes_live.go` `sudoListCommand` (which builds `sudo -n -l -U`). `sudoprobe.ParseOutput` already returns Unknown for "a password is required".
>
> Fix: add `-n` to the sudo -l call in sudoRights. Confirm the password-required case maps to Unknown (=> SudoChecked=false, honestly not-conclusive). Unit-test the argv via the injected Runner and the Unknown mapping. "Done" = `anonctl status` never prompts, the sudo-absence report is honest (Unknown when it can't list unattended), and a real grant/denial is still read correctly.
