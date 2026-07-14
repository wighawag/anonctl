---
title: verify's sudo vector must use `sudo -n` - `sudo -l -U <account>` still pops a GNOME polkit prompt
slug: sudo-vector-must-be-noninteractive
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [30]
---

## What to build

Real-host v0.1.3: `sudo anonctl verify` now PASSES 9/9 (the pkexec probe fix worked), BUT it STILL pops a GNOME polkit/sudo password dialog during the run. The maintainer rejected it and verify still passed - so the prompt is a UX bug, not a correctness one, but a leak-test must NEVER prompt.

Root cause (the sibling of the pkexec fix, which this run missed): `internal/verify/probes_live.go` `runSudoList` runs `sudo -l -U <account>` WITHOUT `-n`. Listing ANOTHER user's sudo privileges (`-U <account>`) requires the CALLER to be authorized, and on a desktop that authorization goes through a polkit/sudo prompt (the GNOME popup) BEFORE any output is produced. The code ignores the exit code and reads the output via `sudoprobe.ParseOutput`, but the prompt fires during the `sudo -l -U` call itself.

FIX: run the sudo probe strictly non-interactively with `sudo -n`.

- Change `runSudoList` to `sudo -n -l -U <account>` (`-n` = non-interactive, no prompts). Confirmed behaviour: `sudo -n -l -U <user>` when auth is required prints `sudo: a password is required` and returns non-interactively, NEVER prompting; when no auth is needed it returns the privilege listing as before.
- Map the new output through `sudoprobe.ParseOutput` and ensure the "a password is required" (auth-blocked, couldn't list) case reads as **Unknown** - NOT a false Denied (which would hide a real sudo grant) and NOT a false Granted (a false alarm). `sudoprobe.ParseOutput` already returns Unknown for anything that is neither the "not allowed to run sudo" negative nor a "may run the following commands" grant, so "a password is required" should already fall to Unknown - VERIFY that, and if not, add the mapping (a `-n`-blocked probe is honestly not-conclusive, consistent with the best-effort framing of no-uid-transition-egress).
- **General guarantee (make it a real property):** `anonctl verify` must NEVER trigger an interactive password/polkit prompt for ANY probe. pkexec was fixed (--disable-internal-agent + scrubbed env); sudo is this task; audit that NO other verify probe can prompt (the setpriv/nft/curl/ping/shim-probe calls do not, but confirm). Consider a short comment/invariant in probes_live.go stating "no verify probe may prompt for interactive auth" so a future probe author preserves it.

## Acceptance criteria

- [ ] `runSudoList` uses `sudo -n -l -U <account>`; `sudo anonctl verify` no longer pops any password/polkit prompt for the sudo vector.
- [ ] The sudo vector still reads its verdict from the OUTPUT via `sudoprobe.ParseOutput`: a real grant => Granted (escape), a "not allowed" => Denied (no escape), and a `-n` auth-blocked "a password is required" => Unknown (honestly not-conclusive), never a false grant or false denial.
- [ ] `no-uid-transition-egress` still passes on a normal host (no false flag) and still catches a real unattended sudo grant.
- [ ] A confirmed invariant: NO `anonctl verify` probe triggers an interactive prompt (pkexec via --disable-internal-agent+scrub already; sudo via -n now; the rest audited). Record it as a short comment/note in probes_live.go.
- [ ] Unit tests: `runSudoList` builds `sudo -n -l -U <account>` (assert the argv via the injectable exec seam); `sudoprobe.ParseOutput("sudo: a password is required")` => Unknown (add the test if missing); the grant/denied cases still map correctly.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: stop `anonctl verify` popping a GNOME polkit/sudo password prompt. Real-host v0.1.3 passes 9/9 but still prompts - from the sudo vector, which runs `sudo -l -U <account>` WITHOUT `-n`, so listing another user's sudo privileges triggers an interactive authorization on a desktop. This is the sibling of the just-fixed pkexec prompt. Source: the maintainer's v0.1.3 run (9/9 PASS but a GNOME popup they rejected).
>
> FIRST, read `internal/verify/probes_live.go` `runSudoList` (`sudo -l -U`, no -n) and `sudoVector`, and `internal/sudoprobe/sudoprobe.go` `ParseOutput` (the Unknown/Denied/Granted tri-state; "anything else is Unknown"). Confirmed: `sudo -n -l -U <user>` when auth is required prints "sudo: a password is required" and does NOT prompt; without auth it lists privileges.
>
> Fix: add `-n` to the sudo -l invocation. Ensure the "a password is required" case reads as Unknown (it should already, via ParseOutput's default-Unknown; verify and add a test). Then audit that NO other verify probe can prompt (setpriv/nft/curl/ping/shim-probe do not; pkexec is already fixed) and record the "no verify probe prompts for interactive auth" invariant as a comment.
>
> Where to test: unit-test that runSudoList's argv is `sudo -n -l -U <account>` (via the injectable seam) and that ParseOutput("sudo: a password is required") is Unknown; no real sudo / no prompt in the unit suite. The live no-prompt behaviour is the real-host confirmation. "Done" = `sudo anonctl verify` runs to a full 9/9 with NO password dialog, the sudo vector is honestly Unknown when it cannot list unattended, and a real sudo grant is still caught.
