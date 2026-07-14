---
title: Fix verify's sudoVector - it trusts the sudo exit code alone (the actual source of the no-uid-transition-egress false-alarm)
slug: fix-verify-sudovector-exit-code
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [30]
---

## What to build

Close the twin of the just-fixed provision sudo bug, on the VERIFY side (`work/notes/observations/verify-sudovector-exit-code-only.md`). `internal/verify/probes_integration.go` `sudoVector` decides whether the anon account can escape via sudo from the `sudo -l -U <account>` EXIT CODE alone (`... .Run(); err == nil => Escaped=true`). On a lenient sudo build that exits 0 for a no-rights account, this reports a FALSE sudo escape - and this is the ACTUAL root cause of the `no-uid-transition-egress` false-positive observed in `work/notes/findings/e2e-binary-revalidation-2.md` (the provision fix hardened `status`; this hardens the `verify` assertion the operator actually sees fail).

FIX: decide the sudo vector from the `sudo -l -U` OUTPUT, not the exit code, exactly as the provision side now does. Reuse the shared parse: `internal/provision` already has `parseSudoOutput` / the `sudoVerdict` tri-state (`sudoNone` / `sudoHas` / `sudoUnknown`). Route `sudoVector` through the same classification (export/reuse `parseSudoOutput`, or lift it to a shared spot both packages import - do not duplicate the parse). Map the verdict onto the UID-transition vector:

- `sudoNone` -> the sudo vector did NOT escape (Escaped=false).
- `sudoHas` -> the sudo vector ESCAPED (Escaped=true, a real sudo path off the anon UID).
- `sudoUnknown` -> do NOT report a false escape and do NOT silently pass: surface it honestly (e.g. the vector is reported as not-conclusively-checked, consistent with the best-effort framing of `no-uid-transition-egress`), never a false Escaped=true (a false alarm) nor a false Escaped=false that hides a real sudo path.

## Acceptance criteria

- [ ] `verify`'s `sudoVector` decides from the `sudo -l -U` OUTPUT (via the shared `parseSudoOutput` / `sudoVerdict`), not the exit code, so a lenient exit-0 no-rights sudo build no longer reports a false sudo escape.
- [ ] A real sudo grant is still reported as an escape (Escaped=true); an ambiguous/unparseable probe is surfaced honestly (not a false escape, not a silent pass), consistent with the best-effort framing of the assertion.
- [ ] The `no-uid-transition-egress` assertion no longer false-fails on a lenient sudo build with a genuinely no-rights anon account (the e2e-revalidation-2 symptom).
- [ ] The sudo output-parse is SHARED with the provision side (reused, not duplicated).
- [ ] Tests cover the vector decision: lenient exit-0 no-rights (=> no escape), a real grant (=> escape), an ambiguous blob (=> honest not-conclusive), through the injectable probe/exec seam (no real sudo).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: fix `verify`'s `sudoVector` to decide the sudo UID-transition vector from the `sudo -l -U` OUTPUT, not the exit code - the twin of the provision fix, and the actual source of the no-uid-transition-egress false-positive on lenient sudo builds. Source: `work/notes/observations/verify-sudovector-exit-code-only.md` + `work/notes/findings/e2e-binary-revalidation-2.md`.
>
> FIRST, read `internal/verify/probes_integration.go` `sudoVector` (the `err == nil => Escaped=true` exit-code decision), and `internal/provision/provision.go` `parseSudoOutput` + the `sudoVerdict` tri-state (sudoNone/sudoHas/sudoUnknown) that the provision task just added. Reuse that parse - export it or lift it to a small shared spot both import; do NOT duplicate the not-allowed / may-run signal matching.
>
> Domain vocabulary: `no-uid-transition-egress` is a BEST-EFFORT assertion over the enumerable UID-transition vectors; sudo is one vector. It must not report a false escape (a lenient exit-0 build) nor silently miss a real one. Map sudoNone => no escape, sudoHas => escape, sudoUnknown => honestly not-conclusive (consistent with best-effort), never a guess in either dangerous direction.
>
> Where to look / seams: the sudo probe is behind an exec/injectable seam - unit-test the vector decision with fixture `sudo -l -U` outputs (lenient exit-0 no-rights, a real grant, an ambiguous blob), no real sudo; the live probe stays integration-tagged. "Done" = a lenient sudo build no longer false-fails no-uid-transition-egress, a real grant is still caught, ambiguity is surfaced honestly, and the parse is shared with provision. This clears the last item from the e2e-revalidation-2 finding.
