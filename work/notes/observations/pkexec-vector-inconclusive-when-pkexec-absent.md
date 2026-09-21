---
title: The pkexec escape vector reports INCONCLUSIVE on a host with no pkexec at all, where it could be a conclusive no-escape
slug: pkexec-vector-inconclusive-when-pkexec-absent
---

Spotted while preparing the live acceptance on telemaque (NixOS), where neither `pkcheck` nor `pkexec` is installed. Not a leak and not a blocker: inconclusive is never counted as an escape, so `NoUIDTransitionEgressAssertion` still passes. But the output reads alarmingly on a stock NixOS box, and the asymmetry below looks unintended.

`internal/verify/probes_live.go` short-circuits the SUDO vector on binary absence, treating it as a conclusive no-escape:

```go
return UIDTransitionVector{Name: "sudo"} // no sudo binary: no sudo transition path here
```

The PKEXEC vector does not do the equivalent. It checks `setpriv`, then `pkcheck`, and if `pkcheck` is missing returns `Inconclusive: true` with "pkcheck not on PATH: the pkexec exec-action policy was not conclusively queried". It never asks whether **`pkexec` itself** exists. On a host with no `pkexec` binary there is definitively no pkexec escape path, so the honest answer is the same one the sudo vector gives: a conclusive no-escape.

So on NixOS without polkit, `anonctl verify` prints an inconclusive vector for an attack surface that is not present at all. The cautious direction is the right default, and "unknown is never reported as safe" is a deliberate and correct property of this verifier, so this is only worth changing if the absence of `pkexec` can be established as confidently as the absence of `sudo` is today.

Two reasons to be careful rather than just patching it:

1. `pkexec` absence must be established the same way `sudo` absence is (a `LookPath` on the probe's own `$PATH` is not necessarily the anon account's `$PATH`), or the fix would trade a noisy-but-safe answer for a quiet-and-wrong one. That is the exact trade this verifier exists to refuse.
2. The two pre-existing unit-test failures (`TestPkexecVector_AuthRequiredIsNotEscaped`, `TestPkexecVector_UnattendedAuthorizationIsEscaped`) fail on this box for the same root cause: they expect `pkcheck` to be resolvable and it is not. Any change here should make those tests hermetic (inject the lookup, as `systemd.Resolver` now does) rather than depend on host tooling. That is probably the more valuable half of the work.

Relevant because it will appear in every `anonctl verify` run on a NixOS host, and an operator reading it cold could reasonably mistake it for a real gap in coverage.

## Update 2026-09-21: the test half is done, the behaviour half is not

Point 2 above (make the tests hermetic) is closed. `internal/verify` now has a `lookPathBinary` seam, and `pkexecVector` + `sudoVector` resolve their guard binaries through it instead of calling `exec.LookPath` directly. Those two vectors already exec behind a seam (`runPkcheck` / `runSudoListCmd`), so the lookup was the single remaining host dependency in an otherwise pure decision, and it was the load-bearing one: on this box the vector short-circuited before `runPkcheck` was ever consulted, so the two tests that scripted `runPkcheck` were exercising nothing and failed on the short-circuit instead.

Three `t.Skip`s went with it (two on `setpriv`, one on `sudo`). Each was silently dropping coverage on a host that happened to lack the tool, which is the same class of problem as the tests that were failing: the suite's answer depended on what was installed.

The absence branches are now tested rather than skipped, which they never were before, and they are the branches that actually fire on a stock NixOS box:

- `TestPkexecVector_AbsentToolingIsInconclusiveWithoutRunningAnything`: with `setpriv` OR `pkcheck` unresolvable, the vector reports Inconclusive, names the missing tool, and **never consults the exec seam**. The seam is scripted to return the ESCAPE verdict, so the test fails if the guard ever lets it through. That is the property that guarantees no `pkexec` runs and no polkit dialog appears on a host that cannot pose the query.
- `TestSudoVector_NoSudoBinaryIsAConclusiveNoEscape`: pins the asymmetry this note is about as a DELIBERATE one, with the reason in the test comment, so a later reader meets it as a decision rather than as an inconsistency to tidy away.

All three are falsified against mutations (revert the seam; drop the short-circuit; make missing `sudo` inconclusive).

Point 1 (should a missing `pkexec` binary read as a conclusive no-escape, as a missing `sudo` does?) is **deliberately untouched**. It is a change to what the verifier CLAIMS, not to how it is tested, and this note's own caution stands: `pkexec` absence would have to be established as confidently as `sudo` absence is, on the anon account's `$PATH` rather than the probe's. Trading a noisy-but-safe answer for a quiet-and-wrong one is the exact trade this verifier exists to refuse. It now has a hermetic suite to be decided in, which was the point.
