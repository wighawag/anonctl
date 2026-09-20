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
