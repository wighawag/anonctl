---
title: The boot-invariant dial probe reads "could not run" as "did not reach", so the invariant passes without being tested
slug: boot-invariant-dial-probe-passes-when-it-could-not-run
---

Spotted 2026-09-21 while re-running the integration suite after the forcing-chain restructure. Pre-existing, NOT introduced by that change. Caught because the test PASSED in an environment where its probe provably cannot work.

`setprivDialReached` (`internal/systemd/boot_invariant_integration_test.go`) is the probe both directions of the boot invariant rest on:

```go
cmd := exec.CommandContext(ctx, "setpriv", "--reuid", strconv.Itoa(uid), "--clear-groups", bin, network, addr)
out, _ := cmd.CombinedOutput()          // <- error DISCARDED
return strings.Contains(string(out), "REACHED")
```

The exit status is discarded and the verdict is read purely from stdout. So ANY failure to run the probe -- `setpriv` refusing the uid, the built helper failing to exec, the context deadline firing, a missing binary -- produces output with no `REACHED` in it and returns `false`. The caller reads `false` as "the anon UID did not reach the destination", which is the PASSING direction:

```go
reached := setprivDialReached(t, ctx, anonUID, "tcp", "1.1.1.1:443")
if reached { t.Errorf("BOOT INVARIANT VIOLATED: ...") }
```

A probe that never ran therefore certifies the invariant. That is the exact discipline ADR-0003 mandates against ("a probe that could not run is NOT a pass") and the same class of bug as `work/tasks/done/fix-verify-counter-false-green.md`, where a swallowed nft counter-plant error made two `verify` assertions pass without probing anything.

Demonstrated: `TestBootInvariantAnonUIDHasNoDirectEgressBeforeShim` PASSES under `unshare -rn`, where uid 424250 is unmapped and `setpriv --reuid 424250` fails with `setresuid failed: Invalid argument`. Nothing was dialled, and the test reported the boot invariant as holding. The polarity is the dangerous one: it FALSE-GREENS, it does not false-fail.

The sibling check in the same file is affected identically -- the forcing-flushed re-probe at the "REPRODUCE THE ORIGINAL FAILURE'S STATE" step uses the same helper, so the post-reboot-leak regression proof has the same hole.

Fix shape: distinguish "could not run" from "did not reach". The probe helper already prints a `DROPPED:` token on a failed dial, so the honest contract is the one `verify`'s `probeAsAnon` already uses -- require one of `REACHED` / `DROPPED:` in the output and `t.Fatal` on neither, rather than inferring a verdict from the absence of a token. Keep the exit status and distinguish `ctx.Err() == context.DeadlineExceeded` from a genuine setpriv/exec failure, as `runSetprivProbe` does after `work/notes/findings/split-tunnel-broken-by-exemption-blind-baseline.md` (Bug 1).

Worth doing as its own task: it touches the trust anchor for the boot invariant, and the fix is the same one already applied twice elsewhere in this repo, so the third occurrence suggests the "absence of a success token means failure" pattern should be a reviewed idiom rather than re-derived per probe.
