---
title: Make verify and use WORK in the released binary (the live probes are wrongly gated behind -tags integration)
slug: verify-and-use-work-in-the-released-binary
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [15, 16, 17, 18, 25]
---

## What to build

The released `anonctl` binary CANNOT verify or `use` an account. Real symptom (v0.1.1, on a real host with Tor up and an account provisioned):

```
$ sudo anonctl use
[FAIL] live-verify-available: this anonctl binary was built WITHOUT the live-verify probes...
anonctl: use: anon did NOT verify as anonymized; refusing to open a shell
```

Root cause: the `integration` build tag is being used for TWO different things, and the second is wrong:
1. Gating slow/privileged TEST FILES so `go test ./...` / CI skip them - CORRECT, that is what the tag is for.
2. Gating the PRODUCT'S live-probe code (`checks_integration.go`, `probes_integration.go`, `use_exec_integration.go`) so the live verify/shell-drop exists ONLY in an `integration`-tagged binary - WRONG. goreleaser / `go install` / any normal build produce a NON-integration binary, so the shipped tool's `verify` always returns the `live-verify-available` FAIL stub and `use` always refuses. verify is the product's trust anchor and use gates on it, so BOTH are dead on arrival for every user.

The live probing (`setpriv` + `nft` + dialing the endpoint) is RUNTIME BEHAVIOUR that needs root, NOT a test. It belongs in the normal binary and should fail at RUNTIME when it lacks root / the endpoint / a needed tool - exactly like `add`/`rm` already do. Fix:

- **Un-gate the product probe code:** remove `//go:build integration` from `internal/verify/checks_integration.go`, `internal/verify/probes_integration.go`, and `use_exec_integration.go` (rename them to non-`_integration` names, e.g. `checks_live.go` / `probes_live.go` / `use_exec.go`, so the filename does not imply a tag). They are now compiled into EVERY build.
- **Delete the stubs:** `internal/verify/checks_default.go` (the `live-verify-available` FAIL) and `use_exec_default.go` (the shell-drop refusal). The real code is now always present.
- **Keep the `integration` tag on the TEST files ONLY** (`*_integration_test.go` everywhere, and `main_integration_test.go`, `rm_teardown_integration_test.go`, `use_integration_test.go`) - those SHOULD stay gated so `go test ./...` / CI still skip the slow/privileged tests. Do NOT un-gate any `_test.go`.
- **Runtime tool dependency, fail LOUD not silent:** the live probes shell out to `setpriv`, `nft`, `curl`, `ping`. Accept that `anonctl verify`/`use` require those on the host (near-universal on a systemd Linux host; `add` already needs `nft`/`useradd`). Where a tool is MISSING or the probe cannot run, the assertion must FAIL LOUD ("need <tool> on PATH to run the <name> probe"), never silently pass and never silently skip - the existing "a probe that could not run is not a pass" discipline must hold (a missing tool is a failing assertion, exactly as a real leak is; verify still exits non-zero, and use still refuses on a non-green verify - but for an HONEST reason, not "this binary can't verify at all").
- **CRITICAL sub-problem - the runtime `go build`:** `probes_integration.go`'s probe helper currently COMPILES a tiny Go dialer at runtime (`buildProbeHelper` -> `exec.Command("go", "build", ...)`) and runs it under `setpriv`. A released binary CANNOT assume a Go toolchain on the user's host, so this must go. Reuse the already-installed static shim binary as the probe executable instead: add a hidden `probe` subcommand/mode to `cmd/anonctl-shim` (e.g. `anonctl-shim -probe <network> <addr>` that dials with a timeout and prints REACHED/DROPPED, mirroring the current `probeSource`), and have `runSetprivProbe` exec `setpriv ... <shim-path> -probe ...` (the shim is at internal/systemd.DefaultShimBinaryPath, already static and installed). No `go build` at runtime. (Alternative: a separate tiny static helper binary shipped alongside - but reusing anonctl-shim avoids a third binary.)

## Acceptance criteria

- [ ] A DEFAULT `go build` of anonctl (no `-tags integration`) produces a binary whose `sudo anonctl verify` actually RUNS the live probes (anonymized-exit, dns-remote, leak-drop-v4/v6, both closures, icmp, non-tcp-udp, no-uid-transition, split-tunnel) against a provisioned account, and `sudo anonctl use` reaches a GREEN verify and drops a shell - NO `live-verify-available` stub, NO shell-drop refusal.
- [ ] The runtime `go build` of a probe helper is GONE: the live probe execs the installed static shim binary (a `probe` mode) under setpriv, so no Go toolchain is needed on the user's host.
- [ ] A missing external tool (`setpriv`/`nft`/`curl`/`ping`) or an un-runnable probe FAILS the relevant assertion LOUD (naming the tool), never a silent pass or a silent skip; verify still exits non-zero and use still refuses on a genuinely non-green verify.
- [ ] The `integration` tag remains on the TEST files only; `go test ./...` still skips the slow/privileged tests, and `go test -tags integration ./...` still runs them (they still compile - update any test that referenced the now-renamed product files).
- [ ] `go vet ./... && go build ./... && go test ./...` is green; the unit suite still proves the pure assertion decisions against the socks5h fixture.
- [ ] The README's verify/use sections stop implying you must rebuild with `-tags integration` to verify/use (that was the bug); they state verify/use need root + the endpoint up + the standard tools, and run in the normal binary.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make `anonctl verify` and `anonctl use` actually work in the RELEASED binary. They are dead on arrival today because the product's live-probe code is compiled only under `-tags integration`, and goreleaser/`go install` ship a non-integration binary, so verify returns a `live-verify-available` FAIL stub and use refuses. This is a build-tag CONFLATION: the tag should gate slow/privileged TEST FILES, never the product's runtime probing (which is root-requiring runtime behaviour like add/rm, not a test). Source: the user report + `internal/verify/checks_default.go` / `checks_integration.go` / `use_exec_default.go` / `use_exec_integration.go`.
>
> FIRST, read: `internal/verify/checks_default.go` (the FAIL stub) + `checks_integration.go` + `probes_integration.go` (the real probes, gated), `use_exec_default.go` (the shell-drop refusal) + `use_exec_integration.go` (the real drop, gated), and note `probes_integration.go`'s `buildProbeHelper` which runs `go build` AT RUNTIME (must be removed). Read `cmd/anonctl-shim/main.go` (flag-based CLI, the static binary at internal/systemd.DefaultShimBinaryPath - reuse it as the probe executable) and `internal/verify/verify.go` (the pure assertion DECISIONS stay; only the live PROBING moves).
>
> Do: un-gate the three product files (rename off the `_integration` suffix), delete the two stubs, keep `integration` on all `*_test.go`, replace the runtime `go build` probe helper with a `probe` mode on the installed static shim binary exec'd under setpriv, and make a missing tool / un-runnable probe a LOUD failing assertion (not a silent pass, not a silent skip - the "a probe that could not run is not a pass" contract). Fix the README verify/use sections. Keep the unit suite (pure decisions vs the fixture) green and the `-tags integration` tests compiling.
>
> Where to test: `go build ./...` (default) must yield a binary whose verify RUNS the probes (the real proof is a root host with Tor - flag that a real-host re-validation is the final gate, like the e2e runs); `go test ./...` green; `go test -tags integration ./...` still compiles + runs on a capable host. "Done" = a normally-built anonctl verifies and uses a real account, no `-tags integration` rebuild needed, missing tools fail loud, no runtime go-build. This is the fix that makes the shipped tool actually usable; do it carefully.

## Requeue 2026-07-09

The gate failure was NOT your change: main was pre-existing RED (TestRmDisablesShimBeforeUserdel hits the real /etc/anonctl marker off-root). That is being fixed by fix-rm-test-marker-isolation. Once it lands, your un-gating work will re-run against a green main.
