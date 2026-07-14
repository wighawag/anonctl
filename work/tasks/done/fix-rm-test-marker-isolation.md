---
title: Fix TestRmDisablesShimBeforeUserdel - it hits the real /etc/anonctl marker, so main is RED off-root
slug: fix-rm-test-marker-isolation
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [22]
---

## What to build

`origin/main` is currently RED on a non-root box (and thus in the `do` acceptance gate and CI): `go test .` fails with

```
--- FAIL: TestRmDisablesShimBeforeUserdel
  main_test.go:264: run(rm --purge-account) = 1, want 0
anonctl: rm: removing marker: remove marker "/etc/anonctl/anon.json": remove /etc/anonctl/anon.json: permission denied
```

Root cause: a SHARED-WRITE-ISOLATION violation. `TestRmDisablesShimBeforeUserdel` stubs the forcing/userdel seams via `swapRmSeams` (rmForcingRemove / rmProvisionRm), but `runRm` ALSO removes the marker in step 3 via the REAL `marker.DefaultStore().Remove()` against the real `/etc/anonctl/<account>.json`. `swapRmSeams` does not isolate that path, so the test writes/deletes a real system path and fails with "permission denied" whenever it runs as non-root (the default `go test ./...` env, the runner's clean-worktree gate, and CI). It presumably passed when authored only because it was run as root / with `/etc/anonctl` absent.

This is a pre-existing landed bug (from the teardown-ordering task), and it BLOCKS everything: the runner's gate fails against the rebased tip for ANY task, so no task can currently pass the gate. Fix it so `go test ./...` is green off-root.

FIX: isolate the marker path in the test, the same way the marker's own tests already do (the marker Store has a `BaseDir` lever; production uses `/etc/anonctl`, tests point it at a `t.TempDir()`). Route `runRm`'s marker removal through an injectable seam (like `rmForcingRemove`/`rmProvisionRm`) OR make the marker Store `runRm` uses overridable in the test, and have `swapRmSeams` (or the test) point it at a scratch dir. After the fix, `TestRmDisablesShimBeforeUserdel` (and any sibling rm test) must:

- exercise the disable-before-userdel ORDERING (its actual purpose) WITHOUT touching the real `/etc/anonctl`,
- pass as a NON-root user in a plain `go test ./...`,
- assert (or at least not depend on) the real marker path being untouched.

Audit the other root-package `run(...)`-driving unit tests (main_test.go) for the same class of real-path/real-nft leak while here (e.g. any that call `run(["add"/"rm"/"verify"...])` without isolating the marker store / nft runner / account config path). Fix any that hit a real system path off-root; a unit test in the default suite must touch nothing outside its own temp fixtures.

## Acceptance criteria

- [ ] `go test ./...` (as a NON-root user, no special perms) is GREEN, including `TestRmDisablesShimBeforeUserdel`; the marker removal in `runRm` is isolated to a scratch dir in the test, never the real `/etc/anonctl`.
- [ ] The test still asserts its real purpose (the disable-shim event is recorded BEFORE the userdel-shim event at the runRm seam).
- [ ] Any sibling root-package unit test that drove `run(...)` into a real system path (marker `/etc/anonctl`, real `nft`, real account config) is likewise isolated; the default unit suite touches nothing outside temp fixtures (the WORK-CONTRACT shared-write isolation rule).
- [ ] `go vet ./... && go build ./... && go test ./...` green off-root.

## Blocked by

- None, can start immediately. (This unblocks the runner gate for every other task, so it should land first.)

## Prompt

> Goal: fix the pre-existing RED on main: `TestRmDisablesShimBeforeUserdel` hits the real `/etc/anonctl/<account>.json` marker (via runRm's step-3 marker.DefaultStore().Remove()), so `go test .` fails "permission denied" off-root - which fails the runner's acceptance gate for EVERY task. A shared-write-isolation violation.
>
> FIRST, read `main.go` `runRm` (step 3 removes the marker via marker.DefaultStore().Remove() - the unisolated real path), `main_test.go` `swapRmSeams` + `TestRmDisablesShimBeforeUserdel` (stubs rmForcingRemove/rmProvisionRm but NOT the marker store), and `internal/marker` (the Store.BaseDir lever its own tests use to isolate to t.TempDir()). Mirror that isolation.
>
> Fix: make the marker Store that runRm uses injectable (a package-level seam like rmForcingRemove, or a MarkerStore var defaulting to marker.DefaultStore()), and have the test point it at a t.TempDir() so no real /etc/anonctl write happens. Keep the test asserting the disable-before-userdel ordering. Then audit the other root-package run(...) unit tests for the same real-path/real-nft leak and isolate any that touch a real system path off-root.
>
> Where to test: `go test ./...` as a NON-root user must be green (that is the exact failing condition). "Done" = main is green off-root, TestRmDisablesShimBeforeUserdel still proves the ordering without touching /etc/anonctl, and no default-suite unit test writes outside temp fixtures. This unblocks the runner gate for all other work, so it lands first.
