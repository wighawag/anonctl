---
title: Fix the minor e2e-validation gaps (leaked test seam, teardown residue, cosmetic message)
slug: fix-e2e-minor-gaps
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [22]
---

## What to build

Close BUGS 3, 4, 5 from the e2e validation (`work/notes/findings/e2e-binary-validation.md`) - the minor/test-only gaps. Three small, independent fixes:

- **BUG 3 (test-only, leaked global seam):** the unit suite's `TestMain` (`internal/provision`) sets `provision.WriteLoginEnv = <no-op>` and never restores it. Under `-tags integration` that stub is shared into the integration test, so the real login-env writer never runs and `TestRealProvisionRoundTrip`'s `.profile` PATH assertion always fails. The PRODUCT is correct (a real `anonctl add` writes the managed `.profile`). FIX: restore the seam in the unit `TestMain` (defer/cleanup), or move the neutralisation into only the specific unit tests that need it, so the integration test exercises the REAL writer and `TestRealProvisionRoundTrip` passes.

- **BUG 4 (teardown residue):** after `--purge-account` of the LAST account, `/etc/systemd/system/anonctl-shim@.service` and empty `/etc/anonctl/{shim,nftables,accounts}` remain. DECIDE and implement one: either (a) the last-account teardown removes the shared template unit + empty dirs (fully clean), or (b) it is documented as intended shared infrastructure that persists. Pick one with a one-line rationale; if (a), make it robust to multiple accounts (only remove when the LAST account goes).

- **BUG 5 (cosmetic):** `anonctl add`'s success message renders `run \`anonctl verify \` to prove ...` with a trailing space where the empty default-account name goes (`verify ` not `verify`). FIX the formatting so the default account prints `anonctl verify` with no trailing space, and a named account prints `anonctl verify <name>`.

## Acceptance criteria

- [ ] BUG 3: the leaked `WriteLoginEnv` stub is restored/scoped so `internal/provision`'s `TestRealProvisionRoundTrip` (under `-tags integration`) exercises the real writer and passes; the unit tests that needed the no-op still work.
- [ ] BUG 4: last-account `--purge-account` teardown either removes the shared template unit + empty `/etc/anonctl/*` dirs, or documents them as intended shared state - decided and implemented, robust to the multi-account case.
- [ ] BUG 5: the `add` success message prints `anonctl verify` (default) / `anonctl verify <name>` (named) with no stray trailing space; a test covers the rendering.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style; any system-mutating part behind the `integration` tag, isolated).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: clear the three minor gaps from `work/notes/findings/e2e-binary-validation.md` (BUGS 3/4/5). All small and independent.
>
> FIRST, read BUGS 3/4/5 in the finding. Then: BUG 3 -> `internal/provision` unit `TestMain` (the leaked `WriteLoginEnv` no-op) + `TestRealProvisionRoundTrip`; BUG 4 -> the teardown path in `internal/forcing` / `internal/systemd` / the `rm --purge-account` handler in `main.go` (where the shared template unit + `/etc/anonctl` dirs are/aren't removed); BUG 5 -> the `add` success-message rendering in `main.go`.
>
> For BUG 4, make a deliberate call (remove-when-last vs document-as-shared) and record the one-line rationale; if removing, guard it so a purge of ONE account among several does not rip out shared infra the others need.
>
> Where to look / seams: unit tests for the message rendering + the seam restoration; the teardown behaviour behind the `integration` tag, isolated. "Done" = TestRealProvisionRoundTrip passes under -tags integration, teardown residue is resolved per your decision, and the add message has no trailing space. RECORD the BUG 4 decision per the task-template guidance.
