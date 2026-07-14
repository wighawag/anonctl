---
title: CLI verb skeleton + account and shim-UID provisioning (add / rm / list / status)
slug: account-provisioning-and-cli-skeleton
spec: per-uid-kernel-anonymized-egress
blockedBy: [manual-per-uid-recipe-validation]
covers: [1, 2, 3, 22]
---

## What to build

The Go CLI skeleton and the account-provisioning half of `add`/`rm`, plus read-only `list`/`status`. NO egress forcing yet (that is the nftables task), this delivers the account + shim-UID lifecycle and the verb surface end-to-end.

- A CLI whose verb dispatch mirrors netcage/anon-pi vocabulary: `add [<name>]`, `rm [<name>]`, `list`, `status`, plus stubs for `verify` and `update`/`reconfigure` (filled by later tasks). A bare name means the default `anon` account across every verb; a `<name>` means `anon-<name>`.
- `add [<name>]` (run as root): provision the dedicated Unix account (`anon` / `anon-<name>`) AND a distinct dedicated shim service UID for it (per the recipe validated in the manual task). Idempotent: re-running `add` on an existing account is a clean no-op or a clear "already exists".
- `rm [<name>]`: tear the account down (remove forcing hooks, a no-op until the nft/persistence tasks exist, and optionally the account, gated by an explicit flag so a bare `rm` does not silently delete a user's home).
- `list` / `status`: enumerate which anon accounts exist and their basic state, reading from what is actually on the box (accounts + later the marker), not a maintained index. Support `--json` on `status`.

## Acceptance criteria

- [ ] `add`, `rm`, `list`, `status` dispatch correctly; a bare name resolves to `anon`, `<name>` to `anon-<name>`.
- [ ] `add` provisions the account + a distinct dedicated shim UID; it is idempotent on re-run.
- [ ] `rm` removes the account only under an explicit opt-in flag; the bare form leaves the account's home intact.
- [ ] `status --json` emits machine-readable state; `list` shows the existing anon accounts.
- [ ] Tests cover the verb dispatch and name resolution (pure logic, no root) plus the account-provisioning logic behind an injectable seam (a Runner interface, mirroring netcage's `ExecRunner`), so the unit tests do NOT create real users.
- [ ] **Shared-write isolation:** any test that would touch real system account state runs behind the injected Runner against a fixture (no real `useradd`/`userdel`); a real-provisioning integration test (if any) sits behind the `integration` build tag and asserts it cleans up the account it made.

## Blocked by

- `manual-per-uid-recipe-validation`: encodes the validated account + shim-UID layout this task provisions.

## Prompt

> Goal: the anonctl CLI skeleton and the account + shim-UID provisioning behind `add`/`rm`, with read-only `list`/`status`. Stories 1, 2, 3, 22 of the `per-uid-kernel-anonymized-egress` prd. NO egress forcing here, that is `nftables-ruleset-install`.
>
> FIRST, check drift: read the recipe finding from `manual-per-uid-recipe-validation` (in `work/notes/findings/`) for the exact account + dedicated-shim-UID layout, and `work/specs/tasked/per-uid-kernel-anonymized-egress.md` for the verb vocabulary. If the recipe landed a different account/UID layout than assumed here, follow the recipe, not this prose.
>
> Domain vocabulary: `anon` is the default account, `anon-<name>` are named ones; anonctl OWNS this generic naming. Each account has its OWN dedicated shim UID (a separate service account) so that later only the shim UID, never the anon UID, may reach the upstream endpoint. anonctl APPLIES changes itself as root (the ufw stance), so provisioning runs privileged.
>
> Where to look: netcage (`~/dev/github/wighawag/netcage`) for the CLI structure and, crucially, its injectable `ExecRunner` seam (`internal/jail`) so system-mutating calls are unit-testable against a fixture without real mutation. Mirror that: put account/UID creation behind a Runner interface; unit tests use a fake, a real integration test sits behind an `integration` build tag.
>
> Seams to test at: verb dispatch + name resolution (pure, everywhere); provisioning behind the injected Runner (fake in unit tests). Do NOT create real Unix users in the default `go test ./...` run.
>
> "Done" = the four verbs work, name resolution is correct, provisioning is idempotent and isolated in tests, and `status --json` is machine-readable. RECORD any non-obvious in-scope decision (e.g. the exact rm-safety flag semantics) per the task-template guidance.
