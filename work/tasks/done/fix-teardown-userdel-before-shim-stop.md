---
title: Fix teardown regression - rm --purge-account userdels the shim account before stopping its unit, aborting cleanup
slug: fix-teardown-userdel-before-shim-stop
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [22]
---

## What to build

Close the SERIOUS teardown regression found in the real-host re-validation (`work/notes/findings/e2e-binary-revalidation.md`): `anonctl rm --purge-account` on the last account ABORTS and leaves major residue.

Root cause: `provision.Rm` runs `userdel` on the shim service account WHILE the shim systemd unit is still running as that account. `userdel` refuses ("user <shim> is currently used by process"), returns an error, and the whole last-account cleanup path never completes - leaving the shim unit, the nft tables, `/etc/anonctl`, and the shared units behind (the exact residue BUG 4's fix was supposed to prevent, now defeated by the ordering).

FIX: order teardown so the shim unit is STOPPED before its account is removed. Correct sequence for `rm` (and `--purge-account`):

1. `systemctl disable --now anonctl-shim@<account>.service` (stop + disable the shim instance) FIRST, so nothing is running as the shim UID.
2. Remove the forcing + baseline nft tables, the account's config/marker, the persisted rule files.
3. On `--purge-account`: THEN `userdel` the login account and the shim account (now that no process holds the shim UID).
4. On the LAST account: remove the shared template unit + anonctl-nftables.service + empty `/etc/anonctl` dirs (the BUG 4 cleanup - which currently never runs because step 3 aborts).

Make each step robust: a teardown should proceed as far as it can and report what it could not remove, rather than aborting the whole cleanup on the first error (a half-torn-down account is worse than a fully-reported partial). At minimum, the shim-stop-before-userdel ordering must be correct so the common path completes.

## Acceptance criteria

- [ ] `rm` / `rm --purge-account` stops (`disable --now`) the shim unit BEFORE `userdel` of the shim account, so `userdel` no longer fails with "user is currently used by process".
- [ ] `rm --purge-account` on the last account COMPLETES: no anon user, no shim user, no `anonctl_<account>` / `anonctl_baseline_<account>` nft tables, no `/etc/anonctl/<account>.json`, and (last account) the shared template unit + anonctl-nftables.service + empty `/etc/anonctl` dirs are gone. The host's OTHER nft rules untouched.
- [ ] Teardown is resilient: a failure in one step is reported and does not silently abort the rest (or, minimally, the ordering guarantees the common path completes cleanly).
- [ ] Tests cover the new behaviour: unit-test the teardown ORDER (the shim-disable call is recorded BEFORE the shim userdel via the injected Runner); the real teardown behind the `integration` tag, isolated to a throwaway account, asserting no residue and the host untouched.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: fix `anonctl rm --purge-account` aborting on the last account because it userdels the shim account before stopping the shim unit. Source: `work/notes/findings/e2e-binary-revalidation.md` (the SERIOUS teardown regression: userdel fails "user is currently used by process", the whole last-account cleanup never runs, leaving the residue BUG 4's fix was meant to prevent).
>
> FIRST, read `main.go` `runRm`, `internal/provision/provision.go` `Rm` (the `userdel` calls), and `internal/forcing/forcing.go` + `internal/systemd` (where the shim unit is disabled and the last-account shared-artifact cleanup lives). Trace the current ORDER and confirm the userdel-before-disable inversion.
>
> Domain vocabulary: each account has a login user (`anon`/`anon-<name>`) and a DISTINCT dedicated shim service user (`<account>-shim`) that runs the `anonctl-shim@<account>.service` unit. You cannot `userdel` the shim account while its unit is running as that UID. Correct order: disable --now the shim unit -> remove nft tables/config/marker -> userdel the accounts -> (last account) remove shared units + empty /etc/anonctl.
>
> Where to look / seams: put teardown behind the injected Runner so a unit test asserts the disable-shim call is recorded BEFORE the shim userdel; the real no-residue teardown is integration-tagged, isolated to a throwaway account, host untouched. Make teardown proceed-and-report rather than abort-on-first-error. "Done" = `rm --purge-account` on the last account leaves zero residue, host's other rules untouched, proven by the integration test. RECORD any non-obvious ordering decision per the task-template guidance.
