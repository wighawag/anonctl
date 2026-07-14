---
title: Reboot persistence (nftables.service include + per-account anonctl-shim@ unit) and the boot invariant
slug: persistence-and-boot-invariant
spec: per-uid-kernel-anonymized-egress
blockedBy:
  [
    account-provisioning-and-cli-skeleton,
    socks-shim-binary,
    nftables-ruleset-install,
    verify-command,
  ]
covers: [19, 21, 26, 27]
---

## What to build

Make the setup survive reboot and re-apply FAIL-CLOSED, with no window where the anon UID has un-anonymized egress at boot. Plus `update`/`reconfigure`.

- **nftables persistence:** persist the anonctl-owned ruleset via `nftables.service` (an include / drop-in). Because the default-DROP-for-the-UID is part of the persisted ruleset, if it loads before the shim/endpoint are up the account is DROPPED, not leaking.
- **Per-account shim unit:** a templated systemd unit `anonctl-shim@<account>.service` running as that account's dedicated shim UID; `add` enables it (`enable --now`), `rm` disables it (`disable --now`). Chosen over one multiplexer unit (the per-account process boundary IS the security boundary; leans on systemd for supervision).
- **update/reconfigure:** change an account's endpoint and RE-APPLY the rules fail-closed, so there is never a window of un-anonymized egress during a reconfigure.
- **Boot invariant:** "at no point during boot does the anon UID have direct egress", asserted by a reboot-`verify` and an integration test (default-DROP loads early; worst case is dropped-until-shim-and-endpoint-up, never leaking-until-forcing-applied).
- anonctl does NOT own the endpoint's boot lifecycle; document "enable your endpoint (e.g. `tor.service`) at boot".

## Acceptance criteria

- [ ] The ruleset persists across reboot via `nftables.service` (include/drop-in) and re-applies fail-closed.
- [ ] `add` installs + enables `anonctl-shim@<account>.service` (as the shim UID); `rm` disables + removes it.
- [ ] `update`/`reconfigure` changes the endpoint and re-applies with no un-anonymized window.
- [ ] Boot invariant: an integration test (reboot or a reboot-equivalent early-boot simulation) asserts the anon UID has NO direct egress at any point during boot; the worst observed case is dropped, never leaking.
- [ ] The unit/include GENERATION is unit-tested (pure text); the enable/persist/reboot behaviour is integration-tested behind the `integration` build tag.
- [ ] **Shared-write isolation:** integration tests isolate to throwaway accounts/units/tables and assert the host's real systemd units + nft rules are untouched (remove only what the test created).

## Blocked by

- `account-provisioning-and-cli-skeleton`: the account + shim UID the unit runs as.
- `socks-shim-binary`: the shim binary the unit launches.
- `nftables-ruleset-install`: the ruleset being persisted.
- `verify-command`: the reboot-verify that asserts the boot invariant.

## Prompt

> Goal: reboot persistence (nftables.service include + per-account `anonctl-shim@<account>.service`) and the boot invariant, plus `update`/`reconfigure`. Stories 19, 21, 26, 27 of the `per-uid-kernel-anonymized-egress` spec.
>
> FIRST, check drift: confirm the ruleset (`nftables-ruleset-install`), the shim binary + its launch args (`socks-shim-binary`), and the account/shim-UID layout (`account-provisioning-and-cli-skeleton`) match what this persists. If any changed, adapt to what landed.
>
> Domain vocabulary: the BOOT INVARIANT is the load-bearing property, "at no point during boot does the anon UID have direct egress." It holds because the nft default-DROP is part of the persisted ruleset and loads early, so the worst case is dropped-until-shim-and-endpoint-are-up, never leaking. The per-account templated unit is chosen over a multiplexer because the per-account process boundary IS the security boundary (distinct shim UID per account).
>
> Where to look: netcage (`~/dev/github/wighawag/netcage`) for the integration-behind-a-build-tag + shared-write-isolation discipline. systemd `@` template units for the per-account instance pattern; `nftables.service` include/drop-in for rule persistence. anonctl APPLIES all of this itself as root (the ufw stance) and does NOT manage the endpoint's own service.
>
> Seams to test at: unit/include text GENERATION (unit, everywhere); the enable/persist/reboot + boot-invariant behaviour (integration, behind the tag, isolated). "Done" = setup survives reboot fail-closed, the boot invariant is asserted, `update` re-applies without a leak window, and integration tests leave the host's real units/rules untouched. RECORD non-obvious in-scope decisions (unit ordering/`After=`/`Wants=`, the include path) as ADRs or a done-record note per the task-template guidance.
