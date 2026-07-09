---
title: Fix the boot-invariant leak - forcing does not survive reboot because nftables.service is not enabled
slug: fix-boot-invariant-nftables-not-enabled
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [26, 27]
---

## What to build

Close BUG 1 from the e2e validation (`work/notes/findings/e2e-binary-validation.md`): the SERIOUS real post-reboot leak. anonctl persists its ruleset via a drop-in on the host's `nftables.service`, but never enables that service, and Debian ships it DISABLED. Proven on a real host: after a systemd reboot the anon nft table was ABSENT and the anon UID egressed with the host's real public IP in the clear (`{"IsTor":false,"IP":"51.7.210.66"}`). The shim came back but the kernel forcing did not. This defeats the whole point of a fail-closed tool.

The persisted rule file is correct (a manual `nft -f` recovers it); this is purely a "who loads it at boot" gap. Fix so the boot invariant does NOT depend on a host service anonctl does not own. Prefer the robust option:

- **Ship anonctl's OWN loader unit** (e.g. `anonctl-nftables.service`, `WantedBy=sysinit.target`, ordered early - `Before=network-pre.target` / `DefaultDependencies=no` as appropriate) that loads `/etc/anonctl/nftables/*.nft` at boot, INDEPENDENT of whether the host's `nftables.service` is enabled. `add` installs + enables it; `rm`/last-account teardown disables + removes it. This is self-contained and does not silently mutate a host-owned service.
- (Alternative, weaker: have `add` run `systemctl enable nftables.service` idempotently. Rejected-leaning because it mutates a host-owned unit's enablement as a side effect, and a host that later `systemctl disable nftables` re-opens the leak silently. If you choose this instead, justify it in the ADR.)
- **Correct ADR-0005:** it currently ASSERTS the boot invariant "holds by construction" because "nftables.service loads early". That assumption is FALSE on a default Debian host. Update the ADR to record the real mechanism (anonctl's own loader unit) and why the drop-in-on-host-service approach was insufficient.

## Acceptance criteria

- [ ] anonctl installs a boot-time loader for its persisted per-account nft rules that does NOT depend on the host's `nftables.service` being enabled; `add` enables it, teardown removes it.
- [ ] After a reboot (or a reboot-equivalent early-boot simulation), the anon nft table is PRESENT and the anon UID's egress is forced/dropped, never the host's real IP in the clear. This is the boot invariant the finding proved broken.
- [ ] The boot-invariant integration test (`internal/systemd`) is updated to reproduce the ORIGINAL failure (rules absent at boot when relying on a disabled host service) and prove the fix (rules present at boot via anonctl's own loader). Behind the `integration` tag, isolated.
- [ ] ADR-0005 is corrected: the "holds by construction / nftables.service loads early" assertion is replaced with the real mechanism and the reason the host-service drop-in was insufficient on a default host.
- [ ] Tests cover the new behaviour (unit-test the loader-unit GENERATION; the boot behaviour is integration-tested, isolated, host untouched).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make anonctl's forcing survive a reboot fail-closed on a DEFAULT host, not just one where `nftables.service` happens to be enabled. BUG 1 of `work/notes/findings/e2e-binary-validation.md` (a real post-reboot leak, proven on a real host: after reboot the table was gone and the anon UID egressed with the host's real IP). Stories 26/27 (persistence + boot invariant).
>
> FIRST, read the finding's BUG 1 in full (it has the observed leak + the fix options), then `internal/systemd/systemd.go` (the current `nftables.service` DROP-IN approach + `NftablesDropIn`), `internal/forcing/forcing.go` (Install/Reconfigure - where enable/persist happens), and ADR-0005 (the false "holds by construction" claim to correct). The persisted rule file itself is fine; only the boot loader is missing.
>
> Domain vocabulary: the boot invariant is "at no point during boot does the anon UID have direct egress" - it must hold because the nft default-DROP loads EARLY. The bug is that the drop-in extends a host service (`nftables.service`) that Debian ships disabled, so nothing loads the rules at boot. Ship anonctl's OWN early-ordered loader unit so the invariant does not depend on a host-owned service's enablement (the robust fix; the weaker `systemctl enable nftables.service` mutates a host unit and can be silently re-disabled - if you pick it, justify in the ADR).
>
> Where to look / seams: unit/loader GENERATION is pure text (unit-test it); the enable/persist/reboot behaviour is integration-tested behind the `integration` tag, isolated to throwaway units/tables that leave the host untouched. UPDATE the boot-invariant integration test to reproduce the original failure and prove the fix. "Done" = after a reboot(-equivalent) the anon table is present and forcing holds, on a host where `nftables.service` is disabled. RECORD the mechanism decision in the corrected ADR-0005.
>
> NOTE: the definitive proof of this fix is a REAL reboot on a real host (as the finding did); the integration test is a reboot-equivalent early-boot simulation. Flag in the done-record that a real-host reboot re-validation is the final gate (a human re-run of the e2e validation's step 5).
