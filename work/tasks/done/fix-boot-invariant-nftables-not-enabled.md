---
title: Standing per-UID default-deny so forcing-absent = dropped (fixes the reboot leak by construction)
slug: fix-boot-invariant-nftables-not-enabled
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [7, 26, 27]
---

## What to build

Close BUG 1 from the e2e validation (`work/notes/findings/e2e-binary-validation.md`) - the SERIOUS real post-reboot leak - by fixing it at the RIGHT layer: a standing per-UID DEFAULT-DENY that is the anon account's resting state, independent of the forcing rules and any host-owned service.

The observed bug: anonctl persists the forcing ruleset via a drop-in on the host's `nftables.service`, which Debian ships DISABLED, so after a reboot the anon nft table was ABSENT and the anon UID egressed with the host's real public IP in the clear (`{"IsTor":false,"IP":"51.7.210.66"}`). The shipped design tries to guarantee the boot invariant by "loading the forcing (allow-through-shim) rules early enough". That is the wrong invariant to chase: it means "un-forced" can mean "free" during any window where the rules are not (yet) loaded.

**Invert it (the design upgrade the maintainer asked for): the anon UID's RESTING STATE is DROP, and forcing is what OPENS a path (only through the shim).** So the ABSENCE of forcing = dropped, never free. Concretely:

- **A standing baseline default-deny for anon UIDs**, applied at `add`-time and persisted as its OWN minimal, always-loaded artifact (a tiny nft rule: for each anon UID, drop all egress), loaded at boot by anonctl's OWN early-ordered loader unit (`WantedBy=sysinit.target`, ordered before the network is up, `DefaultDependencies=no` as appropriate) so it does NOT depend on the host's `nftables.service` being enabled. If NOTHING else loads (the full per-account forcing rules fail, the shim is down, Tor is down), the account is still DROPPED.
- **The per-account forcing rules layer ON TOP** of the baseline: they add the redirect-into-shim (the only way egress is granted) plus the closures. Forcing present => egress goes through the shim; forcing absent/failed => the baseline default-deny still denies. There must be no ordering window where the baseline deny is not yet present but the account can act.
- **Endpoint-down is already safe and stays so:** the persisted forcing ruleset already carries `policy drop` for the UID, so Tor/proxy down => dropped (proven). This task ensures the STRONGER property: even the forcing rules themselves being absent => still dropped, via the standing baseline.
- **Correct ADR-0005** (and/or a new ADR): replace the false "boot invariant holds by construction because nftables.service loads early" with the real mechanism - a standing per-UID default-deny loaded by anonctl's own early unit, forcing layered on top - and why the drop-in-on-a-host-service approach was insufficient on a default host. Record the invariant precisely: "an anon UID with no anonctl forcing loaded is DROPPED, not free; forcing only ever OPENS the shim path."

Do NOT use the weaker `systemctl enable nftables.service` approach: it mutates a host-owned unit and a later `systemctl disable nftables` silently re-opens the leak. anonctl owns its own deny + loader.

## Acceptance criteria

- [ ] A standing per-UID default-deny for anon accounts is applied at `add` and persisted as its own always-loaded artifact, loaded at boot by an anonctl-owned early unit that does NOT depend on the host's `nftables.service` enablement.
- [ ] Invariant proven: with the anon account provisioned but the FORCING rules NOT loaded (simulate: only the baseline deny present, or flush the forcing table), the anon UID's egress is DROPPED, never the host's real IP. And with forcing loaded, egress goes through the shim as before.
- [ ] After a reboot (or a reboot-equivalent early-boot simulation) on a host where `nftables.service` is DISABLED, the anon UID is dropped-or-forced at every point, never free. This is the boot invariant the finding proved broken.
- [ ] `rm` / last-account teardown removes the baseline deny + the loader unit cleanly (and only when the last anon account goes, if the deny is shared).
- [ ] The `internal/systemd` + `internal/nftables` integration tests are updated: reproduce the ORIGINAL failure (forcing rules absent at boot => leak under the old design) and prove the new invariant (baseline deny present => dropped even with forcing absent). Behind the `integration` tag, isolated, host untouched.
- [ ] ADR-0005 corrected (or a new ADR added) recording the standing-default-deny mechanism and the precise inverted invariant.
- [ ] Tests cover the new behaviour (unit-test the baseline-deny + loader-unit GENERATION; boot/deny behaviour integration-tested).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make "the anon UID has no anonctl forcing loaded" mean DROPPED, not free - fixing the reboot leak (BUG 1 of `work/notes/findings/e2e-binary-validation.md`) at the right layer. The maintainer's framing: the account's RESTING STATE is deny; forcing is what OPENS a path (only through the shim), so the ABSENCE of forcing can never leak. This is strictly safer than the shipped "load the allow-rules early enough" approach. Stories 7 (fail-closed default-DROP), 26/27 (persistence + boot invariant).
>
> FIRST, read the finding's BUG 1 in full (the observed real-IP leak after reboot + the fix options), then `internal/nftables/nftables.go` (the forcing ruleset - the filter chain already has `policy drop`, but it is part of the PER-ACCOUNT forcing table that was absent at boot; the baseline deny must be a SEPARATE, minimal, always-loaded artifact), `internal/systemd/systemd.go` (the current `nftables.service` drop-in - replace with anonctl's own early loader unit), `internal/forcing/forcing.go` (Install/Reconfigure/teardown), and ADR-0005 (the false "holds by construction" claim).
>
> Domain vocabulary: the boot invariant is "at no point does the anon UID have direct egress". The shipped design chased it by loading the forcing (allow-through-shim) rules early; the bug is those rules were not loaded at boot at all (host `nftables.service` disabled). The fix inverts it: a standing per-UID default-DENY is the resting state (its own tiny always-loaded rule + anonctl's own early loader unit), forcing layers on top to OPEN the shim path. Un-forced = dropped, by construction. Do NOT rely on `systemctl enable nftables.service` (host-owned, silently re-disableable).
>
> Where to look / seams: the baseline-deny + loader-unit GENERATION is pure text (unit-test it); the deny/boot behaviour is integration-tested behind the `integration` tag, isolated to throwaway UIDs/tables/units that leave the host untouched. Prove BOTH: forcing-absent => dropped (the new guarantee) and forcing-present => shim path works. RECORD the inverted invariant in the corrected/updated ADR.
>
> NOTE: the definitive proof is a REAL reboot on a real host (as the finding did). The integration test is a reboot-equivalent early-boot simulation. Flag in the done-record that a real-host reboot re-validation (a human re-run of the e2e validation's step 5, PLUS a "flush the forcing table, confirm still dropped" check) is the final gate.
