---
title: Honest threat-model + README (what per-UID forcing defends against and what it does NOT)
slug: threat-model-and-docs
spec: per-uid-kernel-anonymized-egress
blockedBy:
  [
    nftables-ruleset-install,
    verify-command,
    marker-contract,
    persistence-and-boot-invariant,
  ]
covers: [29, 30]
---

## What to build

The README / docs, at netcage's honesty bar, documenting the finished system and its residual risk so the boundary is documented rather than surprising.

- **What per-UID kernel forcing DEFENDS against:** an app choosing a wrong/no proxy, a DNS leak, an anonymizer-down leak (fail-closed), and cross-identification of two accounts on a shared endpoint (via `<account>@` on a `tor-shared` endpoint).
- **What it does NOT defend against:** root on the box (root can undo the rules), a process changing its own UID away from the forced one (the policy binds to the UID), and kernel compromise. Be as candid as netcage's "What netcage hides and what it does NOT".
- **The cross-identification boundary:** share-safe ONLY via `<account>@` on a `tor-shared` endpoint; a shared `socks-peruser` endpoint would cross-identify (which anonctl refuses).
- **The Tor-over-Tor caveat:** documented AND detectable via the marker, so anon-pi/netcage can skip re-forcing.
- **Precision note:** "kernel-forced" means the REDIRECT/DROP is kernel-enforced; the relay shim itself is userspace. Say so, so a reader does not over-read "kernel".
- **Operational note:** anonctl does not manage the endpoint; enable your endpoint (e.g. `tor.service`) at boot. Point at `verify` as the trust anchor to re-run after setup/reboot/changes.

## Acceptance criteria

- [ ] The docs state the guarantee (per-UID fail-closed anonymized egress, proven by `verify`) AND the per-category residual (root / UID-change / kernel NOT defended), matching netcage's honesty bar.
- [ ] The cross-identification boundary (`tor-shared` + `<account>@` safe; shared `socks-peruser` unsafe and refused) is documented.
- [ ] The Tor-over-Tor caveat and its marker-based detectability are documented.
- [ ] The "kernel-forced but userspace-relayed" precision note is present.
- [ ] The "enable your endpoint at boot" operational note and the `verify` re-run guidance are present.
- [ ] Docs reference the ADRs written along the way (applies-as-root, uniform-forcing, share-class, shim, ruleset+closures, LAN exemption, marker, persistence) rather than restating their rationale.

## Blocked by

- `nftables-ruleset-install`, `verify-command`, `marker-contract`, `persistence-and-boot-invariant`: the docs describe the FINISHED system, so they land after the behaviour they document.

## Prompt

> Goal: the README / threat-model docs at netcage's honesty bar. Stories 29 (doc half) and 30 of the `per-uid-kernel-anonymized-egress` spec.
>
> FIRST, check drift: read what actually landed (`work/tasks/done/` for the ruleset, verify, marker, persistence tasks, and any ADRs in `docs/adr/`) and document THAT, not this prose, this task lands last precisely so it describes the finished system.
>
> Domain vocabulary: be HONEST (netcage's bar). Defends against: wrong/no-proxy, DNS leak, anonymizer-down leak, cross-identification (via `<account>@` on `tor-shared`). Does NOT defend: root, a process changing its own UID, kernel compromise. The cross-identification guarantee is share-class-bounded. "kernel-forced" is precise about the kernel doing the redirect/drop while the relay is userspace.
>
> Where to look: netcage (`~/dev/github/wighawag/netcage`) README section "What netcage hides and what it does NOT" and its ADR-0013 for the honesty pattern to mirror; the ADRs anonctl wrote for the rationale to POINT AT rather than restate. Do NOT enumerate individual work items or ADRs by number in a way that will go stale, describe what the docs cover and cross-reference the ADR folder.
>
> "Done" = a reader understands anonctl's guarantee, its residual risk, the cross-identification boundary, and the Tor-over-Tor caveat, and is not surprised by anything the tool does not do. Pure docs, agent-buildable.
