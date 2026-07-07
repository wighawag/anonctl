---
title: Grow verify with ICMP-drop and non-53-UDP (incl. QUIC/UDP-443) drop assertions
slug: verify-icmp-and-non53-udp-drop-assertions
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

Close rows 4 and 5 of the Tails leak catalogue (`work/notes/findings/tails-network-filter-lessons.md`) at the verify layer. The fail-closed ruleset ALREADY drops these (they fall through to the anon UID's policy DROP), so this is asserting-not-assuming: `verify` should PROVE them, the way Tails' review closes ICMP and non-TCP.

Add two named `verify` assertions (`internal/verify`), live-probed behind the `integration` build tag:

- **`icmp-drop`** (row 4): an ICMP echo (`ping`) from the anon UID to an off-box address does NOT emit an ICMP packet carrying the real source IP; it is dropped. Note the PMTU-discovery side effect Tails documents (they accept the cost and work around it with PLPMTUD, `net.ipv4.tcp_mtu_probing`); decide whether anonctl mirrors that sysctl or records it as a known caveat in the threat-model docs.
- **`non-tcp-udp-drop`** (row 5): raw non-53 UDP from the anon UID is DROPPED, specifically including UDP/443 (QUIC / HTTP-3). SOCKS carries TCP only, so UDP/443 is unrelayable; assert it is dropped AND note that a real modern client should degrade to TCP rather than leak. (The validated recipe already showed `socat UDP4:...:9999` -> "Operation not permitted"; generalise to a named assertion incl. the QUIC case.)

Pin both assertion names in the verify JSON contract (ADR-0003, or a follow-on ADR notes the additions).

## Acceptance criteria

- [ ] `verify` carries an `icmp-drop` assertion: a ping from the anon UID to an off-box address is dropped (no real-source-IP ICMP emitted). Live check behind the `integration` tag; the assertion/render logic unit-tested.
- [ ] `verify` carries a `non-tcp-udp-drop` assertion covering raw UDP and specifically UDP/443 (QUIC): dropped from the anon UID. Live check behind the `integration` tag.
- [ ] Both assertion names are added to the JSON contract; ADR-0003 updated or a follow-on ADR records the additions.
- [ ] The PMTU/PLPMTUD trade-off (drop ICMP vs mirror the sysctl) is decided and recorded (a threat-model docs note and/or an ADR).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style; live parts isolate to a throwaway account and leave the host untouched).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: grow anonctl's `verify` to PROVE the ICMP-drop and non-53-UDP-drop (incl. QUIC/UDP-443) leak classes are closed, rather than assume the policy DROP handles them. Rows 4 and 5 of `work/notes/findings/tails-network-filter-lessons.md`.
>
> FIRST, check drift: read `internal/verify` (`checks_integration.go` for the live-probe pattern, `verify.go` for the assertion names + JSON contract) and `internal/nftables/nftables.go` (confirm non-53 UDP and ICMP for the anon UID still fall through to the policy DROP; if the ruleset gained explicit ICMP/UDP drops, assert those). Read the validated recipe's confirmations (`manual-per-uid-tor-recipe.md`) for the exact probe shapes that were hand-verified.
>
> Where to look: mirror the existing leak-drop-v4/v6 assertions (they already prove a direct TCP connection is dropped); the new assertions are the ICMP and non-53-UDP analogues. The live probes need root + a provisioned host, so they sit behind the `integration` build tag exactly like the existing ones. Seams to test at: the assertion/render/exit logic (unit) and the live drop probes (integration). "Done" = ping and UDP/443 from the anon UID are proven dropped by named verify assertions, and the PMTU trade-off is recorded. This has a netcage sibling (netcage's verify wants the same QUIC/ICMP assertions, recorded there); keep the assertion intent consistent.
