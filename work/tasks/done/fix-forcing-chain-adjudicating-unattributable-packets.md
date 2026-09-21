---
title: Fix the BOX-WIDE bug - the forcing chain's negative-skuid pass-through drops every uid's unattributable packets
slug: fix-forcing-chain-adjudicating-unattributable-packets
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

`internal/nftables.Generate` emitted `filter_out` as a base chain on the output hook with `policy drop`, whose only pass-through for uninvolved UIDs was a NEGATIVE match:

```
chain filter_out {
    type filter hook output priority filter; policy drop;
    meta skuid != <anon> meta skuid != <shim> accept
    ...
```

`meta skuid` reads `sk->sk_socket->file`, which a large share of ordinary TCP output does not have. Such a packet matches NEITHER `skuid == u` NOR `skuid != u`, so it took no accept, fell through, and was killed by the policy drop. A `drop` is TERMINAL across all base chains at a hook, so one forced account was enough, and the chain's own header claimed "Governs ONLY uid X and uid Y; every other uid is untouched" -- precisely the invariant being violated.

Consequence: any uid on the box, root included, whose TCP transfer was large enough to emit an unattributable packet had it refused by the local output path. `TcpExtTCPRetransFail` rose, the RTO backed off past 50 seconds, and the transfer stalled permanently with no error on either side. Small transfers looked fine, which is why this was misdiagnosed for a while as a Python `http.server` bug. It was live on telemaque, and `nono` runs three forced accounts, i.e. three such chains.

FIX: a base chain must never adjudicate a packet it cannot attribute. Both base chains became `policy accept` holding nothing but POSITIVE `meta skuid <uid> jump` rules into per-UID regular chains (`anon_nat`, `anon_filter`, `shim_filter`). An unattributable packet takes no jump and is accepted by policy; every drop now lives inside a chain entered only after a positive UID match. `anon_filter` ends in an unconditional terminal `drop`, which is what the base chain's `policy drop` used to do for that UID and is NOT optional (see the trap below). `nat_out` had the same hole in the more dangerous direction (an unattributable packet falling through to `meta l4proto tcp redirect to :<relay>`, i.e. an uninvolved uid's traffic redirected INTO the anon shim) and got the same treatment.

Recorded in ADR-0002 (amended: the restructure and the terminal drop), ADR-0005 (amended: how two policy-accept base chains at one hook now compose, and why the baseline must NOT be changed the same way), ADR-0008 (amended: where closure (a)'s rules now live and the new third ordering term).

## Evidence

Measured in unprivileged namespaces (`unshare -rn`), kernel 6.18, against the REAL generated rulesets.

**The unattributable class.** Classifying a 600KB loopback transfer with a policy-accept chain: SYN and SYN-ACK are ALWAYS attributable (0 unattributable); the bulk data super-packets, the pure ACKs and the FIN are NOT (9 packets / 516564 bytes of 614400 transferred). This is what makes the fix safe: fail-closed rests on the FIRST packet of a flow, which always carries a socket UID.

**A RETRANSMITTED SYN is attributable too, and this is the premise the whole design rests on.** Raised in review as the case that could invalidate it, and measured rather than argued. It is not obvious: a dropped SYN is retransmitted from TIMER context (where attribution is normally lost) and is never confirmed in conntrack, so the retransmission arrives as a FRESH connection and re-traverses `nat_out`. Were it unattributable it would take no jump, keep its real off-box destination, and escape both tables -- and because the OLD negative-match nat chain would have swallowed it into the redirect instead, this would have been a REGRESSION introduced by the fix, not a pre-existing hole. Measured over a 20-second dial to an unroutable destination, counted BEFORE either table (filter priority -150, ahead of nat at -100):

| case | v4 SYNs | v6 SYNs | attributable | escaped with an off-box daddr |
| --- | --- | --- | --- | --- |
| forcing + baseline (deployed pair) | 1 | 9 | all | **0** |
| baseline only (forcing absent) | 9 | 9 | all | **0** |
| no tables (control) | 9 | 9 | all | 9 |

Nine SYNs is one original plus eight retransmissions. The control row is what makes the zeros meaningful: with nothing loaded the same probe leaks all nine per family, so the zeros are the tables working, not the probe failing to fire.

**The bug, old ruleset, uninvolved uid.** 600KB x10: 0/10 completed, `TcpExtTCPRetransFail` +78, 169 of 351 packets adjudicated away. 10KB x10: 10/10 completed but 11 of 121 packets still silently dropped -- the bug was present even when it looked fine.

**The fix, new ruleset, uninvolved uid.** 600KB x10 and 5MB x10: 10/10 each, `TcpExtTCPRetransFail` delta 0, and 0 of 315 / 0 of 1116 packets adjudicated away.

**The anon side, forcing table loaded ALONE (no baseline, so it cannot mask a fault).** ICMP DROPPED, non-53 UDP DROPPED, ordinary TCP redirected into the shim and accepted, LAN exemption reaching its destination directly. With ONLY the terminal `drop` line removed: ICMP and UDP both ESCAPE. That is the trap, reproduced.

**`nat_out` and conntrack.** A nat base chain is evaluated ONLY for the first packet of a conntrack flow: 10 evaluations across a 323-packet flow (one per connection), 0 packets reaching the catch-all redirect. So the negative-match hole there was masked in practice, as expected -- but masked is not closed, hence the positive form.

**Conntrack is already engaged, contrary to the standing assumption.** 0 conntrack entries with no forcing table loaded; 10 entries after ten uninvolved-uid loopback connections with it loaded. Registering `nat_out` enables conntrack for the whole namespace, so loopback IS tracked wherever anonctl is installed. This does not affect the fix (which adds no conntrack cost), but it falsifies the premise that a `ct state` approach was rejected over. Captured in `work/notes/observations/`.

**The baseline residual is unreachable.** Baseline loaded alone, anon uid probing an off-box destination: 12 packets left, ALL 12 attributable, all 12 dropped, 0 unattributable ever generated. The anon UID cannot establish a flow when forcing is absent, so the packets that would escape the positive match never come into existence.

## Acceptance criteria

- [x] Both base chains are `policy accept` and contain nothing but positive-skuid jumps; no `meta skuid !=` survives anywhere in either generator.
- [x] `anon_filter` ends in an unconditional, unqualified, LAST `drop`, asserted with AND without exemptions, and the exemption accepts precede it.
- [x] A 600KB and a 5MB loopback transfer as an uninvolved uid succeed 10/10 with a zero `TcpExtTCPRetransFail` delta and zero packets adjudicated away.
- [x] The anon UID's fail-closed behaviour is unchanged with the forcing table loaded ALONE: its non-redirected egress is dropped by an EXPLICIT rule.
- [x] `nat_out`'s negative match converted to a positive jump; the conntrack masking established empirically rather than assumed.
- [x] The baseline keeps its POSITIVE match, with the residual documented in code and pinned by a test that also forbids an unconditional drop in that base chain.
- [x] Integration tests load the real ruleset in a network namespace, isolate (fresh netns + throwaway account + planted sentinel), and assert the host's own ruleset is byte-identical afterwards; gated behind the `integration` build tag.
- [x] Both integration tests FALSIFIED: the uninvolved test fails against the old shape, the anon test fails when the terminal drop is removed.
- [x] ADRs 0002, 0005 and 0008 amended rather than silently contradicted.
- [x] `gofmt -l .`, `go vet ./...`, `go build ./...` clean; `go test ./...` green apart from the two pre-existing environmental `pkcheck` failures.
- [x] The `integration`-tagged suites updated too: three assertions on the literal string `policy drop` (two in `apply_integration_test.go`, one in the boot-invariant test) were stale the moment the base chain became policy-accept. Each was REPLACED with the assertion that now carries the property (the positive-uid jump, no `skuid !=`, and the anon closure chain's last rule being an unconditional `drop`, read back from the KERNEL's own `nft list table` output), not deleted.
- [x] Validated on a real Debian-class host as REAL root by the maintainer: both new tests pass, the two repaired apply tests pass, and the falsification fails as required (0/10, `TcpExtTCPRetransFail` +64, 125 of 297 packets dropped).
- [x] Reviewed adversarially. Seven findings, all addressed: the SYN-retransmission premise measured (above) and the self-contradicting prose corrected in three places; a `-1`-sentinel hole in `TestUninvolvedUIDIsNeverAdjudicated`'s no-traffic guard closed (`== 0` -> `<= 0`, so a failed counter READ can no longer pass as a genuine zero); the README's literal quotation of the now-deleted `meta skuid != ...` rule replaced with the current shape; ADR-0003 amended (it documents `icmp-drop` / `non-tcp-udp-drop`, the two assertions that now rest on the terminal drop specifically, and still described the mechanism as a chain policy); ADR-0005's order-independence argument corrected (it claimed the two chains AGREE on what they drop, which is false -- the forcing chain drops loopback destinations the baseline returns; order-independence holds structurally, because a drop is terminal and an accept is not); eleven stale `policy DROP` comments in `internal/verify` updated; and a note added at the closure-(b) rule recording that for TCP it is belt-and-braces, since the catch-all redirect has already rewritten the dial.

## How the stale integration assertions got missed (process note)

They are behind the `integration` build tag, so `go test ./...` never COMPILED them, and "repo verify is green" was true only of the untagged suite. `go vet -tags integration ./...` passed because a stale string comparison is not a vet error. The new behavioural tests were exercised in a namespace but the PRE-EXISTING integration tests were not, even though `unshare -rn` makes the caller uid 0 and they would have run there. The cheap habit that closes this: after changing generated security-critical text, run `go test -tags integration -c` for every package that has such a suite AND execute it under `unshare -rn`, rather than only compiling it.

## Residual validation gap (a human must close this)

The integration tests were exercised as uid 0 inside `unshare -rn`, which proves the harness and both falsifications, but they have NEVER run as REAL root:

- This session has `NoNewPrivs=1`, which blocks `sudo` and `newuidmap`, so only ONE uid exists per namespace. The anon-side scenario was therefore validated with the anon uid rebound to 0 in a scratch build (shape identical, uid number different) and with `--keep-groups` instead of `--clear-groups`.
- RESOLVED: run as real root on telemaque. `TestUninvolvedUIDIsNeverAdjudicated` (600KB and 5MB) and `TestAnonUIDIsStillDroppedByAnExplicitRule` all PASS, the latter exercising the genuine `setpriv --reuid 424242 --clear-groups` path against a UID with no passwd entry. The falsification against the old generator FAILS as required.
- OUTSTANDING: `go test -tags integration ./internal/systemd/` as real root, to re-run the boot-invariant test against the repaired assertion. Note `work/notes/observations/boot-invariant-dial-probe-passes-when-it-could-not-run.md`: that test's dial probe currently reads "could not run" as "did not reach", so it FALSE-GREENS wherever `setpriv` cannot reach the synthetic uid. Its structural assertions (the positive jump, the terminal drop, no negative uid match) are trustworthy; its live dial verdict is only trustworthy as real root.
- The live `verify` assertions (`leak-drop-v4`, `leak-drop-v6`, `bypass-loopback-closure`, `bypass-endpoint-closure`, `icmp-drop`, `non-tcp-udp-drop`) were reasoned about and their mechanism reproduced in a namespace, but NOT run: telemaque sets `users.mutableUsers = false` so its anonctl accounts are deleted at every activation, and `anonctl add` cannot currently complete on NixOS. Do NOT validate on `nono`.
