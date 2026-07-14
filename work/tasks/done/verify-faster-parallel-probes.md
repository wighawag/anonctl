---
title: Make verify faster - run the independent live probes in parallel and tighten the drop-detection timeouts
slug: verify-faster-parallel-probes
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [15, 18]
---

## What to build

`anonctl verify` is slow (several tens of seconds worst case) for a structural reason, and it can be made much faster WITHOUT dropping any assertion (all 9 are meaningful leak classes; keep them all).

Root cause (measured): the leak/closure probes PASS by TIMING OUT - a dropped packet never answers, so each probe waits its FULL deadline (6-8s each, one is 15s, one is 30s), and `verify.Run` runs the checks SEQUENTIALLY, so wall time is the SUM of all timeouts. The probes are INDEPENDENT (different off-box destinations / different assertions).

Two speedups, both safe:

- **Parallelize the independent probes.** Run the checks CONCURRENTLY instead of sequentially, so wall time becomes the MAX single probe time, not the sum. `verify.Run` currently loops `for _, c := range checks { c.Run(ctx) }`; run them in goroutines and collect, preserving the report's assertion ORDER (sort/emit by the checks' original order, not completion order) so output is deterministic. Each check already has its own timeout/context; a shared parent ctx is fine. Watch for shared-resource contention: the escaped-leak counter probes each plant a per-run scratch nft table - ensure the scratch table NAMES are unique per concurrent probe (or serialize just the nft-planting step) so parallel probes do not collide on one table name. If concurrency makes the nft-counter probes race on a shared table, give each its own uniquely-named scratch table.
- **Tighten the drop-detection timeouts.** A DROPPED packet is knowable quickly - you do not need 6-8s (or 15/30s) to conclude "no response". Reduce the drop/closure probe deadlines to a snappy value (e.g. 2-3s, matching the hand recipe's `ping -W 3` / `curl -m ...`), keeping enough margin that a genuinely slow-but-working path is not mis-read. The exit-IP / DNS checks that make a REAL Tor round-trip may legitimately need longer (Tor can be slow) - keep those generous; only tighten the ones whose PASS is a timeout (leak-drop-v4/v6, the bypass closures, icmp, non-tcp-udp). Justify the chosen values in a comment.

Net effect: verify goes from "sum of ~5-8 timeouts" to "max one timeout", and each drop timeout is smaller - a multi-x speedup, same coverage.

## Acceptance criteria

- [ ] `verify.Run` runs the independent checks CONCURRENTLY; the Report's assertion order is still deterministic (original check order), and the exit code / verdicts are unchanged.
- [ ] The nft-counter / scratch-table probes do NOT collide under concurrency (unique per-probe scratch table names, or the plant step serialized); no flakiness from parallel nft planting.
- [ ] The drop-detection timeouts (leak-drop-v4/v6, bypass closures, icmp, non-tcp-udp) are tightened to a snappy value with a comment justifying it; the Tor-round-trip checks (anonymized-exit, dns-remote) keep a generous timeout.
- [ ] verify is materially faster on a healthy host (wall time ~= the slowest single probe, not the sum) with identical assertions/verdicts.
- [ ] Tests: the concurrent Run preserves assertion order and results (drive with fixtured checks incl. slow ones); the scratch-table uniqueness is asserted; no data race (`go test -race` clean for the verify package).

## Blocked by

- None, can start immediately. (Composes cleanly with verify-progress-output; if both land, progress must still work with concurrent checks - emit a result as each COMPLETES, order the final report deterministically. Whichever lands first, the second rebases.)

## Prompt

> Goal: make `anonctl verify` much faster without dropping any assertion. Measured cause: the leak/closure probes pass by TIMING OUT (each waits its full 6-8s deadline) and verify.Run runs them SEQUENTIALLY, so wall time is the SUM of all timeouts. Fix: run the independent probes CONCURRENTLY (wall time = max, not sum) and tighten the drop-detection timeouts (a drop is knowable in 2-3s).
>
> FIRST, read `internal/verify/verify.go` `Run` (the sequential `for _, c := range checks` loop) and `internal/verify/probes_live.go` (the per-probe `context.WithTimeout` values: 6s/8s/15s/30s - and the escaped-leak counter's scratch nft table, which must be per-probe-unique under concurrency). Identify which checks pass-by-timeout (leak-drop-v4/v6, bypass-loopback/endpoint, icmp, non-tcp-udp) vs which make a real Tor round-trip (anonymized-exit, dns-remote - keep those generous).
>
> Do: run checks in goroutines, collect, emit the report in ORIGINAL order (deterministic); make each nft-counter probe use a UNIQUELY-NAMED scratch table (or serialize the plant) so parallel probes do not collide; tighten the drop timeouts to ~2-3s with a justifying comment; keep the Tor checks' timeouts. Keep every assertion and the exit-code contract identical.
>
> Where to test: `go test -race ./internal/verify/...` clean; a test that concurrent Run preserves order + verdicts with fixtured slow checks; scratch-table uniqueness asserted. "Done" = verify is a multi-x faster on a healthy host, same 9 assertions, deterministic order, no races, no nft-table collisions.
