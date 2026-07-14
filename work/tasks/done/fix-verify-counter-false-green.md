---
title: Fix verify FALSE-GREEN - the escaped-leak counter emits invalid nft for the no-port (all-TCP) closure probes
slug: fix-verify-counter-false-green
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [15, 17, 25]
---

## What to build

Close the LATENT FALSE-GREEN found in the real-host re-validation (`work/notes/findings/e2e-binary-revalidation.md`): two `verify` assertions pass UNCONDITIONALLY without probing anything, because they generate an invalid nft rule and the plant error is swallowed. A trust anchor that silently certifies without checking is worse than the original false-fail (a false-fail is loud; this is silent).

Root cause (confirmed in `internal/verify/counter.go`): `escapedLeakCounterRuleset` builds the match as `meta skuid <uid> ip daddr <X> <l4>` and only appends `dport <port>` when `port > 0`. For the no-port ("count the daddr on ANY port of that l4") case it emits a bare `... tcp counter` - which is INVALID nft syntax (`tcp` is a protocol keyword expecting a match like `dport`; `tcp counter` is a parse error). So:

- `bypass-loopback-closure` calls `offBoxReachedAsAnon(..., "tcp", 0)` -> invalid rule.
- `split-tunnel-tight` calls `offBoxReachedAsAnon(..., host, "tcp", 0)` for the non-exempt LAN host -> invalid rule.

The plant fails, `offBoxLeakReached` swallows the error to `reached=false` (the "safe" reading), so the assertion sees "nothing escaped" and PASSES - without ever planting a working counter or probing. Same bug is the Part A `internal/verify` integration failure (the invalid rule surfaces there as a hard error).

FIX: for the no-port case, emit a VALID all-TCP (or all-UDP) match. Use `meta l4proto <l4>` (e.g. `meta skuid <uid> ip daddr <X> meta l4proto tcp counter`) which matches all TCP to that daddr, instead of a bare `tcp`. Keep the `<l4> dport <port>` form for the port-specific case (that one is valid). AND harden against the class of bug: a counter PLANT error must NOT read as `reached=false` (a swallowed plant error currently means "assertion passes without checking"). A failure to plant/read the counter must fail the assertion LOUD (an error verdict, `Ok=false`), never a silent green - the same "a probe that could not run is not a pass" discipline the other assertions use.

## Acceptance criteria

- [ ] `escapedLeakCounterRuleset` emits VALID nft for the no-port case (all-TCP / all-UDP via `meta l4proto`, not a bare `tcp`/`udp`); a unit test asserts the generated text is valid and matches the whole-protocol case (not just the port-specific case).
- [ ] A counter PLANT or READ error fails the assertion LOUD (error verdict, not `reached=false`): a probe that could not run is NOT a pass. The `bypass-loopback-closure` and `split-tunnel-tight` assertions can no longer pass without a working counter.
- [ ] Against a healthy account these assertions PASS via a REAL planted+read counter (proven in the integration test - the counter is planted, the probe runs, the counter stays 0); against a real leak they FAIL. The Part A `internal/verify` integration test (`TestLiveLeakAndClosuresAgainstRealRuleset` / the counter path) passes with a VALID rule.
- [ ] Tests cover the new behaviour (unit-test the rule generation for BOTH the port and no-port cases + the plant-error-is-loud decision; live plant/probe behind the `integration` tag, isolated).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: fix a LATENT FALSE-GREEN in the trust anchor. Two verify assertions (`bypass-loopback-closure`, `split-tunnel-tight`) pass unconditionally without probing, because the escaped-leak counter generates invalid nft for the no-port case and the plant error is swallowed to reached=false. Source: `work/notes/findings/e2e-binary-revalidation.md` BUGS (the latent false-green + the Part A internal/verify failure, same root cause).
>
> FIRST, read `internal/verify/counter.go` (`escapedLeakCounterRuleset` - the `match` build where `dport` is only appended when port>0, leaving a bare `tcp`/`udp` for port<=0, which is invalid nft), `internal/verify/checks_integration.go` (the callers: `offBoxReachedAsAnon(..., "tcp", 0)` for the closures), `internal/verify/probes_integration.go` (`offBoxLeakReached` - where a plant error is swallowed to reached=false), and the hand recipe's valid rule shapes (`work/notes/findings/manual-per-uid-tor-recipe.md`).
>
> Two fixes: (1) emit VALID nft for the no-port case - `meta l4proto tcp` (all TCP to the daddr) instead of a bare `tcp`; keep `tcp dport <port>` for the port case. (2) Make a counter plant/read FAILURE a LOUD assertion failure (error verdict), NOT reached=false - a probe that could not run is not a pass (mirror the "ProbeErrorIsNotAVerdict" discipline the other assertions already use). Both matter: (1) makes the rule work, (2) means a future rule bug fails loud instead of silently green.
>
> Where to look / seams: the rule generation is pure (unit-test both cases + that a plant error is not a pass); the live plant/probe is integration-tagged, isolated to a per-run scratch table. "Done" = the two assertions plant a VALID counter and genuinely probe (green on healthy via a real 0-count, red on a real leak), and no counter error can produce a silent green. This does NOT change the assertion names or JSON contract (ADR-0003), only the probe correctness.
