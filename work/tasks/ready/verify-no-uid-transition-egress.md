---
title: verify assertion - best-effort no-uid-transition-egress (the enumerable escape vectors do not leak)
slug: verify-no-uid-transition-egress
prd: per-uid-kernel-anonymized-egress
blockedBy: [empirical-uid-transition-escape-audit]
covers: [30]
---

## What to build

Shape 2 of the row-7 design pass (`work/notes/ideas/uid-transition-escape-investigation.md`): a best-effort `verify` assertion (`no-uid-transition-egress`) that actively tests the CONCRETELY ENUMERABLE UID-transition escapes and confirms they do not yield an off-box socket owned by a non-anon, non-shim uid that bypasses forcing.

Grounded in `work/notes/findings/uid-transition-escape-surface.md`, add a named assertion (mirror the existing verify shape in `internal/verify`) that probes the enumerable vectors:

- **sudo:** confirm the anon account cannot reach the network via `sudo` (sudo unavailable / no permitting entry).
- **known setuid network paths:** for the small, documented set of setuid/privileged network paths the audit found, confirm none yields an off-box socket owned by a non-anon, non-shim uid that escapes the `skuid` forcing.

### Honesty framing, RESOLVED in the design pass (do not soften)

- The assertion is **best-effort, NOT exhaustive.** `verify` cannot enumerate every daemon on every host. It proves "the CHECKED transition vectors do not escape", and its detail string + the docs state the residual plainly (an arbitrary triggerable daemon on a busy host may still escape; the per-UID model cannot close that, only netns can). Do NOT present it as a total guarantee.

## Acceptance criteria

- [ ] A named `verify` assertion (`no-uid-transition-egress`) probes the enumerable vectors from the audit finding (at minimum: the anon account cannot egress via sudo; the documented setuid network paths do not escape forcing).
- [ ] The assertion is HONESTLY framed as best-effort: its detail/report text (and the docs) state it proves only the CHECKED vectors, not exhaustive absence.
- [ ] The pure decision logic is unit-tested; the live probe runs behind the `integration` tag, isolated to a throwaway account, host untouched.
- [ ] The assertion name is pinned in the verify JSON contract (ADR-0003 or a follow-on ADR records the addition).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- `empirical-uid-transition-escape-audit` - the finding enumerating the vectors this assertion probes (without it the probe list is a guess).

## Prompt

> Goal: a best-effort `verify` assertion that proves the ENUMERABLE UID-transition escape vectors (sudo, known setuid network paths) do not leak, framed honestly as non-exhaustive. Shape 2 of the row-7 design pass. Sharpens story 30 (honest threat model) into a tested posture.
>
> FIRST, check drift: read the audit finding `work/notes/findings/uid-transition-escape-surface.md` (the vectors to probe - do not invent them), `internal/verify` (the assertion/`Check`/`LiveParams` shape, how the existing leak-drop assertions build a probe + decision, and the JSON contract in `verify.go` + ADR-0003), and the shipped ruleset (`internal/nftables/nftables.go`, the `skuid != ` escape). If `harden-anon-account-against-uid-transition` has landed, the sudo-absence it provisions is what this asserts.
>
> Domain vocabulary: the escape is a socket owned by a non-anon, non-shim uid egressing in the clear (it does not match `skuid == anonUID`). This assertion proves the checked vectors do not do that. It is BEST-EFFORT by nature (verify cannot enumerate every daemon); say so honestly in the detail string and docs - a false total-guarantee here would be worse than an honest partial one.
>
> Where to look / seams: mirror the existing verify assertions (pure decision unit-tested; live probe behind the `integration` tag, isolated to a throwaway account). "Done" = `verify` runs a `no-uid-transition-egress` assertion over the enumerable vectors, honestly framed, unit + integration tested, pinned in the JSON contract. Keep the honesty framing intact; do not let it drift into an over-claim.
