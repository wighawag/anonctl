---
title: The LAN exemption must never carry clear DNS (reject :53, and exclude 53 from the all-ports case) + verify it
slug: lan-exemption-must-not-be-a-dns-hole
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

Close row 2 of the Tails leak catalogue (`work/notes/findings/tails-network-filter-lessons.md`): our own LAN-exemption feature can currently be used to open a CLEAR-DNS hole to a LAN resolver, which Tails explicitly forbids because a `@192.168.x.x` DNS query can reveal the local network's public IP (a deanonymization vector).

The current LAN exemption (`internal/lanexempt`, consumed by `internal/nftables`) is TCP-only, so UDP/53 to a LAN resolver is safely redirected to the shim. BUT two paths still open clear TCP-DNS to the LAN:

1. An explicit port-53 exemption, e.g. `192.168.1.1:53`, emits `... tcp dport 53 accept` before the redirect: a direct clear TCP-DNS hole.
2. A port-omitted exemption (`Port == 0`, "all TCP ports"), e.g. `192.168.1.1`, emits an all-TCP-ports accept that INCLUDES port 53: the same hole, silently.

Fix both, at the guardrail (fail loud, do not silently rewrite):

- `internal/lanexempt.Parse` REJECTS an exemption whose explicit port is 53 (TCP DNS), loudly, naming the value and the reason (a LAN DNS hole can reveal the local network's public IP; route DNS through the anonymizer instead). Consider whether to reject only 53, or 53 + 853 (DoT) + 5353 (mDNS) as clear-DNS-ish ports; at minimum 53.
- For the port-omitted ("all TCP ports") case, the emitted nft accept must EXCLUDE port 53 so an all-ports exemption never carries DNS. Prefer an explicit rule shape (e.g. accept all TCP to the host EXCEPT dport 53, with 53 still redirected to the shim) over silently trusting policy order. Decide and record the exact nft form.
- Add a `verify` assertion (`internal/verify`) that, with a LAN exemption active, a DNS query (tcp AND udp 53) to the exempted host is NOT answered directly / does not leave as clear DNS to the LAN resolver: it is either redirected to the shim or dropped, never a direct clear query to the LAN. Name it e.g. `lan-exemption-not-a-dns-hole`. Pin the assertion name in the verify JSON contract (ADR-0003).

## Acceptance criteria

- [ ] `lanexempt.Parse` rejects an explicit `:53` exemption loudly (naming the value + why); a unit test covers it.
- [ ] A port-omitted (all-TCP) exemption does NOT open clear TCP/53 to the exempted host: the generated nft ruleset excludes 53 from the exemption accept (53 stays redirected to the shim). A `internal/nftables` unit test on the generated text proves 53 is not directly accepted for an all-ports exemption.
- [ ] A new `verify` assertion proves, with a LAN exemption active, that clear DNS (tcp+udp 53) to the exempted host does not egress directly (redirected-or-dropped). Unit-tested for the assertion/render logic; the live check sits behind the `integration` build tag.
- [ ] The verify assertion name is added to the JSON contract and ADR-0003 updated (or a follow-on ADR notes the addition).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style).

## Blocked by

- None, can start immediately (it hardens shipped code in `internal/lanexempt`, `internal/nftables`, `internal/verify`).

## Prompt

> Goal: make the anonctl LAN exemption structurally incapable of being a clear-DNS hole, and prove it in verify. This closes row 2 of the Tails leak catalogue. Source of truth: `work/notes/findings/tails-network-filter-lessons.md` (row 2) and the empirically-validated `work/notes/findings/manual-per-uid-tor-recipe.md` (the DNS subtlety: a transparent redirect means a direct dig STILL answers, so assert via a black-hole/counter probe, not "dig must fail").
>
> FIRST, check drift: read the shipped `internal/lanexempt/lanexempt.go` (the guardrail, `Parse`/`splitPort`), `internal/nftables/nftables.go` (`exemptMatch` and where the exempt `accept`/`return` are emitted), and `internal/verify` (the assertion set + JSON contract). Confirm the exemption is still TCP-only and still emits the accept before the redirect/drop.
>
> Domain vocabulary: the LAN exemption is a narrow, private-only, host+port-scoped direct hole (cops netcage's --allow-direct). The Tails rule this enforces: LAN DNS is forbidden because a `@192.168.x.x` resolver can reveal the local network's public IP. anonctl already scopes the exemption to an exact host:port; this task makes 53 un-exemptable and proves it.
>
> Two holes to close: (1) an explicit `:53` exemption; (2) a port-omitted ("all TCP ports") exemption that includes 53. Fix at the guardrail (reject explicit 53, loud) AND at the nft generation (all-ports accept must exclude 53, which stays redirected to the shim). Decide the exact nft form and record any non-obvious in-scope decision (an ADR if it meets the bar). Then grow `verify` with a `lan-exemption-not-a-dns-hole` assertion.
>
> Where to look: `internal/lanexempt` (guardrail + unit tests), `internal/nftables` (generation + the generated-text unit tests), `internal/verify` (`checks_integration.go` for the live probe, `verify.go` for the assertion name + JSON contract). Seams to test at: the guardrail reject (unit), the generated nft text for the all-ports case (unit), the live no-clear-LAN-DNS probe (integration, behind the tag). "Done" = 53 is un-exemptable by construction and verify proves it. This mirrors a fix that ALSO applies to netcage's --allow-direct (recorded there); keep the anonctl and netcage guardrail shapes consistent where practical.
