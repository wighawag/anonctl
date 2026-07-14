---
title: The fail-closed inet nftables ruleset with the two bypass closures (applied as root)
slug: nftables-ruleset-install
spec: per-uid-kernel-anonymized-egress
blockedBy:
  [
    manual-per-uid-recipe-validation,
    account-provisioning-and-cli-skeleton,
    socks-shim-binary,
    endpoint-classification-and-config,
  ]
covers: [9, 11, 13, 14, 32]
---

## What to build

Generate and APPLY (as root, the ufw stance) the per-account nftables ruleset that IS the kernel half of the forcing. This is the load-bearing security task.

- One `inet` table so IPv4 AND IPv6 are covered in a single ruleset (closing the v4-rules-v6-leaks trap by construction).
- For `meta skuid <anon-uid>`: a `nat`/output redirect of TCP to the account's shim loopback port and of DNS (53) to the shim's DNS port; a `filter`/output chain that accepts ONLY the account's own shim loopback port(s) + established/related and DROPS everything else for that UID (default-DROP is the account's policy).
- **Bypass closure (a):** NO blanket loopback-accept, the anon UID reaches only its own shim; all other `127.0.0.0/8` and `::1` destinations are dropped for that UID.
- **Bypass closure (b):** the shim runs under its distinct dedicated shim UID, and only the SHIM UID may reach the upstream endpoint; the anon UID cannot dial the endpoint directly (so it cannot skip the shim or the `<account>@` isolation username).
- anonctl generates the ruleset from the account's UID, shim UID, shim ports, and endpoint (from the provisioning + endpoint tasks) and applies it itself. Encode the exact `nft` form the manual recipe validated.

## Acceptance criteria

- [ ] The ruleset is a single `inet` table covering v4 and v6; applied by anonctl as root.
- [ ] For the anon UID: TCP is redirected to the shim port, DNS to the shim DNS port, and all else is DROPPED (fail-closed default-DROP).
- [ ] Bypass closure (a): the anon UID cannot reach any loopback destination other than its own shim port (asserted for v4 and v6).
- [ ] Bypass closure (b): the anon UID cannot connect to the upstream endpoint directly; only the shim UID can.
- [ ] Ruleset generation (the pure "given UID/ports/endpoint, produce the nft text" function) is unit-tested; the actual apply + the drop/closure behaviour are integration-tested behind the `integration` build tag (need root + nftables).
- [ ] **Shared-write isolation:** integration tests that apply real nft rules isolate to a throwaway account/UID + a scratch table name and assert the host's other rules are UNTOUCHED after the run (delete only what the test created).

## Blocked by

- `manual-per-uid-recipe-validation`: the proven `nft` recipe this encodes.
- `account-provisioning-and-cli-skeleton`: the anon UID + dedicated shim UID.
- `socks-shim-binary`: the shim loopback + DNS ports the rules redirect to.
- `endpoint-classification-and-config`: the endpoint address closure (b) scopes to the shim UID.

## Prompt

> Goal: generate and apply, as root, the fail-closed `inet` nftables ruleset with the two bypass closures, the kernel half of anonctl's forcing. Stories 9, 11 (nft half), 13, 14 (nft half), 32 of the `per-uid-kernel-anonymized-egress` spec. This is the highest-stakes task: a wrong rule silently leaks a real IP or locks a user out of the network.
>
> FIRST, check drift: the exact `nft` ruleset text is the deliverable of `manual-per-uid-recipe-validation` (a `work/notes/findings/*.md` with `source:`). ENCODE that proven recipe, do not invent a fresh ruleset. Confirm the anon UID + shim UID from `account-provisioning-and-cli-skeleton` and the shim ports from `socks-shim-binary` match what this generates. If any dependency landed differently, route to needs-attention rather than build on a stale premise.
>
> Domain vocabulary: UNIFORM forcing via `meta skuid` redirect into the per-account shim; default-DROP for the UID; the TWO bypass closures (anon UID reaches only its own shim; only the shim UID reaches the upstream endpoint). anonctl APPLIES the rules itself (the ufw stance).
>
> Where to look: the recipe finding (authoritative); Whonix's published transparent-Torification nft rules as the reference (adapt whole-box to per-UID-on-shared-host); netcage's `internal/verify` for the integration-test-behind-a-build-tag pattern and its shared-write isolation discipline (isolate to throwaway resources, assert the host untouched). Split the pure ruleset-GENERATION function (unit-testable: given UID/ports/endpoint, emit nft text) from the APPLY (integration, root, behind the `integration` tag).
>
> Seams to test at: the generated nft text (unit), and the actual drop/redirect/closure behaviour (integration). "Done" = the ruleset applies, forces + fail-closes the anon UID on v4 and v6, both bypass closures hold, generation is unit-covered, and the integration tests isolate and leave the host untouched. RECORD non-obvious in-scope decisions (table/chain names, rule ordering, any priority choices) as ADRs or a done-record note per the task-template guidance.
