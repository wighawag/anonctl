---
kind: idea
title: Wire the endpoint Registry from the on-disk account configs (refuse a second account on a socks-peruser endpoint)
slug: endpoint-registry-from-account-configs
status: proposed
---

## The idea

anonctl already has the MECHANISM for the cross-identification refusal: `endpoint.Registry.Claim` refuses a SECOND account pointed at a `socks-peruser` endpoint (`ErrPeruserAlreadyClaimed`, naming the conflicting account) and ALLOWS many accounts to share a `tor-shared` endpoint (Tor's `<account>@` IsolateSOCKSAuth isolates each). But nothing POPULATES the Registry: `add`/`update` never consult the other accounts' endpoints, so the refusal never fires in practice. The `endpoint.go` doc comment says this out loud: "the persistence task wires the real claim set from the on-disk account configs." This is that wiring.

The change: at `add` and `update`, build the Registry from EVERY existing account config under `/etc/anonctl/accounts/*.json`, then `Claim` the chosen endpoint for the target account. A collision on a `socks-peruser` endpoint already claimed by a DIFFERENT account REFUSES the add/update (fail-loud, naming the owner), so two accounts can never silently share a single-identity endpoint and become cross-identifiable. A `tor-shared` endpoint is never refused (that is the whole point of the class): the "which endpoint is taken" question only meaningfully applies to `socks-peruser`.

## Why now / why it fits

- The refusal is ALREADY unit-tested (`endpoint_test.go` TestRegistryRefusesSharingSocksPeruser / AllowsSharingTorShared / SameAccountReclaimIsAllowed). Only the population from disk is missing.
- The correctness rule the maintainer flagged is already encoded: sharing is safe for Tor, unsafe for a plain socks endpoint. The Registry tracks ONLY `peruserOwner` and deliberately does not track `tor-shared` ("share-safe, nothing to refuse"). So this must NEVER refuse a shared Tor endpoint.
- Idempotency is already handled: `Claim` allows the SAME account to re-claim (a reconfigure/re-add of an account onto its own peruser endpoint is fine).

## What to build

1. **`accountconfig.Store.List()`** (new): enumerate every `<account>.json` under BaseDir and return the parsed Configs (skipping non-config files; a corrupt one is a loud error, never silently dropped). This is the "read the claim set from disk" primitive the Registry needs. Behind the same BaseDir seam as the rest of the store, so tests isolate `/etc`.
2. **A Registry-from-configs builder**: fold the listed Configs into a Registry via `Claim` (each config's account + its endpoint). The target account's OWN existing config is naturally idempotent under `Claim`.
3. **Wire into `add` and `update`**: after resolving the chosen endpoint, build the Registry from the other accounts and `Claim` the target account's endpoint BEFORE installing/reconfiguring the forcing. A refusal aborts with a clear, non-zero error naming the conflicting account; it never reaches the nft/systemd mutation. A `tor-shared` endpoint always passes.

## Open decisions / caveats

- **Root-gating.** The account configs are root-only 0600, and `add`/`update` already run as root, so building the Registry there is fine. A non-root read (a future `status`-side "in use by" annotation) could not see them; that INFORMATIONAL view is a SEPARATE follow-up (the scan-and-offer task), not this one. This task is the ENFORCEMENT half only.
- **Self-consistency on re-add.** When `add` re-runs on an existing account, its own config is in the listing; `Claim`'s same-account allowance keeps that idempotent. Confirm the target account is claimed LAST (or its own prior claim is treated as self) so a re-add never trips on itself.
- **A corrupt sibling config.** `List()` must fail loud on a malformed config (a typo in one account's json must not silently disable the cross-identification guard for a new account). Decide whether a single corrupt file aborts the whole add or is skipped-with-warning; leaning fail-loud (the guard is security-relevant).

## Relationship to the shipped model

Pure enforcement wiring over machinery that already exists. It does not change the forcing, the marker/verify trust anchor, or the endpoint model; it makes the ALREADY-DESIGNED `socks-peruser` sharing refusal actually fire by feeding the Registry the on-disk truth. Follow-up: the interactive scan-and-offer on `add` (default Tor-if-confirmed) can then annotate each offered endpoint with "in use by <account>" using the same config read.
