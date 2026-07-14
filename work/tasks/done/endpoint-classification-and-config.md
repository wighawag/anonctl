---
title: Endpoint model, share-class classification, per-account isolation username, and socks-peruser sharing refusal
slug: endpoint-classification-and-config
spec: per-uid-kernel-anonymized-egress
blockedBy: [manual-per-uid-recipe-validation]
covers: [4, 5, 6, 7, 8]
---

## What to build

The pure-logic core that decides HOW an account is anonymized: which endpoint, which share-class, and the cross-user-safety rules. No root, no system mutation, all unit-testable everywhere.

- **Endpoint config per account:** an account is pointed at a socks5h endpoint. The default endpoint is a local Tor SocksPort (so `add` works out of the box); alternatively ANY existing socks5h endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`, wireproxy-chained-with-gost). anonctl does NOT manage the endpoint's lifecycle.
- **Share-class classification:** classify an endpoint as `tor-shared` (per-username SOCKS-auth isolation available, a Tor SocksPort) vs `socks-peruser` (a single identity, no per-username isolation).
- **Isolation username:** for a `tor-shared` endpoint, derive the per-account `<account>@` SOCKS username so Tor's default `IsolateSOCKSAuth` gives each account its own circuit/exit. (The shim consumes this; this task decides it.)
- **socks-peruser sharing refusal:** refuse (or loudly flag) pointing a SECOND account at a `socks-peruser` endpoint already claimed by another account, else the two accounts exit identically and become cross-identifiable.
- **Scan-and-offer:** detect locally-available socks5h endpoints and offer them (mirror netcage's detect-proxy), so the operator need not hand-type an endpoint they already run.

## Acceptance criteria

- [ ] An account's endpoint config resolves the default (local Tor SocksPort) and accepts an explicit socks5h endpoint.
- [ ] Share-class classification returns `tor-shared` vs `socks-peruser` correctly for representative endpoints.
- [ ] For `tor-shared`, the derived per-account `<account>@` isolation username is distinct per account.
- [ ] Pointing a second account at an already-claimed `socks-peruser` endpoint is REFUSED/flagged loudly; sharing a `tor-shared` endpoint across accounts is allowed.
- [ ] Scan-and-offer enumerates plausible local socks5h endpoints.
- [ ] Tests cover classification, isolation-username derivation, and the socks-peruser sharing refusal, all pure logic, no root, running in the default `go test ./...`.

## Blocked by

- `manual-per-uid-recipe-validation`: confirms the `<account>@` isolation actually yields distinct circuits (the ground-truth this logic relies on).

## Prompt

> Goal: the pure-logic endpoint model, share-class (`tor-shared` vs `socks-peruser`), the per-account `<account>@` isolation username, the socks-peruser-not-shared refusal, and scan-and-offer. Stories 4, 5, 6, 7, 8 of the `per-uid-kernel-anonymized-egress` spec.
>
> FIRST, check drift: read the Tor-isolation ground-truth finding from `manual-per-uid-recipe-validation` (Tor `IsolateSOCKSAuth` is default-on per SocksPort; a distinct SOCKS username gives a distinct circuit). This task's entire cross-user-safety guarantee rests on that; if the finding says otherwise, route to needs-attention. Read `CONTEXT.md` for `endpoint` and `endpoint share-class`.
>
> Domain vocabulary: the axis that matters is NOT tor-vs-socks mechanism (the mechanism is uniform) but whether the endpoint is SAFE TO SHARE. `tor-shared` is safe across accounts BECAUSE anonctl dials with `<account>@`. `socks-peruser` is one identity, so at most one account. anonctl assumes the endpoint exists (netcage's stance) and can scan for one.
>
> Where to look: netcage (`~/dev/github/wighawag/netcage`) `internal/detectproxy` for the scan-and-offer pattern and `internal/setupdefault` for how it validates/persists a socks5h endpoint (note netcage enforces `socks5h://` and refuses embedded credentials at rest, mirror that hygiene). This is PURE logic: no root, no netns.
>
> Seams to test at: classification, username derivation, the sharing refusal (all unit-testable everywhere). "Done" = the endpoint model + share-class + isolation-username + refusal are correct and fully unit-covered. RECORD any non-obvious in-scope decision (e.g. how share-class is detected, where per-account endpoint config is stored) per the task-template guidance.
