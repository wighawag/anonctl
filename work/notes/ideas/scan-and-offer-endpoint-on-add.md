---
kind: idea
title: Scan-and-offer a socks5h endpoint on add (default confirmed Tor), annotate in-use, TTY-aware with a non-interactive fallback
slug: scan-and-offer-endpoint-on-add
status: proposed
---

## The idea

Today a bare `anonctl add` (no `--endpoint`) blindly configures the default Tor SocksPort (`127.0.0.1:9050`) whether or not anything is listening. anonctl ALREADY has the detection engine (`endpoint.Scan`, mirroring netcage's `detect-proxy`: probe 9050/9150/1080, CONFIRM SOCKS5 via a real RFC1928 handshake, offer only confirmed candidates with a suggested share-class) but nothing calls it. This wires `Scan` into `add`'s no-endpoint path: scan the local ports, DEFAULT to a confirmed Tor endpoint when found, let the operator choose (interactively) or fall back cleanly (non-interactively), and ANNOTATE each offered endpoint with "in use by <account>" from the on-disk claim set (reusing task 1's `accountconfig.List`).

## What to build

1. **A PURE endpoint-choice decision** (a new pure seam, unit-testable with no socket/TTY): given the scan offers, the on-disk claim set (which peruser endpoints are taken and by whom), and whether the session is interactive, decide the outcome:
   - **Explicit `--endpoint`**: bypass the whole flow (unchanged; still guarded by task 1's `claimEndpoint`).
   - **A confirmed Tor (tor-shared) offer exists**: that is the DEFAULT selection.
   - **Interactive + candidates**: present the evidence-only list (never labelling the provider, netcage's honesty rule), each annotated share-safe/`in use by <account>`, with the Tor default pre-selected; the operator picks or types one.
   - **Non-interactive (no TTY)**: do NOT prompt. Pick the confirmed Tor default if present; else FAIL CLOSED with a clear message ("no endpoint confirmed; pass --endpoint ...") rather than silently configuring a dead 9050. This keeps `add` scriptable/CI-safe.
2. **The "in use by" annotation**: fold the claim set so a `socks-peruser` offer already owned by another account is shown as taken (and NOT selectable for a second account, dovetailing with task 1's refusal); a `tor-shared` offer is always shown share-safe (never "taken"), because sharing Tor is the point.
3. **Wire into `add`**: replace the blind `resolveEndpoint("")` default with the scan-choose flow when no `--endpoint` is given. The chosen endpoint still flows through task 1's `claimEndpoint` guard before any mutation (belt and suspenders: the annotation is advisory, the Claim is the enforcement).

## Design constraints (this repo's posture)

- **Honesty / never label the provider.** Mirror netcage detect-proxy + anonctl's own `Scan` doc: evidence only (open + SOCKS5-confirmed + a hedged "likely Tor" prior from the port), never "you are on Tor". The suggested class is a port-conventional prior the operator can override.
- **Confirmed, not assumed.** The win is that `add` now CONFIRMS the default endpoint actually speaks SOCKS5 before committing, instead of configuring 9050 blind.
- **Non-interactive must be safe.** No TTY => no prompt => Tor-if-confirmed else fail-closed. A prompt that blocks a script, or a silent wrong pick, are both unacceptable.
- **Pure decision, impure shell.** The choice logic is a pure function over (offers, claim set, interactive bool, chosen index); the TTY read + the real `DialProber` scan are the thin impure edges behind package-var seams (mirroring the verify progress / useExec seams). So the whole decision is unit-tested with no socket and no terminal.

## Open decisions

- **Prompt shape**: a numbered menu (pick N, or type an endpoint, or accept the Tor default on empty-enter) is the netcage-ish shape. Confirm the exact keys and that empty-enter = the default.
- **Root + claim-set read**: the annotation reads root-only account configs; `add` already runs as root (self-elevate), so this is fine. No non-root path is needed here (the annotation only appears in `add`'s interactive flow).
- **`--json` / quiet**: `add` is not a `--json` verb today; the scan output is human-only. If a machine wants the scan, that is the existing `Scan` primitive / a future `detect` verb, out of scope here.

## Relationship to task 1 + the shipped model

Builds directly on `endpoint-registry-from-account-configs` (task 1): the annotation and the "not selectable for a second account" behaviour reuse `accountconfig.List` + the Registry, and the final choice still passes through `claimEndpoint` (the enforcement). It changes only the ERGONOMICS of choosing an endpoint on `add`; the forcing, marker/verify, and the endpoint model are untouched. It is the interactive layer the task-1 idea note flagged as the natural follow-up.
