---
kind: idea
title: Make the host-IP baseline fetch off-by-default (Tor proves egress via the exit-confirmation, not by comparing to the real IP), and run the verify gate inline at add-time
slug: host-ip-fetch-off-by-default-and-verify-on-add
status: implemented
---

> Implemented. verify-side: `needsHostBaseline` (internal/verify/checks_live.go) gates the direct host-IP fetch OFF on the tor-shared default path; `AnonymizedExitAssertion` (internal/verify/verify.go) tolerates an empty hostIP and renders honest detail. add-side: `runAdd` (main.go) runs the shared `verifyAndMark` gate inline via the `addVerifyReport` seam, warn-and-continue. Tests: `TestNeedsHostBaseline`, `TestAnonymizedExitAssertion_TorDefaultPassesWithoutHostBaseline`. Docs: README.md, CONTEXT.md updated.

## The concern

`verify`'s `anonymized-exit` assertion fetches a public IP echo (`api.ipify.org`) TWICE: once over the DIRECT host path (`hostExitIP`, revealing the real IP) and once over the forced path (`forcedExitIP`, revealing the Tor/SOCKS exit). Today the DIRECT host fetch runs UNCONDITIONALLY. That direct request tells the echo provider "this real IP is running an anonymity self-test", and, because it happens within seconds of the forced fetch, gives a motivated, logging echo provider a WEAK timing hint that the real IP and the observed Tor exit might be the same operator. It reveals nothing about anonymized activity (the forced request is only "what is my IP"), and it is not the both-ends traffic-confirmation attack (the provider sees only the exit side, and a single trivial request is poor correlation material). But the identifying half (the real-IP request) is avoidable in the common case, so it should not be on by default.

## The key observation

The host-IP fetch is NOT equally load-bearing across endpoint classes:

- **`tor-shared` (Tor):** there are TWO independent positive proofs of forced egress: (a) `exitIP != hostIP`, and (b) the exit is a CONFIRMED Tor exit via check.torproject.org / onionoo (fetched OVER Tor through the shim, so that request is itself anonymized). Proof (b) alone establishes forced egress (a real Tor exit is definitionally not the host IP). So for the Tor DEFAULT path, the host-IP fetch is REDUNDANT with the Tor-exit confirmation. Note the Tor path already HARD-FAILS on a registry miss unless `--skip-tor-exit-check` is passed, so removing the redundant host-diff does not weaken the default Tor gate: it already requires registry confirmation to pass.
- **`socks-peruser` (non-Tor):** the ONLY positive proof available is `exitIP != hostIP`. Drop the host fetch here and there is NO proof of forced egress left. So for non-Tor the host fetch is ESSENTIAL.
- **`--skip-tor-exit-check` on a Tor endpoint:** the operator has WAIVED proof (b), so proof (a) `exitIP != hostIP` becomes the only remaining proof and the host fetch must run.

## What to build

Gate `hostExitIP` on WHETHER the diff proof is actually needed, so the real-IP request only ever egresses when the Tor-exit confirmation is unavailable or inapplicable:

| Case | Host-IP baseline fetch | Positive proof used |
| --- | --- | --- |
| Tor (`tor-shared`), default | OFF | exit is a confirmed Tor exit (check.torproject.org / onionoo, over Tor) |
| Tor, `--skip-tor-exit-check` | ON | falls back to `exitIP != hostIP` (Tor confirmation waived) |
| Non-Tor (`socks-peruser`) | ON | `exitIP != hostIP` (only available proof) |

Mechanically: `checks_live.go` already calls `hostExitIP` unconditionally then hands `hostIP` to the pure `AnonymizedExitAssertion`. The change is to skip the `hostExitIP` call when `p.Class == ClassTorShared && !p.SkipTorExitCheck`, passing `hostIP=""` in that case. The pure assertion ALREADY tolerates an empty `hostIP` (the `hostIP != "" && exitIP == hostIP` guard is skipped, and the tor-shared branch confirms via `ev.confirmsTor()` without needing the host IP), so the pure decision needs little or no change: the surgery is almost entirely in the live layer that decides whether to make the direct request. The assertion Detail should stop printing "differs from host <hostIP>" when no host baseline was taken, and instead say the proof was the Tor-exit confirmation (honesty: do not claim a host-diff we did not measure).

## verify-on-add (the second, related change)

`add` today provisions + forces, then TELLS the operator to run `anonctl verify`. Fold the verify gate INTO `add` so provisioning ends with an inline proof instead of a homework instruction. Nuances to respect:

- `verify` MUST remain a standalone ongoing verb (re-run after reboot / Tor / kernel / nftables change); this does not remove it, it just also runs it at add-time.
- `add` needs the ENDPOINT UP to prove anything. If the endpoint is down at add-time, `add` must NOT hard-fail the provisioning: the rules are fail-closed and correct regardless (the account is DROPPED, not free). It should loudly report that anonymization could not YET be proven and name the follow-up (`anonctl verify <name>` once the endpoint is up), rather than silently succeeding or wrongly failing.
- Reuse the SAME shared verify path `use`/`exec` already gate on (the assertion set + progress streaming), so add-time proof shows the same per-check progress and the same JSON contract.

## Design constraints (this repo's posture)

- **Fail-closed the verifier.** Never report green unless green was actually proven. Removing the host fetch must not create a path where forced egress is UNproven yet passes: the Tor-default path still requires registry confirmation (a hard fail on a miss today), which is a real positive proof, so this holds.
- **Honesty in the Detail string.** When no host baseline is taken, do not print a host-diff. State the proof used (Tor-exit confirmation) so the message matches what was measured.
- **Pure decision, impure edge.** The whether-to-fetch decision lives in the live layer; the pure `AnonymizedExitAssertion` stays unit-testable and already accepts an empty host IP. Add a live-layer test that the direct fetch is NOT made on the Tor-default path (behind the existing probe seams).

## Open decisions

- Should there be an explicit opt-in flag to force the host baseline even on the Tor-default path (belt-and-suspenders "prove it differs too"), or is the Tor-exit confirmation sufficient on its own? Default posture: confirmation is sufficient; do not re-add the identifying request without an explicit flag.
- add-time verify on a DOWN endpoint: warn-and-continue (provisioning succeeded, proof pending) vs a distinct non-zero-but-provisioned exit code so scripts can tell "forced but unproven" from "green". Lean warn-and-continue with a clearly named follow-up; confirm the exit-code contract.
- Whether `--json` `add` should emit the inline verify report envelope (add is not a `--json` verb today).

## Relationship to the shipped model

Touches only the `anonymized-exit` probe's DIRECT-request policy and `add`'s tail; the forcing, the marker contract, DNS-remote, and the drop/closure assertions are untouched. It TIGHTENS the privacy of the verifier itself (the verifier should not be the thing that most-identifies you) and improves `add` ergonomics (prove at provision-time), without weakening any fail-closed guarantee.
