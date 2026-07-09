---
title: Fix anonctl verify - probes false-fail 5/9 assertions on a healthy account (they misuse the transparent relay)
slug: fix-verify-probes-transparent-relay
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [15, 16, 17, 25]
---

## What to build

Close BUG 2 from the e2e validation (`work/notes/findings/e2e-binary-validation.md`): the trust anchor is broken. `anonctl verify` false-fails 5 of 9 live assertions against an account that is PROVABLY, correctly anonymized (the finding's step 2 proves it by hand: anon exit `107.189.13.253` IsTor:true, differs from host `51.7.210.66`). Because `verify` never returns green, it cannot be the "prove it" verb the README sells, AND the post-verify marker is never written. Two distinct probe-mechanism root causes, both about the TRANSPARENT `SO_ORIGINAL_DST` relay - the SETUP is sound, the PROBES are wrong.

- **`anonymized-exit` + `dns-remote` dial the relay as if it were a SOCKS server.** `forcedExitIP` / `dnsRemoteEvidence` (`internal/verify/probes_integration.go`) build `proxy.SOCKS5("tcp", "127.0.0.1:<RelayPort>", ...)` and send a SOCKS5 handshake to the shim's relay port. But the relay is a TRANSPARENT `SO_ORIGINAL_DST` relay (`internal/shim/relay.go`), NOT a SOCKS server: on a non-redirected direct dial, `SO_ORIGINAL_DST` returns the relay's own listen addr, so it dials itself and resets. FIX: fetch the forced-path exit IP by egressing AS THE ANON UID (so the nat chain redirects it into the relay, which then reads the real `SO_ORIGINAL_DST`), exactly like the step-2 `curl` that works - NOT by dialing the relay port as a SOCKS proxy.
- **`leak-drop-v4`, `bypass-loopback-closure`, `bypass-endpoint-closure`, `split-tunnel-tight` mis-read "TCP handshake with the relay" as "reached the target."** `probeAsAnon` dials destinations the nat chain REDIRECTS into the relay (`127.0.0.1:1`; `127.0.0.1:<relay+100>`; the loopback endpoint `127.0.0.1:9050`; a non-exempt LAN host). The nat redirect (priority -100) rewrites the destination BEFORE the filter drop/closure (priority 0) can match the original, so the handshake ALWAYS completes with the relay (which then fail-closed-drops the upstream). Treating a completed loopback handshake as REACHED means these can NEVER pass against the real relay. Decisive evidence it is not a real break: the shim journal shows the anon UID's `127.0.0.1:9050` dial was redirected into the relay and the relay's upstream SOCKS CONNECT FAILED (drop, fail-closed) - the anon UID reached the RELAY, never real Tor. FIX: assert on OFF-BOX reachability the way the hand recipe does - a raw non-53 UDP EPERM, an IPv6 http_code 000, and/or an nft escaped-leak COUNTER keyed on an off-box daddr staying at 0 - NOT on whether a loopback TCP handshake with the transparent relay completed.

The assertions that dial a genuinely non-redirected/dropped path (`leak-drop-v6`, `icmp-drop`, `non-tcp-udp-drop`) already PASS - mirror their approach. Once verify can certify a healthy host, the marker write (gated on verify passing) also starts working end-to-end.

## Acceptance criteria

- [ ] `anonymized-exit` and `dns-remote` fetch the forced-path exit/DNS by egressing AS THE ANON UID (redirected through the relay), not by dialing the relay port as a SOCKS server; they PASS against a correctly-anonymized account and FAIL when the exit equals the host / DNS is local.
- [ ] `leak-drop-v4`, `bypass-loopback-closure`, `bypass-endpoint-closure`, `split-tunnel-tight` assert on OFF-BOX reachability (raw-UDP EPERM / v6 000 / an off-box-daddr nft escaped-leak counter at 0), NOT on a loopback handshake with the transparent relay; they PASS on a healthy account and FAIL on a real leak.
- [ ] Against the finding's proven-healthy setup, `anonctl verify` returns GREEN (all 9 assertions pass) and the post-verify marker `/etc/anonctl/<account>.json` is then written.
- [ ] The `internal/verify` integration tests are updated so `TestLiveLeakAndClosuresAgainstRealRuleset` (PART A FAIL 2) passes against the REAL relay, and a healthy account is asserted green; a genuinely leaking setup still fails (keep the leak-detecting power, just stop the false-fail).
- [ ] Tests cover the new behaviour (unit-test the decision logic; live probes behind the `integration` tag, isolated to a throwaway account, host untouched).

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make `anonctl verify` correctly CERTIFY a healthy, genuinely-anonymized account (it currently false-fails 5/9 assertions on one). BUG 2 of `work/notes/findings/e2e-binary-validation.md` - the trust anchor is broken, though the underlying setup is sound (the finding proves anonymization by hand). This also unblocks the marker write (gated on verify passing).
>
> FIRST, read the finding's BUG 2 in full (it root-causes each of the 5 false-failing assertions and gives the fix), then `internal/verify/probes_integration.go` (`forcedExitIP`, `dnsRemoteEvidence`, `probeAsAnon` - the broken probes), `internal/shim/relay.go` (why the relay is transparent `SO_ORIGINAL_DST`, NOT a SOCKS server), `internal/nftables/nftables.go` (the nat redirect priority -100 vs filter priority 0 ordering that makes a loopback handshake always complete), and the hand recipe `work/notes/findings/manual-per-uid-tor-recipe.md` (the CORRECT off-box probe shapes: raw-UDP EPERM, v6 000, black-hole-DNS interception, an nft escaped-leak counter).
>
> Domain vocabulary: the shim relay is a TRANSPARENT relay reached via the nat redirect, not a SOCKS endpoint - you egress AS THE ANON UID and the kernel redirects you into it. A loopback TCP handshake with the relay ALWAYS completes (the relay accepts, then fail-closed-drops upstream), so "handshake completed" is NOT "reached the target"; assert on OFF-BOX reachability instead. The assertions that already pass (leak-drop-v6/icmp-drop/non-tcp-udp-drop) show the right pattern - mirror them.
>
> Where to look / seams: the pure assertion decision (unit-testable) and the live probe (integration, behind the tag, isolated). "Done" = verify is GREEN against the finding's healthy setup (and the marker then writes), while still FAILING on a real leak (don't neuter the leak detection - re-point it at off-box reachability). Keep the assertion NAMES + JSON contract stable (ADR-0003); this changes HOW they probe, not the contract.
