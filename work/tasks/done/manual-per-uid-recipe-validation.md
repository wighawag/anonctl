---
title: Manually validate the per-UID recipe (nftables skuid redirect into a shim on a local Tor SOCKS port)
slug: manual-per-uid-recipe-validation
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [31]
---

## What to build

The code-free first milestone: by hand, on one throwaway Unix account, stand up and confirm the whole anonctl model BEFORE any Go code, then record the working recipe as a finding the later Go tasks encode.

End-to-end, by hand as root on a Linux box with a running Tor whose SocksPort is reachable:

1. Create a dedicated `anon` account and a distinct dedicated shim UID (a separate service account).
2. Run a redsocks-style transparent TCP-to-SOCKS relay (any stand-in is fine for validation: distro `redsocks`, or a throwaway script) plus a DNS-over-SOCKS-TCP forwarder, listening on a per-account loopback port, running as the shim UID, pointed at the local Tor SocksPort and dialing it with a per-account `<account>@` SOCKS username (empty password) so Tor's default `IsolateSOCKSAuth` gives that account its own circuit.
3. Install an `inet` nftables ruleset that, for `meta skuid <anon-uid>`: redirects TCP to the shim loopback port and DNS (UDP/TCP 53) to the shim DNS port; default-DROPs everything else for that UID; and enforces the two bypass closures: (a) the anon UID may reach ONLY its own shim loopback port (all other 127.0.0.0/8 and ::1 dropped), and (b) only the shim UID (never the anon UID) may reach the Tor SocksPort. Cover IPv4 AND IPv6 in the one ruleset.
4. Confirm by hand, as the anon account: outbound HTTP exits via Tor (check.torproject.org says Tor / the exit IP differs from the host); DNS resolves remotely (no plaintext query leaves the box); a direct connection attempt is DROPPED (fail-closed); the anon UID cannot reach any other loopback service; and the anon UID cannot dial the Tor SocksPort directly.

Record the exact working recipe (the `nft` ruleset text, the shim/forwarder invocation, the account/UID layout, the `<account>@` isolation detail) as a `work/notes/findings/*.md` with a `source:` line, so the Go ruleset/shim/verify tasks encode a proven recipe rather than a guessed one. Also capture, in that finding or a sibling one, the confirmed external ground-truth that Tor `IsolateSOCKSAuth` is default-on per SocksPort and that a bare `<account>@` username yields a distinct circuit (cite the Tor man page / Whonix Stream Isolation page as the source).

## Acceptance criteria

> Validated 2026-07-07 end-to-end on a real host (Debian 13 "trixie", kernel 6.12.90+deb13.1-amd64, Tor 0.4.9.9, nftables v1.1.3), maintainer at the root keyboard with the agent driving. anon UID = 30034, shim UID = 995. Recipe + observed outputs in `work/notes/findings/manual-per-uid-tor-recipe.md`; Tor isolation ground-truth in `work/notes/findings/tor-isolatesocksauth-default.md`. One deviation from the drafted recipe: the DNS-leak check. A transparent redirect means `dig @<resolver>` STILL returns an answer (silently rerouted to the shim), so "direct dig must fail" is the wrong assertion; the correct check is a black-hole resolver (`@192.0.2.1` still answers => intercepted) plus an nft counter proving zero udp/53 packets leave with an off-box dst (observed 0). Both confirmed no leak.

- [x] On a real Linux host, the anon account's egress exits via Tor (check.torproject.org confirms; exit IP differs from the host). _(anon UID -> {"IsTor":true,"IP":"45.66.35.21"}; host 147.147.37.112.)_
- [x] DNS from the anon account resolves remotely (verified no plaintext DNS leaves the box, e.g. by observing that a direct :53 attempt is dropped and resolution still works through the shim). _(black-hole `dig @192.0.2.1` still answers => transparently intercepted; nft escaped-leak counter = 0; shim DNS port resolves.)_
- [x] A direct (non-shim) connection attempt from the anon UID is DROPPED (fail-closed demonstrated, not just configured), on BOTH IPv4 and IPv6. _(raw UDP/9999 -> "Operation not permitted"; IPv6 curl -> 000/exit7.)_
- [x] Bypass closure (a): the anon UID cannot reach any loopback destination other than its own shim port. _(anon -> 127.0.0.1:9150 dropped (000); own relay port reachable.)_
- [x] Bypass closure (b): the anon UID cannot connect directly to the Tor SocksPort (only the shim UID can). _(anon -> 127.0.0.1:9050 dropped (exit97); shim UID -> 9050 -> {"IsTor":true}.)_
- [x] A `work/notes/findings/*.md` recipe doc is written with a `source:` line, containing the exact `nft` ruleset, the shim/forwarder invocation, the account/shim-UID layout, and the `<account>@` isolation detail. _(`work/notes/findings/manual-per-uid-tor-recipe.md`, fully validated with real outputs + shim source.)_
- [x] A finding captures the Tor `IsolateSOCKSAuth`-is-default + per-username-circuit ground-truth with an external `source:` (Tor man page / Whonix). _(`work/notes/findings/tor-isolatesocksauth-default.md`, empirically confirmed + tor(1) man page + Whonix Stream Isolation cited.)_

## Blocked by

- None, can start immediately.

## Prompt

> Goal: prove the anonctl per-UID anonymized-egress model by hand on ONE account before any Go code, and record the working recipe as a finding the Go tasks will encode. This is story 31 of the `per-uid-kernel-anonymized-egress` spec and the root of every other task (they `blockedBy` this).
>
> FIRST, check this task against current reality: the repo is greenfield (no Go code yet), so there is nothing to drift from except the spec. Read `work/specs/tasked/per-uid-kernel-anonymized-egress.md` (Solution + User Stories) and `CONTEXT.md` for the vocabulary (anon account, shim, endpoint, endpoint share-class, fail-closed/default-DROP, the two bypass closures, marker).
>
> Domain vocabulary: the forcing is UNIFORM (one mechanism, not a per-backend split): an nftables `meta skuid <anon-uid>` redirect of the account's TCP into a per-account shim that speaks socks5h, DNS resolved remotely over the endpoint. Tor is just the default endpoint (its SocksPort). Cross-user safety comes from dialing Tor with a per-account `<account>@` SOCKS username so `IsolateSOCKSAuth` (Tor's default) gives each account its own circuit/exit.
>
> Reference: netcage (`~/dev/github/wighawag/netcage`) already ships a DNS-over-SOCKS-TCP forwarder (`internal/dnsforwarder`) and documents fail-closed forced egress; Whonix publishes the reference transparent-Torification nft rules (adapt from whole-box to per-UID-on-shared-host). This is a MANUAL, human-run validation: use any stand-in for the shim (distro `redsocks`, a script), you are validating the RULESET and the model, not building the production shim (that is a later task).
>
> Where to look: this task writes NO production code. Its deliverable is a `work/notes/findings/*.md` recipe (with `source:`) plus the hand-run confirmation. RECORD the exact nft ruleset text and the isolation detail precisely, the Go ruleset/shim/verify tasks depend on this being a proven, copy-able recipe.
>
> "Done" = every acceptance box is checked on a real Linux host, and the recipe + the Tor-isolation ground-truth are captured as findings with sources.
