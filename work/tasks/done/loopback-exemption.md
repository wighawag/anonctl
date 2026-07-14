---
title: The loopback exemption (exact 127.0.0.1:port direct hole for a same-host service, via the unified --allow)
slug: loopback-exemption
spec: per-uid-kernel-anonymized-egress
blockedBy: [allow-require-explicit-port-and-rename]
covers: []
---

## What to build

Let the unified `--allow` flag accept a same-host loopback destination `127.0.0.1:<port>` (e.g. a local AI/model server bound to loopback), so the anon account can reach that ONE trusted local port DIRECTLY while every OTHER loopback destination stays closed by closure (a) and all external egress stays forced fail-closed.

Motivating use case: run the local model on the SAME host, bound to loopback only, without forcing it onto `0.0.0.0` just so the anon account can reach it via a LAN IP. Binding loopback-only keeps the model private to the host; the `0.0.0.0` + LAN-IP workaround exposes it to the whole LAN and hairpins host-local traffic out the NIC and back.

This builds directly on `allow-require-explicit-port-and-rename`, which already made `--allow` port-mandatory and exact-host:port-only. So a loopback exemption is the SAME shape as a LAN one (`--allow <host>:<port>`); the only new thing is a SECOND guardrail branch for the loopback address class. There is ONE flag (`--allow`) and ONE operator-facing config surface (`defaults.json` `allow`), and the tool DISPATCHES on the address the user typed:

- **Unified flag, class-dispatch (NOT a second flag, NOT a second field).** `--allow 127.0.0.1:8080` and `--allow 192.168.1.150:8080` go through the same flag and the same `allow` config key. `lanexempt.Parse` (or a renamed `exempt.Parse`) inspects the address and routes to the right guardrail branch: loopback vs RFC1918/link-local. The user already typed `127.0.0.1` vs `192.168.x.x`, so the class is self-evident at the call site and needs no separate flag to disambiguate (this was the explicit design decision: a separate field/flag is silly when the address makes the class obvious).
- **The loopback guardrail branch (STRICTER than the LAN branch).** For a loopback host (`127.0.0.0/8`, and `::1` if v6 is in scope):
  - port MANDATORY (already true globally after the prerequisite task, but re-assert: loopback has NO all-ports form under any circumstance);
  - the port must NOT be a known anonymizer control/SOCKS/DNS port. REJECT loudly, naming the port + reason: the account's shim relay/DNS ports; the configured endpoint port; the conventional Tor/SOCKS/control ports (9050 Tor, 9150 Tor Browser, **9051 Tor control**, 1080 generic SOCKS); and 53 (clear-DNS). Allowing the SOCKS/endpoint ports would let the anon UID dial the forced path's own upstream directly (defeating closure (b) and the `<account>@` isolation); allowing 9051 is a self-deanonymization vector.
  This blocklist is the loopback analogue of the LAN branch's `networkWithinPrivateRanges` (which says "must be a private range"). Its completeness is load-bearing: enumerate it in an ADR (mirror ADR-0001's heuristic-with-rationale stance).
- **Mechanism (TWO nft rules per loopback exempt port, both needed):**
  - a nat_out `return` for `ip daddr 127.0.0.1 tcp dport <ai-port>`, emitted alongside the existing `ip daddr 127.0.0.1 tcp dport { relay, dns } return`, so the dial is NOT swallowed by the catch-all `meta l4proto tcp redirect to :<relay>` and actually reaches the service;
  - a filter_out `accept` extending the existing `meta skuid <anon> ip daddr 127.0.0.1 tcp dport { relay, dns } accept` set to include `<ai-port>`, BEFORE the `ip daddr 127.0.0.0/8 drop`. Closure (a) stays intact for every other loopback port.
  The LAN branch of `exemptMatch` (`ip daddr <lan> tcp dport <port>`) is unchanged; add a loopback branch that emits the loopback `return` + `accept` pair. Note both halves are required for loopback for the same reason the LAN case needs the `return`: the catch-all TCP redirect would otherwise swallow it.
- **Persistence + update + defaults: NO new field.** Loopback exemptions ride the SAME `accountconfig.Config.Exemptions` (or renamed) `[]string`, the SAME `defaults.json` `allow` key, and the SAME `cli.Command` plumbing / `main.go` overlay as LAN ones. They are stored raw as `127.0.0.1:<port>`. Nothing new to thread; the class-dispatch happens at parse/generate time from the raw address.

## Acceptance criteria

- [ ] `--allow 127.0.0.1:<port>` (a non-anonymizer TCP port) makes that same-host loopback service reachable DIRECTLY from the anon account, WITHOUT binding it to `0.0.0.0`; it rides the same `--allow` flag and `allow` config key as a LAN exemption (no new flag, no new field).
- [ ] The loopback guardrail branch REJECTS loudly, at config time, naming the port + reason: port 53; the account's shim relay/DNS ports; the endpoint port; the conventional Tor/SOCKS/control ports (9050/9150/9051/1080). (Port-omitted is already rejected globally by the prerequisite task.)
- [ ] Closure (a) STILL holds for every non-exempt loopback port: the anon UID reaching any other `127.0.0.0/8` destination is still DROPPED (the exemption does not widen loopback).
- [ ] Closure (b) STILL holds: the anon UID dialing the upstream endpoint directly is still DROPPED (the exemption cannot re-open the SOCKS/control surface).
- [ ] `verify` gains coverage: the existing `bypass-loopback-closure` probe now dials a non-shim, NON-exempt loopback port and still expects a drop; a new positive assertion proves the exempted port IS reachable AND the anonymizer control ports (e.g. 9050/9051) are STILL dropped (mirror `split-tunnel-tight`'s exempt-reachable-but-rest-tight shape). A probe that cannot run FAILS LOUD (ADR-0003 discipline), never a silent pass.
- [ ] The class-dispatch is unit-tested: a loopback address routes to the loopback branch (control-port rejects fire) and a private address routes to the LAN branch, from the SAME `--allow` entry point.
- [ ] The guardrail (port-blocklist) is unit-tested (pure logic, everywhere); the direct-reachability + still-tight behaviour is integration-tested behind the `integration` tag, isolated to a throwaway account/table, asserting the host's other rules are untouched.
- [ ] An ADR records the loopback port-blocklist (which ports are refused and why) and the "one more load-bearing invariant" tradeoff: closure (a) moves from "only the shim on loopback, full stop" to "the shim plus operator-named non-anonymizer loopback ports", so safety now rests on the blocklist being complete.

## Blocked by

- `allow-require-explicit-port-and-rename`: this task assumes `--allow` is already port-mandatory, exact-host:port-only, and renamed. It extends the SAME `exemptMatch`/config plumbing that task touches, so it is serialized behind it (and to avoid a merge conflict on the same modules).

## Prompt

> Goal: let the unified `--allow` flag accept a same-host loopback destination `127.0.0.1:<port>` (e.g. a loopback-bound local model) so the anon account can reach it directly without binding it to `0.0.0.0`. This LAYERS on the landed `allow-require-explicit-port-and-rename` (which already made `--allow` port-mandatory, exact-host:port-only, and renamed). ONE flag, ONE config key; the tool DISPATCHES on the typed address (loopback vs RFC1918/link-local), because the user already made the class obvious by typing `127.0.0.1`.
>
> FIRST, check drift: read the landed `allow-require-explicit-port-and-rename`, `lan-exemption`, and `nftables-ruleset-install` (`internal/nftables` `exemptMatch`, `internal/lanexempt`, the anon-UID loopback accept set + the nat_out loopback `return`) and the recipe finding. Adapt to what actually landed (including the flag/key names after the rename).
>
> The one new thing is a SECOND guardrail branch for the loopback address class. It is STRICTER than the LAN branch: loopback is the anonymizer's OWN control surface (Tor SOCKS 9050, Tor control 9051, shim relay/DNS ports, the endpoint port). So the loopback branch rejects (naming the port + reason): 53, the shim relay/DNS ports, the endpoint port, and 9050/9150/9051/1080. This blocklist's completeness is load-bearing: enumerate it in an ADR (mirror ADR-0001).
>
> Mechanism = a loopback branch in `exemptMatch` emitting TWO rules per port: a nat_out `return` for `ip daddr 127.0.0.1 tcp dport <port>` (so the catch-all TCP redirect does not swallow it) AND a filter_out `accept` before the `127.0.0.0/8 drop`. The LAN branch is unchanged. Closure (a) must still DROP every non-exempt loopback port and closure (b) must still DROP the direct-endpoint dial; prove both survive.
>
> NO new config field and NO new flag: loopback exemptions ride the same `allow` key / `Exemptions` slice / CLI plumbing, stored raw as `127.0.0.1:<port>`; the class-dispatch is at parse/generate time from the raw address.
>
> `verify`: the existing `bypass-loopback-closure` probe must now target a non-exempt loopback port (still a drop), and add a positive assertion (mirroring `split-tunnel-tight`) that the exempted port is reachable while the anonymizer ports (9050/9051) stay dropped. Fail-loud if a probe cannot run (ADR-0003).
>
> Seams to test at: the class-dispatch + the port-blocklist guardrail (unit, everywhere) and the direct-reachable-but-still-tight behaviour (integration, behind the tag), isolated to a throwaway account/table. RECORD non-obvious in-scope decisions per the task-template guidance, and write the ADR for the port-blocklist + the closure-(a) invariant change.
