---
title: The narrow RFC1918 LAN exemption (exact host:port direct hole, private-only)
slug: lan-exemption
spec: per-uid-kernel-anonymized-egress
blockedBy: [nftables-ruleset-install]
covers: [23, 24]
---

## What to build

An opt-in, narrow, guardrailed hole in the forced egress: exempt a configured RFC1918 / link-local `host:port` (e.g. a local LLM at `192.168.1.150:8080`) so the anon account can reach that ONE trusted local service directly, while ALL other egress stays forced fail-closed.

- **Config + guardrail:** accept an exempt entry as an exact IP/CIDR `host[:port]`; REJECT public IPs, hostnames, and broad/unscoped ranges LOUDLY at config time (private-only; a hostname cannot resolve remotely and a local-resolver hole would be another leak, IP/CIDR only). Mirror netcage's `--allow-direct` guardrails verbatim.
- **Mechanism:** for `meta skuid <anon-uid>`, insert a single `accept` for `ip daddr <host> tcp dport <port>` (and the v6 analogue) BEFORE the redirect and the fail-closed drop, so that traffic egresses the real NIC directly. Because the ruleset's default is already DROP-for-the-UID, a non-exempt LAN host is dropped by construction, so NO separate defense-in-depth RFC1918 drop rules are needed (that is netcage's two-half TUN mechanism, which does not apply here; single-accept-before-drop is enough and gives the same guarantee).

This edits the same ruleset module as `nftables-ruleset-install`, hence the `blockedBy` (serialized to avoid a merge conflict on that module and because the accept must sit before that task's drops).

## Acceptance criteria

- [ ] A configured exact RFC1918/link-local `host:port` is reachable directly from the anon account; the port-omitted form allows all TCP ports to that host.
- [ ] Public IPs, hostnames, and broad/unscoped ranges are REJECTED loudly at config time.
- [ ] Every non-exempt destination (including the rest of the exempted host's /24) stays redirected-or-dropped, the exemption does not widen.
- [ ] The guardrail (private-only, IP/CIDR-only) is unit-tested (pure logic, everywhere); the direct-reachability + still-tight behaviour is integration-tested behind the `integration` build tag.
- [ ] **Shared-write isolation:** integration tests isolate to a throwaway account/table and assert the host's other rules are untouched.

## Blocked by

- `nftables-ruleset-install`: this inserts an `accept` before that task's drops and edits the same ruleset module (serialized).

## Prompt

> Goal: the narrow LAN exemption, a private-only, exact-`host:port` direct hole in the forced egress. Stories 23, 24 of the `per-uid-kernel-anonymized-egress` spec.
>
> FIRST, check drift: read `nftables-ruleset-install`'s landed ruleset and the recipe finding; this task inserts an `accept` BEFORE its drops, in the same module. If the ruleset shape changed, adapt to what landed.
>
> Domain vocabulary: this cops netcage's `--allow-direct` (ADR-0005) guardrails VERBATIM (RFC1918/link-local only, IP/CIDR not hostnames, exact host:port, public/broad rejected loudly). The MECHANISM is simpler than netcage's: there is no TUN here, so a single `accept`-before-drop suffices and the fail-closed default-DROP gives netcage's defense-in-depth RFC1918 drops for FREE, do NOT add separate RFC1918 drop rules.
>
> Where to look: netcage (`~/dev/github/wighawag/netcage`) `internal/cli/allowdirect.go` and ADR-0005 for the exact guardrail semantics to mirror; the anonctl ruleset module from `nftables-ruleset-install` for where the accept goes.
>
> Seams to test at: the guardrail parse/validate (unit, everywhere) and the direct-reachable-but-still-tight behaviour (integration, behind the tag). "Done" = the exempted host:port is reachable, everything else stays forced/dropped, the guardrail rejects non-private loudly, and `verify`'s split-tunnel assertion (its own task) will lock it in. RECORD non-obvious in-scope decisions per the task-template guidance.
