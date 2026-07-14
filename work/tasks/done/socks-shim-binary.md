---
title: The static Go shim (transparent TCP-to-SOCKS relay + DNS-over-SOCKS-TCP forwarder)
slug: socks-shim-binary
spec: per-uid-kernel-anonymized-egress
blockedBy: [manual-per-uid-recipe-validation]
covers: [10, 11, 12, 14]
---

## What to build

anonctl's own static Go shim binary: the userspace half of the data path that the nftables redirect feeds. One instance per account, on a per-account loopback port, run as that account's dedicated shim UID. Two halves in one binary:

- **Transparent TCP-to-SOCKS relay:** accept redirected connections, read the ORIGINAL destination via `SO_ORIGINAL_DST` (and the IPv6 analogue `IP6T_SO_ORIGINAL_DST`), and relay to the account's socks5h endpoint, passing the per-account `<account>@` SOCKS username when configured (for Tor circuit isolation). No plaintext fallback: if the endpoint is unreachable, the connection fails (fail-closed at the relay level too).
- **DNS-over-SOCKS-TCP forwarder:** serve DNS on the account's loopback DNS port and resolve every query REMOTELY over the endpoint via TCP (socks5h), never a local/plaintext lookup. Reuse netcage's `internal/dnsforwarder` (a DNS-to-SOCKS-TCP bridge with optional SOCKS auth) rather than reimplementing.

Not a distro `redsocks` dependency: shipping our own keeps the leak-proof invariant in our code and makes it testable against a socks5h fixture with NO real Tor. Build it static (`CGO_ENABLED=0`) so it runs anywhere the anonctl binary does.

## Acceptance criteria

- [ ] The relay reads the original destination via `SO_ORIGINAL_DST` (v4) and the v6 analogue, and relays to a socks5h endpoint, injecting the `<account>@` username when set.
- [ ] The DNS forwarder resolves queries remotely over the endpoint via TCP (socks5h), and serves the account's loopback DNS port; no query resolves locally / in plaintext.
- [ ] Endpoint-unreachable means the relay/forwarder fails the connection (no direct fallback).
- [ ] The binary builds static (`CGO_ENABLED=0`).
- [ ] Tests cover the relay's original-destination parsing and the forwarder's remote resolution against an in-process socks5h fixture (reuse or mirror netcage's `internal/socks5hfixture`), NO real Tor, no netns, no system mutation in the default `go test ./...` run.

## Blocked by

- `manual-per-uid-recipe-validation`: encodes the validated shim/forwarder invocation and the loopback-port + `<account>@` isolation detail.

## Prompt

> Goal: anonctl's own static Go shim, a transparent TCP-to-SOCKS relay plus a DNS-over-SOCKS-TCP forwarder, one instance per account on a per-account loopback port. Stories 10, 11 (v6 in the shim), 12, 14 (shim half) of the `per-uid-kernel-anonymized-egress` spec.
>
> FIRST, check drift: read the recipe finding from `manual-per-uid-recipe-validation` for the exact shim invocation, loopback-port scheme, and `<account>@` isolation detail; follow it over this prose if they differ. Read `CONTEXT.md` for the `shim` / `endpoint` / `endpoint share-class` vocabulary.
>
> Reuse, do not reinvent: netcage (`~/dev/github/wighawag/netcage`) ships `internal/dnsforwarder`: a running DNS-to-SOCKS-TCP bridge (serves UDP+TCP, `ProxyAddr` + optional `ProxyAuth`, `socks5h` remote resolution). Reuse it for the DNS half. netcage also has `internal/socks5hfixture`, a controllable in-process SOCKS5h proxy: use it (or the same pattern) so all tests run with NO real Tor. For the TCP relay half, `SO_ORIGINAL_DST` is how a transparently-redirected socket recovers its original destination (netcage forces via a TUN sidecar instead, so this half is anonctl-specific, the manual recipe validates the nft redirect that makes `SO_ORIGINAL_DST` meaningful).
>
> Seams to test at: original-destination parsing (fixture sockets), remote DNS resolution (the socks5h fixture), fail-closed-on-unreachable. This is pure userspace: NO root, NO netns, NO system mutation in the unit tests.
>
> "Done" = the shim relays TCP with the original destination + isolation username and resolves DNS remotely, both green against the fixture, built static. RECORD any non-obvious in-scope decision (e.g. how it is told its endpoint/username, flags vs a per-account config file) per the task-template guidance.
