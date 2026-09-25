---
title: A per-account SOCKS front door so the exit resolves names, only behind a peer check and a server-pinned isolation username
slug: per-account-socks-front-door-for-exit-side-resolution
---

Proposed from the fleet side while the DNS forwarder was being reworked (ADR-0013), and deliberately NOT built there. Recorded so the two conditions it needs travel with it.

## The idea

Give each account a SOCKS5 listener on its shim, so a SOCKS-aware client in the account (a browser, `curl --socks5-hostname`, git with a proxy) can hand the exit a HOSTNAME and never resolve it locally at all. Today every name the account uses is resolved by the shim's DNS forwarder (a DNS exchange over the circuit) and then connected to by IP through the transparent relay. A front door would fold the resolution into the CONNECT (Tor resolves at the exit, RESOLVE-free), removing one circuit round trip per new name for clients that use it.

## The benefit is smaller than it was assumed to be

The argument for it was DNS latency, and the measurements behind ADR-0013 have already taken most of that away by other means. At the forwarder's own port on telemaque, a lookup of a fresh name costs ~0.15 to 0.24s with the persistent stream, and repeated lookups of one name (the shape a page load has) went from 1.722s to 0.214s for five, because the CACHE answers the repeats. A front door removes the round trip only for the FIRST lookup of each name, and only for clients that speak SOCKS; everything else still goes through the forwarder. So what it buys is roughly one circuit round trip per new name per SOCKS-aware client, which on a warm circuit is a small fraction of a second. That may still be worth having, but it is not the rescue the proposal assumed, and it should be re-argued from the account's real path once the live verification in `work/notes/observations/dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance.md` has been taken, since that path's cost is currently unexplained.

## Two conditions, both mandatory, because it adds a LISTENING SURFACE

`work/notes/observations/the-shims-dns-port-answers-any-local-uid.md` measured that the shim's DNS port answers ANY local uid. A SOCKS front door with the same property is not a DNS oracle, it is an OPEN PROXY into that account's circuit class for every other uid on the box, including another anon slot. That is exactly the cross-slot linkage the per-account design exists to prevent: slot B could make its own connections look like slot A's to every exit and destination, and nothing in either account's forcing would notice. So:

1. **A uid or peer-credential check on the socket.** Only the account's own uid may use its front door. On loopback TCP that means an input rule keyed on the originating uid, which must be MEASURED against the real packet path rather than reasoned about (ADR-0011's standing rule); a unix socket with `SO_PEERCRED` is the stronger shape if the clients that matter can use one.
2. **The isolation username pinned SERVER-SIDE.** The shim must use the account's own `<account>@` username on the upstream dial whatever the client sends, and must never forward a client-supplied username or password. A front door that passed the client's credentials through would let the account (or anything reaching the port) choose its circuit class, including another account's.

Neither condition is optional, and neither is satisfied by anything in the tree today.

## What not to do

Do not build it as a convenience alongside the DNS work, and do not ship it with the check "to be added later". The first version to exist is the one that gets used.
