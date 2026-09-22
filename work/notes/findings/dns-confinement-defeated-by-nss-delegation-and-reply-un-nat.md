---
title: An anon account's DNS escapes per-UID forcing in two independent ways - glibc resolves it in another process (nscd/nsncd, systemd-resolved), and the shim's ANSWER is dropped after conntrack un-NATs it to the nameserver's address
slug: dns-confinement-defeated-by-nss-delegation-and-reply-un-nat
source: 'Direct measurement on telemaque (NixOS + Tailscale, kernel 6.18) 2026-09-21, against anonctl v0.5.0 and the live adopted account anon-01 (uid 8802, shim uid 413, shim DNS port 19053). Counters were planted in throwaway policy-accept nft tables at output priorities -300 and 50 and read around each probe; probes ran under `sudo setpriv --reuid 8802 --clear-groups`. The reply-side drop was confirmed against tailscaled''s own rule counters (`iptables -L ts-input -n -v` plus `nft -a list ruleset`), read immediately before and after a single probe query. The NSS half was measured with a name nothing could have cached and cross-checked against a tailnet name only MagicDNS can answer. Two earlier hypotheses (route_localnet, SNAT of the query source) were REFUTED by these same measurements and are recorded below so they are not re-tried.'
---

Two independent mechanisms take an anon account's name resolution outside anonctl's per-UID forcing. Both were measured on one host, they compound, and `anonctl verify` v0.5.0 passed all ten assertions (including `dns-remote`) while both were true.

This is EXTERNAL ground truth about glibc, netfilter and tailscaled, not a post-mortem of our code: the fix we made in response is ADR-0011.

## Mechanism 1: glibc resolves `hosts` in another process, under another uid

`meta skuid` matches a socket's OWNER, so it can only govern lookups the account's own process performs. glibc frequently does not perform them:

- **The nscd protocol is consulted BEFORE `nsswitch.conf`.** If an nscd-compatible socket exists, glibc asks it for the `hosts` database first. Nothing in `nsswitch.conf` reveals this, so a detector that reads only that file misses the entire leak. NixOS ships **nsncd** (a non-caching nscd-compatible daemon, uid `nscd`) with a 0777 socket at `/var/run/nscd/socket`.
- **Delegating NSS modules hand the query to a daemon.** `nss-resolve` to systemd-resolved over varlink (the stock configuration on Debian, Ubuntu and Fedora), `nss-mdns` to avahi-daemon, `nss-mymachines` to systemd-machined, `sss` to sssd, `winbind` to winbindd.

In every case the query executes under the DAEMON's uid, on a socket the account does not own, and no nftables rule anonctl can write applies to it.

Measured, with a unique name nothing can have cached (`anonctl-probe-<...>.invalid`) looked up as uid 8802 while counters watched its own sockets:

| counter, during one `getent ahostsv4` as the anon uid | packets |
| --- | --- |
| anon uid emitted udp/53 (output priority -300, pre-nat) | **0** |
| anon uid emitted tcp/53 | **0** |
| anon uid packets toward the shim's DNS port (priority 50, post-nat) | **0** |

Cross-checked against a tailnet name, where the two resolvers must disagree permanently (only MagicDNS can answer it; any public resolver must NXDOMAIN): the shim NXDOMAINs `telemaque.bonobo-gentoo.ts.net`, MagicDNS returns 100.71.110.44, and the anon uid's `getaddrinfo` returns 100.71.110.44 in 0.00s. The account resolved a name its own shim cannot resolve.

**Uniqueness of the probe name is what makes this measurable.** A cacheable name can complete with no query on any socket, so it cannot distinguish "another process resolved it" from "it was already known".

## Mechanism 2: the forced path's ANSWER is destroyed after conntrack un-NATs it

The forward path works. The reply does not, and the two are asymmetric in a way that is easy to misdiagnose.

A redirected query arrives at the shim as `<host's source addr> -> 127.0.0.1:19053`, because the source address is selected BEFORE the OUTPUT nat hook rewrites the destination. The shim answers. Conntrack then un-NATs that answer's SOURCE back to the ORIGINAL destination (the nameserver's address) before it is delivered, because that is what the account's socket is expecting to hear from. So the answer re-enters the input path on `lo` carrying **the nameserver's address as its source**, and any host-owned input filter that judges packets by source address gets to see it.

On this host the nameserver is Tailscale MagicDNS (100.100.100.100) and tailscaled installs an anti-spoofing rule that drops packets sourced from its own CGNAT range arriving on any interface other than `tailscale0`. Measured across one probe query:

| ts-input rule | before | after |
| --- | --- | --- |
| `ip saddr 100.71.110.44 iifname "lo" accept` (the node's own address: the QUERY) | 17 | **18** |
| `ip saddr 100.64.0.0/10 iifname != "tailscale0" drop` (the ANSWER) | 16 | **17** (+89 bytes) |

Counters on the account's own path agree: the query was emitted (1), it survived the redirect toward the shim (1), the shim emitted a reply (1), the reply entered the input path (1), and it did not survive input filtering (0). A raw query addressed straight to `127.0.0.1:19053` answers in 0.55s, so the shim itself is healthy. The account's query is resolved over Tor and the answer is thrown away.

### Two plausible mechanisms that the measurements REFUTED

Recorded because both are what a reasonable engineer reaches for, and each would have produced a confident, wrong fix:

- **`route_localnet=0` makes the DNAT-to-loopback martian.** Refuted: the same host redirects ALL of the account's TCP to `127.0.0.1:19050` successfully with `route_localnet=0` on every interface (`anonymized-exit` passes through a real Tor exit). A packet from a non-loopback source to 127.0.0.1 is delivered normally here, in both UDP and TCP, which is directly testable without root.
- **SNAT the redirected query's source to 127.0.0.1** so the exchange is purely loopback. Refuted: the reply's source is the NAMESERVER's address, taken from conntrack's reverse tuple, not from the query's source, so rewriting the query's source does not change what the input filter sees.

## Why the two compound

Mechanism 2 removes the legitimate path; mechanism 1 supplies a leaking one. **The leak is the only reason the account has working DNS at all.** Disabling nsncd on this host would stop the leak and leave the account unable to resolve anything. That is also why a broken forced DNS path has to be reported RED even when nothing leaked in that probe: it is the precondition for a bypass becoming load-bearing.

## Why no packet-level signal can catch this alone

Every packet-level observation on this host said the forcing worked: the rules were correct on their face, the redirect fired, the query reached the shim, the shim resolved it over Tor. The account still had no DNS, and a separate process was resolving its names. The only signals that catch it are asking for the ANSWER, and watching the account's OWN sockets during a lookup that cannot be served from any cache.

A successful fetch of a name proves a name resolved somehow. It never proves which resolver answered.
