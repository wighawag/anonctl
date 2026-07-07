---
kind: finding
title: What Tails' Tor-enforcement network filter teaches per-UID/per-container forced egress (leak catalogue + verify-assertion backlog)
slug: tails-network-filter-lessons
source: |
  Tails project design docs, retrieved 2026-07-07:
  - "Tor enforcement" https://tails.net/contribute/design/Tor_enforcement/
  - "Network filter" https://tails.net/contribute/design/Tor_enforcement/Network_filter/
  The ruleset referenced by those pages is Tails' committed ferm/iptables config:
  config/chroot_local-includes/etc/ferm/ferm.conf in the tails repo
  (https://gitlab.tails.boum.org/tails/tails). Quotes below are verbatim from the
  two design pages as retrieved. This finding is DOC-DERIVED external ground truth
  about how a mature (10+ year, adversarially reviewed) whole-OS transparent-Tor
  system enforces forced egress and which leak classes it had to close; it is NOT
  hand-validated against our own code (unlike the sibling manual-per-uid-tor-recipe
  finding, which IS empirically validated on a real host). Read the two together:
  this one supplies the "what else could leak" checklist, that one supplies our
  proven mechanism.
---

## Why this is a finding (and who reads it)

Tails and anonctl solve the SAME primitive at different scopes. Tails forces egress for whole **Unix users** (`amnesia`, `debian-tor`, `clearnet`) through Tor via a ferm/iptables ruleset, default-block, DNS forced remote, non-TCP dropped. anonctl forces egress for a dedicated **Unix account** (`anon-<name>`, by `meta skuid`) through a socks5h endpoint, default-DROP, DNS-over-SOCKS, non-TCP dropped. netcage does the same per **container netns**. The mechanism differs (their per-user iptables vs our per-UID nftables vs netcage's per-netns firewall), but **the leak surface is nearly identical**, and Tails has spent a decade closing it under adversarial review.

So the value here is not "copy Tails' architecture" (we deliberately are NOT a whole-OS amnesic system, see the scope table below). The value is: **Tails' committed ruleset and design pages are a ready-made adversarial checklist of what leaks past a transparent-proxy jail, and each item maps to a named `verify` assertion we should have.** anonctl's `verify` and netcage's `verify` are the consumers; this finding is their backlog.

## Scope boundary: what we are NOT taking from Tails (so nobody scope-creeps)

Tails' identity is the amnesic whole-OS + anti-forensics + physical-seizure threat model. anonctl and netcage deliberately scope those OUT. Keep the boundary explicit:

| Property | Tails | anonctl / netcage |
| --- | --- | --- |
| Unit of protection | whole machine / OS | one Unix account (anonctl) / one container (netcage) |
| Delivery | amnesic live USB OS | a manager/wrapper on your normal Linux |
| Amnesia / RAM-wipe / MAC spoof / anti-forensics | core feature | OUT of scope |
| Rest of the system | also anonymized | untouched, uses the real IP |
| In the data path at runtime? | the OS IS the data path | NO: anonctl exits, the kernel rules are the data path; netcage's sidecar is |
| Backend | Tor, baked in | any `socks5h://` endpoint (Tor is the default) |
| Hides kernel/hardware fingerprint | yes (it is the OS) | NO (shared kernel; documented residual) |

The one thing we take is **the network-filter discipline and its leak catalogue**, nothing about amnesia or whole-OS control. Do not let "learn from Tails" drift into "become Tails".

## Tails' network-filter design, quoted (the mechanism they use)

Verbatim from the two design pages (2026-07-07):

- **Default-block, allowlist exceptions** (the fail-closed core): "The default case is to block all outbound network traffic; let us now document all exceptions". This is exactly anonctl's default-DROP-for-the-UID and netcage's fail-closed firewall.
- **Per-user special-casing** (their equivalent of our `meta skuid`): "connections originating from the `debian-tor` Unix user" are special-cased to reach the Internet directly (so Tor itself can connect); "Only the `amnesia` user is granted access to the Tor transparent proxy port". They gate by SOCKET-OWNING USER, exactly the axis anonctl's `meta skuid` and our shim-UID split rely on.
- **DNS forced remote, plaintext UDP blocked:** "Tor does not support UDP so we cannot simply redirect DNS queries ... UDP datagrams are therefore blocked in order to prevent leaks." And crucially: **"Tails also forbids DNS queries to RFC1918 addresses; those might indeed allow the system to learn the local network's public IP address."**
- **LAN carve-out, but NO LAN DNS:** "traffic to the local LAN (RFC1918 addresses) is wide open as well as the loopback traffic ... **LAN DNS queries are forbidden to protect against some attacks.**"
- **IPv6:** Tails "does not support connecting to the Tor network via IPv6 yet" - i.e. v6 is not a bypass; it is not carried, it is closed.
- **UDP / ICMP / other non-TCP dropped:** "Non-TCP traffic to the Internet, such as UDP datagrams and ICMP packets, is dropped." (With a documented PMTU-discovery side effect they work around via PLPMTUD sysctl.)
- **`RELATED` packets dropped** (attack-surface reduction): "the Tails' firewall does not accept `RELATED` packets ... we prefer reducing the attack surface", with a narrow loopback-only ICMP-`RELATED` exception for UX.
- **Local-services allowlist** (defence in depth vs a compromised local process): "grants access to each local service to the users that actually need it. This blocks potential leaks due to misconfigurations or bugs, and deanonymization attacks by compromised processes."

## The leak catalogue -> `verify`-assertion backlog

Each row is a leak class Tails explicitly closes. For each: what it is, and the concrete `verify` assertion anonctl (per-UID) and netcage (per-netns) should carry. "PASS" here means the assertion HOLDS (traffic is confined/dropped, no real-IP/real-DNS escape). Several we already cover; they are listed anyway so `verify` asserts them rather than assuming them.

1. **Plaintext DNS via UDP/53 to an arbitrary resolver.** A tool doing `@8.8.8.8` UDP directly. Tails drops all UDP; we redirect 53 to the shim and drop other UDP.
   - assertion: from the confined identity, a DNS query aimed at an arbitrary/black-hole resolver STILL returns an answer (proves transparent interception) AND a packet counter shows ZERO udp/53 packets leaving with an off-box destination. (This is the exact black-hole-probe subtlety already documented in `manual-per-uid-tor-recipe.md` "The DNS subtlety" - the naive "direct dig must time out" assertion is WRONG for a transparently-redirected setup.)

2. **LAN DNS revealing the local network's public IP.** A resolver at an RFC1918 address (`@192.168.1.1`) is a Tails-documented deanonymization vector even when Internet DNS is forced. **This is a leak class our LAN-exemption design can REINTRODUCE**: netcage's `--allow-direct` and anonctl's LAN exemption open a hole to RFC1918 `host:port`; if that hole permits udp/53 or tcp/53 to the LAN resolver, we have exactly the leak Tails forbids.
   - assertion: with a LAN exemption active, a DNS query to an RFC1918 resolver is NOT allowed out as clear DNS (the exemption is host+port scoped and must not silently include :53). Confirm the LAN hole does not become a DNS hole. (anonctl already scopes the exemption to an exact `host:port`; make `verify` prove 53 is not reachable through it.)

3. **IPv6 as a total bypass.** The classic transparent-proxy leak: v4 is forced, v6 is untouched and goes out in the clear. Tails closes it by not carrying v6 at all. Our validated recipe DROPS all anon v6 (`ip6 daddr ::/0 drop`).
   - assertion: from the confined identity, ANY IPv6 egress (a `curl -6` to a v6 literal, a v6 DNS) FAILS CLOSED (dropped), and there is no v6 path that reaches the real network. Assert both v6 TCP and v6 DNS.

4. **ICMP / raw sockets leaking the real IP.** `ping`, traceroute, raw ICMP. Tails drops all ICMP to the Internet (accepting the PMTU cost).
   - assertion: an ICMP echo (`ping`) from the confined identity to an off-box address does NOT emit an ICMP packet with the real source IP (dropped). Note the PMTU side effect Tails documents; decide if PLPMTUD (`net.ipv4.tcp_mtu_probing`) is worth mirroring, or capture as a known caveat.

5. **Non-53 UDP (QUIC / HTTP-3 / WebRTC / NTP / mDNS / LLMNR / DHCP-style broadcast).** SOCKS carries TCP only, so any UDP that is not the redirected 53 is unrelayable. Tails drops it; our recipe drops it (falls through to policy DROP). QUIC/HTTP-3 is the live one: a modern client may prefer UDP/443 and, if it is merely dropped, ideally falls back to TCP.
   - assertion: raw non-53 UDP from the confined identity (a datagram to `1.1.1.1:9999`, and specifically UDP/443) is DROPPED, and a real client degrades to TCP rather than leaking. (Our recipe already showed `socat UDP4:...:9999` -> "Operation not permitted".)

6. **A different loopback service used as an escape hatch.** The confined identity dialling `127.0.0.1:9150` (another Tor SOCKS), or ANY loopback port other than its own shim. Tails' local-services allowlist is precisely this defence.
   - assertion: the confined identity can reach ONLY its own shim's loopback port(s); every other loopback destination is DROPPED. (Validated in the recipe: `--socks5 127.0.0.1:9150` -> dropped; only `:19050`/`:19053` reachable.)

7. **A UID/identity transition that escapes the `skuid` match (anonctl-SPECIFIC, and our SHARPEST edge).** Tails controls the ENTIRE OS UID map, so every user is accounted for. anonctl runs on a machine full of OTHER UIDs. `meta skuid` matches the SOCKET-OWNING uid. If the anon account can invoke anything whose socket ends up owned by a DIFFERENT uid - a setuid helper, `sudo`, a system daemon it can trigger, a shared service - that socket does NOT match `skuid == anonUID` and egresses in the CLEAR. This is the place where "one account, not the whole OS" actually WEAKENS the guarantee relative to Tails.
   - assertion: enumerate what the anon account can execute that transitions uid; assert that no reachable setuid/privileged path yields an off-box socket owned by a non-anon, non-shim uid that escapes forcing. At minimum, `verify` should probe: can the anon account reach the network via `sudo`/a setuid binary/a triggerable daemon? This is a HIGH-priority anonctl finding-and-test in its own right; it does NOT apply to netcage (a container netns confines by namespace, not by uid, so there is no per-uid escape - which is a genuine advantage of the netns model worth noting).

8. **`RELATED`/`ESTABLISHED` conntrack surprises.** Tails drops `RELATED` on purpose (attack surface), with only a narrow loopback ICMP exception. Not a leak per se, but a reminder that broad `ct state related,established accept` rules can widen the surface unexpectedly.
   - assertion (lower priority): the ruleset does not blanket-accept `RELATED` in a way that would carry an unexpected off-box packet; keep any established-accept scoped to the shim's own relayed connections.

## Cross-cutting lessons (not one assertion each, but design posture)

- **The un-anonymized hole must be LOUD and NARROW.** Tails ships a deliberately-separate Unsafe Browser in a `clearnet` netns, visually unmistakable, precisely so the non-Tor path is never taken by accident. This validates netcage's instinct (`--allow-direct` gated to RFC1918, `forward --bind 0.0.0.0` prints a warning) and anonctl's exact-`host:port` LAN exemption. Posture: **any exemption stays off by default, private-range only, host+port scoped, never a DNS hole (row 2), and announced.**
- **Stream isolation per identity.** Tails puts different apps on different Tor circuits. anonctl already does the account-level equivalent via the per-account SOCKS username (`<account>@`, Tor `IsolateSOCKSAuth`); see the sibling finding `tor-isolatesocksauth-default.md`. netcage forces everything for one container through one proxy connection; if two netcage jails share one Tor SocksPort they may SHARE a circuit and be correlatable - a candidate netcage feature is per-jail SOCKS credentials for per-jail circuits.
- **`verify` is the trust anchor, exactly as it already is.** Tails has NO per-app CI-gateable leak proof; it trusts the OS-wide config after review. anonctl and netcage BOTH ship a `verify` that asserts (exit is the endpoint's, DNS is remote, proxy-killed fails closed). This finding's whole payload is: **grow that `verify` to cover rows 1-7, so the confined-egress guarantee is PROVEN against the full Tails-derived leak surface, not just the happy path.**

## Priority ordering for the `verify` backlog

For BOTH projects, highest-value first: row 3 (IPv6 bypass) and row 1 (plaintext DNS) are table stakes; row 2 (LAN-exemption-as-DNS-hole) is the one our OWN feature can reintroduce; row 5 (QUIC/UDP-443) matters for real modern clients; row 6 (other loopback) is cheap and already validated. For anonctl SPECIFICALLY, row 7 (uid-transition escape) is the single most important NOVEL test, because it is the exact spot where the per-account model is weaker than Tails' whole-OS model - it deserves its own investigation and likely its own finding once probed.
