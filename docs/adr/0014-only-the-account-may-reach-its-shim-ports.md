# Only the account may reach its shim ports (closure c)

## Status

Accepted (0.11.0).

## Context

The forcing table has always governed EGRESS from the account: closure (a) confines the anon UID to its own shim's loopback ports, closure (b) reserves the upstream endpoint for the shim UID (ADR-0002, ADR-0008). Nothing governed the converse: who else may talk to the shim. The relay and DNS ports are plain loopback listeners, so any local uid could send them a query or a connection.

That was measured on telemaque while benchmarking ADR-0013 (`work/notes/observations/the-shims-dns-port-answers-any-local-uid.md`): an ordinary interactive uid, with no root and no `setpriv`, had its queries answered by `anon-01`'s shim, over that account's circuit, under its `anon-01@` isolation username. It was pre-existing, and ADR-0013 made it worse in one specific way: with a per-account answer cache in the forwarder, the same port became a recency oracle, since a cached name answers in microseconds and an uncached one takes a circuit round trip.

What it lets another local uid do:

- resolve names over the account's circuit class, which puts names the account never asked for into that class;
- time the forwarder to learn which names the account resolved recently, without resolving them itself;
- connect to the relay, where the connection is relayed to whatever `SO_ORIGINAL_DST` reports for a flow that was never redirected (in practice the relay's own address, which Tor refuses, but a generic SOCKS endpoint's view of "127.0.0.1" is its own loopback).

Another anon SLOT was already kept out, by closure (a) in its own table: its UDP to a foreign shim port hits the `127.0.0.0/8` drop, and its TCP is redirected into its own relay. So the population this is about is every uid anonctl does not govern: the operator, services, and root.

It also blocked `work/notes/ideas/per-account-socks-front-door-for-exit-side-resolution.md`, since a SOCKS listener with this property would be an open proxy into the account's circuit for every other uid.

## Decision

**The account's forcing table refuses a NEW flow to its own shim ports from any attributable uid that is not the account or its shim.** The filter base chain gains two jumps, AFTER the two uid jumps, keyed on DESTINATION: `ip daddr 127.0.0.1 tcp dport { <relay>, <dns> }` and `ip daddr 127.0.0.1 udp dport <dns>`, both into a new regular chain `shim_ports` holding one rule:

```
ct state new meta skuid >= 0 drop
```

**This is the first base-chain jump that is not on a uid, and it keeps the invariant that motivated the rule against them.** The package's standing rule (ADR-0002's amendment) is that a base chain never adjudicates a packet it cannot attribute, because an unattributable packet matches neither `skuid == u` nor `skuid != u`, and a drop that catches it breaks other uids' TCP box-wide. Closure (c) exists to refuse packets from uids anonctl does NOT govern, so it cannot be a positive jump on one uid. What keeps it inside the invariant:

- The jump is positive, on addresses anonctl allocated for this account and nothing else may bind. It cannot touch another service's traffic.
- It comes after the anon and shim jumps, whose chains accept their own shim-port flows, so a governed uid's attributable packet never reaches it.
- The drop is qualified twice. `ct state new` confines it to the first packet of a flow (a TCP SYN, a UDP datagram with no conntrack entry), which always carries its socket uid (measured for SYNs including timer-context retransmissions, package doc). `meta skuid >= 0` matches ANY attributable uid and cannot match a packet with no socket owner, because the kernel breaks out of a rule whose `meta skuid` load finds none. The anon UID's own unattributable follow-on packets therefore reach the chain, match nothing, and return to the base chain's policy accept.
- No `skuid !=` appears anywhere, and the unit test that forbids it still holds.

**Measured, not reasoned about** (ADR-0011's rule for this area). In a user+network namespace with three mapped uids (anon 2000, shim 2001, a stranger 3000) plus root, the real `anonctl-shim` listening under the shim uid, and the ruleset exactly as `Generate` emits it:

| | today's table | with closure (c) |
|---|---|---|
| anon: tcp relay, tcp dns, udp dns, DNS round trip | reached, answered | reached, answered |
| anon: DNS to `1.1.1.1:53` through the redirect | answered | answered |
| uid 3000: tcp relay / tcp dns | reached | dropped (SYN, times out) |
| uid 3000: udp dns / DNS round trip | reached, answered | EPERM on the send |
| root: all of the above | reached, answered | same as uid 3000 |
| anon: 200 MB bulk transfer through a guarded port | | completed intact |

The bulk leg is the one that tests the invariant: 200 MB is enough traffic that some of the anon UID's packets on those flows go out without a socket uid, take no uid jump, and land in `shim_ports`. An instrumented copy of the chain (a counter on the drop and one after it) saw exactly that across the run: two 52-byte packets fell through the chain undropped, which can only be the anon UID's follow-on packets since no other uid ever established a flow, and the transfer arrived byte-complete. The drop counter held only the stranger's and root's SYNs and datagrams.

**`verify` gains `shim-ports-closure`**, the converse of `bypass-loopback-closure`, and the first probe that does not run as the account. It sends as `nobody` (65534, or the next uid down if the account or shim owns that number): one datagram to the DNS port and one connect to the relay. It passes only on POSITIVE evidence of a kernel refusal on both: EPERM on the UDP send (a datagram that leaves counts as reached even with no listener, so a dead shim cannot fake a pass), and a timed-out or EPERM connect. A REFUSED connect is a fail, not an inconclusive: it means the SYN reached the stack, so nothing dropped it. Anything else is an error. Checked end to end in the same namespace: it passes against the new table and fails against the old one with the fix in its text.

## Consequences

- **An account whose table predates 0.11.0 does not get closure (c) until its table is re-applied.** The table is generated at `add`/`update` and persisted to `/etc/anonctl/nftables/<account>.nft`, which the loader replays at boot, so upgrading the binary changes nothing on its own. `anonctl update <account> --endpoint <url>` re-applies it. `shim-ports-closure` goes red on such an account and says so, so `use` and `exec` will refuse it after an upgrade until it is re-applied. That is deliberate: a gate that stayed green would be claiming a closure the account does not have.
- **Measuring the forwarder now needs the account's uid.** Every benchmark in ADR-0013 was taken by querying the shim's port from an ordinary uid, which is exactly the capability this closes. The deliberate way in is the account's own uid: inside `anonctl use <account>`, or `setpriv --reuid <anon-uid> --clear-groups` as root. Both need root, which is the point.
- **The ADR-0013 cache caveat shrinks to root.** The recency oracle is now reachable only by the account itself and by someone who can defeat the table. The comment at the cache's choice site says so, and says the closure lives in the ruleset: a shim run without anonctl's table in front of it is open again.
- **It is loopback `127.0.0.1` only**, matching where the shim listens and the existing closure (a) accepts. If the shim ever listens on another address, both must move together.
- **What it does not do.** It does not hide the ports' existence (a refused send is itself a signal that a port is guarded), and it does not stop root, who can edit the table.
