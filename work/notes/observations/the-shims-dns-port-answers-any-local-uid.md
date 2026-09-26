---
title: The shim's DNS port answers any local uid, so any local user can resolve over an account's circuit
slug: the-shims-dns-port-answers-any-local-uid
---

Noticed on telemaque while benchmarking the DNS forwarder (the work behind `docs/adr/0013`). Off that change's path: it is PRE-EXISTING behaviour, not something that work introduced, and nothing here is a regression.

## What was observed

Every timing measurement in that work was taken by sending DNS queries to `127.0.0.1:19053` (account `anon-01`'s shim DNS port) from an ordinary interactive uid (`wighawag`, uid 1001), with no root and no `setpriv`. They were answered. The answers came back over the account's circuit, with the account's own `anon-01@` isolation username, resolved by the account's upstream resolver.

That was convenient (it is why a before/after measurement was possible at all on a host where `sudo` was unavailable) and it is worth writing down, because it means:

- **Any local uid can resolve names over an anon account's circuit** by asking that port directly, without being the account and without being root. The forcing governs EGRESS from the account's uid; it says nothing about who may talk to the shim on loopback.
- **With the answer cache added (ADR-0013), the same port is a recency oracle.** A cached name answers in microseconds and an uncached one takes a circuit round trip, so anyone who can reach the port can time it and learn whether the account has recently resolved a given name, without resolving it themselves. The cache's code comment says this at the choice site; this note is the observation behind it.

## Why it is not obviously a defect

The threat model anonctl is built for is a SINGLE-OPERATOR box where the operator is root and the adversary is off-box (the endpoint, the destination, a network observer). Against that adversary this port changes nothing: it is loopback-only, it leaks nothing off the box, and it cannot be used to make the account egress in the clear (it is fail-closed either way). Root and the operator can already learn more by other means: the shim's own connections, conntrack, and the account's processes are all visible to them.

It matters on a MULTI-USER box, where an unprivileged third party can (a) borrow the account's circuit for lookups, which pollutes that circuit class with names the account never asked for, and (b) probe the cache for what the account has been resolving.

## What a fix would look like, and why it is not done here

A uid-filtered input rule on the shim's DNS port: accept from the account's uid and the shim's uid, drop otherwise. Two reasons it is its own task rather than a side quest:

- **`meta skuid` on the INPUT path is the wrong knob.** The account's query arrives on loopback after `nat_out` has rewritten its destination; matching the ORIGINATING uid there needs care, and the rule that looks obvious (`iif lo udp dport <dnsPort> meta skuid != <anonUID> drop`) has to be checked against the actual packet path rather than reasoned about, which is the standing rule for this whole area (ADR-0011: on this question, do not reason about the host, measure it).
- **It would break the measurement path it closes.** Every benchmark in ADR-0013, and any future one, is taken by querying that port. A fix should keep a deliberate way in (running as the account under `setpriv`, which needs root) and say so, rather than discovering later that the only way to time the forwarder is to edit the ruleset.

It is also the precondition that blocks `work/notes/ideas/per-account-socks-front-door-for-exit-side-resolution.md`: a SOCKS front door with this property would be an open proxy into the account's circuit class for every other uid, including another anon slot.

There is also a version of this that is not about DNS at all: the relay port has the same property (any local uid can send it a connection). Whether that is exploitable depends on `SO_ORIGINAL_DST` returning something useful for a connection that was never redirected, which is a separate measurement.

## Closed in 0.11.0 (`docs/adr/0014`)

Fixed in the ruleset as closure (c): the account's forcing table refuses any attributable packet to its shim relay and DNS ports from a uid other than the account's (and its shim's). Both of the reasons above for doing it as its own task held, and shaped the fix:

- **The knob was not `meta skuid` on INPUT.** Measured in the namespace: three datagrams from uid 3000 to the DNS port all arrived at the input hook (`iif lo udp dport 19053` counted 3), and `meta skuid 3000` there matched NONE of them, while the same match on OUTPUT matched all three. Loopback orphans the packet from its socket before local delivery, so the originating uid is gone by input. The fix is on OUTPUT instead, in the account's own `filter_out`: a positive jump on the account's shim ports (after the two uid jumps), into a chain whose one rule is `meta skuid >= 0 drop`. That keeps the package's standing invariant that nothing adjudicates an unattributable packet, without a `skuid !=`. Measured rather than reasoned about, in a user+network namespace with the real shim and the ruleset exactly as `Generate` emits it: before, a stranger uid and root reached all three ports and got DNS answers; after, UDP fails with EPERM and TCP connects time out on a dropped SYN, while the account's own traffic (direct, through the DNS redirect, and a 200 MB bulk transfer whose unattributable packets reach the chain) is untouched. The table is in the ADR.
- **The measurement path now needs the account's uid, deliberately.** Benchmark from inside `anonctl use <account>` or under `setpriv --reuid <anon-uid>` as root. That is the "deliberate way in" this note asked for, and ADR-0014 says so.

The first cut also said `ct state new`; review showed that let a stranger flow predating the table keep reaching the shim, which was then measured and removed (ADR-0014 has the detail).

`verify` has a new assertion, `shim-ports-closure`, which sends as `nobody` and passes only on a kernel refusal on both ports AND the rule being present in the loaded table. It goes red on an account whose table predates 0.11.0 until `anonctl update` re-applies it.

The last paragraph above is answered too: the relay port is covered by the same chain, so the `SO_ORIGINAL_DST` question no longer needs its own measurement to be safe.
