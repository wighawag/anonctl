# DNS confinement is MEASURED, never inferred, and a host that resolves out of process is REFUSED

Status: accepted

## Context

anonctl forces an account's egress with `meta skuid <anonUID>`, a rule that matches a socket's OWNER. v0.4.0 already fixed one consequence of that (a packet the kernel cannot attribute to any uid must never be adjudicated, ADR-0002). This ADR records the second, and more damaging, consequence: **a rule keyed on socket ownership cannot see work done in another process**, and name resolution is the one part of the forced path that routinely happens in another process.

Both halves were measured on a live NixOS + Tailscale host running anonctl v0.5.0 against a correctly adopted, correctly jailed account (`work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md`). `anonctl verify` passed all ten assertions, `dns-remote` included, the entire time.

1. **The account's DNS never worked.** Its queries were redirected into the shim correctly, the shim resolved them over Tor correctly, and the answers never came back: conntrack un-NATs the reply to the NAMESERVER's address before delivering it, and on that host the nameserver was Tailscale MagicDNS (100.100.100.100), so the un-NATed answer matched tailscaled's own anti-spoofing rule (`ip saddr 100.64.0.0/10 iifname != "tailscale0" drop`) and was dropped on `lo`. The query was accepted by the preceding rule because its source was the node's own tailnet address; only the answer matched the drop. Measured at the counter: query accepted (+1 on the accept rule), answer dropped (+1 on the drop rule, +89 bytes).

2. **Something else was resolving for the account.** NixOS runs nsncd, and glibc asks an nscd-compatible socket for the `hosts` database BEFORE consulting `nsswitch.conf` at all, so `getaddrinfo` ran in nsncd's process under uid 998. Measured with a name nothing could have cached: the account resolved it while every counter on its own sockets stayed at zero.

The two compound in the worst possible way: **the leak was the only reason the account had working DNS.** Disabling nsncd would have stopped the leak and left the account unable to resolve anything.

`dns-remote` could not catch either, because its evidence was a successful fetch of a name plus `hostSaw=false` HARDCODED in the probe, with a comment reasoning that the anon UID cannot do plaintext DNS off-box so the name must have been resolved proxy-side. A successful fetch proves a name resolved SOMEHOW. It never proves which resolver answered.

## Decisions

- **DNS confinement is MEASURED, and the assertion that used to infer it is gone, not repaired.** `dnsRemoteEvidence` was deleted. Three assertions now rest on packet counters keyed on the ACCOUNT's own sockets plus a round-trip answer: `dns-remote` (the account's own lookup was carried into the shim), `dns-nss-not-bypassed` (the lookup happened on the account's own sockets at all), `dns-forced-path-answers` (a query through the redirect actually comes back). BOTH halves of that last one are required for its pass: an answer alone does not prove the forced path carried it, since a query going straight to the nameserver in the clear is answered too, so an answered query that did not reach the shim FAILS and is named as clear DNS. Adding two names is additive under ADR-0003, so `schemaVersion` stays 1.

- **The probe name is a bare random label under `.invalid` (RFC 2606), ABSOLUTE (trailing dot), and all three properties are load-bearing.** Uniqueness is what makes the bypass MEASURABLE: no cache anywhere can answer it, so any completed lookup MUST have produced a query somewhere, and a lookup that completes while the account's own sockets stay silent is proof another process did the work. The other two are about what the probe itself discloses, because the name is carried through the shim to the endpoint's upstream resolver and is seen there. It must therefore carry no product string, pid or timestamp (a first version spelled it `anonctl-probe-<pid>-<nanos>`, handing that resolver a product fingerprint and a high-resolution cross-run correlator), and it must be absolute, because `.invalid` NXDOMAINs and glibc walks the `search` list on NXDOMAIN: a non-absolute probe is re-queried as `<probe>.<search-domain>`, which sends the HOST'S OWN search domain (a tailnet name, on the host this was measured on) to a public resolver over the circuit. The trailing dot suppresses that walk. NXDOMAIN is the expected healthy answer.

- **The counters are planted at TWO output priorities, before (-300) and after (50) the nat hook.** One chain alone cannot distinguish "the account never emitted a query" (the NSS bypass) from "the query was emitted and the redirect did not fire" (a ruleset fault) from "the query reached the shim and the answer was destroyed" (a host-owned filter). Those are three different bugs with three different owners, so the failure detail names which one happened.

- **`add` REFUSES a host whose glibc resolves `hosts` out of process, before anything is provisioned.** The refusal names the daemon, the evidence and a remedy. `--allow-nss-bypass` proceeds for an operator who accepts the exposure, and does NOT make the report green: `verify` keeps measuring and keeps reporting `dns-nss-not-bypassed` RED while the bypass is real. Certifying a box that leaks is the one outcome this design exists to prevent.

- **Only a BROAD provider refuses.** nscd/nsncd, nss-resolve (systemd-resolved), sss and winbind answer ARBITRARY hostnames, so they can carry the account's whole browsing history to the host's resolver. nss-mdns (`.local`), nss-mymachines and nss-libvirt answer a bounded name class; they are disclosed at `add` and reported by `verify` as a residual, but they do not refuse, because refusing on them would refuse on most Linux desktops for a narrow leak.

- **The DETECTOR IS NOT THE AUTHORITY; the measurement is.** `internal/nssbypass` exists to make the refusal and the failure message actionable, and to catch the case at `add` time before provisioning. A daemon it does not know about is caught by the measurement anyway, and a detector hit with a clean measurement PASSES (if glibc did put the query on the account's own socket, that provider is not serving this account's lookups, and failing on the detector alone would cry wolf over a measurement that disagrees with it).

- **anonctl does NOT fix either defect in the host's configuration, and will not.** It neither forces a system daemon's egress (nsncd serves every uid on the box; capturing it would be anonctl reaching far outside the account it manages) nor edits another tool's ruleset (tailscaled's anti-spoofing rule is correct on its own terms). It also cannot install a per-account resolver configuration: `/etc/resolv.conf` and `/etc/nsswitch.conf` are global, glibc has no per-uid override, and giving one account a private view would require a mount namespace at login, which would make anonctl a runtime wrapper. It is a setup-and-verify manager and is deliberately not in the data path (CONTEXT.md). What it owes the operator is a true report and an actionable refusal, and that is what these decisions buy.

## Considered options, for the record

- **Enable `net.ipv4.conf.*.route_localnet=1`** was the first hypothesis for defect 1, and the measurement REFUTED it: the same host redirects all of the account's TCP to the same loopback address successfully with `route_localnet=0` everywhere. Had anonctl shipped that sysctl as a fix, it would have widened 127/8 routability box-wide and fixed nothing.

- **SNAT the redirected DNS to a loopback source** inside anonctl's own table was the second hypothesis, and the measurement refuted that too: the reply's source is the NAMESERVER's address (conntrack's reverse tuple), not the query's source, so rewriting the query's source does not change what the host's input filter sees.

Both are recorded because they are plausible, they are what a reasonable engineer reaches for, and each would have produced a confident, shipped, wrong fix. The general lesson is the same one the assertions now encode: on this particular question, do not reason about the host, measure it.

## Consequences

- On a host with a broad provider, `anonctl add` now refuses where it used to succeed. That is a deliberate behaviour change: such a host was previously provisioned into a state where the account's DNS leaked and `verify` certified it clean.
- `verify` gains two assertion names and gains failure modes it could not previously express, including a RED on a host where nothing leaks but the account's forced DNS does not work. A broken forced path is reported red on purpose: it is the condition under which a bypass becomes the only reason the account resolves anything.
- On a host where the answer is destroyed, `verify` spends both probes' deadlines waiting for answers that will never come, measured at 29s for the DNS phase in the live suite (the NSS lookup retries until its budget, then the round trip waits out its 20s). Because the DNS checks are EXCLUSIVE they run before the others rather than alongside them, so that time is added to the run rather than hidden in it. It is paid ONLY on a host that has the defect, where a 30-second answer naming the exact mechanism is a good trade against a silent green, and a healthy host's DNS phase is about two seconds. An early exit is possible and is recorded as an idea (`work/notes/ideas/exit-the-dns-round-trip-early-when-the-shim-already-replied.md`) rather than built under release pressure.
- The DNS probes need `getent` (glibc's own front end to the account's real resolution path) and the installed shim binary in `-dns-probe` mode. A missing tool fails LOUD, like every other probe: a probe that could not run is not a pass. An `anonctl` upgraded ahead of its installed shim is this class too, since the older shim has no `-dns-probe` flag.
- `update`/`reconfigure` deliberately carries NO equivalent of the `add` gate. It re-applies an existing account's rules and does not provision, so the refusal has nothing to protect there; `verify` is what reports the condition on an account that already exists.

## Addendum: the counters measure the ACCOUNT, not the probe

Found in review, before release. The planted rules match `meta skuid <anonUID> ... dport 53`, so they count the account's DNS rather than this probe's: nothing in a counted packet ties it to the probe's name or socket. Any other process running as the account that emits a query during the measurement moves the counters, and `AccountEmittedQuery` then reads true on a host where NSS is bypassing every lookup, passing both bypass assertions. That is the same false green one level down, and it is reachable in practice (a Go binary resolves with the pure-Go resolver, bypassing NSS while still emitting its own UDP; so does a musl-linked tool or a stray `dig`), on a verb documented as "re-run after any change", i.e. typically while the account is in use.

The mitigation shipped is a CONTROL WINDOW: watch the account for 300ms while the probe does nothing, and if the counters move there, report the run as unattributable. That is a LOUD error, never a pass, and its wording says plainly that nothing was proven in either direction, because "we could not tell" must not read as a leak finding nor as an all-clear.

Be precise about what it does and does not buy. It catches a CONCURRENT emitter, which is what a resolving process is, since such a process queries repeatedly. It does NOT catch a single stray query landing between the control read and the probe. Exact attribution requires the probe's packets to be distinguishable in the rule itself, which means matching the socket's cgroup (`socket cgroupv2`) so it covers the account's UDP and TCP alike rather than a payload offset that only works for UDP. That is recorded as the follow-up, not as a refinement of this: it needs live validation on a real kernel before it can be trusted, exactly as everything else in this ADR did.

## Addendum: what `--allow-nss-bypass` buys, decided rather than left implicit

Also found in review. Consent was consumed once at `add` and recorded nowhere, which left three consequences unstated and therefore undecided: `verify` stays red (intended), so `use`/`exec` refuse the account permanently (not stated anywhere), and the marker is never written, so sibling tools lose the double-anonymization signal on exactly those hosts (not stated either).

The decision is to KEEP the hard refusal and make the text honest, rather than to record the consent and let `use`/`exec` proceed past the recorded assertion.

The reasoning: `use` exists for one purpose, to refuse a session that cannot be proven anonymized, and an override on that gate is the kind of thing that stops being exceptional. The account is still perfectly usable through `sudo -iu <account>`, which CONTEXT.md already calls the day-to-day path, so the cost of refusing is ergonomic rather than functional. And the marker's contract (ADR-0004) is that it is written only after a green verify; an operator's consent to a known leak is a reason for anonctl to let them PROCEED, never a reason for anonctl to start certifying the host to another tool that will make its own decisions from that certification.

So the flag installs the forcing and buys nothing else, and `add` now prints all three consequences at the moment it is used, with `docs/nixos.md` carrying the same table. The rejected alternative is recorded because it is reasonable and may be revisited: persist `allowNSSBypass` in the account config, keep the assertion red in every report, and let `use`/`exec` proceed past that one recorded assertion while printing it. If that is ever wanted, the thing to preserve is the invariant it was designed around: the REPORT never goes green, and the marker stays a separate, explicit decision.

## Addendum: a loopback resolver needed a baseline rule, or the remedy would have holed the boot invariant

Recommending a loopback nameserver (the remedy for the un-NATed-reply defect) turned out to interact with the standing baseline default-deny, and the interaction runs the wrong way.

The baseline RETURNS loopback destinations, because forcing rewrites the account's traffic to a loopback shim port, so "loopback dst" is the signature of a packet the forcing table is about to govern. That reasoning holds for every destination except a local RESOLVER. With an off-box nameserver, an UNFORCED query (the boot window, or a flushed forcing table) was caught by the baseline's broad non-loopback drop. With a loopback nameserver it is returned instead, reaches the host's resolver, and is forwarded with the host's real identity. So "forcing absent means DROPPED, not free" would have quietly stopped holding for DNS on exactly the hosts this ADR tells operators to configure that way.

The baseline therefore drops the anon UID's `udp/tcp dport 53` outright, before its loopback return. It cannot touch forced traffic: `anon_nat` rewrites the destination port to the shim's DNS port at `dstnat` (-100) and the baseline chain runs at filter priority (0), so a forced query arrives carrying the shim port and no longer matches :53, while an unforced one still carries :53 and is dropped. It cannot collide with an exemption either, since `lanexempt` rejects :53 outright (ADR-0008). The match is family- and address-agnostic, so it covers 127.0.0.53, 127.0.0.1, ::1 and glibc's no-nameserver default in one rule, and the off-box case it also covers was already dropped anyway.

The general lesson is the one this whole ADR keeps arriving at: a remedy that is correct in isolation can move a load-bearing assumption somewhere else, and the way to find that out is to state the assumption ("loopback means forced") and go looking for the case that breaks it.

## Addendum: the `add` gate measures too, because the detector has a false positive by construction

Found by running the fixed host. `internal/nssbypass` reports an nscd-compatible socket as a broad provider from its EXISTENCE, because glibc consults such a socket before nsswitch.conf. That is the correct default reading and it is what found the original leak. It is also, by construction, unable to tell a serving daemon from a refusing one: nsncd with `NSNCD_IGNORE_HOSTS=true` keeps its socket, because it still serves passwd and group, while refusing hosts. That is the remedy this ADR recommends, so `add` refused precisely the operator who had just applied it, with a message telling them to apply it.

So the gate now MEASURES before refusing, with the same technique the per-account assertions use and for the same reason. The question "does glibc resolve `hosts` in the calling process on this host?" is uid-INDEPENDENT (it is a property of the host's configuration, not of who asks), so `add` can answer it with its own uid before the account it is about to provision exists: plant a counter on the caller's own sockets, look up a unique unresolvable name, and see whether a query was emitted.

The three outcomes are deliberately not symmetric:

- **Measured, in-process:** proceed, and disclose that the daemon is present and not serving hosts.
- **Measured, out-of-process:** refuse, as before. This is a proof, not a hint.
- **Not measurable** (no nft, no getent, or another process emitting DNS during the control window): PROCEED with a loud warning. `add` runs `verify` inline moments later and measures it per-account, so a wrong guess in this direction is caught within seconds and reported red, while a wrong refusal leaves a correctly configured operator with no route forward except a flag that costs them `use`/`exec` and the marker. Refusing on an unanswered question would be the same mistake as refusing on the detector, one step further back.

The detector keeps its job: naming the daemon and carrying the remedy, so a refusal is actionable. It just no longer decides.
