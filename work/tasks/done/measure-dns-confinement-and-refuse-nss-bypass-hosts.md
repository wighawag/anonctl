---
title: Measure DNS confinement instead of inferring it, and refuse a host that resolves names out of process
slug: measure-dns-confinement-and-refuse-nss-bypass-hosts
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What was built

`verify` certified a live account as clean while that account had **no working DNS of its own** and had **every hostname resolved for it by the host resolver**. Both were measured on telemaque (NixOS + Tailscale) against anonctl v0.5.0 and a correctly adopted, correctly jailed `anon-01`; all ten assertions passed, `dns-remote` included. The mechanisms are recorded in `work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md` and the decisions in `docs/adr/0011`.

**Why `dns-remote` could not catch it.** Its live evidence was a successful forced fetch of a name, after which `dnsRemoteEvidence` returned `hostSaw=false` HARDCODED, reasoning in a comment that the anon UID cannot do plaintext DNS off-box so the name must have been resolved proxy-side. A successful fetch proves a name resolved somehow; it never proves which resolver answered. Both halves of that premise were false on the measured host.

**Defect 1 (NSS delegation, the serious one).** glibc asks an nscd-compatible socket for the `hosts` database BEFORE reading `nsswitch.conf`, so on NixOS (nsncd, uid `nscd`) `getaddrinfo` executes in another process under another uid. `meta skuid` matches a socket's OWNER, so no rule anonctl can write governs it. This is the NSS instance of the v0.4.0 chain-bug principle. It is not a NixOS quirk: `nss-resolve`/systemd-resolved is the same bypass and is the stock configuration on Debian, Ubuntu and Fedora.

**Defect 2 (the answer is destroyed).** The account's own DNS path was packet-perfect and still returned nothing: conntrack un-NATs the shim's reply to the NAMESERVER's address before delivering it, and tailscaled's anti-spoofing rule drops packets sourced from `100.64.0.0/10` arriving on `lo`, which is exactly what an un-NATed MagicDNS answer is. The two compound: defect 2 removes the legitimate path and defect 1 supplies a leaking one, so **the leak was the only reason the account had DNS at all**.

The change:

- Three MEASURED assertions replace one inferred one. `dns-remote` keeps its name and meaning (the account's own lookup was carried into the shim); `dns-nss-not-bypassed` and `dns-forced-path-answers` are new and additive (`schemaVersion` stays 1, ADR-0003 amended). `dnsRemoteEvidence` was deleted, not repaired.
- The probe name is a fresh `<random>.invalid` (RFC 2606). Uniqueness is load-bearing: no cache can answer it, so any completed lookup MUST have produced a query somewhere, which is what makes the bypass measurable rather than inferable.
- Counters are planted at output priority -300 (pre-nat: did the account emit a query at all) and 50 (post-nat: did it reach the shim), in a throwaway policy-accept table. One priority alone cannot separate "the account never emitted a query" from "the redirect did not fire" from "the answer was destroyed", and those are three different bugs with three different owners.
- `anonctl-shim -dns-probe` is the round-trip tool: one A query from the calling uid, no NSS, no Go resolver. Reusing the installed shim keeps verify free of a `dig`/python dependency, exactly as `-probe` already does for dials.
- `internal/nssbypass` detects the delegating-resolution class (nscd/nsncd socket, plus `resolve`/`sss`/`winbind` broad and `mdns`/`mymachines`/`libvirt` narrow). `add` REFUSES a broad provider before provisioning, naming daemon, evidence and remedy; `--allow-nss-bypass` proceeds and does NOT buy a green report. The detector is never the authority: a clean measurement passes over a detector hit, and an unknown daemon fails just the same.
- `anonymized-exit` robustness: `check.torproject.org` is consulted FIRST for a tor-shared endpoint (it carries the exit IP as well as IsTor), and the generic IP-echo became a fallback LIST. One blocked echo previously failed the assertion on a correctly jailed account, in the shape of a forcing failure.

## Acceptance criteria

- [x] `dns-remote` decides from a measurement, never from a hardcoded flag; the inferred probe is gone from the tree.
- [x] A lookup that completes while the account's own sockets stay silent FAILS `dns-nss-not-bypassed` and names the detected daemon (or admits the resolver is unidentified).
- [x] A forced DNS path that does not ANSWER fails `dns-forced-path-answers`, with the three packet-level fates distinguished and the un-NAT mechanism named.
- [x] `add` refuses a broad-provider host before `provision.Add`, with an actionable remedy; `--allow-nss-bypass` proceeds while stating the exposure and disclaiming a green verify.
- [x] A narrow (bounded-name-class) provider warns and proceeds rather than refusing, and is reported as a residual by verify.
- [x] `anonymized-exit` survives a blocked IP-echo.
- [x] Tests cover the new behaviour in the repo's style: pure decisions over evidence structs, the counter ruleset + parser (proven against real `nft list table` output), the DNS wire format and probe polarity (against a real local responder), the detector's branches, and all four of `add`'s gate branches.
- [x] `--allow-nss-bypass` discloses its FULL price (verify stays red, `use`/`exec` refuse, no marker) rather than only the red assertion; ADR-0011 records that hard refusal was chosen over recorded consent, and why.
- [x] Live integration coverage of the real probe (`internal/verify/dns_live_integration_test.go`, in-package so it calls `dnsEvidence` itself rather than a twin): a healthy path goes green and proves the planted ruleset is valid nft in a live kernel; the answer-destroyed fate is reproduced and classified; cross-talk is reported as unattributable.
- [x] The host-reading guard is behind an injectable seam and stubbed in `TestMain`, so the suite does not pass or fail according to whether the developer's box runs nsncd (it does on the host this was written on).

## Review findings, resolved before landing

A single adversarial review (read-only) returned do-not-ship and was right on four counts, all now closed and each with a test:

- **The counters measured the ACCOUNT, not the probe.** `meta skuid <anon> dport 53` counts any DNS the account emits, so a concurrent process running as it (a Go binary bypasses NSS entirely and still emits its own UDP) moved the counters and passed both bypass assertions on a host leaking every name: the same false green one level down. Mitigated by a 300ms CONTROL WINDOW; a run it cannot attribute is a loud error saying nothing was proven in either direction. Exact attribution by cgroup is the follow-up (`work/notes/ideas/attribute-dns-probe-packets-by-cgroup.md`), because it needs live validation.
- **The probe name was a privacy regression in the verifier itself.** It spelled `anonctl-probe-<pid>-<nanos>` (a product fingerprint plus a cross-run correlator) and, being non-absolute, was re-queried with the `search` list appended on NXDOMAIN, sending the HOST'S OWN search domain (a tailnet name on the measured host) to a public resolver over the circuit. Now a bare CSPRNG label with a trailing dot, with a test asserting all three properties.
- **`DNSProbeTimeout` was smaller than the shim's own budget for the same query** (an unbounded SOCKS dial plus a 5s upstream deadline), so a cold Tor circuit made a healthy path report "the shim never answered" and refused the operator a shell. Now derived from that budget.
- **`dns-forced-path-answers` passed on the answer alone,** which called clear DNS straight to the nameserver "working, anonymized DNS": the last inferred verdict in the new code. The pass now requires the redirect counter too, and an answered-but-not-redirected query fails, named as clear DNS.

Plus: stdout-only classification for the NSS probe (a `setpriv` failure could be reported as the account's answer), glibc's 127.0.0.1 default treated as a nameserver rather than "no DNS to force", `context.WithoutCancel` for the scratch-table delete (Ctrl+C no longer leaves tables loaded), a settle delay so the measured host's own fate is not misclassified, and several comment/doc claims corrected where they outran the code.

## Evidence

Measured on telemaque, kernel 6.18, anonctl v0.5.0, live account `anon-01` (uid 8802, shim uid 413, shim DNS port 19053).

NSS bypass, one `getent ahostsv4 <unique>.invalid` as uid 8802: `anon udp/53 = 0`, `anon tcp/53 = 0`, `toward-shim = 0`, and the lookup nevertheless answered `100.71.110.44` for a tailnet name the shim NXDOMAINs.

Answer destroyed, one raw query to `100.100.100.100:53` as uid 8802: `anon udp/53 = 1`, `toward-shim = 1`, `shim replied = 1`, reply entered the input path = 1, reply survived input filtering = **0**; tailscaled's `ip saddr 100.64.0.0/10 iifname != "tailscale0" drop` moved 16 to 17 (+89 bytes) across that single probe, while its preceding `ip saddr <node's own addr> iifname "lo" accept` moved 17 to 18 (the query). A query addressed straight to `127.0.0.1:19053` answers in 0.55s, so the shim is healthy.

Live integration run on telemaque (`sudo go test -tags integration -run TestLiveDNS ./internal/verify/`), all three green: the healthy forced path answers through the redirect (which is also the only proof that the planted counter ruleset is valid nft in a live kernel, since unit tests only string-compare it); the answer-destroyed fate is reproduced and classified, with the shim observed replying; and cross-talk is reported as unattributable rather than passing. The first run of that suite FAILED two of the three, for a harness reason worth keeping: it ran the shim in-process as root, copying the sibling suite, where that is explicitly fine because those closures key on the ANON uid. The shim-reply counter keys on the SHIM uid, so an in-process shim replied from uid 0 and no rule could match it. The harness now runs the shim under `setpriv --reuid <shimUID>`, the way production does.

FINAL LIVE STATE, after the host was remediated (nsncd told to ignore the hosts database with `NSNCD_IGNORE_HOSTS=true`, and the system resolver moved to the systemd-resolved stub on 127.0.0.53 so the shim's answer is never un-NATed onto an address tailscaled drops): `anonctl verify anon-01` passes ALL TWELVE assertions, with `dns-forced-path-answers` reporting the query going through the redirect into the shim and being answered, and `dns-nss-not-bypassed` passing while still disclosing that nsncd is configured. The live integration suite passes all three tests. That is the first green this work has produced; every run before it proved only that the change failed correctly.

Three further defects were found by those live runs and fixed here, each with a test: verify could not measure itself (the DNS checks watch the account's own sockets while `anonymized-exit` resolves a hostname as that same account, so anonctl's own probe was indistinguishable from the third-party emitter the control window exists to catch; checks can now be marked EXCLUSIVE and run first, alone); `add` would have refused a correctly remediated host (the detector reports an nscd socket from its existence, but nsncd keeps its socket while refusing hosts, so the gate now MEASURES before refusing and treats an unanswerable question as proceed-with-warning); and a `getent` killed by its own deadline was reported as a broken probe rather than as the observation it is (the counters are the evidence and do not need the lookup to finish).

Two hypotheses were REFUTED by these measurements and are recorded in the finding so they are not re-tried: `route_localnet=0` (the same host redirects all of the account's TCP to the same loopback address successfully) and SNAT of the query's source (the reply's source comes from conntrack's reverse tuple, not the query's source).
