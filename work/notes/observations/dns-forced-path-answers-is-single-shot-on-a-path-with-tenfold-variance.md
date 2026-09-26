---
title: dns-forced-path-answers is single-shot on a path whose honest variance is tenfold, and it gates use/exec
slug: dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance
---

Noticed on a NixOS host (telemaque, anonctl 0.9.0, two adopted accounts, endpoint `socks5h://127.0.0.1:9050` against the system tor) while verifying an unrelated feature. Off that change's path and not fixed by it.

## What happened

```
[FAIL] dns-forced-path-answers: the shim ANSWERED a query from the account to 127.0.0.53 and the
answer never arrived: conntrack un-NATs the reply back to source 127.0.0.53 before delivering it,
and something on the host's input path dropped it there
(no answer: read udp 127.0.0.1:54293->127.0.0.53:53: i/o timeout)

anonctl: use: anon-01 did NOT verify as anonymized; refusing to open a shell
```

Fourteen of fifteen passed in the same run, `dns-remote` and `anonymized-exit` among them. Every run since has been 15/15, across a dozen or more. Nothing on the host's DNS path had been restarted: `systemd-resolved`, `firewall`, `nftables`, `tailscaled`, `nscd` and `anonctl-shim@<account>` were all still at their boot timestamps with `NRestarts=0`.

## The timing distribution, which is the useful part

Measured INSIDE the account's own shell, so that nothing else is in the clock (`TIMEFORMAT=%3R; time getent ahostsv4 <name>`):

```
forced, example.com, 10 runs:      0.257 0.611 2.195 2.214 2.394 2.512 0.739 2.071 2.195 2.356
forced, check.torproject.org, 3:   0.666 2.283 3.600
unforced account, example.com, 3:  0.018 0.003 0.002
```

Median about 2.2s, spread 0.26s to 3.6s, against 2 to 18 MILLISECONDS unforced. So the honest variance on a warm path is roughly tenfold, and the typical cost is about four times the "~0.5s on a warm circuit" figure in `DNSProbeTimeout`'s comment. That comment is not wrong, it is optimistic for this host.

**Worth measuring this way rather than through `exec`.** A first attempt timed `anonctl exec --as <n> getent ...` and produced 5.067s and 4.999s, which looked like a five-second timeout firing somewhere. It was not: `exec` runs the whole verify suite before the command, so those numbers were verify plus the lookup. Anyone repeating this should time inside `use`, not through `exec`.

## What the failure was not

Not the 5s-versus-20s problem the comment already fixed: the budget was twenty seconds and the answer did not arrive in it, while the worst honest sample here is 3.6s. That is a 5.5x margin over anything observable.

## What it leaves

Two candidates, which one sample cannot separate. A cold circuit build on a first query after idle, which `DNSProbeTimeout`'s comment explicitly sizes the window for and which can exceed any warm sample. Or a genuinely lost answer, the un-NAT-then-drop the failure text describes, occurring transiently rather than structurally (a structural one could not pass fifteen times afterwards).

## The suggestion, which is not "raise the timeout"

The window is already generous and raising it would only make a real failure slower to report. The narrower observation is about SHAPE: this check is single-shot on a path with tenfold variance, and it gates `use` and `exec`. So its false-negative rate is the rate at which an operator is locked out of a healthy account, and the message they get confidently describes a kernel-level drop that did not happen, which sends them to `nft` and `conntrack` rather than to a retry.

A second attempt before the verdict costs nothing when the path is healthy (the first query answers in ~2s) and would separate "one answer was lost, or one circuit was cold" from "this path is broken", which is the distinction the check exists to draw. If a retry is unwelcome, the alternative is cheaper still: say so in the failure text, so the first thing the operator does is run `verify` again rather than open the ruleset.

## Added after reading the forwarder, which changes the diagnosis

`internal/shim/dnsforwarder.go` dials a FRESH SOCKS stream per query:

```go
func (f *Forwarder) resolveViaSOCKS(query []byte) ([]byte, error) {
	conn, err := f.dialer.Dial("tcp", f.cfg.Upstream)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
```

So one name costs a TCP connect THROUGH THE CIRCUIT to an upstream resolver addressed by hostname (the exit resolves that name first), then a DNS-over-TCP exchange, then a close. That explains the ~2.2s far better than a RESOLVE round trip does, and it makes the measured tenfold variance unsurprising: it is circuit-build variance plus connect variance, once per lookup, and glibc asking for A and AAAA pays it twice.

**A better hypothesis for the failure, which fits everything.** The exchange carries its own 5s deadline. Our observed spread already reaches 3.6s on a warm path, so a cold circuit exceeding 5s is unremarkable rather than exotic. The forwarder would then give up and close, emitting nothing, and the probe would sit out its full 20s waiting for an answer nobody was going to send. That matches the failure text (the query provably reached the shim; no answer arrived), matches why every retry passed, and needs no conntrack or input-path drop at all. `DNSProbeTimeout`'s comment already names this deadline as something the probe window must exceed; the part not considered is that the deadline itself can be the thing that fires.

If that is right, the probe's message is actively misleading: it asserts the un-NAT-and-drop mechanism, which sends the reader to `nft` and `conntrack`, when the likelier event is upstream of both and inside anonctl's own forwarder.

## Three fixes, in the order of what they buy

1. **Reuse the connection.** RFC 7766 exists for exactly this: DNS-over-TCP connections are meant to be persistent and pipelined. Holding one stream to the upstream resolver per account, and re-dialling only on error or idle timeout, removes a full circuit connect from every lookup. This is the biggest win available and it changes no anonymity property: the stream is already per-account (the `<account>@` isolation username pins its circuit class), so keeping it open links nothing that opening it repeatedly did not already link. If anything it links LESS, since fewer streams mean fewer opportunities for the endpoint to observe a new one.
2. **Cache answers, with TTL, per account.** Removes repeat lookups entirely, which is most of a browser's traffic after the first page. Per-account by construction, since the shim is per-account, so no slot can learn anything about another from it. The one honest caveat is a local cache-probing side channel (anyone who can reach that DNS port can time it to learn what the account resolved), which on this box means the operator and root, who can already see more than that.
3. **Reconsider the 5s exchange deadline**, or make the failure loud. A deadline shorter than the tail of the latency distribution it governs will fire, and today it fires SILENTLY: the query is dropped and the client waits out its own timeout with no signal. Either give it room (it can afford to, once connections are reused) or return SERVFAIL so the client fails fast and the reason is visible.

The verify-side suggestion at the top of this note stands and becomes smaller: with the forwarder fixed, a single-shot probe is on a much tighter distribution, and a retry is belt-and-braces rather than the main defence.

## CLOSED: what the follow-up measurements said

All three fixes landed, plus the verify-side change, in five commits (2f1d1ec, 73a9639, a9e6300, 971c9f8, 3aad225), and `docs/adr/0013` records the decisions. An adversarial review of those commits found no blocker and real defects (a retry that could hide an off-path answer behind a pass, one query's deadline failing its neighbours, a cache key a local uid could collide with, and four tests that could not fail); they are fixed in follow-up commits (9bbd00a, be675c9, a8e4a5c, ecd556a) and listed in the ADR's amendment. None of the fixes changes how many circuit round trips a lookup needs or what the cache hits, so the latency numbers below stand; they were not re-measured. What the measurements said is not uniformly what this note predicted, so here it is straight. **Everything below was measured by an agent WITHOUT root**, so none of it went through the account's nft redirect or inside `anonctl use`; the before/after on the account's real path is still to be taken (see "Live verification" below).

**The hypothesis held, and was caught in the act.** Against the RELEASED 0.9.0 binary, through an endpoint that completes the SOCKS handshake and then goes quiet, the client got NOTHING for as long as it was willing to wait and the shim's journal recorded NOTHING either. With the endpoint simply dead, the same: no answer (the client timed out at 8s) and an empty log. So a failed resolution produced silence, exactly as argued, and silence is indistinguishable at the probe from an answer destroyed on the way back. Now: a dead endpoint gets SERVFAIL in about a millisecond and the log line `dns: endpoint unreachable: nothing accepted a connection at ... (is the anonymizer, e.g. Tor, running and listening there?)`; a hanging one gets SERVFAIL at the 10s deadline and `dns: deadline expired: ... (the endpoint is up and the circuit was slow ...)`.

**But the note's reading of WHICH failure text the operator saw was wrong, and that matters more than it looks.** Their message was the un-NAT one, which is the branch where the `shim-reply` counter MOVED, and a forwarder that gives up silently emits nothing to move it. The two are reconciled by what that counter actually measures: the un-NAT branch fires on a counter proving only that A packet left during the window, which glibc's own retries can satisfy (and so can a late reply to the NSS probe that runs immediately before the round-trip probe). That is why the failure text now reports the observation and ranks candidates instead of asserting the mechanism.

**A second-order trap, caught before it shipped.** Making the forwarder answer SERVFAIL instead of staying silent would, on its own, have made things WORSE in one place: `dns-forced-path-answers` would otherwise have started PASSING on a dead endpoint, because any rcode counted as ANSWERED. The verdict now reads the rcode, and the SERVFAIL carries its reason (as an RFC 8914 Extended DNS Error) so verify can say "your Tor is down" or "your circuit was slow" rather than just "failed".

**The two numbers in this note and in my measurements are NOT like for like, and the gap between them is unexplained.** They were taken on the same host on the same day, about two hours apart, so this is not drift:

```
2.195s median   operator, inside `anonctl use anon-01`: getent ahostsv4 example.com
                (glibc, ONE query, A only, through the nft redirect), 10 samples
0.340s median   agent, unprivileged uid, straight at anon-01's shim DNS port
                (127.0.0.1:19053, the same deployed 0.9.0 shim): A and AAAA in
                parallel (TWO queries), 10 samples
```

The second does MORE work and is six times faster, so the measurement POINT is a likelier explanation than circuit weather, and nothing measured here supports the weather reading. If the account's real path is still ~2.2s while the shim's port answers in ~0.3s, then something between `getaddrinfo` and the forwarder (the NSS modules ahead of `dns` in this host's `hosts:` line, the nft redirect and conntrack, or glibc's own behaviour with `options edns0 trust-ad` and the search domain) costs more than the whole upstream exchange, and that would be a finding in its own right. An attempt to reproduce glibc's path without root (glibc in an unprivileged user+net+mount namespace, aimed through a unix-socket relay at the shim) was abandoned inside its own time bound: `getent` there returned "not found" in about a millisecond with the relay listening, most likely because the NSS path inside the namespace differs (nsncd's socket is still reachable and sees a remapped uid), so it measured nothing trustworthy. The operator's loop below is what settles it.

**The change's effect at the forwarder's port.** Leg A is `anon-01`'s deployed 0.9.0 shim on `127.0.0.1:19053`, leg B each commit's own binary in the same circuit class (`-socks-user anon-01`, same tor, same upstream), samples interleaved with the leg order alternating, a fresh name per sample, ten samples each, medians:

```
reuse only (73a9639)   one lookup, A+AAAA                0.361s -> 0.153s
with cache (a9e6300)   one lookup, A+AAAA                0.338s -> 0.237s
with cache (a9e6300)   five lookups of one name           1.722s -> 0.214s
```

And on a deliberately slow endpoint (a SOCKS endpoint adding 250ms one-way), where the round trips a lookup spends are visible as wall time:

```
reuse only (73a9639)   one lookup, A+AAAA                1.036s -> 0.529s
reuse only (73a9639)   burst of five distinct names       5.157s -> 2.723s
```

**A fix bought less than expected, and it is worth naming which.** Connection reuse ALONE on a fast warm circuit is worth tens to low hundreds of milliseconds, because a stream open through an established circuit is cheap. Its structural value is on a slow or cold circuit, where it halves the traversals a lookup needs. The order-of-magnitude change on the shape a real workload has (five lookups of one name: 1.722s to 0.214s) is the CACHE. Anyone repeating this on a fast circuit and finding reuse close to noise has not found a bug.

**Measurement traps, since this note already contains one.** (1) `anonctl exec` runs the whole verify suite first, which is what produced this note's original 5.067s figures; time inside `use`, or query the shim's port directly and say that you did. (2) An A/B where leg A always goes first is not an A/B: both legs share one circuit class, so the second leg is systematically warmer. Alternate the order. (3) A driver that parses timings out of text turns a TIMEOUT into a non-number, and a median that sorts non-numbers silently reports zero; count failures as failures. (4) A benchmark shim that fails to bind because a previous one still holds the port leaves the OLD process answering, and the run silently becomes a same-binary control; check each shim's log line before trusting a leg.

## Live verification, which is the operator's (needs root)

Each step: the command, what good looks like, what bad looks like. Run them against the NEW shim, which means installing the new `anonctl-shim` and restarting the account's unit (`systemctl restart anonctl-shim@anon-01`): a running shim keeps its old binary until restarted, and a stale shim reproduces every old behaviour. Take the BEFORE loop first, while 0.9.0 is still running.

1. **The benchmark, on the account's real path, before and after.**

   ```
   anonctl use anon-01
   TIMEFORMAT=%3R; for i in $(seq 10); do time getent ahostsv4 example.com >/dev/null; done
   ```

   Good: the AFTER median is materially below the BEFORE one, and on the repeat samples (every one after the first, since the name is now cached) well under a second. Bad: the AFTER median is still ~2s. That would mean the cost is NOT in the forwarder (whose port answers in ~0.2 to 0.3s), and the next step is to split the path: time `getent` for the same name as `getent ahostsv4 <fresh-random-name>.example.com` (no cache hit possible), and compare with a direct query to 127.0.0.1:19053 from the same shell. Record both distributions here.

2. **`anonctl verify anon-01` on a healthy account.**

   Good: all assertions pass, and `dns-forced-path-answers` says the query went through the redirect and was ANSWERED, with nothing more. Bad: a red that was green on 0.9.0; or a pass whose detail says `It passed on attempt 2, NOT the first`, on a path that is fast and healthy. That line means the first attempt failed and the retry is what made it pass; the detail then carries what the first attempt saw. Run verify three times: that line may appear rarely (one cold circuit), but if it appears every time, the first query is failing for a reason worth finding, and the retry must not be allowed to hide it.

3. **A deliberately dead endpoint.**

   ```
   systemctl stop tor          # or whatever serves the account's endpoint
   anonctl verify anon-01
   journalctl -u anonctl-shim@anon-01 -n 5
   systemctl start tor
   ```

   Good: `dns-forced-path-answers` FAILS, says the account failed CLOSED, and says the anonymizer is DOWN or not listening (not "slow", and nothing about un-NAT or nft). The shim's journal carries `dns: endpoint unreachable: ... (SERVFAIL, fail-closed)`. Inside `anonctl use anon-01`, `getent ahostsv4 example.com` returns promptly with no address instead of hanging. Bad: the assertion passes (a SERVFAIL counted as working DNS), the text blames the ruleset, or the journal is silent (the shim was not restarted onto the new binary). And the one that must never happen: any address at all coming back for a name the account had not already resolved, which would be a fallback to a resolver other than the endpoint.

**Noticed while measuring, and recorded separately.** `work/notes/observations/the-shims-dns-port-answers-any-local-uid.md`: the shim's DNS port answered queries from an ORDINARY unprivileged uid on this host, which is how every number above was measured without root. That is pre-existing, it is not what this work changed, and the new cache turns it into a recency oracle over the account's names. Also: the forwarder's TCP listener still serves the queries on ONE client connection one at a time, so a `use-vc` client's A and AAAA are serialised on it (RFC 7766 says a server SHOULD process pipelined queries concurrently). It does not affect this host, whose glibc queries over UDP, and it was left out of this change.

## Not asked for, but adjacent

`exec` running the full verify suite per invocation is correct and it does make `exec` unsuitable for timing anything, and awkward for scripting a loop. Not a complaint, just the reason the first numbers in this note were wrong.

## Live verification, taken on telemaque 2026-09-26 (closes this note)

Taken by the operator with root, on the account's real path: `getent ahostsv4 example.com` ten times inside `anonctl use anon-01`, BEFORE on the deployed 0.9.0, AFTER on 0.11.0 with the account's table re-applied by `anonctl update` (which also restarted its shim onto the new binary).

```
BEFORE 0.9.0:   0.345 0.491 0.521 0.528 0.509 0.462 0.409 0.405 0.404 0.422   median 0.44s
AFTER  0.11.0:  0.544 0.002 0.002 0.002 0.002 0.002 0.002 0.001 0.001 0.001   median 0.002s
```

What they say, including where they disagree with this note:

- **Repeat lookups are solved.** After the first, every sample is 1 to 2 ms, which is the unforced figure this note opened with (2 to 18 ms). That is the ADR-0013 cache answering. The first AFTER sample, 0.544s, is a lookup on a shim restarted moments earlier: a fresh stream dial plus a cache miss, and it lands inside the BEFORE range.
- **The 2.2s this note was built on did not reproduce, on the SAME binary, path and method.** BEFORE today, still 0.9.0, still `getent` inside `use`, has a median of 0.44s with a spread of 0.35 to 0.53, five times faster than on 2026-09-25 and far tighter. It is also close to the ~0.34s the agent measured at the forwarder's port. So the explanation this note leaned on at the end (that the gap between 2.2s and 0.34s was the MEASUREMENT POINT, i.e. NSS, the redirect or glibc adding seconds) is not supported: through the whole path, today costs about what the port cost then. The better reading is that 2026-09-25's circuits were slow, and that the per-lookup variance this note measured is also day-to-day variance. It was never a fixed property of the path, and it does not need a host-side finding.
- **Not measured: a FRESH name on a warm stream.** The benchmark repeats one name, so after the first lookup it measures the cache. What a page load of new hosts pays is the miss cost with the stream already up, which the port-level numbers above put at ~0.15 to 0.24s against the per-query dial it replaced. That is expected rather than shown on the real path.
- **The gate.** `anonctl verify anon-01` three times in a row: 16 of 16 each time (`shim-ports-closure` included), and `dns-forced-path-answers` passed on the FIRST attempt every time (no "passed on attempt 2" line), which is step 2 above. The failure that started this note has not recurred.
- **Closure (c) on the real host** (ADR-0014, shipped in the same release): from the operator's own uid, `anonctl-shim -dns-probe 127.0.0.1:19053 example.com` failed at once with `operation not permitted`; the same command inside the account was ANSWERED.
- **Step 3 above (a deliberately dead endpoint) was not run.** Stopping the system tor would take every Tor user on the box down with it. The SERVFAIL path it would exercise is covered by the unit tests and by the namespace runs in ADR-0014, not by a live run on this host.

Closed: the fixes shipped, the gate is stable, and the remaining open question (the fresh-name cost on the real path) is a nice-to-know rather than a defect.

**Addendum, the same day: the fresh-name cost, measured.** Ten DIFFERENT names (`wikipedia.org github.com mozilla.org debian.org kernel.org python.org rust-lang.org gnu.org archlinux.org nixos.org`), one lookup each, inside `anonctl use anon-01` on 0.11.0, so none can be a cache hit:

```
0.542 0.262 0.305 0.260 0.266 0.323 0.230 0.278 0.274 0.302   median 0.28s (0.23 to 0.32 after the first)
```

The first is the one that pays for a stream dial: the stream had been idle past its 30s teardown since the previous run. The other nine are the true miss cost on a warm stream, 0.23 to 0.32s, against the 0.44s median every 0.9.0 lookup paid (a fresh stream each time). That is roughly a third off for a name the account has not seen, on top of repeats dropping to 1 to 2 ms. It sits a little above the ~0.15 to 0.24s measured at the port, which is what the full path adds. One sitting, different names from the BEFORE run, and circuits vary day to day, so read the one-third as indicative rather than exact. The second account (`anon`) also verified 16/16 on 0.11.0, `shim-ports-closure` included.
