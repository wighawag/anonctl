---
title: End the DNS round-trip probe as soon as the shim-reply counter proves the path is not merely slow
slug: exit-the-dns-round-trip-early-when-the-shim-already-replied
---

`dns-forced-path-answers` waits the full `shim.DNSProbeTimeout` (20s) for an answer, and the NSS probe ahead of it waits out its own budget, so on a host with the answer-destroyed defect the DNS phase costs about 29s (measured in the live integration suite). Since the DNS checks are exclusive, that is added to the verify run rather than hidden inside it.

The 20s exists for ONE case: a cold Tor circuit, where a healthy path is simply slow. The `shim-reply` counter distinguishes that case from the broken one, and it is already being read: if the shim has ALREADY emitted a reply and the account still has nothing, the path is not slow, it is broken, and waiting longer cannot change the verdict.

So: probe with a short deadline (~5s), read the counters, and only if the shim has NOT replied fall back to the full window, which is exactly the cold-circuit case the long deadline is for. That should cut a broken host's DNS phase from ~29s to ~7s while keeping the protection that made the deadline long in the first place.

**Caveat added after ADR-0013, and it undercuts the premise.** The `shim-reply` counter does not prove that the shim replied to THIS query. It proves only that A packet left the shim's DNS port during the window, which glibc's own retries can satisfy, and so can a late reply to the NSS probe that runs just before the round-trip probe. Early exit on that counter could therefore cut short a healthy-but-cold path whose counter was moved by somebody else's reply, which is the false negative the long window exists to prevent. Since ADR-0013 the shim also answers every query within its own 10s deadline (with an answer or a SERVFAIL naming the reason), so the window can be reasoned about from that deadline instead; any version of this idea should start from there, not from the counter.

Not built under release pressure, because it adds a second read-and-branch to the one probe whose polarity errors are the most expensive in this tool, and it wants its own live test on a host with the defect (drop the shim's replies with `meta skuid <shimUID> udp sport <dnsPort> drop` at priority -250, as the integration suite already does).
