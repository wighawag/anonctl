---
title: Attribute the DNS probe's packets exactly, by cgroup, instead of mitigating cross-talk with a control window
slug: attribute-dns-probe-packets-by-cgroup
---

The DNS confinement measurement (ADR-0011) counts packets with `meta skuid <anonUID> ... dport 53`, which counts the ACCOUNT's DNS rather than the PROBE's. Any other process running as the account that emits a query during the measurement moves the counters, and the bypass assertions then pass on a host that is leaking every name. What shipped is a 300ms control window that reports the run as unattributable when the account is not quiet: honest, but it degrades to "could not measure" on a busy account, and it cannot catch a single stray query landing between the control read and the probe.

The exact fix is to make the probe's packets distinguishable IN THE RULE. Run each probe inside a transient cgroup and match `socket cgroupv2 level <n> "<path>"` in the counter rules, so a counted packet provably belongs to the probe's own process tree. That is protocol-agnostic, which matters here: the account's DNS may be TCP (the shim's forwarder exists partly because glibc falls back to `use-vc` when UDP egress is dropped), so the obvious alternative of matching the unique QNAME at a fixed payload offset works for UDP and is unreliable for TCP, whose header length varies.

Open questions a live test on a real kernel must answer before this can be trusted, in the spirit of everything else in ADR-0011:

1. Does `socket cgroupv2` match in the `output` hook at the priorities the probes plant at (-300 and 50), or only in `prerouting`?
2. What is the cheapest way to put the probe in its own cgroup: `systemd-run --scope` (systemd is already a dependency, but this adds a unit per probe and needs the exec to survive it) or writing the pid into a cgroup anonctl creates itself?
3. Does the cgroup path survive the `setpriv` uid drop the probes already do, and does it still match once the process is the anon uid?
4. Does an nft rule naming a cgroup path that has since been removed fail to load, or match nothing? The scratch table is planted per probe, so the lifetime is short, but a stale path must not make the plant fail in a way that reads as a passing assertion.

Validate with the same method that produced the finding: plant a scratch table with both rule shapes, run the probe, read the counters, and compare against a deliberately noisy account (a second process emitting DNS as the same uid) to prove the cgroup rule counts only the probe's packets while the skuid rule counts both.
