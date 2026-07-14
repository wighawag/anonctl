---
title: Per-UID kernel-forced anonymized egress (anonctl v1)
slug: per-uid-kernel-anonymized-egress
---

> Launch snapshot. Records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked: they move into tasks/ADRs and this spec settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

> Architecture note: this spec was grilled after its first draft. The original "two mutually-exclusive backends (tor kernel-redirect vs socks shim)" model was collapsed into a SINGLE uniform socks5h-forcing mechanism where Tor is just the default endpoint, and the real axis became the endpoint's cross-user share-safety class. All six original open questions are resolved; the frontmatter carries no `needsAnswers`.

## Problem Statement

You want a whole Unix account to be anonymized: anything that user runs (a shell, arbitrary tools, an editor, a script) should have ALL of its network egress forced through an anonymizer, transparently, with no per-application proxy configuration and no way for a misconfigured or proxy-unaware app to leak your real IP or DNS. App-level `HTTP_PROXY`/`ALL_PROXY` is not enough: raw sockets and DNS ignore it and leak. Per-container jails (netcage) solve this per-container, but require you to run everything inside a jail; you instead want to just log into an account natively and have the kernel do the anonymizing.

The failure modes to defend against are concrete: an app choosing the wrong proxy (or none), a DNS query going out in plaintext, and the anonymizer being down while traffic quietly falls back to the direct route. The defense must be fail-closed (anonymizer down means traffic dropped, never sent in the clear) and leak-free (DNS via the anonymizer, IPv6 handled, not just IPv4).

There is no honest, scoped tool for this. Whonix/Tails do transparent Torification but at whole-machine / VM granularity; you want it scoped to ONE UID on a normal multi-user Linux host, configurable (not Tor-only), and with a `verify` that PROVES it rather than asks you to trust it. And on a SHARED multi-user host you want a second guarantee: two anonymized accounts must not be cross-identifiable (must not exit through the same identity), which a naive shared proxy would violate.

## Solution

anonctl is a Linux-only setup-and-verify MANAGER (like ufw/firewalld, specialized to per-UID fail-closed anonymized egress). It is NOT a runtime wrapper and NOT in the data path: the kernel nftables rules plus the per-account shim (and the unmanaged endpoint) ARE the data path; anonctl installs, verifies, and manages the rules and shim. Day-to-day you `sudo -iu anon` / `su - anon` and the kernel anonymizes everything that account does; anonctl is out of the loop at runtime.

anonctl provisions a dedicated Unix account (`anon` by default, `anon-<name>` for named ones) and installs per-UID kernel egress-forcing with a fail-closed default-DROP for that UID. The forcing mechanism is UNIFORM: the anon UID's TCP is transparently redirected into a per-account socks5h shim (a redsocks-style TCP-to-SOCKS relay plus a DNS-over-SOCKS-TCP forwarder), which speaks to a socks5h endpoint. There is no separate kernel-redirect-to-Tor-TransPort path: Tor is just one socks5h endpoint (its SOCKS port), the easy default; a plain socks endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`, wireproxy-chained-with-gost) is another. Everything is leak-free (DNS resolved remotely over the endpoint via TCP, never a plaintext query; IPv6 handled) and fail-closed (endpoint unreachable means the UID's traffic is dropped, never sent in the clear).

The axis that actually matters is not "tor vs socks" but whether the endpoint is SAFE TO SHARE across accounts. A shared host-wide Tor daemon is share-safe because anonctl dials it with a per-account SOCKS username (`<account>@`), and Tor's `IsolateSOCKSAuth` gives each username a separate circuit and exit, so two accounts on one Tor are not cross-identifiable. A plain socks endpoint has no such per-username isolation, so it is a single identity and must be used by AT MOST ONE account (else the two accounts exit identically and are cross-identifiable). anonctl knows an endpoint's share-class (`tor-shared` vs `socks-peruser`), wires the isolation username for the shared case, and refuses/flags sharing a `socks-peruser` endpoint across accounts. anonctl does NOT manage endpoint lifecycle (netcage's stance): it assumes the socks5h endpoint already exists, and like netcage can scan what is available locally and ask.

Because anonctl's whole job requires root, it APPLIES the rules itself when run as root (the ufw/firewalld stance), rather than printing commands to paste (the anon-pi stance), the deliberate divergence from anon-pi, justified below. It persists the setup across reboots, exposes a marker at `/etc/anonctl/<account>.json` so sibling tools avoid double-anonymization, and ships a `verify` that proves the account is anonymized, DNS is via the anonymizer, and a direct connection from the UID is actually DROPPED.

The signature ongoing verb is `verify`: run it after setup, after a reboot, and after any Tor/kernel/nftables change. anonctl is not a one-shot tool; it is a persistent-policy manager you re-verify.

## User Stories

1. As an operator, I want a one-line `anonctl add` that provisions the `anon` account AND installs per-UID kernel egress-forcing, so that logging into that account is anonymized with zero per-app config.
2. As an operator, I want `anonctl add <name>` to provision a named `anon-<name>` account the same way, so that I can run several independently-anonymized accounts.
3. As an operator, I want a bare account name to mean the default `anon` account across every verb (`add`, `verify`, `rm`, `update`), so that the common case is terminationless, mirroring netcage/anon-pi vocabulary.
4. As an operator, I want the default endpoint to be a local Tor SOCKS port (no proxy of my own to stand up), so that `anonctl add` gives me anonymized egress out of the box.
5. As an operator, I want to point an account at ANY existing socks5h endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`, wireproxy-chained-with-gost), so that I can anonymize through an anonymizer I already run, via the same transparent shim.
6. As an operator, I want anonctl to scan for locally-available socks5h endpoints and offer them (like netcage's detect-proxy), so that I do not have to hand-type an endpoint I already run.
7. As a security-conscious user on a shared host, I want a shared Tor daemon to be safe across multiple anon accounts because anonctl dials it with a per-account `<account>@` SOCKS username (Tor `IsolateSOCKSAuth` gives a separate circuit and exit per account), so that two anonymized accounts on one Tor are NOT cross-identifiable.
8. As a security-conscious user, I want a plain socks endpoint (no per-username isolation) to be treated as a single identity that AT MOST ONE account may use, and anonctl to refuse/flag sharing it across accounts, so that I cannot accidentally make two accounts exit identically and become cross-identifiable.
9. As a security-conscious user, I want the UID's default egress policy to be DROP (fail-closed), so that if the endpoint is unreachable my traffic is dropped, never sent in the clear.
10. As a security-conscious user, I want DNS from the account resolved remotely over the endpoint (DNS-over-SOCKS-TCP, socks5h), never a plaintext query, so that I do not leak via DNS.
11. As a security-conscious user, I want IPv6 handled explicitly (forced or dropped, never a v6 bypass of v4 rules), so that dual-stack does not silently leak.
12. As a security-conscious user, I want each account's shim to run under its OWN dedicated shim UID and listen on a per-account loopback port, so that account A's forced traffic can never ride account B's shim/circuit (structural per-account isolation).
13. As a security-conscious user, I want the anon UID to be able to reach ONLY its own shim's loopback port (all other `127.0.0.0/8` / `::1` destinations dropped for that UID), so that a process in the account cannot pivot to another local service or bypass the shim.
14. As a security-conscious user, I want ONLY the shim UID (never the anon UID) to be able to reach the upstream socks endpoint, so that a process in the account cannot dial the endpoint directly and thereby skip the shim or the `<account>@` isolation username.
15. As an operator, I want `anonctl verify [<name>]` to PROVE anonymization: the exit IP differs from the host's and, for a Tor endpoint, is a Tor exit (checked against check.torproject.org), so that I trust the setup rather than assume it.
16. As an operator, I want `verify` to prove DNS resolves via the anonymizer (remotely, not locally), so that the DNS-leak failure mode is actually tested, not assumed.
17. As an operator, I want `verify` to run a LEAK TEST that a direct (non-anonymized) connection from the UID is actually DROPPED, so that fail-closed is demonstrated, not just configured.
18. As an operator, I want `verify` to emit named assertions, exit non-zero on any failure, and support `--json`, so that I can gate CI / automation on it, mirroring netcage's `verify`.
19. As an operator, I want to re-run `verify` after a reboot and after any Tor/kernel/nftables change, so that I catch a setup that silently stopped forcing.
20. As an operator, I want `anonctl list` / `anonctl status` to show which accounts exist, their endpoint share-class (`tor-shared` / `socks-peruser`), and their current forced/verified state (with `--json`), so that I can see the fleet at a glance.
21. As an operator, I want `anonctl update`/`reconfigure <name>` to change an account's endpoint and re-apply the rules fail-closed, so that there is never a window of un-anonymized egress during a reconfigure.
22. As an operator, I want `anonctl rm [<name>]` to remove the forcing (and optionally the account), so that I can cleanly tear an account down.
23. As an operator with a local model, I want a narrow LAN exemption for a configured RFC1918 `host:port` (e.g. `192.168.1.150:8080`), scoped to the exact host and port, so that the anon account can reach a trusted local LLM directly while ALL other egress stays forced fail-closed.
24. As a security-conscious user, I want the LAN exemption to reject public IPs / hostnames / broad ranges loudly (private-only, like netcage's `--allow-direct`), so that I cannot accidentally punch an anonymity leak.
25. As a security-conscious user, I want `verify` to prove the split-tunnel stays tight WITH a LAN exemption active (the exempted host:port reachable directly, but the rest of that LAN /24, other loopback, and everything else still redirected-or-dropped), so that the exemption cannot silently widen into a leak.
26. As an operator, I want the setup to persist across reboots (an anonctl-owned nftables ruleset loaded via `nftables.service`, plus a per-account `anonctl-shim@<account>.service` systemd unit), so that the account stays anonymized without me re-running setup, and re-applies fail-closed at boot (no un-anonymized window).
27. As a security-conscious user, I want the boot invariant "at no point during boot does the anon UID have direct egress" to hold (the nft default-DROP loads early, so the worst case is dropped-until-shim-and-endpoint-are-up, never leaking-until-forcing-is-applied), so that a reboot cannot open a leak window.
28. As a sibling tool (anon-pi / netcage), I want to read a marker at `/etc/anonctl/<account>.json` to detect "this account is already kernel-anonymized", so that I skip re-forcing a proxy and avoid Tor-over-Tor / double-anonymization.
29. As an operator, I want the Tor-over-Tor caveat documented and detectable, so that I do not unknowingly stack two anonymizers (which degrades anonymity and breaks connectivity).
30. As a user weighing trust, I want an HONEST threat model documented (as honest as netcage's docs): what per-UID kernel forcing DEFENDS against (an app choosing a wrong/no proxy, a DNS leak, an anonymizer-down leak, and cross-identification of two accounts on a shared endpoint) and what it does NOT (root on the box, a process changing its own UID away from the forced one, kernel compromise), so that I understand the residual risk rather than over-trust the tool.
31. As the maintainer, I want the FIRST deliverable to be a MANUAL per-UID recipe (an nftables `skuid` redirect into a shim pointed at a local Tor SOCKS port) I run by hand on one account to validate the model, so that the kernel/nftables/shim approach is proven correct BEFORE any Go code is written.
32. As an operator, I want anonctl to APPLY the rules itself when run as root (the ufw stance), so that a tool whose entire purpose is root-level egress policy does not offload its core job onto me as copy-paste commands.

### Autonomy notes (the two gate axes, set the frontmatter flags accordingly)

- **`humanOnly` (DECIDED):** NOT set on this spec. A human is expected to review before tasking regardless (the spec lands unstaged), but nothing here requires a human to DRIVE the tasking once the open questions are resolved. The individual tasks are strongly security- and root-sensitive (they install kernel firewall rules that, if wrong, silently leak a real IP or lock a user out of the network); the maintainer drives the build one task at a time, so no per-task gate was needed beyond the repo's `autoBuild: false`.
- **`needsAnswers` (DISCOVERED): NOT set (cleared after grilling).** The six original open questions were resolved in a grilling pass and folded into the tasks. The manual-recipe task still exists to VALIDATE the resolved nft/shim recipe empirically before Go code, but it is a validation step, not an unresolved fork.

> Tasked. The Implementation and Testing detail that used to live here has moved into `work/tasks/` (what to build) and will be recorded, where it is durable rationale, in `docs/adr/` (why). This spec has settled to its durable framing below. The ~8 decisions the grilling produced (applies-as-root divergence from anon-pi; uniform socks5h-forcing that collapsed the two-backend split; endpoint share-class + `<account>@` isolation; own-static-Go-shim one-per-account; the `inet` fail-closed ruleset + two bypass closures; the LAN-exemption simpler-mechanism note; the marker schema/precedence/trust contract; the persistence mechanism + boot invariant) are each flagged in their tasks as an ADR to write with a real why.

## Out of Scope

- **netcage / anon-pi running INSIDE an anonctl account.** Compatibility of the per-jail model nested inside a per-UID-forced account is a LATER concern, explicitly out of scope for v1 (primary use case A is using the anonymized account directly (a shell, tools) with anon-pi/netcage NOT required inside it).
- **Renaming anon-pi's hardened accounts** to `anon-pi` / `anon-pi-<name>`. Tracked in anon-pi's own repo; anonctl's only interest is the marker contract.
- **Non-Linux platforms.** anonctl is Linux-only (the kernel primitives, per-UID nftables `skuid` matching and `SO_ORIGINAL_DST` transparent redirect, do not transfer).
- **Managing the endpoint's lifecycle.** anonctl assumes the socks5h endpoint exists; it does not install/start/stop Tor or a per-user wireproxy (it may scan for and suggest one). Enabling the endpoint at boot is the operator's job (documented).
- **Defending against root / a process changing its own UID / kernel compromise.** Documented in the threat model as explicitly NOT defended (per-UID forcing binds to the UID; root can undo it, and a process that leaves the forced UID leaves the policy). Being honest about this is in scope; defending against it is not.
- **A GUI / daemon.** anonctl is a CLI manager (ufw-like); no long-running anonctl daemon (the persistence is the OS's nftables + the per-account shim units + the endpoint, not an anonctl supervisor process). The per-account `anonctl-shim@<account>.service` is a systemd-supervised shim, not an anonctl control daemon.

## Further Notes

- **First milestone is deliberately code-free.** The first task is a MANUAL per-UID recipe run by hand on one account to validate the model BEFORE any Go code; it produces the reference the Go tasks encode. Every other task `blockedBy` it.
- **Honesty bar: match netcage's docs.** The threat-model doc must be as candid as netcage's "What netcage hides and what it does NOT" about the residual (root, UID-change, kernel) and about the cross-identification boundary (share-safe only via `<account>@` on a `tor-shared` endpoint; a shared `socks-peruser` endpoint would cross-identify).
- **Tor-over-Tor caveat** must be both documented AND detectable (via the marker), so anon-pi/netcage can programmatically skip re-forcing.
- **Grilling provenance.** This launch snapshot was pressure-tested in a grilling pass immediately after its first draft; the six original open questions were resolved there. It was then reviewed (verdict: approve) and tasked into `work/tasks/`.
