---
title: Per-UID kernel-forced anonymized egress (anonctl v1)
slug: per-uid-kernel-anonymized-egress
needsAnswers: true
---

> Launch snapshot — records intent at creation, NOT maintained. Current truth: `docs/adr/` (decisions) + the code; remaining work: `work/tasks/ready/` tasks. (The technical-detail sections below are trimmed by `to-task` once the work is tasked — they move into tasks/ADRs and this prd settles to its durable framing: Problem / Solution / User Stories / Out of Scope.)

<!-- open-questions -->
<!--
  TRANSIENT BLOCK — stripped by the apply rung on full resolution.
  While the spec has unresolved questions blocking autonomous tasking:
    1. Set `needsAnswers: true` in the frontmatter above.
    2. List the questions under the `## Open questions` heading below.
    3. Clear the flag (and let apply strip this block) once they are answered.
  Delete the whole fenced block — markers and all — if the prd launches fully resolved.
-->

## Open questions

These are deferred by design (from-idea does not force-resolve genuine forks). Resolve before the Go tool is tasked; the first task (the manual recipe) is buildable regardless and is where several of these get their empirical answer.

1. **Exact nftables strategy for per-UID redirect.** Whonix's published rules are the reference, but Whonix runs on a Gateway VM where the whole box is the Tor client, not on a shared multi-user host redirecting a single UID. The concrete v1 recipe must settle: `nft` `meta skuid` matching for OUTPUT redirection, the interaction with `iptables`-vs-`nftables` on the target distro, and whether a `REDIRECT`/`DNAT`-to-TransPort in the `nat` table plus a fail-closed `filter` default-DROP for the UID composes cleanly for BOTH IPv4 and IPv6. The manual recipe task exists to answer this empirically before any Go code.
2. **Loopback / local-proxy bypass vector.** The forcing must not let the anon UID reach the Tor/redsocks listener's own `127.0.0.1:port` in a way that bypasses the redirect, nor reach OTHER local services to pivot. What loopback traffic is permitted for the UID (only the redirect targets?), and how is the Tor daemon's own UID exempted without opening a hole the anon UID can ride? Whonix's rules address this; confirm the per-UID-on-shared-host analogue.
3. **socks backend shim: bundle vs depend.** The transparent TCP-to-SOCKS shim is redsocks-style. Does v1 depend on the distro `redsocks` package, vendor/ship its own shim, or reuse a netcage component? (netcage ships a `netcage-dns` helper and forces via the network layer; some of that may transfer.) Affects install/persistence and the fail-closed guarantee's surface.
4. **DNS for the socks backend.** For `tor` DNS is Tor's DNSPort. For `socks`, DNS must be remote (socks5h / through the shim) with no plaintext leak. Is UDP DNS from the UID redirected into a DNS-over-the-shim path, hard-dropped in favour of a forced resolver, or handled by a local forwarder? Must be leak-proof and cover IPv6.
5. **Persistence mechanism across reboots.** nftables rules, the redsocks/shim process, and any torrc drop-ins must survive reboot. Which of: an nftables systemd service / `nftables.service` include, a systemd unit for the shim, torrc `.d` drop-ins? Pick a coherent set per backend and confirm it re-applies fail-closed (never a window where the UID has un-anonymized egress at boot).
6. **Marker schema.** The marker is `/etc/anonctl/<account>.json` (decided). Its exact fields (backend, uid, created-at, anonctl version, a schema version so anon-pi/netcage can parse it stably) are an implementation decision to pin when the Go tool is tasked; the manual-recipe task may write a first cut by hand.

<!-- /open-questions -->

## Problem Statement

You want a whole Unix account to be anonymized: anything that user runs (a shell, arbitrary tools, an editor, a script) should have ALL of its network egress forced through an anonymizer, transparently, with no per-application proxy configuration and no way for a misconfigured or proxy-unaware app to leak your real IP or DNS. App-level `HTTP_PROXY`/`ALL_PROXY` is not enough: raw sockets and DNS ignore it and leak. Per-container jails (netcage) solve this per-container, but require you to run everything inside a jail; you instead want to just log into an account natively and have the kernel do the anonymizing.

The failure modes to defend against are concrete: an app choosing the wrong proxy (or none), a DNS query going out in plaintext, and the anonymizer being down while traffic quietly falls back to the direct route. The defense must be fail-closed (anonymizer down ⇒ traffic dropped, never sent in the clear) and leak-free (DNS via the anonymizer, IPv6 handled, not just IPv4).

There is no honest, scoped tool for this. Whonix/Tails do transparent Torification but at whole-machine / VM granularity; you want it scoped to ONE UID on a normal multi-user Linux host, configurable (not Tor-only), and with a `verify` that PROVES it rather than asks you to trust it.

## Solution

anonctl is a Linux-only setup-and-verify MANAGER (like ufw/firewalld, specialized to per-UID fail-closed anonymized egress). It is NOT a runtime wrapper and NOT in the data path: the kernel nftables rules plus the Tor/redsocks config ARE the data path; anonctl installs, verifies, and manages them. Day-to-day you `sudo -iu anon` / `su - anon` and the kernel anonymizes everything that account does; anonctl is out of the loop at runtime.

anonctl provisions a dedicated Unix account (`anon` by default, `anon-<name>` for named ones) and installs per-UID kernel egress-forcing with a fail-closed default-DROP for that UID. Two mutually-exclusive egress backends: `tor` (kernel redirect of the UID's TCP to Tor's TransPort and DNS to Tor's DNSPort; the easy default) and `socks` (force the UID through ANY socks5h endpoint via a transparent redsocks-style TCP-to-SOCKS shim, with DNS forced remote). Both are leak-free (DNS via the anonymizer, IPv6 handled) and fail-closed.

Because anonctl's whole job requires root, it APPLIES the rules itself when run as root (the ufw/firewalld stance), rather than printing commands to paste (the anon-pi stance) — this is the deliberate divergence from anon-pi, justified below. It persists the setup across reboots, exposes a marker at `/etc/anonctl/<account>.json` so sibling tools avoid double-anonymization, and ships a `verify` that proves the account is anonymized, DNS is via the anonymizer, and a direct connection from the UID is actually DROPPED.

The signature ongoing verb is `verify`: run it after setup, after a reboot, and after any Tor/kernel/nftables change. anonctl is not a one-shot tool; it is a persistent-policy manager you re-verify.

## User Stories

1. As an operator, I want a one-line `anonctl add` that provisions the `anon` account AND installs per-UID kernel egress-forcing, so that logging into that account is anonymized with zero per-app config.
2. As an operator, I want `anonctl add <name>` to provision a named `anon-<name>` account the same way, so that I can run several independently-anonymized accounts.
3. As an operator, I want a bare account name to mean the default `anon` account across every verb (`add`, `verify`, `rm`, `update`), so that the common case is terminationless, mirroring netcage/anon-pi vocabulary.
4. As an operator, I want to choose the `tor` backend (kernel redirect to Tor's TransPort/DNSPort) as the easy default, so that I get anonymized egress without standing up my own proxy.
5. As an operator, I want to choose the `socks` backend pointed at ANY socks5h endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`), so that I can anonymize through an anonymizer I already run, via a transparent TCP-to-SOCKS shim.
6. As a security-conscious user, I want the two backends to be mutually exclusive as the egress mechanism for a given account, so that there is exactly one well-defined forced path, never an ambiguous overlap.
7. As a security-conscious user, I want the UID's default egress policy to be DROP (fail-closed), so that if the anonymizer is unreachable my traffic is dropped, never sent in the clear.
8. As a security-conscious user, I want DNS from the account forced through the anonymizer (Tor DNSPort or socks5h remote DNS), never a plaintext query, so that I do not leak via DNS.
9. As a security-conscious user, I want IPv6 handled explicitly (forced or dropped, never a v6 bypass of v4 rules), so that dual-stack does not silently leak.
10. As an operator, I want `anonctl verify [<name>]` to PROVE anonymization: the exit IP is a Tor exit (checked against check.torproject.org) for `tor`, or the SOCKS exit differs from the host for `socks`, so that I trust the setup rather than assume it.
11. As an operator, I want `verify` to prove DNS resolves via the anonymizer, so that the DNS-leak failure mode is actually tested, not assumed.
12. As an operator, I want `verify` to run a LEAK TEST that a direct (non-anonymized) connection from the UID is actually DROPPED, so that fail-closed is demonstrated, not just configured.
13. As an operator, I want `verify` to emit named assertions, exit non-zero on any failure, and support `--json`, so that I can gate CI / automation on it, mirroring netcage's `verify`.
14. As an operator, I want to re-run `verify` after a reboot and after any Tor/kernel/nftables change, so that I catch a setup that silently stopped forcing.
15. As an operator, I want `anonctl list` / `anonctl status` to show which accounts exist, their backend, and their current forced/verified state (with `--json`), so that I can see the fleet at a glance.
16. As an operator, I want `anonctl update`/`reconfigure <name>` to change an account's backend or endpoint and re-apply the rules fail-closed, so that there is never a window of un-anonymized egress during a reconfigure.
17. As an operator, I want `anonctl rm [<name>]` to remove the forcing (and optionally the account), so that I can cleanly tear an account down.
18. As an operator with a local model, I want a narrow LAN exemption for a configured RFC1918 `host:port` (e.g. `192.168.1.150:8080`), scoped to the exact host and port, so that the anon account can reach a trusted local LLM directly while ALL other egress stays forced fail-closed.
19. As a security-conscious user, I want the LAN exemption to reject public IPs / hostnames / broad ranges loudly (private-only, like netcage's `--allow-direct`), so that I cannot accidentally punch an anonymity leak.
20. As an operator, I want the setup to persist across reboots (nftables service / systemd unit / torrc drop-ins), so that the account stays anonymized without me re-running setup, and re-applies fail-closed at boot (no un-anonymized window).
21. As a sibling tool (anon-pi / netcage), I want to read a marker at `/etc/anonctl/<account>.json` to detect "this account is already kernel-anonymized", so that I skip re-forcing a proxy and avoid Tor-over-Tor / double-anonymization.
22. As an operator, I want the Tor-over-Tor caveat documented and detectable, so that I do not unknowingly stack two anonymizers (which degrades anonymity and breaks connectivity).
23. As a user weighing trust, I want an HONEST threat model documented (as honest as netcage's docs): what per-UID kernel forcing DEFENDS against (an app choosing a wrong/no proxy, a DNS leak, an anonymizer-down leak) and what it does NOT (root on the box, a process changing its own UID away from the forced one, kernel compromise), so that I understand the residual risk rather than over-trust the tool.
24. As the maintainer, I want the FIRST deliverable to be a MANUAL per-UID Tor recipe (nftables + torrc) I run by hand on one account to validate the model, so that the kernel/nftables/Tor approach is proven correct BEFORE any Go code is written.
25. As an operator, I want anonctl to APPLY the rules itself when run as root (the ufw stance), so that a tool whose entire purpose is root-level egress policy does not offload its core job onto me as copy-paste commands.

### Autonomy notes (the two gate axes — set the frontmatter flags accordingly)

- **`humanOnly` (DECIDED):** NOT set on this prd. A human is expected to review before tasking regardless (the prd lands unstaged), but nothing here requires a human to DRIVE the tasking once the open questions are resolved. Note, though, that individual TASKS derived from this prd are strongly security- and root-sensitive (they install kernel firewall rules that, if wrong, silently leak a real IP or lock a user out of the network); the tasker should set task-level `humanOnly` on the rule-installing / verify-defining tasks per each task's own build-nature (the prd flag does NOT propagate). The manual-recipe task (story 24) is a human-run validation by construction.
- **`needsAnswers` (DISCOVERED): SET.** The `## Open questions` block above lists the genuine forks (nftables strategy, loopback bypass, socks shim sourcing, socks DNS, persistence mechanism, marker schema). The auto-tasker must refuse to task until these are resolved and the flag cleared. Several are answered empirically by the first (manual-recipe) task; that task itself is buildable now and does not depend on the others.

## Implementation Decisions

Decisions made at launch (settle the rest at tasking time):

- **Model.** Two anonymization models exist across the sibling tools and are mutually exclusive as EGRESS mechanisms for a given account: netcage/anon-pi = per-jail forced socks5h proxy; anonctl = per-UID kernel transparent forcing. anonctl is the per-UID-kernel one, for a WHOLE account, not a per-container jail.
- **Not in the data path.** anonctl is a setup + verify manager (ufw/firewalld-like). The nftables rules + Tor/redsocks config are the data path; anonctl installs/verifies/manages them and is out of the loop at runtime. Do not build a runtime wrapper.
- **Applies as root itself (divergence from anon-pi, justified).** anon-pi prints root commands and never sudo's, because its core job (launching an agent in a jail) does NOT inherently require root. anonctl's ENTIRE job is root-level egress policy, so print-only would offload its core function onto the user as copy-paste. Therefore anonctl, run as root, APPLIES the rules directly (the ufw stance). Record this divergence as an ADR (`docs/adr/`) with the rejected alternative (print-only) and the why.
- **Backends.** `tor` = kernel redirect of the UID to Tor TransPort + DNSPort (easy default). `socks` = force the UID through any socks5h endpoint via a transparent redsocks-style TCP-to-SOCKS shim (raw SOCKS is not transparent). Both fail-closed, leak-free (DNS via the anonymizer, never plaintext), IPv6 handled.
- **Account naming.** anonctl OWNS the generic `anon` / `anon-<name>` naming (the generic "anonymized account"). `anon` is the default; `anon-<name>` are named. (anon-pi's hardened accounts are separately renamed to `anon-pi` / `anon-pi-<name>` in anon-pi's own repo; not anonctl's concern beyond the marker contract.)
- **Command vocabulary** mirrors anon-pi/netcage: `add [<name>]`, `verify [<name>]`, `list` / `status`, `update`/`reconfigure`, `rm [<name>]`. Bare name = default `anon`.
- **fail-closed nftables ruleset (tor backend).** IPv4 AND IPv6; TCP redirected to TransPort; UDP DNS redirected to DNSPort; default-DROP for the UID; exempt the Tor daemon's own UID; close the loopback/local-proxy bypass vector. Reference Whonix's published rules (adapted from whole-box to per-UID-on-shared-host). Exact `nft` recipe settled by the manual-recipe task (story 24, open question 1/2).
- **socks backend.** Transparent TCP-to-SOCKS shim (redsocks-style); DNS forced through it (socks5h / remote DNS); same fail-closed default-DROP for the UID. Shim sourcing (distro package vs vendored vs netcage-reuse) is open question 3.
- **LAN exemption.** A narrow direct hole like netcage's `--allow-direct`: exempt a configured RFC1918 `host:port`, scoped to the exact host/port, private-only, public/hostname/broad rejected loudly.
- **verify** mirrors netcage: named assertions, non-zero exit, `--json`. For `tor`, prove the exit IP is a Tor exit (check.torproject.org). For `socks`, prove the SOCKS exit differs from the host. Prove DNS via the anonymizer. Run a leak test proving a direct connection from the UID is DROPPED.
- **Marker / double-anonymization contract.** `/etc/anonctl/<account>.json` is the marker sibling tools read to detect "already kernel-anonymized" and skip re-forcing. Schema fields are open question 6. anonctl also exposes `status --json` for the same purpose.
- **Persistence.** Across reboots via an nftables service / systemd unit / torrc drop-ins, re-applying fail-closed at boot. Exact set is open question 5.
- **Reuse from netcage.** netcage is Go and already deals with fail-closed forced egress, socks5h, the narrow LAN hole, and a `verify` leak-test with named assertions; reuse its findings/idioms where they transfer. anonctl is likewise Go.

## Testing Decisions

- **`verify` IS the primary test surface** (the trust anchor), exactly as in netcage: named assertions, non-zero exit, `--json`. Its three assertions (anonymized exit, DNS via anonymizer, direct connection DROPPED) are the behavioural contract. Test at that seam, not at nftables-rule-string internals (which will churn).
- **The leak test is the load-bearing assertion.** A test that a direct, non-anonymized connection from the UID is actually dropped is what proves fail-closed; prioritize it. It must cover IPv6 as well as IPv4, and must hold with a LAN exemption active (only the exempted host/port is reachable directly; everything else stays dropped) — mirror netcage's split-tunnel `verify` proof.
- **Integration tests need a real kernel + Tor / a SOCKS endpoint.** Like netcage (whose jail/verify integration tests sit behind an `integration` build tag because GitHub runners lack the primitives), anonctl's rule-installing / verify integration tests need root, nftables, and a live anonymizer; gate them behind an `integration` build tag and run them on a capable host. Unit tests (config parsing, RFC1918 guardrail on the LAN exemption, marker (de)serialization, argument/backend validation) run everywhere and are the CI default (`go test ./...`).
- **The manual-recipe task (story 24) is validated by a human running it**, not by an automated test; its output is a documented, working recipe that the later Go tasks encode and the `verify` assertions then lock in.

## Out of Scope

- **netcage / anon-pi running INSIDE an anonctl account.** Compatibility of the per-jail model nested inside a per-UID-forced account is a LATER concern, explicitly out of scope for v1 (primary use case A is using the anonymized account directly — a shell, tools — with anon-pi/netcage NOT required inside it).
- **Renaming anon-pi's hardened accounts** to `anon-pi` / `anon-pi-<name>`. Tracked in anon-pi's own repo; anonctl's only interest is the marker contract.
- **Non-Linux platforms.** anonctl is Linux-only (the kernel primitives — per-UID nftables, Tor Trans/DNSPort redirect — do not transfer).
- **Defending against root / a process changing its own UID / kernel compromise.** Documented in the threat model as explicitly NOT defended (per-UID forcing binds to the UID; root can undo it, and a process that leaves the forced UID leaves the policy). Being honest about this is in scope; defending against it is not.
- **A GUI / daemon.** anonctl is a CLI manager (ufw-like); no long-running anonctl daemon (the persistence is the OS's nftables/systemd/Tor, not an anonctl process).

## Further Notes

- **First milestone is deliberately code-free.** The first task must be the MANUAL per-UID Tor recipe (nftables + torrc) run by hand on one account to validate the model BEFORE any Go code. It de-risks open questions 1 and 2 empirically and produces the reference the Go implementation encodes.
- **Honesty bar: match netcage's docs.** netcage documents precisely what it hides and what it does not ("What netcage hides and what it does NOT"). anonctl's threat-model section must be equally candid about the residual (root, UID-change, kernel).
- **ADRs to expect** (write each with a real human-supplied why, per the ADR discipline): the applies-as-root-itself divergence from anon-pi; the tor-vs-socks backend split and their mutual exclusivity; the marker schema/location contract; the loopback-bypass closure; the persistence mechanism chosen; the LAN-exemption guardrail (private-only).
- **Tor-over-Tor caveat** must be both documented AND detectable (via the marker), so anon-pi/netcage can programmatically skip re-forcing.
