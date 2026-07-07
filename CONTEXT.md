# CONTEXT: anonctl domain language

The domain glossary for `anonctl`. Agents and skills use THIS vocabulary when naming modules, tests, and discussing the system. Architectural rationale lives in `docs/adr/` (decisions); product framing lives in `work/prds/`.

## What anonctl is

anonctl is a Linux-only setup-and-verify manager that provisions a dedicated Unix user and forces all of that user's egress through an anonymizer (Tor or any socks5h endpoint) at the kernel level, fail-closed and default-DROP, then verifies it is leak-free. It applies the rules itself as root (like ufw/firewalld), and exposes a marker (`/etc/anonctl/<account>.json`) that sibling tools read to avoid double-anonymization.

anonctl is a SETUP + VERIFY MANAGER, not a runtime wrapper: it is NOT in the data path. The kernel nftables rules plus the Tor/redsocks config ARE the data path; anonctl installs, verifies, and manages them. Day-to-day the user logs into the account natively (`sudo -iu <account>` / `su - <account>`) and the kernel does the anonymizing; anonctl is out of the loop at runtime.

## Core domain terms

- **anon account / `anon-<name>`**: the dedicated Unix user whose egress anonctl forces. `anon` is the default account; `anon-<name>` are named ones. anonctl OWNS this generic "anonymized account" naming (distinct from anon-pi's `anon-pi` / `anon-pi-<name>` hardened accounts).
- **per-UID kernel forcing**: the mechanism: nftables `meta skuid` rules keyed on the account's UID that transparently redirect the UID's TCP into a per-account shim (or drop it), so anything the user runs is anonymized with no per-app proxy config. UNIFORM: there is one forcing mechanism, not a per-backend split.
- **shim**: anonctl's own static Go binary, one instance per account, on a per-account loopback port: a transparent TCP-to-SOCKS relay (reads the original destination via `SO_ORIGINAL_DST`) plus a DNS-over-SOCKS-TCP forwarder (reused from netcage's `netcage-dns`). It relays the forced traffic to the account's socks5h endpoint. Not a distro `redsocks` dependency (leak-proof invariant stays in our code). Runs under a distinct dedicated shim UID so only it (never the anon UID) can reach the upstream endpoint.
- **endpoint**: the socks5h proxy an account is forced through. anonctl does NOT manage its lifecycle (it can scan for and suggest one, netcage-style). Tor's SOCKS port is the default endpoint; a plain socks endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`, wireproxy-chained-with-gost) is another.
- **endpoint share-class**: the axis that matters: `tor-shared` (per-username SOCKS-auth isolation available) vs `socks-peruser` (single identity). A `tor-shared` endpoint is safe across many accounts because anonctl dials it with a per-account `<account>@` SOCKS username (Tor `IsolateSOCKSAuth` gives a distinct circuit/exit per account). A `socks-peruser` endpoint is one identity and may be used by AT MOST ONE account (else the accounts are cross-identifiable); anonctl refuses/flags sharing it.
- **fail-closed / default-DROP**: if the endpoint is unreachable, the UID's traffic is dropped, never sent in the clear. The default policy for the UID is DROP; the anon UID may reach ONLY its own shim's loopback port, nothing else.
- **leak-free**: DNS goes via the anonymizer (never plaintext); IPv4 AND IPv6 are both handled (no v6 bypass).
- **verify**: the trust anchor and the signature ONGOING verb (run after setup, after reboot, after a Tor/kernel/nftables change). It asserts the account is anonymized (exit differs from host; a Tor exit for a Tor endpoint), DNS is resolved remotely via the endpoint, a direct connection from the UID is actually DROPPED (the leak test), the split-tunnel stays tight with a LAN exemption active, and the boot invariant holds. Named assertions, non-zero exit on failure, `--json` for machines. Mirrors netcage's `verify`.
- **marker**: `/etc/anonctl/<account>.json`, versioned JSON (`schemaVersion`, `account`, `uid`, `endpointClass`, `createdAt`, `anonctlVersion`; deliberately NO endpoint URL/creds since it is world-readable). The dependency-free contract anon-pi / netcage read to detect "this account is already kernel-anonymized" and skip re-forcing (the double-anonymization guard). Written only after `verify` passes; a coordination claim, not a live security proof. The name prefix is a hint only; `anonctl status --json` reads the same truth.
- **LAN exemption**: a narrow, guardrailed hole (like netcage's `--allow-direct`) exempting a configured RFC1918 `host:port` (e.g. a local LLM at `192.168.x.x`) from forcing, scoped to the exact host and port, not a broad allow.
- **Tor-over-Tor / double-anonymization**: running an already-anonymized account through a second anonymizer. anonctl makes this DETECTABLE (via the marker/verify) and documents the caveat so it is avoided.
- **reboot persistence**: the forcing survives a reboot via two anonctl-owned, anonctl-applied artifacts (the ufw stance): the per-account shim as a systemd `@`-template unit (`anonctl-shim@<account>.service`, one instance per account under its dedicated shim UID; `add` `enable --now`s it, `rm` `disable --now`s it), and the ruleset persisted via an `nftables.service` DROP-IN (`/etc/systemd/system/nftables.service.d/anonctl.conf`) that loads anonctl's per-account rule files at boot WITHOUT editing the host's `/etc/nftables.conf`. anonctl does NOT own the endpoint's boot lifecycle (enable your endpoint, e.g. `tor.service`, yourself).
- **boot invariant**: the load-bearing property "at no point during boot does the anon UID have direct egress". It holds because the nft default-DROP is part of the persisted ruleset and loads early, so the worst case is dropped-until-shim-and-endpoint-are-up, never leaking. Asserted by `verify` and by a reboot-equivalent early-boot integration test.
- **account config**: anonctl's OWN per-account at-rest operational record (`/etc/anonctl/accounts/<account>.json`, root-only 0600) holding the endpoint + share-class, the shim loopback ports, and the UIDs. It is the source of truth the boot re-apply and `update`/`reconfigure` read. DISTINCT from the world-readable, credential-free marker: the config is anonctl-private and may carry the endpoint address the marker must never hold.
- **update / reconfigure**: the verb that changes an account's endpoint (`--endpoint`) and re-applies the rules FAIL-CLOSED, re-applying the nft rules (an atomic table replace: the default-DROP is never absent) BEFORE restarting the shim, so there is never a window of un-anonymized egress during a reconfigure.
- **promptGuidance**: the per-repo NUDGE namespace in `.dorfl.json` whose members (currently just `testFirst`) strengthen the wording in the worker's in-band prompt. NOT a gate: the `verify` step is still the only acceptance bar. Omitted means off; absence is the default.
- **work/ contract**: the on-disk system this repo uses, defined by the reference docs in **`work/protocol/`** (copied here by `setup`): `WORK-CONTRACT.md` (the contract), `CLAIM-PROTOCOL.md`, `REVIEW-PROTOCOL.md`, `task-template.md`, `prd-template.md`, `ADR-FORMAT.md`. Three REGIME umbrellas (`notes/` capture buckets, `tasks/` the build board, `prds/` the prd lifecycle) plus top-level `questions/` and `protocol/`. One markdown file per item, status = the folder it lives in (never a field). Capture buckets: `notes/ideas/` (proposed), `notes/observations/` (spotted, unverified, append-only), `notes/findings/` (verified external/domain ground truth, each with a `source:`). ADRs (`docs/adr/`, format in `work/protocol/ADR-FORMAT.md`) record what WE decided and why.

## Sibling tools (context, not dependencies)

- **netcage** (Go): a Linux network-jail that runs a container in a netns and forces ALL its egress through a configurable socks5h proxy (fail-closed, per-CONTAINER). anonctl reuses netcage's findings/idioms where they transfer (fail-closed language, `verify` assertions, the narrow LAN hole).
- **anon-pi** (TypeScript/npm): launches the pi coding agent inside a netcage jail; its hardened mode provisions a dedicated `anon-pi` Unix account. anonctl is a DIFFERENT model: per-UID kernel forcing for a whole account, not a per-container jail. netcage/anon-pi compatibility inside an anonctl account is a LATER concern, out of scope for v1.

## Conventions

Standing per-change rules agents must follow in this repo.

<!-- e.g. "Every change requires a changeset (`pnpm changeset`)" / a CHANGELOG fragment / a news entry. Add yours here, or delete this section. For enforcement, wire your own check into the `.dorfl.json` `verify` gate. -->

## Skills this repo uses

- Required: `setup` (onboarding/migration), `to-prd`, `to-task`.
- Recommended: `review`, `grill-me`.
