# CONTEXT — anonctl domain language

The domain glossary for `anonctl`. Agents and skills use THIS vocabulary when naming modules, tests, and discussing the system. Architectural rationale lives in `docs/adr/` (decisions); product framing lives in `work/prds/`.

## What anonctl is

anonctl is a Linux-only setup-and-verify manager that provisions a dedicated Unix user and forces all of that user's egress through an anonymizer (Tor or any socks5h endpoint) at the kernel level, fail-closed and default-DROP, then verifies it is leak-free. It applies the rules itself as root (like ufw/firewalld), and exposes a marker (`/etc/anonctl/<account>.json`) that sibling tools read to avoid double-anonymization.

anonctl is a SETUP + VERIFY MANAGER, not a runtime wrapper: it is NOT in the data path. The kernel nftables rules plus the Tor/redsocks config ARE the data path; anonctl installs, verifies, and manages them. Day-to-day the user logs into the account natively (`sudo -iu <account>` / `su - <account>`) and the kernel does the anonymizing; anonctl is out of the loop at runtime.

## Core domain terms

- **anon account / `anon-<name>`** — the dedicated Unix user whose egress anonctl forces. `anon` is the default account; `anon-<name>` are named ones. anonctl OWNS this generic "anonymized account" naming (distinct from anon-pi's `anon-pi` / `anon-pi-<name>` hardened accounts).
- **per-UID kernel forcing** — the mechanism: nftables rules keyed on the account's UID that transparently redirect (or drop) all egress at the kernel level, so anything the user runs is anonymized with no per-app proxy config.
- **tor backend** — kernel redirect of the UID's TCP to Tor's TransPort and DNS to Tor's DNSPort (the easy default).
- **socks backend** — forcing the UID through ANY socks5h endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`) via a transparent TCP-to-SOCKS shim (redsocks-style), since raw SOCKS is not transparent. The two backends are mutually exclusive as the egress mechanism for a given account.
- **fail-closed / default-DROP** — if the anonymizer is unreachable, the UID's traffic is dropped, never sent in the clear. The default policy for the UID is DROP; only anonymized paths are permitted.
- **leak-free** — DNS goes via the anonymizer (never plaintext); IPv4 AND IPv6 are both handled (no v6 bypass).
- **verify** — the trust anchor and the signature ONGOING verb (run after setup, after reboot, after a Tor/kernel/nftables change). It asserts the account is anonymized (Tor exit / SOCKS exit differs from host), DNS is via the anonymizer, and a direct connection from the UID is actually DROPPED (the leak test). Named assertions, non-zero exit on failure, `--json` for machines. Mirrors netcage's `verify`.
- **marker** — `/etc/anonctl/<account>.json`, the contract anonctl exposes so anon-pi / netcage can detect "this account is already kernel-anonymized" and skip re-forcing a proxy (the double-anonymization guard).
- **LAN exemption** — a narrow, guardrailed hole (like netcage's `--allow-direct`) exempting a configured RFC1918 `host:port` (e.g. a local LLM at `192.168.x.x`) from forcing, scoped to the exact host and port, not a broad allow.
- **Tor-over-Tor / double-anonymization** — running an already-anonymized account through a second anonymizer. anonctl makes this DETECTABLE (via the marker/verify) and documents the caveat so it is avoided.
- **promptGuidance** — the per-repo NUDGE namespace in `.dorfl.json` whose members (currently just `testFirst`) strengthen the wording in the worker's in-band prompt. NOT a gate: the `verify` step is still the only acceptance bar. Omitted ⇒ off; absence is the default.
- **work/ contract** — the on-disk system this repo uses, defined by the reference docs in **`work/protocol/`** (copied here by `setup`): `WORK-CONTRACT.md` (the contract), `CLAIM-PROTOCOL.md`, `REVIEW-PROTOCOL.md`, `task-template.md`, `prd-template.md`, `ADR-FORMAT.md`. Three REGIME umbrellas — `notes/` (capture buckets), `tasks/` (the build board), `prds/` (the prd lifecycle) — plus top-level `questions/` and `protocol/`. One markdown file per item, status = the folder it lives in (never a field). Capture buckets: `notes/ideas/` (proposed), `notes/observations/` (spotted, unverified, append-only), `notes/findings/` (verified external/domain ground truth, each with a `source:`). ADRs (`docs/adr/`, format in `work/protocol/ADR-FORMAT.md`) record what WE decided and why.

## Sibling tools (context, not dependencies)

- **netcage** (Go) — a Linux network-jail that runs a container in a netns and forces ALL its egress through a configurable socks5h proxy (fail-closed, per-CONTAINER). anonctl reuses netcage's findings/idioms where they transfer (fail-closed language, `verify` assertions, the narrow LAN hole).
- **anon-pi** (TypeScript/npm) — launches the pi coding agent inside a netcage jail; its hardened mode provisions a dedicated `anon-pi` Unix account. anonctl is a DIFFERENT model: per-UID kernel forcing for a whole account, not a per-container jail. netcage/anon-pi compatibility inside an anonctl account is a LATER concern, out of scope for v1.

## Conventions

Standing per-change rules agents must follow in this repo.

<!-- e.g. "Every change requires a changeset (`pnpm changeset`)" / a CHANGELOG fragment / a news entry. Add yours here, or delete this section. For enforcement, wire your own check into the `.dorfl.json` `verify` gate. -->

## Skills this repo uses

- Required: `setup` (onboarding/migration), `to-prd`, `to-task`.
- Recommended: `review`, `grill-me`.
