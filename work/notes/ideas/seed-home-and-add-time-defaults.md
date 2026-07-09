---
kind: idea
title: Seed an anon account's home from a template + box-wide add-time defaults (default home dir, default LAN exemptions)
slug: seed-home-and-add-time-defaults
status: proposed
---

## The idea

Today a fresh anon account is provisioned with an almost-empty home: `useradd --create-home` copies `/etc/skel`, then anonctl writes its minimal-PATH `.profile` (the CLOSE-AT-ADD hardening). There is no way to have anonctl populate the home with operator-chosen content (dotfiles, a tool config), and no way to have a bare `anonctl add <name>` carry a standing LAN exemption. This idea adds two generic, composable primitives so a one-shot `sudo anonctl add <name>` can land a ready-to-use, correctly-exempted account.

Two independent pieces (they compose but are separately useful):

1. **`seed-home` verb.** `anonctl seed-home [--from <dir>] [--force] [<name>]`, targeting an EXISTING account, copies a template directory's contents into the account's home. No `--from` reads the directory-exists default `/etc/anonctl/default-home/`. Per-file collision is an ERROR unless `--force` (import beats an existing file only when explicitly forced). Every copied file is chowned to the account and has its setuid/setgid bits STRIPPED on copy (a template must never introduce a setuid binary — that is the README threat model's sharpest residual, the uid-transition escape). This is where `--force` lives; it is NOT on `add`.

2. **Add-time defaults, read from the config folder.**
   - **Default home is a directory-exists convention.** On FRESH creation only, if `/etc/anonctl/default-home/` exists, `add` seeds from it (never overwriting, no `--force` on `add`); absent, no seeding. No `homeTemplate` config key — the directory's presence IS the switch. Populated by plain `sudo cp -r <src>/. /etc/anonctl/default-home/` (no helper verb in v1).
   - **Default LAN exemptions live in `/etc/anonctl/defaults.json`** (root-owned), e.g. `{ "allowDirect": ["192.168.1.50:11434"] }`. When `add` is given no `--allow-direct`, it applies these. CLI overrides file. A default exemption STILL goes through `lanexempt.Parse` (public / hostname / `:53` rejected loudly) — a default must never be a quieter path to a leak than the flag.

Net effect for the motivating use case (pi + a LAN model): populate `/etc/anonctl/default-home/` once, put the AI machine's `ip:port` in `defaults.json` once, then `sudo anonctl add work` yields a seeded, LAN-exempted account with zero flags.

## Scope boundary: anonctl stays generic (the pi model-derivation does NOT belong here)

anonctl seeds ARBITRARY home content and punches a LAN hole. It must have NO knowledge of pi, a model provider, or a `models.json`. The "smart" step — given the LAN exemption, find the host `~/.pi/agent/models.json` provider whose `baseUrl` matches that endpoint and generate a scoped `models.json` seed reading ONLY that provider (never leaking other keys) — ALREADY EXISTS in anon-pi (`pickLocalProviderModels` + the seed logic in `packages/anon-pi/src/cli.ts`). The right division of labour:

- **anonctl** provides the generic primitives above.
- **anon-pi** (or a thin separate CLI) owns the pi-specific seed by pointing its EXISTING, tested derivation logic at an anonctl-managed account's home (a mode where anon-pi seeds into an arbitrary directory rather than only its own `anonpi` tree). No provider logic leaks into anonctl.

This idea is therefore ONLY the anonctl half. The anon-pi "seed into an external home" mode is a separate item in that repo.

## Design details to pin before tasking

- **`add` stays create-only.** It already no-ops on an existing account. Seeding happens ONLY on fresh creation and never overwrites, so re-running `add` is still boring/idempotent. All override behaviour is on `seed-home --force`.
- **Ordering vs anonctl's `.profile`.** `ensureLoginAccount` does `useradd --create-home` (skel) then `WriteLoginEnv` (the minimal-PATH `.profile`). The seed must slot so anonctl's security-relevant `.profile` ALWAYS wins even if the template ships its own — seed BEFORE the PATH pin, or never let a template `.profile` clobber the pin silently. Decide and test this precedence explicitly.
- **Collision granularity is per-file** (like `cp -n`): error on the first pre-existing target, list all collisions, `--force` overwrites. A whole-tree "non-empty" check fights the skel files `useradd` already dropped.
- **Setuid/setgid strip on copy** is a hard rule with its own test — it touches the threat model.
- **Seam discipline.** Add a `SeedHome` package var seam beside `WriteLoginEnv` so unit tests capture WHAT WOULD be copied without touching a real home; the real recursive copy runs only under integration. Mirrors the existing test discipline (and the task-template SHARED/GLOBAL-location isolation criterion applies: `/etc/anonctl/...` must be redirected to a scratch dir in tests, real path asserted untouched).
- **Runs as root.** `add`/`seed-home` self-elevate (see `elevate.go`), so the config folder is read as root — which is exactly why the default home is a root-owned `/etc/anonctl/` convention, not a `~/.anonctl` under an ambiguous `$SUDO_USER` home.

## Open decisions (why this is an idea, not yet a task)

1. **`defaults.json` is a NEW concept (box-wide add-time defaults).** This repo names concepts deliberately (CONTEXT.md glossary) and records load-bearing choices as ADRs. A file that changes what `add` reads from disk, and can apply a network exemption without a CLI flag, likely wants: a glossary term, and an ADR (its precedence over the CLI, and the "a default exemption is still Parse-gated, never a quieter leak" invariant). Confirm the ADR before building.
2. **Does `seed-home` require the account to be forced already, or just to exist?** It writes into a home; it does not touch egress. Probably just "exists", but decide the refusal shape (a `seed-home` on a non-existent account should fail loud, not silently create one).
3. **README threat-model note.** The setuid-strip rule and the "a default exemption is Parse-gated" invariant are worth a short line in the guarantees/threat-model section, since both touch documented residuals.

## Relationship to the shipped model

Purely additive convenience over the existing account lifecycle: it does NOT change the forcing, the baseline default-deny, or the marker/verify trust anchor. The LAN-exemption default reuses the already-shipped `lanexempt` + account-config plumbing (exemptions already persist to `/etc/anonctl/accounts/<account>.json` and re-apply via `update`); this only adds the "apply a configured default when no flag is given" path in front of it. The home seed is new I/O but confined to the account's own home and the root-owned `/etc/anonctl/` config folder.
