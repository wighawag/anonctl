# Seed an account's home from a template, and box-wide add-time defaults

## Context

A fresh anon account lands with a near-empty home (skel + anonctl's minimal-PATH `.profile`), and a bare `anonctl add <name>` cannot carry any standing configuration: to get a usable account an operator had to re-type `--allow` (and hand-populate the home) every time. The motivating case is running a coding agent inside the account against a local model on the LAN, which needs both a seeded tool config AND the model host exempted.

## Decision

anonctl gains a generic `seed-home` verb and two box-wide, add-time defaults, all under the existing root-owned config root `/etc/anonctl/`:

1. **`seed-home [--from <dir>] [--force] [<name>]`** copies a template directory's contents into an EXISTING account's home. Per-file collision is a loud error unless `--force`. Every copied file is chowned to the account and has its **setuid/setgid/sticky bits stripped** on copy (a template must never introduce a setuid binary: that is exactly the uid-transition escape ADR-0002 / the README threat model call out as the sharpest residual, so the seed engine closes it at copy time rather than trusting the template). Symlinks in a template are refused (they could point a seeded file at another uid's target or escape the home).

2. **The default home is a directory-exists CONVENTION, not a config key.** If `/etc/anonctl/default-home/` exists, `add` seeds a FRESH account's home from it (never overwriting: `add` stays create-only and has no `--force`; re-adding never re-seeds, mirroring the login-env write). Its presence IS the switch. Populate it with a plain `sudo cp -r <src>/. /etc/anonctl/default-home/`; there is deliberately no helper verb.

3. **Default LAN exemptions live in `/etc/anonctl/defaults.json`** (`{"allow": [...]}`, root-owned). `add` applies them when given no `--allow`. A CLI flag OVERRIDES the file (CLI beats config). A default exemption is re-validated through the SAME `lanexempt.Parse` guardrail the CLI flag uses, so a public / hostname / `:53` / port-omitted default is rejected loudly (a port is mandatory, ADR-0007): a default is NEVER a quieter path to a leak than the flag. (The flag was `--allow-direct` and the key `allowDirect` before ADR-0007's clean-break rename.)

`--force` lives ONLY on `seed-home`, never on `add`. All the seed/defaults filesystem seams sit behind a configurable `BaseDir` (mirroring `marker.Store` / `accountconfig.Store`) so tests isolate the shared `/etc` read/write and assert the real path is untouched.

## Boundary (the explicit no)

anonctl stays GENERIC: it seeds arbitrary files and punches a LAN hole, and knows nothing about pi, a model provider, or a `models.json`. The "smart" step (derive the model config from the exempted LAN endpoint) already exists in anon-pi (`pickLocalProviderModels`) and stays there; anon-pi can point its own seed logic at an anonctl-managed account's home. No provider logic enters anonctl.

## Consequences

- A configured default exemption reaches the kernel forcing rules on a bare `add`, so the defaults file is security-relevant surface; it is root-owned and Parse-gated for that reason. A corrupt `defaults.json` fails `add` loudly rather than silently dropping a configured hole.
- `add`'s output now reports seeded files; `seed-home` reports copied/overwritten files. Neither changes the marker/verify trust anchor: seeding is additive convenience over the account lifecycle and does not touch the forcing, the baseline default-deny, or verify.
