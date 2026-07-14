---
title: Thread LAN exemptions end-to-end (CLI flag -> persisted config -> verifyParams) so the exemption verify assertions fire live
slug: thread-lan-exemptions-end-to-end
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: [23, 25]
---

## What to build

Close the gap captured in `work/notes/observations/exempt-not-wired-into-verifyparams.md`: LAN exemptions are supported at the RULESET layer (`forcing.Install`/`Reconfigure` accept `[]lanexempt.Exempt`, `nftables.Generate` emits the accept), but they are UNREACHABLE end-to-end, so the two exemption `verify` assertions never fire in a live `anonctl verify`:

1. **No CLI flag.** `add`/`update` in `main.go` parse `--endpoint`/`--json`/`--purge-account` but NO exemption flag, so an operator cannot actually configure a LAN exemption.
2. **Not persisted.** `accountconfig.Config` has no `Exemptions` field, so a configured exemption would not survive to the next verb / reboot.
3. **Not read back by verify.** `verifyParams` (main.go ~L267) never sets `verify.LiveParams.Exempt`, so BOTH `split-tunnel-tight` AND `lan-exemption-not-a-dns-hole` are skipped at runtime (they only run when `p.Exempt != ""`). The leak FIX (guardrail reject of :53 + nft `dport != 53`) is already live; this task makes it PROVABLE on every verify, and makes the exemption feature actually usable.

Thread the one concept end-to-end (mirror how `--endpoint` already flows: CLI -> Config -> forcing -> verify):

- **CLI:** add a repeatable exemption flag to `add` and `update`/`reconfigure` (name it consistently with netcage's vocabulary, e.g. `--allow-direct <IP|CIDR[:port]>`, repeatable). Parse each value through `lanexempt.Parse` (which already rejects public/hostname/:53). Put the parsed `[]lanexempt.Exempt` on `cli.Command`.
- **Persist:** add an `Exemptions` field to `accountconfig.Config` (serialised; store the canonical raw/CIDR+port form, credential-free like the rest of the config). `add`/`update` write it; the config round-trips.
- **Apply:** `add`/`update` pass the configured exemptions to `forcing.Install`/`Reconfigure` (which already take `[]lanexempt.Exempt`) instead of the current empty slice, so the rules actually carry the operator's exemptions.
- **Verify:** `verifyParams` reads the persisted `Exemptions` and populates `verify.LiveParams.Exempt` (match the shape the assertions expect - the integration tests already drive `RunVerify` with `Exempt` set, so mirror that exact field/shape). Both `split-tunnel-tight` and `lan-exemption-not-a-dns-hole` then run for an account that has an exemption.

## Acceptance criteria

- [ ] `add` and `update`/`reconfigure` accept a repeatable exemption flag; each value is validated via `lanexempt.Parse` (public/hostname/:53 rejected loudly at the CLI boundary); parsed onto `cli.Command`.
- [ ] `accountconfig.Config` persists the exemptions (round-trips through the store; credential-free; a config with no exemptions is byte-compatible / omitempty so existing markers/configs still load).
- [ ] `add`/`update` pass the configured exemptions to `forcing.Install`/`Reconfigure`, so the applied ruleset carries them (not the current hardcoded empty slice).
- [ ] `verifyParams` populates `verify.LiveParams.Exempt` from the persisted config, so `split-tunnel-tight` AND `lan-exemption-not-a-dns-hole` FIRE for an account that has an exemption (and are cleanly skipped, as today, for one that has none).
- [ ] Unit tests: the CLI flag parse (incl. the :53/public reject surfaced at the CLI), the Config round-trip with exemptions, and the verifyParams-populates-Exempt wiring (a pure test that a config with an exemption yields a LiveParams with Exempt set).
- [ ] An integration test (behind the `integration` tag) provisions an account WITH an exemption and asserts the two exemption assertions actually run and pass (extend the existing exemption integration test rather than duplicating it).
- [ ] Tests cover the new behaviour (mirror the repo's existing test style; live parts isolate to a throwaway account and leave the host untouched).

## Blocked by

- None, can start immediately (all the pieces exist; this wires them together).

## Prompt

> Goal: make LAN exemptions reachable and provable end-to-end. The row-2 leak FIX already shipped (the guardrail rejects `:53` and the nft layer emits `tcp dport != 53`), but exemptions are wired at the ruleset layer ONLY: there is no CLI flag to set one, `accountconfig.Config` does not persist them, and `verifyParams` does not read them back, so the `split-tunnel-tight` and `lan-exemption-not-a-dns-hole` verify assertions never fire in a live `anonctl verify`. This task threads the one concept CLI -> Config -> forcing -> verify. Source: `work/notes/observations/exempt-not-wired-into-verifyparams.md`.
>
> FIRST, check drift: read `main.go` (the `add`/`update`/`verify` verb handlers, `verifyParams` ~L267, `buildConfig`), `internal/cli/cli.go` (`Parse` + `Command` - see how `--endpoint` is threaded, mirror it), `internal/accountconfig/accountconfig.go` (`Config` fields + the store round-trip), `internal/forcing/forcing.go` (`Install`/`Reconfigure` already take `[]lanexempt.Exempt`), `internal/lanexempt` (`Parse`, already validates), and `internal/verify` (`LiveParams.Exempt`, how the assertions consume it - the integration tests already set `Exempt`, so match that exact shape). The whole task is wiring existing pieces; do NOT re-implement the guardrail or the nft generation.
>
> Domain vocabulary: a LAN exemption is a narrow, private-only, host+port-scoped direct hole (cops netcage's `--allow-direct`); it is TCP-only and can NEVER carry clear DNS (port 53 is un-exemptable, already enforced). anonctl's config, marker, and endpoint are all credential-free at rest; keep the persisted exemption that way (it is just an IP/CIDR[:port], no secret).
>
> Where to look / seams to test at: the CLI flag parse (unit, incl. the reject surfaced at the boundary), the Config round-trip with exemptions (unit), the verifyParams-populates-Exempt wiring (unit), and the two assertions firing live for an exempted account (integration, behind the tag, isolated to a throwaway account). "Done" = an operator can `anonctl add --allow-direct 192.168.1.150:8080`, it persists, the rules carry it, and `anonctl verify` runs the split-tunnel + no-DNS-hole assertions on it. RECORD any non-obvious in-scope decision (the flag name, the persisted shape) per the task-template guidance; keep the flag name/vocabulary consistent with netcage's `--allow-direct`.
