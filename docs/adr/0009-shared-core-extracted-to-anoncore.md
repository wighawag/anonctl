# The substrate-agnostic core was extracted to anoncore

## Status

Accepted. Retroactive note that a slice of anonctl's `internal/` moved OUT into the shared `anoncore` module. This keeps anonctl's own decision record honest: the account/seed/marker/elevation logic that earlier ADRs describe as anonctl's now LIVES in `github.com/wighawag/anoncore`, and anonctl imports it.

## Context

Two sibling tools are planned that share anonctl's account/identity model but NOT its egress substrate: `anonbox` (egress via a netcage network namespace) and `anonseed` (config seeding into an anonymized home). Both need the same account-creation-with-no-sudo-grant, `seed-home` hardening (ADR 0006), marker contract (ADR 0004), and self-elevation logic anonctl already has. Copying it would let the security-critical hardening DRIFT between tools. So the substrate-agnostic core was extracted into one shared module both consumers import, rather than vendored.

## Decision

The following packages MOVED from `anonctl/internal/` to `anoncore/`: `provision`, `seedhome`, `marker`, `accountconfig`, `endpoint`, `sudoprobe`, `ui`, plus a new `anoncore/account` package (the account-NAME vocabulary extracted DOWN out of `internal/cli` to break the `provision -> cli` layering inversion). anonctl now imports these from `github.com/wighawag/anoncore/...`.

What STAYED in anonctl is its per-UID egress substrate: `nftables`, `forcing`, `shim`, `lanexempt`, `systemd`, the anonctl-config-specific `defaults`, the `cli` command surface, and `verify`. `verify` is deliberately NOT shared in this pass: its load-bearing assertions (the nftables per-UID forcing, the shim closures, the UID-transition probes) are substrate-specific; only its account-layer / `--json` scaffolding might be shared later, driven by anonbox's and anonseed's actual verify shapes rather than guessed at now.

`internal/cli` keeps its `DefaultAccount` / `ResolveAccount` / `ShimAccount` NAMES as thin re-exports of `anoncore/account`, so every anonctl caller is unchanged and there is a single source of truth for the account naming.

anonctl depends on anoncore, never the reverse. Until anoncore is published, anonctl consumes it via a `replace github.com/wighawag/anoncore => ../anoncore` directive in `go.mod`, to be swapped for a version tag on release.

## Consequences

- Earlier ADRs still describe the BEHAVIOUR correctly (the setuid strip of ADR 0006, the marker contract of ADR 0004, the endpoint share-class of ADR 0001, the verify JSON contract of ADR 0003), but the CODE for the account/seed/marker/endpoint half now lives in anoncore. Read those ADRs together with anoncore's founding ADR 0001, which pins the exact shared-core-vs-substrate boundary and records the `provision -> cli` inversion resolution and the verify-split deferral.
- The injected-`Runner` test discipline is preserved: the moved packages' unit tests travel with them (pass against the fake runner, no root), the integration-tagged tests travel too, and anonctl's own tests exercise the rewired call path.
- No security property changed: the extraction is a code MOVE plus a layering-inversion fix (the account-name vocabulary moved down out of `cli`); no hardening was loosened, no default path or mode changed.

## References

- anoncore founding ADR: `docs/adr/0001-module-boundary-shared-core-vs-per-tool-substrate.md` in `github.com/wighawag/anoncore`.
- netcage design note `work/notes/ideas/netcage-machines-scope-fork.md` (update 5a).
