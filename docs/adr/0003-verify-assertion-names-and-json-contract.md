# The `verify` assertion names and `--json` report contract

Status: accepted

## Context

`anonctl verify` is the trust anchor and the signature ongoing verb: it PROVES an account is anonymized rather than assuming it, and is meant to be re-run after setup, a reboot, and any Tor/kernel/nftables change. Story 18 requires it to emit named assertions, exit non-zero on any failure, and support `--json` so CI/automation can gate on it (mirroring netcage's `verify`). The assertion NAMES and the JSON SHAPE are consumed by machines (a CI gate keys on a name; a sibling tool may read the report), so they are a CONTRACT, not incidental output. This ADR records the shape and the names so a later change is a deliberate, versioned decision rather than an accidental break.

## Decisions

- **The assertion set is a fixed, named vocabulary (kebab-case), declared once as constants, never spelled inline.** The names are `anonymized-exit`, `dns-remote`, `leak-drop-v4`, `leak-drop-v6`, `bypass-loopback-closure`, `bypass-endpoint-closure`, `split-tunnel-tight`. kebab-case mirrors netcage's assertion names. `leak-drop-v4` and `leak-drop-v6` are SEPARATE names (not one `leak-drop`) so a v6 bypass of v4 rules can never hide behind a single line: each family reports independently. The two bypass closures map one-to-one onto the ruleset's two closures (ADR 0002): closure (a) non-shim-loopback drop, closure (b) direct-endpoint drop.

- **`--json` is a versioned envelope carrying a derived top-level `ok`.** The wire shape is `{schemaVersion, ok, account, endpoint, assertions:[{name, ok, detail, error}]}`. `schemaVersion` starts at 1 and evolves ADDITIVELY only (new optional fields keep a pinned consumer working; a breaking change bumps it). The top-level `ok` is the derived greenness (`== Report.Ok()`), so a consumer gates on ONE boolean without re-walking the array. The wire type (`jsonReport`) is DISTINCT from the in-memory `Report`, so the contract is explicit and stable rather than whatever the struct happens to look like.

- **A report is a pass IFF every assertion passed AND at least one ran; an empty report is NOT a pass and exits non-zero.** "Nothing was asserted" is never proof of anonymization. A probe that ERRORED counts as a failure (a check that could not run is not a pass), and its error is flattened to a string in the JSON (`error`), never a Go error object.

- **The `endpoint` in the report is the credential-free socks5h URL (`endpoint.URL()`), never a `user:pass@` form.** A shared or logged verify report must never leak a secret; the per-account isolation username is derived at dial time, not embedded (consistent with ADR 0001's credential-free-at-rest stance).

- **The pure assertion/render/exit logic is split from the live probes; live probes are compiled only under the `integration` build tag.** The pure decisions (the `*Assertion` functions, `Report`, `Run`, `RunVerify`) are unit-tested EVERYWHERE against the socks5h fixture with no root and no real Tor; the live probes that stand up real connections AS the anon UID (setpriv + nft + a live endpoint) live behind `//go:build integration`. The DEFAULT binary therefore cannot silently "pass" verification: its `LiveChecks` returns a single honest failing assertion telling the operator to run the integration build on the provisioned host, and `verify` exits non-zero. This keeps the fail-closed / CI-gating contract intact without privilege.

## Consequences

The account's endpoint host:port and the shim's relay/DNS ports are `LiveParams` inputs the runtime command discovers from the provisioned account. Until the persistence task persists that per-account config, the default-build `verify` uses the account's default endpoint for the report header and the UIDs read from the box; the integration harness supplies the live params directly. Adding a new assertion is additive (append a name constant + a check); removing or renaming one, or changing the JSON envelope's existing fields, is a breaking change that bumps `schemaVersion`.
