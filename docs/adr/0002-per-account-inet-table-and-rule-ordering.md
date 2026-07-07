# The per-account fail-closed `inet` nftables ruleset: table/chain naming, priorities, and rule ordering

Status: accepted

## Context

The kernel half of anonctl's forcing is one `nftables` ruleset per anon account. It was hand-validated end-to-end (`work/notes/findings/manual-per-uid-tor-recipe.md`) as a single `inet table anonctl` with a `nat_out` (dstnat) and a `filter_out` (drop-policy) chain. The Go generator (`internal/nftables`) encodes that proven recipe verbatim, but the manual recipe was for ONE account on one host; anonctl runs many accounts and applies the rules itself. That surfaced a few decisions the recipe did not have to make. This is the highest-stakes code path (a wrong rule silently leaks a real IP or locks a user out), so the decisions are recorded here.

## Decisions

- **Per-account table name `anonctl_<account>`, not the recipe's shared `anonctl`.** Multiple anon accounts coexist; a single shared table would make each account's Apply clobber the others. Naming the table per-account lets Apply/Delete scope to exactly one account and leave every other table (the whole rest of the host firewall) untouched, which is also what makes the shared-write isolation acceptance test possible. nft identifiers cannot contain `-`, so a named account's `-` becomes `_` (`anon-work` -> `anonctl_anon_work`); this only names the table, never the Unix account.

- **Chain priorities are kept exactly as validated: `nat_out` at `dstnat` (-100) and `filter_out` at `filter` (0).** The recipe proved (with a scratch counter) that a REDIRECTed packet re-enters the filter hook with its destination already rewritten to the shim port, so `nat` must run before `filter` and the filter accepts match the SHIM ports, not the original destination. Reordering or re-prioritising either chain breaks that invariant.

- **Within `filter_out`, rule ORDER is load-bearing and fixed:** the endpoint DROP for the anon UID (closure b) is emitted BEFORE the shim-port ACCEPT (closure a), so an anon-UID dial of the endpoint can never be shadowed into an accept; and the shim-port ACCEPT is emitted before the broad `127.0.0.0/8` DROP, so the account's own shim ports are not swallowed by the loopback drop. Both orderings are asserted in the unit tests by index, not just by presence, because a first-match firewall is only as correct as its ordering.

- **The load is idempotent via a create-if-absent + `delete table` preamble, applied with `nft -f -` (stdin).** The generated text begins `table inet <t> {}` then `delete table inet <t>` then the real definition, so a re-Apply is an atomic REPLACE of that one table (never an append of stale rules) and never touches another table. Delete issues only `delete table inet <t>`, never `flush ruleset`.

- **The endpoint host must be an IP literal (v4 or v6), and closure (b) uses the matching `ip`/`ip6` family.** A hostname in a firewall rule is ambiguous and a DNS-lookup-at-rule-time is itself a leak vector; and picking the family from the endpoint's actual address keeps closure (b) from being silently v4-only for a v6 endpoint. Generation rejects a non-literal host loudly rather than emit a rule that half-forces.

## Consequences

The ports the rules redirect to (the shim's per-account relay + DNS ports) and the UIDs are `Params` inputs, resolved by the caller (the persistence/wiring task) from the account/shim names and the shim binary's defaults (19050/19053), exactly as the recipe embeds them. IPv6 remains drop-only (there is no v6 redirect target), matching the recipe's documented, deliberate property: the anon account has no IPv6 connectivity, but it never leaks over v6.
