---
title: The verify command (named assertions, non-zero exit, --json), the trust anchor
slug: verify-command
prd: per-uid-kernel-anonymized-egress
blockedBy: [nftables-ruleset-install, lan-exemption]
covers: [15, 16, 17, 18, 25]
---

## What to build

`anonctl verify [<name>]`: the trust anchor that PROVES an account is anonymized rather than assuming it. Mirror netcage's `verify`: named assertions, non-zero exit on any failure, `--json`. It runs each assertion (no short-circuit) so the report is complete.

Assertions:

- **Anonymized exit:** the account's exit IP differs from the host's; for a Tor endpoint, it is a Tor exit (checked against check.torproject.org).
- **DNS remote:** DNS resolves remotely via the endpoint (not locally / in plaintext).
- **Leak test (load-bearing):** a direct, non-anonymized connection from the UID is actually DROPPED, on IPv4 AND IPv6.
- **Bypass closures:** the anon UID reaching any loopback destination other than its own shim port is DROPPED; the anon UID dialing the upstream endpoint directly is DROPPED.
- **Split-tunnel tight (with a LAN exemption active):** the exempted host:port is reachable directly, but the rest of that /24, other loopback, and everything else stay redirected-or-dropped.
- **Cross-user isolation (where applicable):** two accounts sharing one `tor-shared` endpoint exit through DIFFERENT circuits/exits.

Signature ongoing verb: it is meant to be re-run after setup, after a reboot, and after any Tor/kernel/nftables change.

## Acceptance criteria

- [ ] `verify [<name>]` runs every assertion (no short-circuit), prints named results, exits non-zero if any fails, and supports `--json`.
- [ ] The leak-test assertion proves a direct connection from the UID is DROPPED on v4 and v6.
- [ ] The two bypass-closure assertions and the split-tunnel-tight assertion are present.
- [ ] The assertion/reporting/exit-code/JSON logic is unit-tested against a fixture (mirror netcage's `internal/verify` + `internal/socks5hfixture`, no real Tor); the live assertions run behind the `integration` build tag (need root + a live endpoint).
- [ ] **Shared-write isolation:** integration runs isolate to throwaway accounts/rules and leave the host untouched.

## Blocked by

- `nftables-ruleset-install`: verify proves what the ruleset installed (the leak test and bypass-closure assertions test that ruleset's behaviour).
- `lan-exemption`: story 25's split-tunnel-tight assertion needs a real LAN exemption in place to exercise (exempted host reachable, everything else still redirected-or-dropped).

## Prompt

> Goal: `anonctl verify`: the named-assertion, non-zero-exit, `--json` trust anchor that proves an account is anonymized, DNS is remote, direct egress is DROPPED, the bypass closures hold, and the split-tunnel stays tight. Stories 15, 16, 17, 18, 25 of the `per-uid-kernel-anonymized-egress` prd.
>
> FIRST, check drift: confirm the ruleset behaviour from `nftables-ruleset-install` and the recipe finding match the assertions here; verify tests the SAME closures that task installed. If they diverged, adapt to what landed.
>
> Domain vocabulary: verify is the SIGNATURE ongoing verb (re-run after setup / reboot / any Tor/kernel/nftables change). The leak test (a direct connection from the UID is DROPPED) is the LOAD-BEARING assertion, fail-closed is proven, not assumed. Cover v4 AND v6.
>
> Where to look: netcage (`~/dev/github/wighawag/netcage`) `internal/verify` is the direct template, named assertions, run-every-check-no-short-circuit (`verify.go`), non-zero exit for CI, `--json`; and `internal/socks5hfixture` + `internal/detectproxy` for testing the anonymized-exit assertion with NO real Tor. Split the pure assertion/render/exit logic (unit, everywhere) from the live checks (integration, behind the `integration` tag).
>
> Seams to test at: the assertion set + JSON/exit rendering (unit against the fixture) and the live leak/closure/split-tunnel checks (integration). "Done" = verify emits named assertions, exits non-zero on any failure, supports `--json`, and its unit suite is green against the fixture. RECORD non-obvious in-scope decisions (assertion names, the JSON shape) per the task-template guidance, the JSON shape is a contract others may consume, so treat it deliberately.
