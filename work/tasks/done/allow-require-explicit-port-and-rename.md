---
title: --allow requires an explicit port (drop the all-ports form) and rename --allow-direct -> --allow
slug: allow-require-explicit-port-and-rename
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

Two coupled, deliberately BACKWARD-INCOMPATIBLE changes to the direct-egress exemption (no compat aliases, no migration shims: this is a clean break, the project does not care about backward compatibility at this point):

1. **Port is MANDATORY. Drop the all-ports (bare-IP / port-omitted) form entirely.** Today `--allow-direct 192.168.1.150` (or a bare `10.0.0.0/24`) opens `ip daddr <host> tcp dport != 53 accept`: EVERY TCP port except 53, direct and un-anonymized. That is a real deanonymization leak, not just a wide hole: if the exempted LAN host happens to run ANY forwarding proxy on some other port (an `ssh -D` SOCKS on 1080, a squid/HTTP proxy on 3128, a Tor SOCKS on 9050, a socat/reverse tunnel), the anon account can dial that proxy directly and egress to the WHOLE internet from your real IP. The 53-exclusion patched one symptom (clear DNS); the disease is "all ports", and a forwarding-proxy port deanonymizes MORE than a DNS port (it carries arbitrary traffic, not just name lookups). The only defensible granularity for an anonymity tool is "reach exactly THIS service", so a direct hole must ALWAYS be an exact `host:port` (or `CIDR:port`). Reject a port-omitted value LOUDLY at config time, naming the value and telling the user to add `:port`.

2. **Rename the flag `--allow-direct` -> `--allow`, and the config keys to match.** With the port now always explicit and (in the sibling task) loopback added, one flag covers all direct-destination classes; `--allow` reads as "allow this exact destination directly, whatever its class", and the tool dispatches on the address the user already typed. This is a clean break: rename the CLI flag, the `defaults.json` key (`allowDirect` -> `allow`), and any user-facing config/doc token. (Whether to also rename the INTERNAL `accountconfig.Config.Exemptions` field / `exemptions` JSON key is an implementation-tidiness call; the persisted account record is anonctl-internal, so renaming it is optional, but the OPERATOR-facing `defaults.json` key MUST change.)

## Why this is its own task (a prerequisite)

The port-mandatory tightening is a security fix to SHIPPED behaviour and stands alone; the loopback feature (`loopback-exemption`) layers on top of it and is much simpler once "exact host:port only" is the invariant (both LAN and loopback holes become the same shape, differing only in the per-class guardrail). Landing this first makes the loopback task a clean addition rather than a tangle. Serialized before `loopback-exemption`.

## Blast radius (every site the grep found; adapt to what is actually there)

- **`internal/lanexempt/lanexempt.go`**: `Parse` must REJECT a port-omitted value (`port == 0`) loudly. Remove the "port optional" contract from the doc comments. `HostPort(defaultPort)` and `exemptMatch`'s `Port == 0` branch (in `internal/nftables`) become dead and must go, along with the now-unreachable "all TCP except 53" nft path (the `tcp dport != 53` clause). Keep the explicit-`:53` rejection (still valid) and the private-range guardrail.
- **`internal/nftables/nftables.go`**: `exemptMatch` drops the `Port == 0` branch; every exemption now emits an exact `tcp dport <port>`. Update the comment that explains the all-ports/53-exclusion rationale.
- **`internal/cli/cli.go` + `cli_test.go`**: rename the `--allow-direct` token (space and `=` forms), the dangling-value error message, and `addExemption`'s wording. Update `TestAllowDirectFlag` / `TestAllowDirectRejectsUnsafeValues` (rename + add a port-omitted-is-rejected case).
- **`internal/defaults/defaults.go` + `defaults_test.go`**: rename `AllowDirect` field's JSON key `allowDirect` -> `allow`; update the doc comment and the test fixtures (`{"allow":[...]}`), and change the fixtures to use explicit ports (the bare `10.0.0.0/8` fixture must become `10.0.0.0/8:<port>` or be dropped, since bare is now invalid).
- **`main.go`**: rename every `--allow-direct` in the usage string and operating-notes block; update the `defaults.json` example to `{"allow": ["192.168.1.150:8080"]}`; adjust `resolveAddExemptions` / `exemptionsForUpdate` messages that mention the flag by name.
- **`internal/accountconfig/*`, `internal/verify/*`, `main_test.go`, `main_integration_test.go`, `internal/verify/verify_integration_test.go`**: any test that constructs a port-omitted exemption (`"192.168.1.150"`, `"10.0.0.0/24"`, `exemptHost` port-omitted, the `verify_integration_test.go` "all-TCP LAN exemption" row-2 case) must be updated to an explicit port. The row-2 (`lan-exemption-not-a-dns-hole`) assertion still matters, but it is now about an exact-port exemption not carrying `:53`, not about the all-ports form; keep the assertion, re-express the test.
- **README.md**: rename `--allow-direct` -> `--allow` everywhere, update the `allowDirect` -> `allow` JSON examples, and rewrite the split-tunnel section to state that a port is required (and WHY: an all-ports hole to a host running a proxy is a deanonymization vector). Note anonctl mirrors netcage's vocabulary, so flag docs cross-reference netcage's matching change (see the netcage idea note).
- **`docs/adr/`**: the LAN-exemption ADR text (and any place that documents "port-omitted = all TCP except 53") must be corrected to "port is mandatory; all-ports form removed as a deanonymization risk". Add a short ADR or amend the existing one recording the port-mandatory decision and its rationale (a forwarding proxy on an unspecified port is a real leak).

## Acceptance criteria

- [ ] A port-omitted direct exemption (`--allow 192.168.1.150`, `--allow 10.0.0.0/24`, or the same in `defaults.json`) is REJECTED loudly at config time, naming the value and instructing the user to add `:port`. There is NO code path that emits `tcp dport != 53` (all-ports) any more.
- [ ] An exact `--allow <IP|CIDR>:<port>` still works: the exempted host:port is reachable directly, everything else stays forced/dropped, and `:53` is still rejected.
- [ ] The flag is `--allow` (not `--allow-direct`) and the `defaults.json` key is `allow` (not `allowDirect`); the whole test suite, usage text, README, and ADRs are consistent with the new names, with NO lingering `--allow-direct` / `allowDirect` operator-facing tokens.
- [ ] `verify`'s split-tunnel and not-a-dns-hole assertions still pass, re-expressed for exact-port exemptions.
- [ ] Unit tests cover: port-omitted rejected; `:53` rejected; public/hostname rejected; a valid `IP:port` and `CIDR:port` accepted. Integration tests (behind the tag) still prove direct-reachable-but-tight for an exact-port exemption, isolated to a throwaway account/table.

## Prompt

> Goal: make the direct-egress exemption port-mandatory (DROP the all-ports / bare-IP form, which is a deanonymization leak when the exempted host runs a forwarding proxy on an unspecified port) and rename `--allow-direct` -> `--allow` (and `defaults.json` `allowDirect` -> `allow`). This is a deliberate BACKWARD-INCOMPATIBLE clean break: no compat aliases, no migration. Prerequisite for `loopback-exemption`.
>
> FIRST, check drift: grep the repo for `allow-direct` / `allowDirect` / `Port == 0` / `dport != 53` and read `internal/lanexempt`, `internal/nftables` (`exemptMatch`), `internal/cli`, `internal/defaults`, `main.go` usage, `internal/verify`, and the README + ADRs. Adapt to what actually landed.
>
> The security core: `lanexempt.Parse` must reject `port == 0` loudly (name the value, say "add :port"). Then the `Port == 0` branch in `exemptMatch` and the whole `tcp dport != 53` all-ports nft path become dead and MUST be removed, so no exemption can ever open more than one exact port. Keep the explicit-`:53` rejection and the private-range guardrail. Every exemption now emits `tcp dport <port>`.
>
> The rename: `--allow-direct` -> `--allow` in the CLI (space + `=` forms, dangling-value error, `addExemption` message), the `defaults.json` key `allowDirect` -> `allow` (field tag + doc + fixtures), the `main.go` usage/operating-notes and the `{"allow": ["192.168.1.150:8080"]}` example, and the README everywhere. The internal `accountconfig` `exemptions` key is anonctl-internal, renaming it is optional tidiness; the operator-facing `defaults.json` key is NOT optional.
>
> Fix EVERY test that builds a port-omitted exemption (`main_test.go`, `accountconfig_test.go`, `verify_integration_test.go`'s all-TCP row-2 case, defaults fixtures) to use an explicit port, and add the port-omitted-is-rejected unit test. The `lan-exemption-not-a-dns-hole` assertion stays but is re-expressed for an exact-port exemption.
>
> Correct the LAN-exemption ADR text and add/amend an ADR recording the port-mandatory decision + rationale (a forwarding proxy on an unspecified port is a real deanonymization vector, so "reach exactly this service" is the only defensible granularity). RECORD non-obvious in-scope decisions per the task-template guidance. Mirror the rename note into the netcage side (the paired idea) so the two tools' vocabulary stays aligned.
