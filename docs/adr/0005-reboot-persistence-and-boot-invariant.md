# Reboot persistence: templated per-account shim unit, an nftables.service drop-in, and the boot invariant

Status: accepted

## Context

An anon account's forcing must SURVIVE a reboot and re-apply FAIL-CLOSED, with no window where the anon UID has un-anonymized egress at boot (the BOOT INVARIANT: "at no point during boot does the anon UID have direct egress"). anonctl applies everything itself as root (the ufw stance) and does NOT own the endpoint's lifecycle. This task (`persistence-and-boot-invariant`) chose the persistence mechanism and the unit shape; several decisions are load-bearing and would surprise a future reader, so they are recorded here.

## Decisions

- **The per-account shim is a systemd `@`-template unit (`anonctl-shim@<account>.service`), NOT one multiplexer process for all accounts.** The per-account process boundary IS the security boundary: each account's shim runs under its OWN dedicated shim UID (closure b: only the shim UID may reach the endpoint), so a single multiplexer would collapse that boundary. systemd's `@`-template gives every account its own supervised instance from ONE unit file; `add` runs `enable --now`, `rm` runs `disable --now`, `update` runs `restart` (to pick up a rewritten endpoint). One template file, N independent instances, N distinct shim UIDs.

- **The template unit is account-AGNOSTIC; per-account parameters come from a per-instance `EnvironmentFile` (`/etc/anonctl/shim/<account>.env`).** `%i` is the account (the instance), and the shim UID, loopback ports, endpoint address, and derived isolation username are read from the env file, so ONE template serves every account. The unit starts as root only long enough to `setpriv --reuid ${ANONCTL_SHIM_UID}` down to the account's dedicated shim UID (exactly as the validated recipe runs the shim); the shim itself never runs as root. `User=` was rejected because it cannot read a per-instance env var, and baking the UID into the unit would break the single-template property.

- **Unit ordering is `After=network.target` only; the shim deliberately does NOT `Wants=`/`After=` the endpoint's own service.** anonctl does not own the endpoint lifecycle (it does not manage `tor.service`), and the nft rules FAIL CLOSED (drop) if the endpoint is not yet up, so there is no leak window to order against: the worst case is dropped-until-shim-and-endpoint-are-up, never leaking. `add` prints a reminder to enable the endpoint (e.g. `tor.service`) at boot, since that is the operator's job.

- **The nftables ruleset is persisted via an `nftables.service` DROP-IN (`/etc/systemd/system/nftables.service.d/anonctl.conf`), NOT by editing the host's `/etc/nftables.conf`.** The drop-in's `ExecStartPost` loads anonctl's per-account rule files from `/etc/anonctl/nftables/*.nft` AFTER the host's own rules, so the host's `nftables.conf` is left untouched (the shared-write isolation discipline extends to persistence). Because the persisted rules carry the fail-closed default-DROP and `nftables.service` loads early, the boot invariant holds by construction. The loader tolerates an empty rules dir (a `for` over a possibly-empty glob), so boot never fails when no account is forced.

- **The boot invariant is proven by a reboot-EQUIVALENT early-boot simulation, not a real reboot.** The integration test loads ONLY the persisted rules (the rule file the drop-in loads) with the shim NOT running, reproducing the boot window, then asserts AS the anon UID that a direct outbound connection is DROPPED (worst case dropped, never leaking). It isolates to a throwaway account/table + a planted sentinel and asserts the host's rules are untouched.

## Consequences

Persistence introduced a per-account at-rest config (`internal/accountconfig`, `/etc/anonctl/accounts/<account>.json`, root-only 0600) as the source of truth the boot re-apply and `update` read; it is deliberately SEPARATE from the world-readable, credential-free marker (it may carry the endpoint address the marker must never hold). The `update`/`reconfigure` verb re-applies the nft rules (an atomic table replace: the default-DROP is never absent) BEFORE restarting the shim, so a reconfigure has no un-anonymized window. `add` gained an `--endpoint` flag (default: the local Tor SocksPort); `update`/`reconfigure` require it.
