---
title: verify must fail loudly when the forced account has vanished or no longer owns its UID
slug: verify-must-detect-a-vanished-or-reassigned-account
blockedBy: []
---

## What to build

`anonctl verify` probes an account by the UID recorded in its at-rest config (`/etc/anonctl/accounts/<account>.json`). It never checks that the account still EXISTS, or that it still owns that UID. On a host where accounts can disappear underneath anonctl, that turns the trust anchor into a source of noise at exactly the moment it should be shouting.

This is not hypothetical. On a NixOS host with `users.mutableUsers = false`, activation deletes every undeclared account on each boot and each `nixos-rebuild switch`, while anonctl's rules, units, config and home directory all survive. Measured on telemaque (see `work/notes/findings/nixos-account-conventions-break-anonctl-provisioning.md`): after one reboot both the anon and shim accounts were gone, their UIDs were unallocated, the shim was still running as a bare numeric UID, and the nft tables were faithfully restored for accounts that no longer existed.

What `verify` reported was a scatter of leak assertions (`leak-drop-v4`, `bypass-endpoint-closure`, `non-tcp-udp-drop` all "REACHED its target") which an operator would reasonably read as "the forcing is broken". The true finding -- "this account does not exist any more" -- was not reported at all.

Add assertions, ordered so the account's existence is established BEFORE any UID-based probe runs:

- the login account exists (`getent passwd <account>`), and its UID equals the UID in the at-rest config;
- the shim account exists, and its UID equals the config's shim UID;
- no OTHER account has been assigned either UID.

Any of these failing must be a loud, specific failure that names the drift, and it should SHORT-CIRCUIT the UID-based probes rather than letting them run and produce misleading verdicts about a UID that is not the account's any more.

The third check is the one that matters most and is easiest to leave out. A freed UID gets reallocated: the next account NixOS (or `useradd`) creates can be handed the old anon UID and will silently inherit the forcing -- every TCP connection redirected into a shim it knows nothing about. Detecting "uid 1002 now belongs to `someone-else`" is what turns a silent mis-jailing into a reported one.

Consider whether `anonctl status` should carry the same check, since that is the cheaper thing an operator runs first.

Out of scope: making the accounts survive (that is a host-configuration question, and on NixOS it means either declaring the accounts or setting `users.mutableUsers = true`); and any attempt to self-heal by recreating or re-UID-ing an account, which would silently paper over a real change in host state.

## Acceptance criteria

- [ ] `verify` fails, naming the account, when the login account is absent but its config and rules remain.
- [ ] `verify` fails when the account exists but its UID differs from the at-rest config.
- [ ] `verify` fails when the config's anon or shim UID is now owned by a DIFFERENT account.
- [ ] These checks run BEFORE the UID-based probes, and a failure short-circuits them rather than emitting leak verdicts about a UID that is no longer the account's.
- [ ] The failure detail is specific enough to act on (which account, which UID, what it found instead) and never reads as a leak.
- [ ] The shim account is covered, not only the login account.
- [ ] New assertion names are recorded in `docs/adr/0003-verify-assertion-names-and-json-contract.md`.
- [ ] Tests isolate their account lookups (inject the lookup, as `systemd.Resolver` does) so they neither need root nor depend on the host's real passwd database.
- [ ] `gofmt` / `go vet` / `go build` / `go test ./...` green. Note two pre-existing `TestPkexecVector_*` failures are environmental (`pkcheck` absent on NixOS) and not yours.

## Blocked by

Nothing.

## Prompt

`anonctl verify` is the trust anchor: it must never report green unless it proved green, and it must not report a confusing red when the real problem is simple. Today it probes an account by the UID stored in `/etc/anonctl/accounts/<account>.json` and never checks that the account still exists or still owns that UID.

That matters on any host where accounts can vanish underneath the tool. On NixOS with `users.mutableUsers = false`, activation deletes undeclared accounts at every boot, while anonctl's nft rules, units, at-rest config and home directory all survive. This was measured on a real host: after a reboot both accounts were gone, their UIDs unallocated, the shim still running as a bare numeric UID, and the rules faithfully restored for accounts that no longer existed. `verify` responded with three "REACHED its target" leak assertions and never mentioned the missing account.

Add existence-and-identity assertions that run BEFORE the UID-based probes and short-circuit them on failure: the login account exists and its UID matches the config; the shim account exists and its UID matches; and neither UID has been reassigned to a different account. That last one is the important one, because a freed UID gets reused and the next account created can silently inherit this account's forcing.

Failures must name the drift specifically and must never read as a leak. Do not attempt to self-heal (no recreating accounts, no re-UID-ing): a changed host is a thing to report, not to paper over.

Record new assertion names in `docs/adr/0003-verify-assertion-names-and-json-contract.md`. Keep tests hermetic by injecting the account lookup rather than reading the host's passwd database, following the `systemd.Resolver` seam added for binary resolution. Background and the measured evidence: `work/notes/findings/nixos-account-conventions-break-anonctl-provisioning.md`.

Repo verify: `gofmt -l .`, `go vet ./...`, `go build ./...`, `go test ./...`. Two pre-existing `TestPkexecVector_*` failures are environmental and not yours.
