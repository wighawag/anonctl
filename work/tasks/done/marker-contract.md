---
title: The /etc/anonctl/<account>.json marker (double-anonymization contract) written after verify passes
slug: marker-contract
spec: per-uid-kernel-anonymized-egress
blockedBy: [account-provisioning-and-cli-skeleton, endpoint-classification-and-config, verify-command]
covers: [20, 28, 29]
---

## What to build

The marker file that sibling tools (anon-pi, netcage) read to detect "this account is already kernel-anonymized" and skip re-forcing (the Tor-over-Tor / double-anonymization guard).

- **Schema:** versioned JSON at `/etc/anonctl/<account>.json`: `schemaVersion` (int), `account`, `uid`, `endpointClass` (`tor-shared` | `socks-peruser`), `createdAt`, `anonctlVersion`. DELIBERATELY EXCLUDE the endpoint URL/credentials, the file is world-readable under `/etc` and consumers only need "forced + which share-class".
- **Write timing:** anonctl writes the marker only AFTER `verify` passes at setup (it is a coordination CLAIM, not a live proof). `rm`/teardown removes it.
- **Read + precedence:** `anonctl status --json` reads and reports the marker. Document the detection precedence: the marker FILE is the authoritative, dependency-free signal (a consumer reads `/etc/anonctl/<account>.json` with no anonctl binary needed); the `anon`/`anon-<name>` name prefix is a HINT only, never authoritative; `status --json` is a convenience reader of the same truth.
- **Trust framing:** document that the marker is a coordination hint to avoid double-anonymization, NOT a security proof, a consumer needing certainty runs `anonctl verify` or its own leak check.

## Acceptance criteria

- [ ] The marker is written to `/etc/anonctl/<account>.json` with exactly the fields above (and NO endpoint URL/creds), only after `verify` passes.
- [ ] `rm`/teardown removes the marker.
- [ ] `status --json` reads and reports the marker; a missing marker is a clean "not forced".
- [ ] Marker (de)serialization + the versioned schema + the write-after-verify gating are unit-tested; a real `/etc` write is isolated in tests (a temp dir via a configurable path lever) and the real `/etc/anonctl` is asserted untouched.
- [ ] **Shared-write isolation:** tests that would write the real `/etc/anonctl` path redirect it to a scratch dir and assert the real location is untouched.

## Blocked by

- `account-provisioning-and-cli-skeleton`: the account + uid the marker records, and the `status` reader.
- `endpoint-classification-and-config`: defines the `endpointClass` (`tor-shared` | `socks-peruser`) values the marker serializes.
- `verify-command`: the marker is written only after verify passes (the write is gated on verify success).

## Prompt

> Goal: the `/etc/anonctl/<account>.json` marker contract, the dependency-free signal anon-pi/netcage read to avoid double-anonymization. Stories 20 (share-class in status), 28, 29 of the `per-uid-kernel-anonymized-egress` prd.
>
> FIRST, check drift: read the marker decision in `work/specs/tasked/per-uid-kernel-anonymized-egress.md` (Solution + the resolved marker decision) and confirm the `endpointClass` values match `endpoint-classification-and-config`. Read `CONTEXT.md` for the `marker` term.
>
> Domain vocabulary: the marker is a COORDINATION CLAIM, not a security proof. Fields: `schemaVersion`, `account`, `uid`, `endpointClass`, `createdAt`, `anonctlVersion`: and deliberately NO endpoint URL/creds (world-readable `/etc`). Precedence: file authoritative, name-prefix a hint, `status --json` a reader. Written only after `verify` passes.
>
> Where to look: the marker path is a SHARED/GLOBAL system location (`/etc`), so put the base path behind a configurable lever and isolate it in tests (netcage's shared-write isolation discipline, assert the real path untouched). The `status --json` reader is in `account-provisioning-and-cli-skeleton`.
>
> Seams to test at: (de)serialization + schema version + the write-after-verify gate (unit, with the path isolated). "Done" = the marker round-trips, is written only post-verify, is removed on teardown, and `status --json` reports it, with the real `/etc` untouched by tests. RECORD non-obvious in-scope decisions (the exact `schemaVersion` starting value, file mode) per the task-template guidance.
