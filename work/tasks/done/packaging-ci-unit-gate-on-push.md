---
title: Packaging - CI workflow running the unit gate on push/PR (anonctl has none)
slug: packaging-ci-unit-gate-on-push
spec: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

anonctl has NO continuous integration: nothing runs even the unit gate on push or PR (netcage itself only has a release workflow, so this is a genuine improvement, not just a mirror). Add a CI workflow that runs anonctl's `verify` gate on every push and pull request, so a regression is caught in CI, not only by a human driving.

- **`.github/workflows/ci.yml`**: on `push` (to main) and `pull_request`, set up Go 1.26, and run the repo's acceptance gate: `test -z "$(gofmt -l .)" && go vet ./... && go build ./... && go test ./...` (the `dorfl.json` `verify` command). This is the UNIT gate only.
- **Document the integration gap honestly**: the integration suite (`go test -tags integration ./...`) needs root + nftables + a live socks5h endpoint (and, for the boot-invariant/teardown tests, a systemd-PID1 environment), which GitHub-hosted runners lack. A comment in the workflow must say the integration suite is NOT run here and must be run on a capable Linux host (as the e2e validations did). Do NOT try to fake it on a runner that cannot support it (a green-but-vacuous integration run would be worse than an honest "unit only").
- Keep it simple and fast (the unit suite is quick); no matrix beyond a single Linux/amd64 runner is needed for the unit gate.

## Acceptance criteria

- [ ] `.github/workflows/ci.yml` runs on push (main) and pull_request, sets up Go 1.26, and runs the `dorfl.json` verify gate (gofmt check + go vet + go build + go test, unit only), failing the check on any red.
- [ ] The workflow comments that the integration suite is behind `-tags integration`, needs a capable host (root + nftables + live endpoint + systemd-PID1), and is deliberately NOT run in GitHub CI.
- [ ] The gate command matches the repo's actual `dorfl.json` verify (single source of truth; if they can drift, note it).
- [ ] It does not duplicate the release workflow's test step confusingly (CI = every push/PR unit gate; release = tag-triggered build+publish); the two are distinct and both documented.

## Blocked by

- None, can start immediately. (Independent of the goreleaser/release task, though they share the `.github/workflows/` dir; if that task lands first, just add ci.yml alongside release.yml.)

## Prompt

> Goal: add CI that runs anonctl's unit gate on every push/PR. anonctl currently has no CI at all. This is the unit gate only; the integration suite genuinely cannot run on a GitHub runner (needs root + nftables + a live endpoint + systemd-PID1), so document that honestly rather than fake it.
>
> FIRST, read anonctl's `dorfl.json` (the exact `verify` gate: `test -z "$(gofmt -l .)" && go vet ./... && go build ./... && go test ./...`) so CI runs the SAME gate, and `~/dev/github/wighawag/netcage/.github/workflows/release.yml` for the Go-setup shape to reuse (Go 1.26). Note netcage has no separate PR-CI, so there is no exact mirror; this is a straightforward Go CI workflow.
>
> Where to test: the workflow is exercised by GitHub on push/PR; locally, confirm the gate command it runs is exactly the dorfl.json verify and passes on a clean tree. "Done" = every push/PR runs the unit gate and fails on a regression, with an honest comment that the integration suite runs on a capable host, not here. Keep it minimal (single Linux runner, no needless matrix).
