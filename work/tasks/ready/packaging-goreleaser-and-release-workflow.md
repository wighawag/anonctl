---
title: Packaging - goreleaser config + GitHub release workflow (both binaries, static, Linux multi-arch)
slug: packaging-goreleaser-and-release-workflow
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

anonctl is functionally validated but has NO release path (no `.goreleaser.yaml`, no `.github/`). Add the release tooling, mirroring the sibling netcage's proven setup (`~/dev/github/wighawag/netcage/.goreleaser.yaml` + `.github/workflows/release.yml`), adapted for anonctl's TWO binaries and its shim-placement requirement.

- **`.goreleaser.yaml`** (version 2): build BOTH `anonctl` (main `.`) and `anonctl-shim` (`./cmd/anonctl-shim`), static (`CGO_ENABLED=0`), `-trimpath`, ldflags `-s -w -X main.version={{.Version}}` (anonctl already has `resolveVersion()` in version.go that reads this stamp, with a build-info fallback). Linux only (anonctl is Linux-only: nftables + SO_ORIGINAL_DST). goarch amd64 + arm64 + arm (goarm 7 and 6) as netcage does, unless there is a reason to trim (the shim + anonctl are pure Go, so all these cross-compile fine). Archive BOTH binaries side by side (as netcage archives netcage + netcage-dns together), so a release artifact contains anonctl AND anonctl-shim.
- **`.github/workflows/release.yml`**: on a `v*` tag push, set up Go 1.26, run `go test ./...` (unit only; note in a comment that the integration suite is behind `-tags integration` and needs a capable Linux host with root + nftables + a live endpoint, which GitHub runners lack), then run goreleaser to cross-compile + publish the release. Mirror netcage's release.yml (permissions: contents: write; fetch-depth: 0 for the changelog).
- **The anonctl-specific note:** the shim binary MUST end up at `/usr/local/bin/anonctl-shim` for the systemd unit's ExecStart (`internal/systemd.DefaultShimBinaryPath`). goreleaser just SHIPS both binaries in the archive; WHERE they get installed is the install-script/docs task's concern (`packaging-install-script-and-docs`). Make sure the archive layout puts both binaries where an install step can find and place them.

## Acceptance criteria

- [ ] `.goreleaser.yaml` (v2) builds both `anonctl` and `anonctl-shim` static (CGO_ENABLED=0), Linux, amd64/arm64/armv7/armv6, version-stamped via `-X main.version={{.Version}}`; `goreleaser check` passes (or a dry `goreleaser build --snapshot --clean` succeeds locally).
- [ ] The release archive contains BOTH binaries side by side.
- [ ] `.github/workflows/release.yml` runs `go test ./...` then goreleaser on a `v*` tag, with a comment documenting that the integration suite needs a capable host and is not run here.
- [ ] A comment/doc records the shim-placement requirement (the unit needs `/usr/local/bin/anonctl-shim`) so the install task honours it.

## Blocked by

- None, can start immediately.

## Prompt

> Goal: give anonctl a release path (goreleaser + a tag-triggered release workflow), mirroring the sibling netcage, adapted for anonctl's two binaries. anonctl is Linux-only and already version-stamps via version.go `resolveVersion()` (reads `-X main.version`).
>
> FIRST, read the netcage templates to mirror: `~/dev/github/wighawag/netcage/.goreleaser.yaml` (two-binary build: netcage + netcage-dns, static, Linux multi-arch, version stamp) and `~/dev/github/wighawag/netcage/.github/workflows/release.yml` (go test ./... then goreleaser on a v* tag). Read anonctl's `version.go` (`resolveVersion` + the `-X main.version` it expects) and `internal/systemd/systemd.go` `DefaultShimBinaryPath` (= /usr/local/bin/anonctl-shim, the shim placement the install task must satisfy).
>
> anonctl's two binaries are `anonctl` (main `.`) and `anonctl-shim` (`./cmd/anonctl-shim`), the analogue of netcage + netcage-dns; both pure Go, so CGO_ENABLED=0 static builds cross-compile cleanly. Archive both side by side.
>
> Where to test: `goreleaser check` and a local `goreleaser build --snapshot --clean` (no publish) prove the config; the workflow itself is exercised on a real tag (not in this task). "Done" = goreleaser builds both static multi-arch binaries version-stamped, the archive carries both, and a v* tag would run tests + publish. Do NOT invent macOS/Windows targets (anonctl is Linux-only). RECORD the shim-placement note for the install task.
