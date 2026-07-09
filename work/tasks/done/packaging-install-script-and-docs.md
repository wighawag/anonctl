---
title: Packaging - install.sh + README install section (place both binaries, shim at /usr/local/bin)
slug: packaging-install-script-and-docs
prd: per-uid-kernel-anonymized-egress
blockedBy: [packaging-goreleaser-and-release-workflow]
covers: []
---

## What to build

Give anonctl a documented install path, mirroring netcage's install.sh + README install section (`~/dev/github/wighawag/netcage` README "Install" + its `install.sh`), adapted for anonctl's shim-placement requirement.

- **`install.sh`** (shipped as a release asset, like netcage's): detect arch (amd64 / arm64 / armv7 / armv6), download the latest (or `ANONCTL_VERSION`-pinned) release archive, VERIFY its sha256 checksum, and install BOTH `anonctl` and `anonctl-shim`. CRITICAL anonctl-specific requirement: the systemd shim unit's ExecStart looks for the shim at `/usr/local/bin/anonctl-shim` (`internal/systemd.DefaultShimBinaryPath`), so the shim MUST land there (or the install must be to a prefix on that path). Since anonctl's whole job needs root anyway, installing to `/usr/local/bin` (root-writable) is the natural default here (unlike netcage which prefers `~/.local/bin`); make `anonctl-shim` reachable at the unit's expected path. Support a `PREFIX` override and an `ANONCTL_VERSION` pin like netcage.
- **README "Install" section**: the curl-pipe-sh one-liner (with the honest note that it needs root / installs to /usr/local/bin because the shim must be at the unit's path), the `go install` route for both binaries (`go install github.com/wighawag/anonctl@latest` + `CGO_ENABLED=0 go install github.com/wighawag/anonctl/cmd/anonctl-shim@latest`, then place/symlink the shim at /usr/local/bin/anonctl-shim), and the manual-download route. Mirror netcage's three-route structure.
- **Be explicit about the shim path** everywhere: unlike netcage (which finds its helper as a sibling of its own binary), anonctl's shim is launched by a systemd unit with a fixed ExecStart path, so "just put them both on PATH" is NOT sufficient, the shim must be at /usr/local/bin/anonctl-shim (or wherever DefaultShimBinaryPath resolves). If the shim is elsewhere, say how (the unit's ShimBinaryPath is configurable via the Store; document the default and that add uses it).

## Acceptance criteria

- [ ] `install.sh` detects arch, downloads + sha256-verifies the release archive, and installs both binaries with `anonctl-shim` reachable at the systemd unit's expected path (`/usr/local/bin/anonctl-shim` by default); supports `PREFIX` and `ANONCTL_VERSION`.
- [ ] The README has an "Install" section with the curl-pipe-sh one-liner, `go install` (both binaries + the shim-placement step), and manual download, each honest about the shim-path requirement and the root/`/usr/local/bin` default.
- [ ] The docs state clearly that anonctl is Linux-only and root is required for `add`/`verify`/`use`/`rm` (already true elsewhere in the README; the install section should not contradict it).
- [ ] install.sh is shellcheck-clean (or at least POSIX-sh safe) and fails loud on a checksum mismatch (never installs an unverified binary).

## Blocked by

- `packaging-goreleaser-and-release-workflow` - the install script downloads the release archive that task's goreleaser produces (it needs to know the archive name/layout + that a checksums file is published).

## Prompt

> Goal: a documented install path for anonctl (install.sh + README Install section), mirroring netcage but honouring anonctl's shim-placement requirement. anonctl is Linux-only and root-required.
>
> FIRST, read netcage's `~/dev/github/wighawag/netcage/install.sh` and its README "Install" section (the three routes: curl|sh, go install, manual). Then read anonctl's `internal/systemd/systemd.go` `DefaultShimBinaryPath` (/usr/local/bin/anonctl-shim - the shim unit's ExecStart path) and how `add` wires the shim unit (`internal/forcing`/`internal/systemd`). This is the ONE way anonctl's install differs from netcage: netcage finds its helper as a sibling of its own binary; anonctl's shim is launched by a systemd unit at a FIXED path, so the install MUST place anonctl-shim there.
>
> Because anonctl needs root anyway, default the install to /usr/local/bin (root-writable, on the unit's path) rather than ~/.local/bin. Verify the sha256 (fail loud on mismatch - never install an unverified anonymity tool). Support PREFIX + ANONCTL_VERSION like netcage.
>
> Where to test: shellcheck install.sh; a dry run against a real release (or a --snapshot archive) proves the download/verify/place flow. "Done" = a user can curl|sh install anonctl with the shim at the unit's path, or go install both + place the shim, with the README documenting all routes honestly. Depends on the goreleaser task for the archive/checksums layout.
