---
title: Fix the release - install.sh is not published as a release asset, so the curl one-liner 404s
slug: fix-release-ship-install-script-asset
prd: per-uid-kernel-anonymized-egress
blockedBy: []
covers: []
---

## What to build

The v0.1.0 release surfaced a real packaging bug: the README's headline install one-liner `curl -fsSL https://github.com/wighawag/anonctl/releases/latest/download/install.sh | sudo sh` returns **404**, because `install.sh` is NOT uploaded as a release asset. The release published the archives + `checksums.txt` only; `.goreleaser.yaml`'s `release:` block has no `extra_files`, so `install.sh` never gets attached to the GitHub Release. (The raw repo copy at `raw.githubusercontent.com/.../main/install.sh` works, which is why the "read it first" fallback is fine, but the documented headline route is broken.)

FIX (mirror the sibling netcage, which does this correctly): add `release.extra_files` to `.goreleaser.yaml` so `install.sh` ships as a standalone release asset served from stable release object storage:

```yaml
release:
  draft: false
  prerelease: auto
  extra_files:
    - glob: ./install.sh
```

That is the whole code change. After it lands, the release needs to be RE-CUT so an actual release carries the asset (a config fix alone does not retro-add the asset to the existing v0.1.0). See the re-release note below.

## Acceptance criteria

- [ ] `.goreleaser.yaml`'s `release:` block includes `extra_files` with `- glob: ./install.sh`, so a release publishes `install.sh` as an asset alongside the archives + checksums.
- [ ] `goreleaser check` passes (or a local `goreleaser release --snapshot --clean` shows install.sh in the dist as a release extra file), confirming the config is valid.
- [ ] The done-record notes the RE-RELEASE step: after this lands on main, a new tag (e.g. re-cut v0.1.0 if it can be moved, or a fresh v0.1.1) must be pushed for the asset to actually appear on a release; the `releases/latest/download/install.sh` URL then resolves. (The human/driver cuts the tag; this task only fixes the config.)

## Blocked by

- None, can start immediately.

## Prompt

> Goal: make `install.sh` a published release asset so the README's `curl .../releases/latest/download/install.sh | sudo sh` one-liner works (it 404s on v0.1.0 because goreleaser was not told to upload it). One-line goreleaser config fix.
>
> FIRST, read anonctl's `.goreleaser.yaml` `release:` block (has draft/prerelease but NO extra_files) and the sibling `~/dev/github/wighawag/netcage/.goreleaser.yaml` `release:` block (which correctly has `extra_files: [{glob: ./install.sh}]` with a comment about stable release object storage). Mirror it.
>
> Add `extra_files: - glob: ./install.sh` under `release:`. That is the fix. If goreleaser is installed, confirm with `goreleaser check` and/or a `--snapshot` that install.sh is picked up as a release extra file; if not, a YAML-valid mirror of netcage's proven block is sufficient here.
>
> "Done" = the config publishes install.sh as a release asset. NOTE in the done-record that a RE-TAG is required for it to take effect on an actual release (the config change alone does not add the asset to the already-published v0.1.0); the driver will re-cut the tag after this merges.
