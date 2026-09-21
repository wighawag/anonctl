---
title: A unit's resolved nft/setpriv path can still be a garbage-collectable /nix/store path, because it arrives through the caller's $PATH
slug: resolved-unit-binaries-can-bake-a-nix-store-path-from-path
---

Handed over from a parallel session working on anoncore v0.2.0 (2026-09-21), captured here because the fix belongs to anonctl's `internal/systemd`, not to that change or to the nftables chain restructure it was reported alongside. Not a measured failure on this box: latent, and dependent on how `anonctl` was invoked.

ADR-0005 records that `systemd.Resolver.Binary` must NOT resolve symlinks when baking `nft` and `setpriv` into generated units: `filepath.EvalSymlinks` would return `/nix/store/<hash>-nftables-1.1.6/bin/nft`, which is garbage-collected on the next rebuild, leaving `ExecStart` pointing at a file that no longer exists. The loader then fails `203/EXEC` and the account is silently unjailed with no baseline default-deny, weeks after the install, with nothing in the config having changed.

That rule is right and it is NOT sufficient. The same store path can arrive by a completely different route: `exec.LookPath` returns the `$PATH` ENTRY VERBATIM, so if a store path sits EARLIER in `$PATH` than `/run/current-system/sw/bin`, `LookPath` hands back the store path having resolved no symlink at all. Measured on this host, in an ordinary session:

```
$ which bash
/nix/store/yisa2lg79zcvgk4ck4yr6r0lz6j63hs3-bash-interactive-5.3p9/bin/bash
```

(Observed incidentally while building the nftables behaviour tests: the test's own `exec.LookPath("bash")` returned exactly that path.)

So the time bomb arrives through the CALLER'S ENVIRONMENT, not through symlink resolution, and nothing inside `LookPath` can prevent it. Whether `nft` and `setpriv` actually hit it depends on how `anonctl` was invoked: a `nix develop` shell, a direnv environment, or anything that prepends a store path to `$PATH` is enough. The failure has the same shape and the same fail-open consequence as the `EvalSymlinks` one ADR-0005 already closed, so the existing decision reads as if it were handled when it is not.

anoncore solved the equivalent problem for the login shell by preferring an `/etc/shells` entry naming the SAME file (`os.SameFile`, a comparison only -- it never returns a resolved target). There is no `/etc/shells` analogue for `nft` or `setpriv`, so anonctl needs a different mechanism: a stable-alias preference against a known-good directory set, or a refusal to bake a path under `/nix/store` at all, or an install-time check that the baked path survives a rebuild. Picking between those is the work; this note only records that the gap is open.

Worth pairing with `provision.PreflightShells()` (new in anoncore v0.2.0), which pairs with `systemd.PreflightUnitBinaries` so an unresolvable shell is refused while the box is still untouched.
