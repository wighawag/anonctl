---
title: the loader's ExecStart exits 1 when no rule file exists, so a rule-less enabled loader shows as failed at boot
slug: loader-execstart-exits-1-when-the-rules-dir-is-empty
---

Noticed while adding host-owned units (ADR-0012), off that change's path and NOT fixed by it. Recording it rather than widening that change.

`LoaderUnit` generates:

```
ExecStart=/bin/sh -c 'for f in <rulesdir>/*.nft; do [ -e "$f" ] && <nft> -f "$f"; done'
```

The generator's own comment says a missing or empty rules dir is "a clean no-op ... so boot never fails when no account is forced". The no-op half is right (nothing is loaded); the exit status half is not. Measured with /bin/sh here:

```
$ /bin/sh -c 'for f in /tmp/emptyrules/*.nft; do [ -e "$f" ] && echo load "$f"; done'; echo $?
1                       # no files: the glob stays literal, [ -e ] is false, && short-circuits
$ touch /tmp/emptyrules/a.nft
$ /bin/sh -c 'for f in /tmp/emptyrules/*.nft; do [ -e "$f" ] && echo load "$f"; done'; echo $?
load /tmp/emptyrules/a.nft
0
```

A `for` loop exits with the status of its last command, so with no matching files the compound command is false and `sh -c` exits 1. The unit is `Type=oneshot`, so that is a FAILED unit at boot.

Why the exposure is narrow, and why this is an observation rather than a bug report:

- With at least one account forced there is always a `<account>.baseline.nft`, so the last iteration succeeds and the status is 0. That is every normally-operating host.
- `rm`'s last-account teardown DISABLES the loader, so a torn-down host does not have it enabled with an empty dir.
- It therefore surfaces only where the loader is enabled with no rule files: a host that declares the units itself AND sets `wantedBy = [ "sysinit.target" ]` on the loader (docs/nixos.md section 8 tells hosts not to, precisely because enablement is anonctl's), or a hand-enabled loader.

There is no security consequence in either direction: there is nothing to load, and the standing baseline default-deny only exists for accounts that have rule files. It is noise (a red unit in `systemctl --failed`) that would wrongly suggest the forcing is broken, which is the kind of false signal this codebase otherwise works hard to avoid.

If it is ever fixed, the shape is a trailing `:` or `exit 0` inside the `sh -c`, or `[ -e "$f" ] || continue`. Note that changing the generated text changes what every host's unit looks like after an upgrade, and the `.in` data files must be regenerated with `go generate ./...` in the same commit (the byte-identity tests enforce this).
