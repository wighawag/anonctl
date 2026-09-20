---
title: The `use` session hands the account an FHS PATH that is nearly empty on NixOS
slug: use-session-path-is-unusable-on-nixos
---

Spotted while fixing the unit-install FHS assumptions (`portable-unit-install-and-enablement`). Deliberately left out of that task's scope because it is a USABILITY problem, not a safety one: both failures below fail closed.

`use_exec.go` builds the dropped session's environment with a fixed

```go
"PATH=/usr/local/bin:/usr/bin:/bin",
```

On telemaque (NixOS) those three directories contain, in total, two commands: `/usr/bin/env` and `/bin/sh`. `/usr/local/bin` does not exist. So `anonctl use <account>` produces a session that is correctly jailed and essentially unusable: no `ls`, no `curl`, nothing the account was created to run.

Note this PATH is also a deliberate hardening choice, not an accident: README §"NOT defended" records that it OMITS the `sbin` dirs carrying setuid network binaries (`exim4`, `pppd`, `mount.nfs`) that an audit of a real host flagged. So any fix must not simply widen it to the host's full PATH, or it undoes that hardening. On NixOS the equivalent of "the system's normal command set" is `/run/current-system/sw/bin`, which mixes both, so the shape of the fix is not obvious and deserves a moment's thought rather than a quick patch.

Second, smaller: the `getent`-fallback shell when a passwd entry has an empty shell field is

```go
shell = "/bin/bash"
```

`/bin/bash` does not exist on NixOS (only `/bin/sh` does). This only bites an account whose passwd shell field is empty, which anonctl's own provisioning does not produce, so it is a narrow edge.

Neither is a leak: a session with no usable commands, or a missing shell, fails closed. Both make the account unusable rather than unsafe, which is why this is an observation and not a fix task yet.
