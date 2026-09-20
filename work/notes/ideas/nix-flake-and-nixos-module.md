---
title: Ship a Nix flake with a nixosModule so Nix users get a declaratively packaged anonctl
slug: nix-flake-and-nixos-module
---

Split out of `portable-unit-install-and-enablement` as explicitly out of scope, and recorded so the reasoning is not lost.

`anonctl` now installs and enables itself correctly on NixOS (units in `/usr/local/lib/systemd/system`, anonctl's own `.wants` symlinks, resolved binary paths). That makes the CLI WORK on NixOS, which was the blocking problem. It does not make anonctl a good NixOS CITIZEN: the binaries and units are still imperative state that `nixos-rebuild` knows nothing about.

The natural next step is a flake exposing a package plus a `nixosModule` that declares the two binaries and, optionally, the units, so a fleet can put anonctl in its system closure.

Two reasons this was NOT done as part of the fix:

1. **It does not help anyone who is not using the module.** A flake is opt-in packaging; the CLI has to work unaided regardless, and that is what the fix delivers. Shipping the flake first would have left the plain-CLI NixOS user exactly as stuck.
2. **It overlaps with a bigger, genuinely different design: "externally managed units".** The correct shape for NixOS's model is that the HOST declares the units and the binaries, and anonctl manages only what is really per-account and mutable (the accounts, the ledger under `/etc/anonctl/`, the nftables forcing). That is the same division the rest of the design already uses and it fits `users.mutableUsers = true`, which is what lets `anonctl add` create accounts out of band at all. But it SPLITS OWNERSHIP of the forcing between the host and the tool, which is a real architectural decision with failure modes of its own (what happens when the declared unit and anonctl's expectation drift?). It deserves its own spec and an ADR, not a corner of a bug fix.

So the order that makes sense is: the CLI works unaided (done) -> decide the ownership split for externally-managed units (spec + ADR) -> package it, with the flake reflecting whatever that decision was. Doing the flake before the ownership decision would bake in an answer by accident.
