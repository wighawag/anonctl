---
kind: idea
title: Investigate the UID-transition escape (anonctl's sharpest structural edge vs Tails' whole-OS model)
slug: uid-transition-escape-investigation
status: proposed
---

## The idea

Row 7 of the Tails leak catalogue (`work/notes/findings/tails-network-filter-lessons.md`) is anonctl's single most important NOVEL weakness, and it is a genuine design question, not a straight build, which is why it is an idea and not a task yet.

anonctl forces egress by `meta skuid <anonUID>`: the nftables rules match the SOCKET-OWNING UID. Tails controls the ENTIRE OS UID map, so every user is accounted for. anonctl runs on a machine full of OTHER UIDs. If the anon account can cause a socket to be owned by a DIFFERENT uid, that socket does not match `skuid == anonUID` and egresses IN THE CLEAR, bypassing all the forcing. Vectors to consider:

- a **setuid** binary the anon account can execute (its socket is owned by the target uid, e.g. root);
- **`sudo`** (if the anon account has any sudo rights at all);
- a **triggerable system daemon / shared service** the anon account can cause to make an outbound connection on its behalf (a cron job, a dbus-activated service, a local HTTP service that fetches a URL, a print/scan/avahi daemon);
- any **socket-activation / passing** path where the anon account hands work to a differently-owned process.

This is the exact spot where "one account, not the whole OS" is structurally WEAKER than Tails. It does NOT apply to netcage (a container netns confines by NAMESPACE, not by uid, so there is no per-uid escape inside the jail: a genuine advantage of the netns model, already recorded in netcage's `learning-from-anonctl-tails-leak-catalogue.md`).

## Why it is an idea, not yet a task

The RESPONSE is an open design question with several candidate shapes, some of which anonctl may not be able to fully close (and saying so honestly is a valid outcome):

1. **Provision the anon account with NO sudo and a minimal, audited PATH** (reduce the setuid/sudo surface at `add` time). Cheap, partial, worth doing regardless.
2. **A `verify` PROBE**: enumerate what the anon account can execute that transitions uid, and actively test whether any reachable setuid/privileged/daemon path yields an off-box socket owned by a non-anon, non-shim uid that escapes forcing. This is a real, high-value assertion but non-trivial to make robust (the enumeration is host-specific).
3. **A cgroup/network-namespace-assisted second layer** so forcing does not rest on uid alone (this drifts toward netcage's model and may be out of scope / a different product; evaluate honestly).
4. **Document it as an accepted residual with mitigations** (the README threat-model already lists "a process changing its own UID" as NOT defended; this idea would sharpen that from a sentence into a concrete, tested posture).

The investigation should: (a) enumerate the real vectors on a representative host, (b) decide which anonctl can close at `add`-time (sudo/PATH hardening) vs prove-absent in `verify` vs must document as residual, and (c) likely spawn its OWN finding (the empirical "what escapes on a real machine") plus one or more tasks once the design is settled. Treat the whole-OS-vs-per-account boundary honestly: some of this is inherent to the per-account model and the right answer may be "harden what we can, prove what we can, document the rest loudly", not "fully close it".

## Cross-repo note

This idea is anonctl-specific by construction (netcage's netns model does not have the per-uid escape). It is recorded in netcage's finding only as "the one axis where netcage is structurally tighter than anonctl", not as a netcage task.
