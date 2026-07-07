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

## The concrete mechanism (confirmed against the shipped ruleset)

This is not hypothetical: it is the literal FIRST rule of the filter chain. `internal/nftables/nftables.go` emits, in `filter_out`:

```
type filter hook output priority filter; policy drop;
meta skuid != <anonUID> meta skuid != <shimUID> accept   # <-- every OTHER uid egresses freely
```

That first line is CORRECT for anonctl's scope (it must not break the rest of the machine, so it governs only the two UIDs and lets every other UID through). But it IS the row-7 escape made concrete: any socket the anon account can cause to be owned by a different UID (setuid, sudo, a triggerable daemon) matches this `accept` and egresses in the clear. So the escape is inherent to the per-UID design, not a bug to "fix" so much as a boundary to harden, prove where possible, and document loudly.

## Design pass: the four candidate shapes, RESOLVED

Resolved 2026-07-07 (design pass). anonctl commits to shapes 1, 2, 4 and REJECTS shape 3:

1. **Harden at `add`-time (COMMIT -> task).** Provision the anon account so it CANNOT trivially transition UID: no entry in sudoers (assert it has no sudo rights), a minimal PATH, and a documented recommendation to mount the account's reachable filesystem `nosuid` where practical (a setuid binary on a `nosuid` mount does not gain its owner's UID). Cheap, partial, worth doing regardless. This becomes the task `harden-anon-account-against-uid-transition`.
2. **A best-effort `verify` PROBE (COMMIT -> task).** A named assertion (`no-uid-transition-egress`) that actively tests the CONCRETELY ENUMERABLE escapes: (a) can the anon account reach the network via `sudo` (is sudo even available/permitted to it)? (b) does a small, documented set of common setuid/privileged network paths yield an off-box socket owned by a non-anon, non-shim UID? Reported HONESTLY as best-effort, NOT exhaustive: verify cannot enumerate every daemon on every host, so the assertion proves "the checked transition vectors do not escape" and the docs state the residual. This becomes the task `verify-no-uid-transition-egress`.
3. **A cgroup / network-namespace second layer (REJECT, with rationale).** Making forcing not rest on UID alone drifts anonctl toward netcage's model. anonctl's entire identity is per-UID transparent forcing on a SHARED host you log into natively (`sudo -iu anon`); wrapping the account in a netns would change what it IS and duplicate netcage. RESOLUTION: out of scope. If you need namespace-strength confinement, that is netcage (run it INSIDE the anon account, or use netcage directly). Record this boundary in the docs so it is a deliberate non-goal, not an oversight.
4. **Sharpen the documented residual (COMMIT -> docs, folded into task 1/2's docs criteria).** The README threat-model already lists "a process changing its own UID" as NOT defended; this sharpens that one sentence into a concrete subsection: the exact mechanism (the `skuid != ` accept), what anonctl DOES do about it (no-sudo provisioning + the best-effort verify probe), what it explicitly does NOT (namespace confinement -> that is netcage), and the honest residual (an arbitrary triggerable daemon on a busy host may still escape; the per-UID model cannot close that, only netns can).

## What this idea spawns (ready to task once promoted)

The design is now settled enough to task. In priority order:

- **`empirical-uid-transition-escape-audit` (a finding-gathering task, do first).** On a representative freshly-provisioned anon account, enumerate what actually transitions UID and egresses (sudo availability, setuid binaries on PATH and reachable mounts, dbus-activatable/socket-activated services the account can trigger). Output: a `work/notes/findings/` note that grounds tasks 1 and 2 in real vectors rather than a guessed list. HUMAN-run-ish (like the original manual recipe): it inspects a real host.
- **`harden-anon-account-against-uid-transition` (shape 1).** `add` provisions no-sudo + minimal PATH; `verify`/`status` can report the account has no sudo rights; docs recommend `nosuid` mounts. Depends on the audit for the exact hardening list.
- **`verify-no-uid-transition-egress` (shape 2).** The best-effort `no-uid-transition-egress` verify assertion over the enumerable vectors; honest best-effort framing; pinned in the JSON contract (ADR-0003). Depends on the audit.
- Docs sharpening (shape 4) folds into the acceptance criteria of the two tasks above rather than being its own task.

Treat the whole-OS-vs-per-account boundary honestly throughout: the right answer is "harden what we can, prove the enumerable vectors, document the rest loudly, and point at netcage for namespace-strength confinement", NOT "fully close it" (the per-UID model cannot).

## Cross-repo note

This idea is anonctl-specific by construction (netcage's netns model does not have the per-uid escape). It is recorded in netcage's finding only as "the one axis where netcage is structurally tighter than anonctl", not as a netcage task.
