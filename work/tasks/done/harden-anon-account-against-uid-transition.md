---
title: Harden the anon account against UID transition at add-time (no sudo, minimal PATH, nosuid guidance)
slug: harden-anon-account-against-uid-transition
spec: per-uid-kernel-anonymized-egress
blockedBy: [empirical-uid-transition-escape-audit]
covers: [30]
---

## What to build

Shape 1 of the row-7 design pass (`work/notes/ideas/uid-transition-escape-investigation.md`): reduce the UID-transition escape surface at `add`-time, so the anon account cannot trivially cause a socket owned by a different uid to egress in the clear (bypassing `meta skuid` forcing). Cheap, partial, worth doing regardless; the exact hardening list comes from the audit finding.

Based on `work/notes/findings/uid-transition-escape-surface.md` (produced by the audit task), harden provisioning:

- **No sudo:** `add` provisions the anon account with NO sudoers entry, and does not add it to any sudo/wheel group. `verify`/`status` can REPORT that the account has no sudo rights (a positive check, not just an absence).
- **Minimal PATH:** provision the account with a minimal, documented PATH / login environment that does not gratuitously expose setuid network binaries (exact list from the audit).
- **nosuid guidance (docs, not enforced by anonctl):** document the recommendation to mount the account's reachable filesystems `nosuid` where practical (a setuid binary on a `nosuid` mount does not gain its owner's uid), since anonctl cannot own the host's mount policy.
- **Docs (shape 4, folded in here):** sharpen the README threat-model's one-line "a process changing its own UID" residual into a concrete subsection: the exact mechanism (the `skuid != ` accept), what anonctl DOES about it (no-sudo provisioning + the best-effort verify probe from the sibling task), what it does NOT (namespace confinement, that is netcage), and the honest residual (an arbitrary triggerable daemon on a busy host may still escape; only netns closes that).

## Acceptance criteria

- [ ] `add` provisions the anon account with no sudoers entry and no sudo/wheel group membership; a test asserts the provisioning commands do not grant sudo.
- [ ] `verify`/`status` can positively report the account has no sudo rights (or the check is surfaced somewhere an operator sees it).
- [ ] The account is provisioned with a minimal, documented login PATH/environment per the audit finding.
- [ ] The README threat-model gains a concrete UID-transition subsection (mechanism + what anonctl does / does not do + the honest residual + the pointer to netcage for netns-strength confinement) and the nosuid mount recommendation.
- [ ] Tests cover the new behaviour (mirror the repo's existing test style; system-mutating parts behind the `integration` tag, isolated to a throwaway account).

## Blocked by

- `empirical-uid-transition-escape-audit` - the finding that lists the real vectors this hardening closes (the exact PATH / setuid / sudo picture).

## Prompt

> Goal: shrink the UID-transition escape surface at `add`-time (no sudo + minimal PATH + nosuid docs) and sharpen the documented residual. Shape 1 (+ shape 4 docs) of the row-7 design pass (`work/notes/ideas/uid-transition-escape-investigation.md`). Stories: sharpens story 30 (honest threat model).
>
> FIRST, check drift: read the audit finding `work/notes/findings/uid-transition-escape-surface.md` (the REAL vectors to close - do not guess), the shipped `internal/provision/provision.go` (`Add`, `ensureLoginAccount` - where the account is created; today it is `useradd --create-home --shell /bin/bash` with no hardening), and the README threat-model section (the current one-line "a process changing its own UID" residual to expand).
>
> Domain vocabulary: forcing is `meta skuid <anonUID>`; the escape is a socket owned by a DIFFERENT uid (setuid/sudo/daemon) hitting the ruleset's `skuid != anon skuid != shim accept`. anonctl cannot close this fully (the per-UID model cannot); the honest posture is harden-what-we-can, prove-the-enumerable (sibling task), document-the-rest, and point at netcage for netns confinement.
>
> Where to look / seams: provisioning (`internal/provision`, behind its Runner seam so unit tests use a fake, no real useradd), the sudo-absence check (positive assertion), the README threat-model. "Done" = a freshly-added anon account has no sudo and a minimal PATH, verify/status can say so, and the docs concretely describe the residual + the nosuid recommendation. RECORD any non-obvious in-scope decision (the exact PATH, how the sudo-absence check is surfaced) per the task-template guidance; if a decision meets the ADR bar, write one.
