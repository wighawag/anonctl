---
kind: finding
title: The LAN exemption never completed because the baseline default-deny was exemption-blind (a terminal drop overriding the forcing accept); plus a verify probe timeout race that false-failed leak-drop-v6 / split-tunnel-tight
slug: split-tunnel-broken-by-exemption-blind-baseline
source: |
  Live diagnosis on the anonctl maintainer's real host `nono` (bare-metal, a
  Tailscale + GNOME workstation), 2026-07-09, driven from an interactive session
  against the INSTALLED binary (anonctl v0.1.7+dirty). Trigger: `sudo anonctl verify`
  on a `socks-peruser` account (endpoint socks5h://127.0.0.1:1080) with a box-wide
  default LAN exemption `192.168.1.150:8080` (a local model host). Two of the eleven
  assertions failed. All nft/route/probe evidence below was captured read-only on the
  host with sudo; the fixes were built, installed, and re-verified GREEN on the same
  host.
---

## Symptom

`anonctl verify` reported two failures, in two DIFFERENT modes across two runs:

1. First run: `leak-drop-v6` AND `split-tunnel-tight` both failed with
   `the anon-UID probe could not run (setpriv could not drop to uid 30034, or the
   shim probe did not execute):` and an EMPTY trailing detail.
2. After fixing (1): `leak-drop-v6` PASSED, but `split-tunnel-tight` now failed with
   a REAL verdict: `the exempted destination 192.168.1.150:8080 was NOT reachable
   directly: the split-tunnel hole is broken`.

Two independent bugs, uncovered in sequence.

## Bug 1: verify probe timeout race (a false "probe could not run")

`probeAsAnon` (internal/verify/checks_live.go) execs the installed shim as a dialer
under `setpriv --reuid <anon>` inside `exec.CommandContext(ctx, ...)`, and greps the
output for `REACHED` / `DROPPED:`. Neither token => it declares the probe un-runnable.

The outer context was `context.WithTimeout(ctx, 3*time.Second)` while the shim's own
dialer used `shim.ProbeTimeout` = **3s**. Equal timeouts race: the outer clock starts
FIRST and must still fork+exec setpriv + privdrop before the inner dialer even begins
its 3s, so on any FULL-WINDOW dial (a silently-dropped v6 SYN with no fast RST; a slow
LAN host) the outer deadline fires first and `CommandContext` SIGKILLs the shim before
it can `fmt.Print` its verdict. Empty stdout => misread as "could not run". Only the
two shim-dial probes that can burn the whole window hit it; the nft-counter / ping /
udp probes resolve fast and passed. The sibling `pingAsAnon` already documented the
right shape (`ping -W 2` under a 3s context: a 1s margin).

Fix: `probeExecBudget = shim.ProbeTimeout + 1*time.Second` for the outer exec, and
`runSetprivProbe` now distinguishes `ctx.Err() == context.DeadlineExceeded` (report an
honest "timed out before printing a verdict") from a genuine setpriv/privdrop failure,
instead of blaming "setpriv could not drop to uid". This bug's polarity was safe (it
FAILED, never false-greened), but it blocked a healthy host from verifying and sent
diagnosis down the wrong path (setpriv/uid, not a timeout).

## Bug 2: the baseline default-deny was exemption-blind (the real one)

Evidence that isolated it:
- `sudo nft list table inet anonctl_anon`: BOTH exemption halves were present and
  correctly ordered (nat `... 192.168.1.150 tcp dport 8080 return` before the
  redirects; filter `... 192.168.1.150 tcp dport 8080 accept` before the drops).
- `ip route get 192.168.1.150 uid 30034` == `... uid 1000`: IDENTICAL route
  (`dev wlp1s0 src 192.168.1.61`). Tailscale was NOT diverting it (ruled out).
- The anon UID REACHED non-exempt LAN hosts (`192.168.1.1:80`, `192.168.1.150:22`)
  but TIMED OUT (i/o timeout, no RST) on the single EXEMPTED `192.168.1.150:8080`.
  That inversion is the tell.

Why: there are TWO base chains for the anon UID at the SAME `output` / `priority
filter` hook: the forcing `filter_out` (which `accept`s the exemption) and the
standing baseline `baseline_out` (`ip daddr != 127.0.0.0/8 drop`). In nftables a
`drop` is TERMINAL across chains at a hook and a non-terminal `accept` cannot override
it. Everything EXCEPT the exemption is redirected to loopback first (the baseline
`return`s loopback), so it never reaches the broad drop; the exemption is deliberately
NOT redirected (that is the whole point of a direct LAN hole), so it arrives at the
baseline with its real LAN daddr and the baseline's terminal drop kills it BEFORE the
forcing accept can matter. The baseline knew about loopback but not about exemptions.

It passed in tests only because the nftables integration test loaded the forcing table
WITHOUT the baseline (the two tables were never proven together with an exemption).

Fix: `GenerateBaseline` now takes the exemption set and emits `meta skuid <anon>
<exemptMatch> return` before its broad drop (reusing the SAME `exemptMatch` the forcing
return+accept use, so the three cannot diverge). Threaded through `ApplyBaseline`,
`forcing.Install` + `forcing.Reconfigure` (so `update --allow-direct` fixes the LIVE
baseline, not just the persisted file), and `systemd.WriteAccount` (so the persisted
`<account>.baseline.nft` restores the return at boot). Documented as a new decision
point in docs/adr/0005. Regression tests: baseline generator (return precedes drop;
inert when empty), `WriteAccount` (persisted baseline carries the return), and the
nftables integration test now loads the baseline WITH an exemption and asserts it.

## After the fix (live, GREEN)

`sudo anonctl update --endpoint socks5h://127.0.0.1:1080` (re-runs Reconfigure ->
re-applies the baseline with the exemption return), then `sudo anonctl verify`: all 11
assertions PASS, including `split-tunnel-tight: exempted 192.168.1.150:8080 reachable,
but the rest of the LAN / loopback stays redirected-or-dropped (tight)`. The live
`anonctl_baseline_anon` now shows `meta skuid 30034 ip daddr 192.168.1.150 tcp dport
8080 return` immediately before `ip daddr != 127.0.0.0/8 drop`.

## Lesson

Any anon-UID egress that forcing does NOT redirect to loopback (today: only LAN
exemptions) MUST also be `return`ed by the baseline, or the baseline's terminal
non-loopback drop silently breaks it. The invariant "a drop in one chain overrides an
accept in another at the same hook" (ADR-0005) applies to exemptions exactly as it
does to loopback. When adding any future direct (un-forced) egress class, thread it
into BOTH the forcing chains AND the baseline, and prove the two tables together, not
in isolation.
