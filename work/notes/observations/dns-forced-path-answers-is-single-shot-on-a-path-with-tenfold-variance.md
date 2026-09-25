---
title: dns-forced-path-answers is single-shot on a path whose honest variance is tenfold, and it gates use/exec
slug: dns-forced-path-answers-is-single-shot-on-a-path-with-tenfold-variance
---

Noticed on a NixOS host (telemaque, anonctl 0.9.0, two adopted accounts, endpoint `socks5h://127.0.0.1:9050` against the system tor) while verifying an unrelated feature. Off that change's path and not fixed by it.

## What happened

```
[FAIL] dns-forced-path-answers: the shim ANSWERED a query from the account to 127.0.0.53 and the
answer never arrived: conntrack un-NATs the reply back to source 127.0.0.53 before delivering it,
and something on the host's input path dropped it there
(no answer: read udp 127.0.0.1:54293->127.0.0.53:53: i/o timeout)

anonctl: use: anon-01 did NOT verify as anonymized; refusing to open a shell
```

Fourteen of fifteen passed in the same run, `dns-remote` and `anonymized-exit` among them. Every run since has been 15/15, across a dozen or more. Nothing on the host's DNS path had been restarted: `systemd-resolved`, `firewall`, `nftables`, `tailscaled`, `nscd` and `anonctl-shim@<account>` were all still at their boot timestamps with `NRestarts=0`.

## The timing distribution, which is the useful part

Measured INSIDE the account's own shell, so that nothing else is in the clock (`TIMEFORMAT=%3R; time getent ahostsv4 <name>`):

```
forced, example.com, 10 runs:      0.257 0.611 2.195 2.214 2.394 2.512 0.739 2.071 2.195 2.356
forced, check.torproject.org, 3:   0.666 2.283 3.600
unforced account, example.com, 3:  0.018 0.003 0.002
```

Median about 2.2s, spread 0.26s to 3.6s, against 2 to 18 MILLISECONDS unforced. So the honest variance on a warm path is roughly tenfold, and the typical cost is about four times the "~0.5s on a warm circuit" figure in `DNSProbeTimeout`'s comment. That comment is not wrong, it is optimistic for this host.

**Worth measuring this way rather than through `exec`.** A first attempt timed `anonctl exec --as <n> getent ...` and produced 5.067s and 4.999s, which looked like a five-second timeout firing somewhere. It was not: `exec` runs the whole verify suite before the command, so those numbers were verify plus the lookup. Anyone repeating this should time inside `use`, not through `exec`.

## What the failure was not

Not the 5s-versus-20s problem the comment already fixed: the budget was twenty seconds and the answer did not arrive in it, while the worst honest sample here is 3.6s. That is a 5.5x margin over anything observable.

## What it leaves

Two candidates, which one sample cannot separate. A cold circuit build on a first query after idle, which `DNSProbeTimeout`'s comment explicitly sizes the window for and which can exceed any warm sample. Or a genuinely lost answer, the un-NAT-then-drop the failure text describes, occurring transiently rather than structurally (a structural one could not pass fifteen times afterwards).

## The suggestion, which is not "raise the timeout"

The window is already generous and raising it would only make a real failure slower to report. The narrower observation is about SHAPE: this check is single-shot on a path with tenfold variance, and it gates `use` and `exec`. So its false-negative rate is the rate at which an operator is locked out of a healthy account, and the message they get confidently describes a kernel-level drop that did not happen, which sends them to `nft` and `conntrack` rather than to a retry.

A second attempt before the verdict costs nothing when the path is healthy (the first query answers in ~2s) and would separate "one answer was lost, or one circuit was cold" from "this path is broken", which is the distinction the check exists to draw. If a retry is unwelcome, the alternative is cheaper still: say so in the failure text, so the first thing the operator does is run `verify` again rather than open the ruleset.

## Not asked for, but adjacent

`exec` running the full verify suite per invocation is correct and it does make `exec` unsuitable for timing anything, and awkward for scripting a loop. Not a complaint, just the reason the first numbers in this note were wrong.
