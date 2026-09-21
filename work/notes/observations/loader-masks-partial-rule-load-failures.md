---
title: The early-boot loader reports success even when some rule files failed to load
slug: loader-masks-partial-rule-load-failures
---

Spotted while reading the boot journal during the live acceptance on telemaque (2026-09-21). Not the cause of anything observed there (the rules loaded correctly and matched the persisted files exactly), but it is a real gap in the one unit whose failure is fail-OPEN.

`systemd.LoaderUnit` generates:

```
ExecStart=/bin/sh -c 'for f in /etc/anonctl/nftables/*.nft; do [ -e "$f" ] && <nft> -f "$f"; done'
```

A shell `for` loop exits with the status of the **last** command it ran. So if an earlier `nft -f` fails (a corrupt rule file, a kernel module missing, a table name clash, a partially-written file after an unclean shutdown) and a later one succeeds, the loop still exits `0` and systemd records:

```
anonctl-nftables.service  Active: active (exited)  (code=exited, status=0/SUCCESS)
```

The operator, and `systemctl is-failed`, both see a healthy loader while one or more accounts have NO rules loaded. For an account whose baseline default-deny is the file that failed, that is precisely the fail-open state ADR-0005 exists to prevent: the resting DROP is absent, so the anon UID egresses in the clear, and the only signal is the absence of a table nobody is looking for.

Worth fixing with a status-accumulating loop so any failure surfaces, e.g. keeping a failure flag and exiting non-zero at the end, while still attempting EVERY file first (a proceed-and-report teardown shape, matching `runRm`'s existing discipline). Attempting all of them matters: aborting at the first failure would leave the remaining accounts unloaded too, turning one broken file into a host-wide outage of forcing.

Two related notes for whoever picks this up:

- The unit must stay a clean no-op when the rules dir is absent or empty (`add` has never run, or the last account was torn down), which is why the loop guards with `[ -e "$f" ]` today. A status-accumulating version must preserve that: an unmatched glob is not a failure.
- `verify` should probably assert the loader is not in a failed state as part of the boot-persistence work already tracked in `work/tasks/ready/verify-boot-enablement-and-loader-health.md`. That assertion only becomes meaningful once a partial failure actually produces a non-zero exit, so these two belong together.
