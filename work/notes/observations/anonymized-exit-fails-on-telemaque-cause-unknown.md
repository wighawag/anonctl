---
title: anonymized-exit fails with curl exit 6 on telemaque, cause not established
slug: anonymized-exit-fails-on-telemaque-cause-unknown
---

Parked, deliberately, during the live acceptance run on telemaque (2026-09-21). Recording it so the evidence is not lost, and recording just as clearly that it is NOT diagnosed.

`anonctl verify` on that host reports:

```
[FAIL] anonymized-exit (error: forced-path curl as anon UID failed: exit status 6 ())
[PASS] dns-remote: check.torproject.org was resolved proxy-side (remotely, via the endpoint), not locally
```

curl exit 6 is `CURLE_COULDNT_RESOLVE_HOST`. Tor itself is healthy: a SOCKS fetch from an ordinary UID returns `{"IsTor":true,"IP":"192.42.116.59"}`, `tor.service` is active and bootstrapped, and the shim unit is `active` with `Result=success`, `ExecMainStatus=0`.

What makes it confusing rather than merely broken: `dns-remote` PASSES in the same run, which reads as "resolution via the endpoint works", while `anonymized-exit` fails on resolution.

Environmental facts that may or may not be involved, measured but not tied to the failure:

- `/etc/resolv.conf` is tailscale MagicDNS: `nameserver 100.100.100.100`, plus an IPv6 `nameserver fd7a:115c:a1e0::53`, with `search bonobo-gentoo.ts.net lan`.
- The shim's DNS forwarder listens on `127.0.0.1:19053`, IPv4 only. The forcing nat chain is in an `inet` table, so `udp dport 53 redirect to :19053` applies to IPv6 too and would redirect a v6 query to `[::1]:19053`, where nothing is listening.
- The tor log recorded, during the run: `[warn] Rejecting SOCKS request for anonymous connection to private address [scrubbed].` Tor refuses private destinations, and `100.100.100.100` is CGNAT space.
- The host runs NixOS's scripted iptables firewall (`networking.nftables.enable = false`), so `iptables` is `xtables-nft-multi` and anonctl's native `inet` tables coexist with compat `ip`/`ip6` tables plus tailscale's `ts-*` chains.

**Why it is parked rather than pursued.** The run in which this was measured turned out to be invalid for a different reason: `users.mutableUsers = false` had deleted the anon account at boot (see `work/notes/findings/nixos-account-conventions-break-anonctl-provisioning.md`), so several other assertions in the same report are uninterpretable too. Chasing this one before there is a host where the account survives a reboot risks diagnosing an artifact. Note the pre-reboot run on the same host ALSO showed this failure, with the account present, so it is probably real and probably independent of the account deletion; that is a hypothesis, not a finding.

Next step when a valid host exists: re-run `anonctl verify`, and if it still fails, resolve as the anon UID directly (`setpriv --reuid <uid> getent hosts check.torproject.org`, and a query pinned to each nameserver in turn) to separate "the v6 nameserver is redirected into a black hole" from "tor refuses the CGNAT destination" from "something else entirely".
