---
kind: finding
title: Tor IsolateSOCKSAuth is default-on; a distinct SOCKS username yields a distinct circuit/exit
slug: tor-isolatesocksauth-default
source: |
  Hand-validated by the anonctl maintainer's agent on a real host (Debian GNU/Linux 13
  "trixie", kernel 6.12.90+deb13.1-amd64, Tor 0.4.9.9) on 2026-07-07, plus two external
  authoritative sources cited inline (tor(1) man page and the Whonix "Stream Isolation"
  wiki page).
---

## Claim

Tor's `IsolateSOCKSAuth` is **on by default** for every `SocksPort`. Two SOCKS connections that present **different** SOCKS authentication (username/password) are never placed on the same circuit, so each distinct SOCKS username gets its own circuit and (in general) its own exit relay. This is the mechanism anonctl relies on to make one shared host-wide Tor daemon safe to share across multiple anon accounts: dial Tor with a per-account `<account>@` SOCKS username (empty password) and each account is on its own circuit/exit, so two anonctl accounts on one Tor are not cross-identifiable.

An **empty password** is sufficient: the username alone drives the isolation. The bare `<account>@` form the spec specifies works.

## External ground-truth (sources)

- **tor(1) man page** (Tor 0.4.9.9, `man tor`, "SocksPort ... isolation flags" section), verbatim:

  > **IsolateSOCKSAuth** - Don't share circuits with streams for which different SOCKS authentication was provided. (For HTTPTunnelPort connections, this option looks at the Proxy-Authorization and X-Tor-Stream-Isolation headers.) **On by default; you can disable it with NoIsolateSOCKSAuth.**

  Same text in the published Debian testing manpage: https://manpages.debian.org/testing/tor/torrc.5.en.html

- **Whonix "Stream Isolation"** (https://www.whonix.org/wiki/Stream_Isolation): documents that presenting a distinct SOCKS username/password per application ("stream isolation aware applications ... and/or configurations such as Tor SocksPort") places each stream on a different Tor circuit/exit and thereby prevents identity correlation through circuit sharing. Whonix's own per-application SocksPorts and uwt wrappers use exactly this to keep applications on separate circuits.

## Empirical confirmation (commands actually run, outputs actually observed)

Host: Debian 13, Tor 0.4.9.9, `SocksPort 127.0.0.1:9050`. `/etc/tor/torrc` had **no** explicit `SocksPort` or `IsolateSOCKSAuth`/`NoIsolateSOCKSAuth` line (only commented-out defaults), so the compiled-in default (`IsolateSOCKSAuth` on) is in force. Verified via:

```
grep -iE 'SocksPort|IsolateSOCKSAuth' /etc/tor/torrc
# -> only commented "#SocksPort 9050 ..." lines; no Isolate/NoIsolate line -> defaults apply
```

Different username -> different exit; same username -> same exit; empty password still isolates:

```
# non-empty password form
curl -s --socks5-hostname anon:x@127.0.0.1:9050  https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"45.84.107.33"}
curl -s --socks5-hostname anon2:x@127.0.0.1:9050 https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"64.190.76.14"}       <- DIFFERENT username -> DIFFERENT exit
curl -s --socks5-hostname anon:x@127.0.0.1:9050  https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"45.84.107.33"}       <- SAME username -> SAME circuit/exit (stable)

# EMPTY password form (the <account>@ the spec specifies)
curl -s --socks5-hostname "anon:@127.0.0.1:9050"        https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"45.84.107.76"}
curl -s --proxy "socks5h://anon@127.0.0.1:9050"         https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"45.84.107.76"}       <- "anon:" and "anon@" agree (same circuit)
curl -s --socks5-hostname "anon2:@127.0.0.1:9050"       https://check.torproject.org/api/ip
#   -> {"IsTor":true,"IP":"192.42.116.108"}     <- DIFFERENT username, empty pw -> DIFFERENT exit
```

Observed result: distinct SOCKS usernames land on distinct exits (`45.84.107.x` vs `64.190.76.14` vs `192.42.116.108`); the same username is stable across calls; and an **empty** password isolates just as well as a non-empty one. This confirms both the claim and that the `<account>@`-with-empty-password form is the right one for anonctl to dial.

## Implication for anonctl

The shim, when the endpoint is Tor (`tor-shared` share-class), must dial the SocksPort with SOCKS username = the account name (e.g. `anon`, `anon-<name>`) and an empty password. That is a **socks5h** dial (name resolved remotely by Tor). This is what makes a single host-wide Tor share-safe across accounts; a plain `socks-peruser` endpoint has no such per-username isolation and must be used by at most one account (per the spec's endpoint share-class axis).
