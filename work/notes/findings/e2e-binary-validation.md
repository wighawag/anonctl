---
kind: finding
title: First end-to-end validation of the anonctl binary on a real host (add / verify / reboot / rm)
slug: e2e-binary-validation
source: |
  First real end-to-end run of the COMPILED anonctl binary (never before run: no
  `anonctl add` had ever provisioned a real account + installed real forcing, and
  no `anonctl verify` had ever run against a live setup). Driven by the agent, on
  a real-but-disposable Linux host, on 2026-07-09.

  Because the maintainer's box `nono` is a bare-metal workstation (NOT a throwaway
  VM: `systemd-detect-virt` -> `none`) and the run mutates the system (creates
  users, loads firewall rules, installs a systemd unit) and step 5 calls `reboot`,
  the validation was run inside a DISPOSABLE, ISOLATED podman container instead of
  on the host directly, at the maintainer's request ("what I care is that we can
  run the test and then have our system exactly as it was before"). The container
  is a full systemd-PID1 Debian trixie sandbox with its OWN Tor, its OWN network
  namespace, and its OWN users/units, torn down with `podman rm`. The host `nono`
  had NO users, units, /etc/anonctl, /usr/local/bin/anonctl-shim, or nft-table
  changes made to it, and was NOT rebooted. The container's kernel is the host
  kernel (shared, as always with containers); everything else is isolated.

  Every command below was actually run inside that container and every output is
  its real observed output; nothing is fabricated. Where a check could not be run
  as a true bare-metal power-cycle (the reboot step), that is stated explicitly and
  the substitute (a container restart = systemd re-run of its boot sequence, plus
  the repo's own boot-invariant integration test) is labelled as such.

  Environment (observed, inside the container):
  - OS: Debian GNU/Linux 13 (trixie), VERSION_ID=13.
  - Kernel (shared with host): 6.12.90+deb13.1-amd64.
  - systemd: 257 (257.13-1~deb13u1), running as PID 1 in the container.
  - Tor: 0.4.9.11 (container's own tor.service, bootstrapped; SocksPort 127.0.0.1:9050).
  - nftables: v1.1.3 (Commodore Bullmoose #4).
  - Go: go1.26.0 linux/amd64 (toolchain auto-fetched; Debian trixie ships 1.24).
  - Host runtime: podman 5.4.2 rootless (no host sudo was available/used).
  - anonctl build: from repo HEAD 16f8be4, `anonctl --version` -> `anonctl dev`.
    Two binaries built: the shipped `anonctl` (default build) and `anonctl-live`
    (`go build -tags integration`), the live-verify build the README points to.
---

## Verdict

**anonctl runs end-to-end on a real host: YES-WITH-CAVEATS.**

The provisioning, kernel forcing, per-UID anonymization, DNS-over-SOCKS, fail-closed drops, LAN split-tunnel, the `:53` guardrail, `update`, and teardown all work on a real host and reproduce the hand-validated recipe. Two things do NOT work as the README/tests claim, and one is serious:

1. **BOOT INVARIANT IS BROKEN on a host where `nftables.service` is not already enabled (serious).** After a reboot the anon UID egressed with the host's REAL public IP in the clear, because anonctl's rule-persistence rides on `nftables.service` (a systemd drop-in `ExecStartPost`) but anonctl never ENABLES `nftables.service`, and Debian ships it disabled. The shim came back; the kernel forcing did not. This directly contradicts the README's "the default-DROP loads early, so there is never a window where the account has un-anonymized egress."
2. **`anonctl verify` cannot certify a correctly-working setup (serious for the trust anchor).** 5 of 9 live assertions FALSE-FAIL against a genuinely-anonymized account, so `verify` never returns green and (as a knock-on) the post-verify marker is never written. The failures are probe-mechanism bugs, not real leaks (proven by hand below), but a trust anchor that always reports red on a healthy host is unusable as-is.

Caveats enumerated in full in BUGS/GAPS.

## PART A: the automated integration suite

Command (as root, inside the container):

    go test -tags integration ./...

Result: **8 packages PASS, 2 packages FAIL.** These had never run before. Full log at `/tmp/anonctl-integration.log` (in the run); reproduced verbatim:

```
ok    github.com/wighawag/anonctl                       89.598s
?     github.com/wighawag/anonctl/cmd/anonctl-shim      [no test files]
ok    github.com/wighawag/anonctl/internal/accountconfig 0.009s
ok    github.com/wighawag/anonctl/internal/cli          0.009s
ok    github.com/wighawag/anonctl/internal/endpoint     0.008s
ok    github.com/wighawag/anonctl/internal/forcing      0.009s
ok    github.com/wighawag/anonctl/internal/lanexempt    0.007s
ok    github.com/wighawag/anonctl/internal/marker       0.009s
ok    github.com/wighawag/anonctl/internal/nftables     0.702s
FAIL  github.com/wighawag/anonctl/internal/provision    0.861s
ok    github.com/wighawag/anonctl/internal/shim         4.015s
?     github.com/wighawag/anonctl/internal/socks5hfixture [no test files]
ok    github.com/wighawag/anonctl/internal/systemd      0.531s
FAIL  github.com/wighawag/anonctl/internal/verify       86.922s
```

No test SKIPPED (root was present, and `nft`/`setpriv`/`useradd`/Tor@9050 were all available inside the container, so the root/tor/tool gates were all satisfied). The `systemd` package's boot-invariant test PASSED (see the boot nuance in step 5).

### FAIL 1: `internal/provision` -> `TestRealProvisionRoundTrip` (TEST BUG, product is correct)

```
--- FAIL: TestRealProvisionRoundTrip (0.85s)
    provision_integration_test.go:101: "/home/anon-anonctlitest/.profile" must pin
    the minimal login PATH "/usr/local/bin:/usr/bin:/bin"; got:
        # ~/.profile: executed by the command interpreter for login shells.
        ...(the default Debian skel .profile)...
```

Diagnosed to root cause: the UNIT suite's `TestMain` (`internal/provision/provision_test.go:22`) globally replaces the `provision.WriteLoginEnv` seam with a NO-OP and never restores it. Under `-tags integration`, `provision_test.go` and `provision_integration_test.go` compile into ONE test binary with ONE shared `TestMain`, so that no-op is in effect when `TestRealProvisionRoundTrip` runs `provision.Add`. The real login-env writer therefore never runs, and the `.profile` stays as the skel copy. Proven directly with a throwaway probe test: under `-tags integration`, `provision.WriteLoginEnv(bogus-account)` returned `nil` (a no-op) instead of the real writer's error, confirming the seam is stubbed.

The PRODUCT is correct: a real `anonctl add anonctlitest` wrote the managed profile every time:
```
# /home/anon-anonctlitest/.profile
# Managed by anonctl: minimal login PATH for the anon account.
...
export PATH=/usr/local/bin:/usr/bin:/bin
```
So this is a test-only defect (a leaked global test seam), not a product defect.

### FAIL 2: `internal/verify` -> `TestLiveLeakAndClosuresAgainstRealRuleset` (`leak-drop-v4`)

```
--- FAIL: TestLiveLeakAndClosuresAgainstRealRuleset (1.01s)
    verify_integration_test.go:307: leak-drop-v4 must hold (a direct v4 dial from
    the anon UID must be DROPPED); got {Name:leak-drop-v4 Ok:false Detail:a direct
    v4 connection from the anon UID REACHED its target: fail-closed is broken (a leak)}
2026/... relay: socks dial 127.0.0.1:1: socks connect tcp 127.0.0.1:42655->127.0.0.1:1:
    unknown error host unreachable (drop, fail-closed)
```

This is the same probe-mechanism bug as the live-verify failures in PART B step 3 (see BUGS/GAPS #2). The probe dials `127.0.0.1:1` (a LOOPBACK port) as the anon UID and expects a DROP. But the nat chain redirects ALL of the anon UID's TCP into the shim relay BEFORE the filter chain's `127.0.0.0/8 drop` (closure a) can see the original destination, so the TCP handshake COMPLETES with the relay (which then fails the upstream SOCKS dial, "host unreachable"). `probeAsAnon` reads "handshake completed" as "REACHED", so the assertion false-fails. The real OFF-BOX leak drops DO hold (proven by hand in PART B step 2).

## PART B: the real operator flow

Note on running "as the account": the container has no `sudo` (good for the threat model, but the README's `sudo -u anon <cmd>` is unavailable), so every "as anon" command below was run via `setpriv --reuid <anonuid> --regid <anongid> --clear-groups <cmd>`, which owns the socket by the anon UID exactly as `sudo -u anon` would (the nft rules key on `meta skuid`).

Baseline for the anonymization comparison: the container's DIRECT egress IP (as root, no forcing) = **`51.7.210.66`** (`{"IsTor":false,"IP":"51.7.210.66"}`). This is also the host's real public IP (podman NAT egresses through the host).

### Step 1: provision + force (`anonctl add`) -> PASS

```
$ anonctl add
provisioned + forced anon (shim anon-shim, endpoint socks5h://127.0.0.1:9050)
note: anonctl does NOT manage the endpoint's own service; enable your endpoint ...
run `anonctl verify ` to prove the account is anonymized       (exit 0)

$ getent passwd anon anon-shim
anon:x:1001:1001::/home/anon:/bin/bash
anon-shim:x:996:996::/home/anon-shim:/usr/sbin/nologin
```

nftables ruleset loaded (`nft list table inet anonctl_anon`), with both closures and the default-DROP exactly as the hand recipe prescribes:
```
chain nat_out { type nat hook output priority dstnat; policy accept;
    meta skuid != 1001 return
    ip daddr 127.0.0.1 tcp dport { 19050, 19053 } return
    ip daddr 127.0.0.1 udp dport 19053 return
    udp dport 53 redirect to :19053
    tcp dport 53 redirect to :19053
    meta l4proto 6 redirect to :19050 }
chain filter_out { type filter hook output priority filter; policy drop;   # DEFAULT-DROP
    meta skuid != 1001 meta skuid != 996 accept
    meta skuid 996 ip daddr 127.0.0.1 tcp dport 9050 accept     # (b) only the shim may dial Tor
    meta skuid 996 oifname "lo" accept
    meta skuid 996 accept
    meta skuid 1001 ip daddr 127.0.0.1 tcp dport 9050 drop      # (b) anon may NOT dial Tor
    meta skuid 1001 ip daddr 127.0.0.1 tcp dport { 19050, 19053 } accept  # (a) only its shim ports
    meta skuid 1001 ip daddr 127.0.0.1 udp dport 19053 accept
    meta skuid 1001 ip daddr 127.0.0.0/8 drop                   # (a) no other loopback
    meta skuid 1001 ip6 daddr ::1 drop
    meta skuid 1001 ip6 daddr ::/0 drop }                       # IPv6 dropped, never leaked
```

Shim unit `systemctl status anonctl-shim@anon`: **enabled + active (running)**, PID 5242:
```
/usr/local/bin/anonctl-shim -relay 127.0.0.1:19050 -dns 127.0.0.1:19053 -proxy 127.0.0.1:9050 -socks-user anon -upstream-dns 1.1.1.1:53
```

Marker `/etc/anonctl/anon.json`: **absent pre-verify** (correct: written only after verify passes).

### Step 2: prove anonymization by hand, AS anon -> PASS (this is the core "does it work" result)

```
# anon exit via Tor:
$ setpriv --reuid 1001 --regid 1001 --clear-groups curl -s https://check.torproject.org/api/ip
{"IsTor":true,"IP":"107.189.13.253"}
$ setpriv ... curl -s https://api.ipify.org
107.189.13.253
```
**Proof of anonymization: the anon exit IP `107.189.13.253` (IsTor:true) differs from the host's real IP `51.7.210.66`.**

```
# DNS resolves through the shim:
$ setpriv ... dig +short example.com A            -> 104.20.23.154 / 172.66.147.243
# DNS interception proof (the recipe's "DNS subtlety"): a BLACK-HOLE resolver still answers,
# proving every @<resolver>:53 is transparently redirected to the shim (no clear DNS leak):
$ setpriv ... dig +short @192.0.2.1 example.com A -> 104.20.23.154 / 172.66.147.243
$ setpriv ... dig +short @127.0.0.1 -p 19053 example.com A -> 104.20.23.154 / 172.66.147.243
# direct connection DROPPED:
$ echo x | setpriv ... socat - UDP4:1.1.1.1:9999 -> write(...): Operation not permitted   (DROP)
$ setpriv ... curl -6 --max-time 6 http://[2606:4700:4700::1111]/ -> v6http=000, exit 7    (DROP)
```
All five hand confirmations reproduce the recipe: Tor exit, remote DNS, no clear DNS leak, raw-UDP drop, IPv6 drop.

### Step 3: the binary's own verifier -> FAIL (verify cannot certify a healthy host)

Shipped `anonctl verify` (default build) behaves per the README's "the default binary cannot silently pass":
```
$ anonctl verify
verify anon (endpoint: socks5h://127.0.0.1:9050)
[FAIL] live-verify-available: this anonctl binary was built WITHOUT the live-verify
       probes; ... Rebuild with `-tags integration` ...
$ echo $?    -> 1     (non-zero on failure: contract holds)
$ anonctl verify --json | python3 -m json.tool
{ "schemaVersion": 1, "ok": false, "account": "anon",
  "endpoint": "socks5h://127.0.0.1:9050",
  "assertions": [ { "name": "live-verify-available", "ok": false, "detail": "..." } ] }
$ echo $?    -> 1
```
The `--json` envelope is well-formed with a derived top-level `ok`. Good.

The integration-tagged build (`anonctl-live verify`, the live-verify build the README points to) runs all assertions against the live `anon` account. Result (`ok:false`, exit 1):
```
  FAIL  anonymized-exit           # error: socks connect ...127.0.0.1:19050... connection reset by peer
  FAIL  dns-remote                # error: socks connect ...127.0.0.1:19050... connection reset by peer
  FAIL  leak-drop-v4              # "a direct v4 connection from the anon UID REACHED its target"
  PASS  leak-drop-v6
  FAIL  bypass-loopback-closure   # "the anon UID reaching a non-shim loopback destination REACHED"
  FAIL  bypass-endpoint-closure   # "the anon UID dialling the upstream endpoint directly REACHED"
  PASS  icmp-drop
  PASS  non-tcp-udp-drop
  PASS  no-uid-transition-egress
```
**5 of 9 assertions FALSE-FAIL against an account that step 2 PROVED is correctly anonymized and fail-closed.** These are probe-mechanism bugs, not real leaks (see BUGS/GAPS #2 for the per-assertion root cause and the hand-evidence that the underlying setup is sound). Because `verify` never returns green, the post-verify marker `/etc/anonctl/anon.json` is never written (confirmed absent throughout).

### Step 4: LAN exemption -> MOSTLY PASS (the `:53` guardrail is excellent; one false-fail)

```
$ anonctl add --allow-direct 192.168.1.150:8080 work        (exit 0)
```
The exemption is installed exactly and narrowly (nat `return` + filter `accept`, scoped to `192.168.1.150 tcp dport 8080`, nothing wider). `lan-exemption-not-a-dns-hole` PASSES:
```
lan-exemption-not-a-dns-hole -> clear DNS (tcp+udp 53) to the exempted host ... does not
egress directly (redirected to the shim or dropped): the LAN hole is not a DNS hole
```
`split-tunnel-tight` FALSE-FAILS ("a NON-exempt LAN destination was reachable directly"): same `probeAsAnon` redirect-into-relay artifact as step 3, not a real widening (the ruleset exemption is exact-match).

The `:53` guardrail works and is loud:
```
$ anonctl add --allow-direct 192.168.1.1:53 dnsattempt
anonctl: add: --allow-direct: LAN exemption "192.168.1.1:53" targets DNS port 53: a
direct clear-DNS query to a LAN resolver can reveal your local network's public IP (a
deanonymization vector); DNS must go through the anonymizer, so port 53 cannot be exempted
$ echo $?    -> 2     (non-zero; NO account and NO table were created: confirmed absent)
```

### Step 5: reboot persistence -> FAIL (the serious one)

The real `sudo reboot` was replaced with a container restart (systemd re-runs its boot sequence) PLUS the repo's own boot-invariant integration test. Both are labelled as substitutes for a bare-metal power-cycle.

The repo's boot-invariant integration test PASSES:
```
--- PASS: TestBootInvariantAnonUIDHasNoDirectEgressBeforeShim (0.36s)
```
BUT that test only proves "IF the persisted `.nft` rules are loaded, the anon UID is dropped." It manually `nft -f`s the rule file; it does NOT test that anything loads them at boot.

The container restart (a real systemd re-boot of the sandbox) exposed the gap:
```
# BEFORE restart:  rules PRESENT, shim active, nftables.service DISABLED
# (podman restart; systemd re-runs boot)
# AFTER restart, WITHOUT re-running add:
nft list table inet anonctl_anon  -> ABSENT   (rules did NOT survive boot)
systemctl is-enabled/active anonctl-shim@anon -> enabled / active   (shim DID come back)
systemctl is-enabled/active nftables.service  -> disabled / inactive
# SEVERITY: with the rules gone, the anon UID egressed IN THE CLEAR:
setpriv --reuid 1001 ... curl -s https://check.torproject.org/api/ip
    -> {"IsTor":false,"IP":"51.7.210.66"}     # the HOST'S REAL IP, un-anonymized
```
**Root cause:** anonctl persists its rules via a drop-in on `nftables.service`
(`/etc/systemd/system/nftables.service.d/anonctl.conf`, `ExecStartPost=... nft -f
/etc/anonctl/nftables/*.nft`), but `nftables.service` ships DISABLED on Debian and
**anonctl never enables it**. So the drop-in never fires at boot and the forcing is
absent until something reloads it. The persisted rule file `/etc/anonctl/nftables/anon.nft`
was intact and a manual `nft -f` on it restored the table immediately.

**Diagnosis confirmed:** after `systemctl enable nftables.service` and another restart, the
anon table WAS present at boot and the anon UID's egress was no longer the clear host IP:
```
systemctl is-enabled/active nftables.service -> enabled / active
nft list table inet anonctl_anon -> PRESENT   (boot invariant HOLDS)
setpriv --reuid 1001 ... curl https://check.torproject.org/api/ip -> {"IsTor":true,"IP":"192.42.116.145"}
```
So the invariant holds if and only if `nftables.service` is enabled, which anonctl must ensure (or replace with its own independent loader unit).

### Step 6: reconfigure with no leak window (`anonctl update`) -> PASS

```
$ anonctl update --endpoint socks5h://127.0.0.1:9050 anon
reconfigured anon -> endpoint socks5h://127.0.0.1:9050 (re-applied fail-closed, no leak window)   (exit 0)
# table still present, default-DROP intact after the reconfigure:
nft list table inet anonctl_anon | grep "policy drop" -> type filter hook output priority filter; policy drop;
# and the anon forced path still exits via Tor: {"IsTor":true,"IP":"192.42.116.145"}
```

### Step 7: teardown -> PASS (clean, scoped, host untouched)

A sentinel host table `inet host_sentinel` (plus the pre-existing `inet filter`) was planted to prove `rm` does not touch other nft rules.
```
$ anonctl rm                                   (exit 0)
removed forcing for anon; account left intact (pass --purge-account to delete it)
  anonctl_anon table -> GONE ;  host_sentinel + filter -> UNTOUCHED
  anonctl-shim@anon -> disabled / inactive ;  anon account + /home/anon -> KEPT

$ anonctl rm --purge-account                   (exit 0)
removed anon and its shim anon-shim
  anon + anon-shim accounts -> GONE ;  /home/anon -> GONE ;  marker -> GONE
  anonctl_anon table -> GONE ;  /etc/anonctl/nftables/anon.nft -> GONE
  host filter + host_sentinel tables -> UNTOUCHED
```
Teardown is clean and scoped: no collateral damage to the host's other nft rules. One residual (minor): the SHARED template unit `/etc/systemd/system/anonctl-shim@.service` and the (now empty) `/etc/anonctl/{shim,nftables,accounts}` directories remain after `--purge-account`. This is defensible as shared infrastructure (one template, N instances), but a strict "leaves no residue" reading would expect them removed on the last account's teardown.

## BUGS / GAPS (each becomes a fix task)

1. **BOOT INVARIANT: forcing does not survive reboot unless `nftables.service` is already enabled (SERIOUS, a real post-reboot leak).** anonctl persists rules via an `nftables.service` drop-in but never enables `nftables.service`; Debian ships it disabled. Observed after a real systemd re-boot: the anon nft table was ABSENT and the anon UID egressed with the host's real public IP in the clear (`{"IsTor":false,"IP":"51.7.210.66"}`). The shim came back but the kernel forcing did not. Fix options: have `add` run `systemctl enable nftables.service` (idempotent), or ship anonctl's OWN loader unit (`anonctl-nftables.service`, `WantedBy=sysinit.target`, `Before=network-pre.target`) that loads `/etc/anonctl/nftables/*.nft` independent of the host's `nftables.service` enablement, so the boot invariant does not depend on a host service anonctl does not own. The persisted rule file is correct and a manual `nft -f` recovers it, so this is purely a "who loads it at boot" gap. ADR-0005 currently ASSERTS the invariant "holds by construction" because "nftables.service loads early"; that assumption is false on a default Debian host and should be corrected.

2. **`anonctl verify` false-fails 5 of 9 live assertions against a healthy, genuinely-anonymized account (SERIOUS for the trust anchor).** The setup is provably sound (step 2), yet `verify` never returns green, so it cannot be used as the "prove it" verb the README sells, and it blocks the post-verify marker write. Two distinct probe-mechanism root causes, both about the TRANSPARENT relay:
   - **`anonymized-exit` + `dns-remote` speak SOCKS5 to a NON-SOCKS relay.** `forcedExitIP`/`dnsRemoteEvidence` (`internal/verify/probes_integration.go`) build `proxy.SOCKS5("tcp", "127.0.0.1:<RelayPort>", ...)` and send a SOCKS5 handshake to the shim's relay port. But the relay is a TRANSPARENT `SO_ORIGINAL_DST` relay (`internal/shim/relay.go`), NOT a SOCKS server: on a non-redirected direct dial, `SO_ORIGINAL_DST` returns the relay's OWN listen addr, so it dials itself and the connection resets. Observed error: `socks connect tcp 127.0.0.1:19050->api.ipify.org:443: ... connection reset by peer`; and `curl --socks5 127.0.0.1:19050 https://api.ipify.org` -> empty, exit 97. To fetch the forced-path exit IP, the probe must egress AS THE ANON UID (so nat redirects it into the relay, which then reads the real SO_ORIGINAL_DST), exactly like the step-2 `curl` that works, NOT dial the relay port as a SOCKS proxy.
   - **`leak-drop-v4`, `bypass-loopback-closure`, `bypass-endpoint-closure`, `split-tunnel-tight` mis-read "handshake with the relay" as "reached the target."** `probeAsAnon` dials a destination the nat chain REDIRECTS into the relay (`127.0.0.1:1`; `127.0.0.1:<relay+100>`; the loopback endpoint `127.0.0.1:9050`; a non-exempt LAN host). The nat redirect (priority -100) rewrites the destination BEFORE the filter chain's drop/closure (priority 0) can match the original, so the TCP handshake ALWAYS completes with the relay (which then fail-closed-drops the upstream SOCKS dial). `probeAsAnon` treats a completed handshake as REACHED, so these assertions can never pass against the real transparent relay. Decisive evidence it is NOT a real closure break: the shim journal shows the anon UID's dial to `127.0.0.1:9050` was redirected into the relay and the relay's upstream SOCKS CONNECT FAILED (`relay: socks dial 127.0.0.1:9050: ... general SOCKS server failure (drop, fail-closed)`), i.e. the anon UID reached the RELAY, never real Tor. The assertions that dial a genuinely non-redirected/dropped path (`leak-drop-v6`, `icmp-drop`, `non-tcp-udp-drop`) correctly PASS. The fix is to make the "leak"/closure probes assert on OFF-BOX reachability the way the hand recipe does (raw non-53 UDP EPERM; IPv6 http_code 000; an nft escaped-leak counter keyed on an off-box daddr staying at 0), NOT on whether a loopback TCP handshake with the transparent relay completed. This same bug is FAIL 2 in PART A.

3. **`internal/provision/TestRealProvisionRoundTrip` is broken by a leaked global test seam (TEST-ONLY, product is correct).** The unit suite's `TestMain` sets `provision.WriteLoginEnv = no-op` and never restores it; under `-tags integration` that stub is shared into the integration test, so the real login-env writer never runs and the `.profile` PATH assertion always fails. The product writes the managed `.profile` correctly (verified via a real `anonctl add`). Fix: restore the seam in the unit `TestMain` (defer/cleanup), or move the neutralisation into the specific unit tests that need it, so the integration test exercises the real writer.

4. **Minor: teardown leaves the shared template unit and empty `/etc/anonctl/*` dirs after `--purge-account`.** `/etc/systemd/system/anonctl-shim@.service` and empty `/etc/anonctl/{shim,nftables,accounts}` remain after the last account is purged. Defensible as shared infra, but worth a decision: either document it as intended shared state, or have the last-account teardown remove it.

5. **Minor / environmental: `anonctl add`'s success message has a formatting seam with the default account.** `run `anonctl verify ` to prove ...` renders a trailing space where the (empty) default account name goes (`verify ` not `verify`). Cosmetic; noted because it is in the operator-facing output.

## What this run did NOT cover (honest scope)

- **Not a bare-metal power-cycle.** The reboot test was a container systemd restart plus the repo's boot-invariant test, not a host `reboot`. The container restart IS a real systemd boot sequence (it is what exposed the `nftables.service`-disabled gap), but it does not exercise firmware/initramfs ordering. The boot-invariant FINDING (#1) is robust regardless: it is about a disabled systemd unit, which a real reboot would hit identically.
- **Shared kernel.** The container shares the host kernel (as all containers do); the nft/skuid/redirect primitives are the host kernel's. This matches how anonctl runs in production (it is a host-kernel tool), so it is representative, not a simulation, for the kernel-forcing behaviour.
- **`sudo -u anon` path.** The container had no `sudo`; "as anon" used `setpriv --reuid` (socket owned by the anon UID identically). The README's literal `sudo -u anon` invocation was therefore not exercised as-such, only its egress-equivalent.
