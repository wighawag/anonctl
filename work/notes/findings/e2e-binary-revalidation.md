---
kind: finding
title: Real-host re-validation after the e2e fixes (verify green, boot invariant, use, teardown)
slug: e2e-binary-revalidation
source: |
  Second real end-to-end run of the COMPILED anonctl binary, RE-VALIDATING the four
  fix tasks now in work/tasks/done/ (fix-verify-probes-transparent-relay,
  fix-boot-invariant-nftables-not-enabled, anonctl-use-verify-then-shell,
  fix-e2e-minor-gaps) against the two SERIOUS bugs the first run found
  (work/notes/findings/e2e-binary-validation.md). Driven by the agent on
  2026-07-09. Binaries built from repo HEAD 1996953 (anonctl --version ->
  v0.0.0-20260709085235-1996953db26d).

  ISOLATION (identical stance to the first run, and for the same reason). The
  maintainer's box `nono` is a bare-metal workstation (systemd-detect-virt ->
  `none`), and this run MUTATES the system (creates users, loads nft rules,
  installs systemd units) and REBOOTS. It also cannot run unattended on the host
  because `sudo` on `nono` requires a password. So the whole matrix was run inside
  a DISPOSABLE, ISOLATED podman container: a full systemd-PID1 Debian trixie
  sandbox with its OWN Tor (own tor.service, SocksPort 127.0.0.1:9050), its OWN
  network namespace, and its OWN users/units, torn down with `podman rm` at the
  end. The host `nono` had NO users, units, /etc/anonctl, /usr/local/bin/anonctl-shim,
  or nft-table changes made to it, and was NOT rebooted. The container shares the
  host kernel (as all containers do); everything else is isolated. Every command
  below was actually run inside that container and every output is its real
  observed output; nothing is fabricated.

  Critically for BUG 1: the container's own `nftables.service` is DISABLED
  (`systemctl is-enabled nftables.service` -> `disabled`), which is the EXACT leak
  condition of the first run. The host `nono`'s nftables.service is also disabled
  (confirmed on the host before starting). So the BUG-1 fix was proven under the
  condition that broke it last time.

  The "reboot" is a systemd-PID1 container restart (`podman restart`), which tears
  the sandbox down and re-runs its FULL systemd boot sequence from scratch (the
  enabled units re-execute) - this is exactly what exposed the nftables.service-
  disabled leak in the first run, so it is a faithful re-test of the same gate, not
  a firmware/initramfs power-cycle (that caveat is unchanged from run 1).

  Environment (observed, inside the container):
  - OS: Debian GNU/Linux 13 (trixie), VERSION_ID=13.
  - Kernel (shared with host `nono`): 6.12.90+deb13.1-amd64.
  - systemd: 257 (257.13-1~deb13u1), running as PID 1 in the container.
  - Tor: 0.4.9.11 (container's own tor.service, Bootstrapped 100%; SocksPort 127.0.0.1:9050).
  - nftables: v1.1.3 (Commodore Bullmoose #4). `nftables.service` = DISABLED (the leak condition).
  - Go: go1.26.0 linux/amd64 (host toolchain, GOFLAGS=-mod=vendor, GOTOOLCHAIN=local, offline).
  - Host `nono`: bare-metal (virt none), Debian 13, kernel 6.12.90, Tor 0.4.9.9 active,
    nftables.service DISABLED, sudo needs a password. podman 5.4.2 rootless.
  - anonctl build: repo HEAD 1996953. Two binaries: shipped `anonctl` and
    `anonctl-live` (`go build -tags integration`, the live-verify build the README
    points to). "as anon" uses `setpriv --reuid 1000 --regid 1000 --clear-groups`
    (the container has no sudo; the socket is owned by the anon UID identically -
    the nft rules key on `meta skuid`).
---

## Verdict

**The two serious bugs are fixed on a real host: YES (both), with one NEW SERIOUS teardown regression and one latent verify false-green found in this run.**

- **BUG 1 (post-reboot leak) is FIXED.** The inverted standing default-deny (ADR-0005 amended) holds: with forcing absent the anon UID is DROPPED, not free; and after a REAL reboot on a host where `nftables.service` is DISABLED, both the baseline-deny table and the forcing table were present and the anon UID egressed via Tor (`{"IsTor":true,"IP":"204.8.96.75"}`), NEVER the host's real IP `51.7.210.66` (last run leaked exactly that). anonctl's own loader unit is enabled and does not depend on the host's nftables.service.
- **BUG 2 (verify can't certify a healthy account) is FIXED for the headline claim.** `anonctl verify` returns GREEN (9/9, exit 0) on a genuinely-anonymized account, the marker `/etc/anonctl/anon.json` is then written, and verify still goes RED when the setup breaks (it is NOT neutered as a whole).

Per part: (B) verify green + marker written + still-red-when-broken: YES; BUT two of the nine assertions (`bypass-loopback-closure`, `split-tunnel-tight`) pass VACUOUSLY on a nft-syntax error, a latent false-green (BUGS #2). (C) forcing-absent = dropped AND after a real reboot the anon UID never egressed with the host's real IP: YES. (D) `use` drops you in on green (IsTor:true) and refuses (non-zero, no shell) on red: YES. (E) teardown leaves no residue: NO - `rm --purge-account` on the last account ABORTS mid-teardown and leaves major residue (BUGS #1); the cleanup LOGIC is correct once the shim is stopped, but the ordering bug means a single `rm` never gets there.

The integration suite is 11 PASS / 1 FAIL (NOT the expected 10/10): the previously-failing `internal/provision` now PASSES, but `internal/verify` still FAILS - for a NEW reason (the invalid-nft counter, BUGS #2), not the old false-fail.

## PART A: the tagged integration suite (`go test -tags integration ./...`)

Command (as root, inside the container, offline vendored build):

    go test -tags integration ./...

Result: **11 packages PASS, 1 package FAIL** (not 10/10). Verbatim:

```
ok    github.com/wighawag/anonctl                        65.993s
?     github.com/wighawag/anonctl/cmd/anonctl-shim       [no test files]
ok    github.com/wighawag/anonctl/internal/accountconfig 0.011s
ok    github.com/wighawag/anonctl/internal/cli           0.010s
ok    github.com/wighawag/anonctl/internal/endpoint      0.008s
ok    github.com/wighawag/anonctl/internal/forcing       0.015s
ok    github.com/wighawag/anonctl/internal/lanexempt     0.010s
ok    github.com/wighawag/anonctl/internal/marker        0.018s
ok    github.com/wighawag/anonctl/internal/nftables      1.418s
ok    github.com/wighawag/anonctl/internal/provision     0.867s   <- was FAIL last run, now PASS (BUG 3 fix holds)
ok    github.com/wighawag/anonctl/internal/shim          4.014s
?     github.com/wighawag/anonctl/internal/socks5hfixture [no test files]
ok    github.com/wighawag/anonctl/internal/systemd       1.015s
FAIL  github.com/wighawag/anonctl/internal/verify        66.466s  <- still FAIL, but a NEW cause
```

- `internal/provision` -> **PASS** (the leaked `WriteLoginEnv` global test seam from BUG 3 is fixed; `TestRealProvisionRoundTrip` now exercises the real writer).
- `internal/verify` -> **FAIL**, but NOT the old false-fail. The new failure is a test-side (and product-side, see BUGS #2) invalid nft:

```
--- FAIL: TestLiveLeakAndClosuresAgainstRealRuleset (4.24s)
    verify_integration_test.go:318: plant escaped-leak counter: exit status 1:
    /dev/stdin:4:44-50: Error: syntax error, unexpected counter
        meta skuid 1002 ip daddr 192.0.2.1 tcp counter
                                            ^^^^^^^
```

**PART A verdict: FAIL (1 package). NOT 10/10.** The verify package regressed into a different failure (invalid nft in the new escaped-leak counter), root-caused in BUGS #2.

## PART B: BUG 2 fixed - verify certifies a healthy account GREEN

### Setup: `anonctl add` (fresh account, anon UID 1000)

```
$ anonctl add
provisioned + forced anon (shim anon-shim, endpoint socks5h://127.0.0.1:9050)
note: anonctl does NOT manage the endpoint's own service; enable your endpoint ...
run `anonctl verify` to prove the account is anonymized        (exit 0)
```
BUG 5 (cosmetic) is FIXED: the message reads `anonctl verify` with NO trailing space (default account).

Both tables present after add (the BUG-1 baseline is new this run):
```
table inet anonctl_baseline_anon    # standing per-UID default-deny (NEW; the BUG-1 fix)
table inet anonctl_anon             # forcing (nat redirect + closures + policy drop)
```
The baseline table (the resting-state DROP):
```
chain baseline_out { type filter hook output priority filter; policy accept;
    meta skuid 1000 ip daddr 127.0.0.0/8 return
    meta skuid 1000 ip6 daddr ::1 return
    meta skuid 1000 ip daddr != 127.0.0.0/8 drop
    meta skuid 1000 ip6 daddr != ::1 drop }
```

### verify GREEN (exit 0) - the core BUG-2 result

`anonctl-live verify` (the live-verify build):
```
verify anon (endpoint: socks5h://127.0.0.1:9050)
[PASS] anonymized-exit: exit IP 185.183.157.214 differs from host 51.7.210.66 and is a Tor exit (IsTor=true)
[PASS] dns-remote: check.torproject.org was resolved proxy-side (remotely, via the endpoint), not locally
[PASS] leak-drop-v4: a direct v4 connection from the anon UID was DROPPED (fail-closed holds)
[PASS] leak-drop-v6: a direct v6 connection from the anon UID was DROPPED (fail-closed holds)
[PASS] bypass-loopback-closure: the anon UID reaching a non-shim loopback destination was DROPPED (fail-closed holds)   # <- see BUGS #2: VACUOUS
[PASS] bypass-endpoint-closure: the anon UID dialling the upstream endpoint directly was DROPPED (fail-closed holds)
[PASS] icmp-drop: an ICMP echo (ping) from the anon UID to an off-box address was DROPPED (fail-closed holds)
[PASS] non-tcp-udp-drop: raw non-53 UDP and UDP/443 (QUIC) from the anon UID were DROPPED (fail-closed holds)
[PASS] no-uid-transition-egress: the checked UID-transition vectors did not yield an off-box socket owned by a non-anon, non-shim uid (checked: sudo). ...best-effort...
verify exit=0
```
`--json`: `ok=true`, 9 assertions, all pass (parsed with python: `all(a["ok"] for a in assertions) == True`). Last run 5/9 false-failed and verify never went green; this run it is GREEN. **PASS.**

### Marker written (the gated knock-on) - PASS

```
$ cat /etc/anonctl/anon.json
{ "schemaVersion":1, "account":"anon", "uid":"1000", "endpointClass":"tor-shared",
  "createdAt":"2026-07-09T10:07:06Z", "anonctlVersion":"...+dirty (1996953db26d)" }
```
The marker is present (it is written only after a green verify - it was absent throughout the first run).

### Anonymization sanity (as anon) - PASS

```
$ setpriv --reuid 1000 --regid 1000 --clear-groups curl -s https://check.torproject.org/api/ip
{"IsTor":true,"IP":"45.84.107.17"}
$ setpriv ... curl -s https://api.ipify.org
45.84.107.17
# host direct (contrast): {"IsTor":false,"IP":"51.7.210.66"}
```
Anon exit `45.84.107.17` (IsTor:true) differs from the host IP `51.7.210.66`: genuinely anonymized.

### verify still FAILS on a real break (NOT neutered) - PASS (as a whole)

Flushed the forcing table (baseline deny stays), re-ran verify:
```
$ nft delete table inet anonctl_anon
$ anonctl-live verify
[FAIL] anonymized-exit (error: forced-path curl as anon UID failed: exit status 6 ())
[FAIL] dns-remote (error: forced-path curl as anon UID failed: exit status 6 ())
[PASS] leak-drop-v4 ... [PASS] bypass-loopback-closure ... (the leak/closure probes)
verify exit=1
```
verify correctly goes RED (exit 1) when the setup is broken. Restored with
`anonctl update --endpoint socks5h://127.0.0.1:9050 anon` -> verify green again.
NOTE the nuance: with forcing flushed the anon UID is DROPPED (the baseline deny),
so there is genuinely no leak for the leak/closure probes to catch here; this test
proves verify is not globally neutered, but it does NOT exercise the vacuous
assertions against a real leak - that is why BUGS #2 is a LATENT false-green.

**PART B verdict: PASS on the headline (verify green + marker + red-when-broken), with a latent false-green in 2 of 9 assertions (BUGS #2).**

## PART C: BUG 1 + Q1 fixed - standing default-deny holds; survives a real reboot

### Step 1: forcing-absent = DROPPED (the core Q1 guarantee), no reboot yet - PASS

```
$ nft delete table inet anonctl_anon        # remove forcing, leave the baseline deny
$ setpriv --reuid 1000 ... curl -s -m 8 -o /dev/null -w '%{http_code}\n' https://api.ipify.org
http=000        (curl exit 6)                # DROPPED, not a 200
$ setpriv ... curl -s https://api.ipify.org
                                             # empty body: no real-IP leak
$ setpriv ... curl -s https://check.torproject.org/api/ip
                                             # empty: NOT the host IP 51.7.210.66
$ nft list table inet anonctl_baseline_anon  # baseline deny STILL PRESENT
```
Forcing absent -> anon UID DROPPED, never the host IP. **PASS** (this is the exact guarantee the first run proved broken).

### Step 2: anonctl's OWN loader is enabled, host nftables.service is NOT - PASS

```
$ systemctl is-enabled anonctl-nftables.service   -> enabled
$ systemctl is-enabled nftables.service           -> disabled
$ systemctl show anonctl-nftables.service -p Wants -p After -p WantedBy -p DefaultDependencies
  Wants=network-pre.target  WantedBy=sysinit.target  DefaultDependencies=no
  (no reference to nftables.service anywhere)
```
The loader unit globs `/etc/anonctl/nftables/*.nft` (baseline + forcing), loads EARLY (Before=network-pre.target, DefaultDependencies=no), and does NOT depend on the host's nftables.service. **PASS.**

### Step 3: the REAL reboot (the definitive gate) - PASS

Re-applied forcing, then rebooted the systemd-PID1 sandbox (`podman restart`, a full systemd re-boot). AFTER reboot, WITHOUT re-running add:

```
# tables loaded by anonctl-nftables.service:
$ nft list table inet anonctl_baseline_anon   -> PRESENT (the baseline deny)
$ nft list table inet anonctl_anon            -> PRESENT (the forcing table)
$ systemctl is-active anonctl-nftables.service -> active
$ systemctl is-enabled nftables.service        -> disabled   (host service STILL not enabled)

# THE CRITICAL ASSERTION - anon egress after reboot:
$ setpriv --reuid 1000 ... curl -s https://check.torproject.org/api/ip
{"IsTor":true,"IP":"204.8.96.75"}             # Tor, NOT the host IP
$ setpriv ... curl -s https://api.ipify.org
103.91.65.44                                  # a Tor exit
$ curl -s https://api.ipify.org               # host contrast
51.7.210.66                                   # the leak IP from run 1

$ systemctl status anonctl-shim@anon          -> active (running), Main PID 56
$ anonctl-live verify                          -> exit 0 (green)
```

**At NO point after the reboot did the anon UID egress with the host's real IP.**
Last run: `{"IsTor":false,"IP":"51.7.210.66"}` in the clear. This run: forced through
Tor (`204.8.96.75`). Additionally proven post-reboot: flushing the forcing table
again left the anon UID DROPPED (`http=000`, empty body), confirming the standing
baseline holds independent of forcing even across a boot.

**PART C verdict: PASS. The post-reboot leak is GONE; BUG 1 is fixed by construction (standing default-deny + anonctl's own loader).**

## PART D: the new `anonctl use` front door

### Green: drops into an anon shell, IsTor:true - PASS

```
$ printf 'curl -s https://check.torproject.org/api/ip; echo; exit\n' | anonctl-live use
anon verified anonymized; opening a shell as anon (the kernel forcing is in effect for this session)
{"IsTor":true,"IP":"103.91.65.44"}
use exit=0
```
On a healthy account `use` verified green, opened the account shell, and inside it Tor egress was in effect (IsTor:true, not the host IP). **PASS.**

### Red: refuses, non-zero, NO shell - PASS

```
$ nft delete table inet anonctl_anon                    # break forcing
$ printf 'echo THIS_SHELL_SHOULD_NOT_RUN\n' | anonctl-live use
verify anon (endpoint: socks5h://127.0.0.1:9050)
[FAIL] anonymized-exit (error: forced-path curl as anon UID failed: exit status 6 ())
[FAIL] dns-remote (error: forced-path curl as anon UID failed: exit status 6 ())
[PASS] leak-drop-v4 ... (rest)
anonctl: use: anon did NOT verify as anonymized; refusing to open a shell (fix it, then `anonctl verify`)
use exit=1
```
On a broken account `use` printed the failing assertions, refused loudly, exited non-zero, and NEVER ran the shell command (`THIS_SHELL_SHOULD_NOT_RUN` did not print). You cannot get an un-anonymized shell via `use`. **PASS.**

(Restored forcing with `anonctl update --endpoint ... anon` afterward.)

**PART D verdict: PASS both ways.**

## PART E: teardown cleanliness (BUG 4 fix) - FAIL (NEW regression)

Planted a host sentinel (`inet host_sentinel`) to prove `rm` does not touch other nft tables, then ran the last-account purge:

```
$ anonctl rm --purge-account
anonctl: rm: remove account "anon-shim": exit status 8: userdel: user anon-shim is currently used by process 323
rm exit=1                                     # ABORTED
```
The blocking process 323 is the shim, still running under `anonctl-shim@anon.service`:
```
$ ps -o pid,uid,user,comm,args -p 323
  323 997 anon-shim anonctl-shim /usr/local/bin/anonctl-shim -relay 127.0.0.1:19050 ...
$ systemctl is-active anonctl-shim@anon        -> active   (NOT stopped)
```
Because `rm` aborted, it left MAJOR residue (everything BUG 4 was supposed to clean):
```
$ getent passwd anon anon-shim   -> anon-shim STILL present (anon was already deleted before the failure)
$ nft list tables                -> anonctl_baseline_anon, anonctl_anon BOTH still present
$ ls /etc/anonctl                -> accounts/ anon.json nftables/ shim/  (marker + all dirs still there)
$ systemctl status anonctl-nftables.service anonctl-shim@anon -> both still loaded/enabled
$ ls /etc/systemd/system/anonctl-*.service -> template unit + loader unit both still present
```

**Root cause (a real ordering regression in `main.go:runRm`).** `runRm` calls
`provision.Rm(...)` (which `userdel`s the shim account) BEFORE `forcing.Remove(...)`
(which `systemctl disable --now`s the shim). So at userdel time the shim is still
running, `userdel` fails with "user ... is currently used by process", `runRm`
returns 1 (main.go:130) and `forcing.Remove` - and therefore the ENTIRE last-account
cleanup (tables, marker, dirs, template unit, loader unit) - is NEVER reached. The
comment in `forcing.Remove` ("Stop + disable the shim first so it is not left
running against rules we are about to delete") is correct in intent but that
DisableNow is sequenced AFTER the userdel that fails, so it never runs. The fix
tasks' BUG-4 last-account cleanup logic is present and, as shown next, correct - it
is just unreachable through the normal `rm` path because the shim is torn down in
the wrong order.

**The cleanup LOGIC itself is sound once the shim is down** (so this is an ordering
bug, not a broken teardown): manually stopping the shim and re-running rm completes
cleanly and is scoped:
```
$ systemctl disable --now anonctl-shim@anon    # stop the shim manually
$ anonctl rm --purge-account
anon did not exist; nothing to remove          # (anon was userdel'd by the first, failed rm)
$ getent passwd anon anon-shim   -> gone
$ nft list tables                -> host_sentinel ONLY (anonctl tables gone; the host table UNTOUCHED)
$ ls /etc/anonctl                -> (gone)
$ ls /etc/systemd/system/anonctl-*.service -> No such file (template + loader unit both removed)
$ systemctl status anonctl-nftables.service anonctl-shim@anon -> not-found
```
So the last-account cleanup (BUG 4 fix) DOES remove the shared template unit, the
loader unit, and the empty `/etc/anonctl` dirs, and leaves the host's other nft
tables untouched - but ONLY when the shim is already stopped. Through the shipped
`rm` path it aborts and leaves everything.

**PART E verdict: FAIL. A single `anonctl rm --purge-account` on the last account
aborts and leaves major residue; it takes a manual `systemctl disable --now
anonctl-shim@<account>` plus a SECOND `rm` to actually clean up.** This defeats the
BUG-4 "leaves no residue" goal for the common path.

## BUGS (this run)

1. **`anonctl rm --purge-account` ABORTS on the last account and leaves major residue (SERIOUS, a real teardown regression).** `main.go:runRm` runs `provision.Rm` (userdel the shim account) BEFORE `forcing.Remove` (systemctl disable --now the shim). The shim is therefore still running when userdel runs, userdel fails ("user anon-shim is currently used by process N", exit 8), runRm returns 1, and `forcing.Remove` + the whole last-account cleanup never runs. Observed residue after one `rm`: both nft tables, the marker, the entire /etc/anonctl tree, the anon-shim user, the template unit AND the loader unit all left behind. The cleanup logic is correct once the shim is stopped (manual `systemctl disable --now anonctl-shim@anon` + a second `rm` cleans up fully and leaves host tables untouched), so the fix is to REORDER runRm: disable --now the shim (forcing.Remove's DisableNow, or a dedicated stop) BEFORE any userdel. Bonus hardening: userdel could retry after the disable, or provision.Rm could stop the shim unit itself. NOTE: the first run's teardown "passed" because it did `rm` then `rm --purge-account` as two steps with the shim already disabled by the bare `rm`; the single-shot `--purge-account` on a live last account is what exposes this.

2. **`bypass-loopback-closure` and `split-tunnel-tight` pass VACUOUSLY on an invalid-nft counter (SERIOUS-latent, a false-green in the BUG-2 fix).** The escaped-leak counter rule `verify.escapedLeakCounterRuleset(uid, daddr, l4, port)` renders `meta skuid <uid> ip daddr <off-box> tcp counter` when `port <= 0` (the port-omitted TCP-closure shape used by `bypass-loopback-closure` at checks_integration.go:110 and `split-tunnel-tight` at :166). That is INVALID nftables: a bare `tcp` before `counter` is a syntax error (proven directly: `nft -f` -> `Error: syntax error, unexpected counter`, exit 1, on nftables v1.1.3). Production's `offBoxLeakReached` (probes_integration.go) SWALLOWS a plant error and returns `reached=false`, and `reached=false` => the closure assertion PASSES. So these two assertions can NEVER plant their counter and pass UNCONDITIONALLY, regardless of whether the closure actually holds - a false-green. Evidence: (a) the production renderer, called directly, emits the invalid rule (`escapedLeakCounterRuleset(1000,"192.0.2.1","tcp",0)` -> `... ip daddr 192.0.2.1 tcp counter`, while the valid udp/port form `... udp dport 9999 counter` plants fine); (b) `nft -f` on that exact rule fails with the syntax error; (c) this same invalid rule is what fails PART A's `internal/verify` integration test (the test twin `offBoxLeakReachedTest` hits it first and t.Fatal's, so the whole test is red). The valid fix is to render a valid l4 match for the port-omitted case, e.g. `meta l4proto tcp` (or `ip protocol tcp`) instead of a bare `tcp`, in BOTH counter.go (production) and the test twin. Until then, verify's headline "green on a healthy account" is real, but two of its nine closure assertions are not actually probing anything. (The other seven assertions - including the leak-drop-v4 udp counter, leak-drop-v6, icmp-drop, non-tcp-udp-drop, anonymized-exit, dns-remote - do genuinely probe and correctly go red when the setup breaks.)

## What this run did NOT cover (honest scope)

- **Not a bare-metal power-cycle.** The reboot was a systemd-PID1 container restart (a real, full systemd boot sequence - it is what re-runs the enabled loader/shim units and is exactly the mechanism that exposed the run-1 leak), not a host firmware/initramfs power-cycle. The BUG-1 result is robust regardless: it is about a DISABLED systemd unit at boot, which a real reboot hits identically, and the standing default-deny makes even a partial/late boot safe by construction.
- **Shared kernel** (as all containers): the nft/skuid/redirect primitives are the host kernel's, matching how anonctl runs in production.
- **`sudo -u anon` path**: the container has no sudo; "as anon" used `setpriv --reuid` (socket owned by the anon UID identically), and `anonctl use` uses setpriv internally.
- **The vacuous-assertion impact (BUGS #2) was proven by construction, not by a live escape.** I proved the counter can never be planted (so the assertions pass unconditionally); I did not additionally engineer a live off-box clear escape that the assertion fails to catch, because the standing default-deny + the forcing redirect made a genuine escape hard to stage without dismantling the very protections under test. The by-construction proof (invalid nft -> plant fails -> reached=false -> PASS) is decisive on its own.
