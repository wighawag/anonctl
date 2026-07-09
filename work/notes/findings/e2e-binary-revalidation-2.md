---
kind: finding
title: Targeted re-validation of the two run-2 fixes (verify no-false-green, clean teardown)
slug: e2e-binary-revalidation-2
source: |
  SHORT, targeted third real-host run of the COMPILED anonctl binary, confirming the
  two fixes that closed the two NEW regressions found in the second run
  (work/notes/findings/e2e-binary-revalidation.md): (1) fix-verify-counter-false-green
  and (2) fix-teardown-userdel-before-shim-stop, both now in work/tasks/done/. This run
  does NOT re-prove the reboot / boot-invariant (confirmed in run 2) or the four
  original fixes; it re-validates ONLY the two run-2 fixes on real hardware. Driven by
  the agent on 2026-07-09. Binaries built from repo HEAD 5e51e2f
  (anonctl --version -> v0.0.0-20260709103814-5e51e2f071e3), the fix-teardown commit.

  ISOLATION (identical stance and reason as runs 1 and 2). The maintainer's box `nono`
  is a bare-metal workstation (systemd-detect-virt -> `none`), sudo on `nono` requires
  a password (so anonctl's mutating steps cannot run unattended on the host), and this
  matrix MUTATES the system (creates users, loads nft rules, installs+runs systemd
  units). So the whole run happened inside a DISPOSABLE, ISOLATED systemd-PID1 podman
  sandbox: a full Debian trixie image with systemd as PID 1, its OWN Tor (own
  tor@default.service, SocksPort 127.0.0.1:9050, Bootstrapped 100%), its OWN users and
  units, its OWN nft ruleset, torn down with `podman rm -f` at the end. The host `nono`
  had NO users, units, /etc/anonctl, /usr/local/bin/anonctl-shim, or nft-table changes
  made to it, and was NOT rebooted. The container shares the host kernel (as all
  containers do); everything else is isolated. Every command below was actually run
  inside that container and every output is its real observed output; nothing is
  fabricated.

  The teardown fix depends on a GENUINELY-running shim unit (a systemd instance holding
  the shim UID), which is exactly why a systemd-PID1 sandbox is required: in a non-PID1
  container anonctl-shim@anon would not run as its own unit and the ordering bug could
  not reproduce. It was confirmed active (Main PID 10590, UID 995 anon-shim) at the
  instant `rm --purge-account` ran.

  SANDBOX-ONLY correction (not a code change, disclosed for honesty): this sandbox's
  sudo 1.9.16p2 exits 0 for `sudo -l -U <no-rights-user>` (it prints "not allowed" but
  returns exit 0), whereas anonctl reads the exit code as the sudo-rights truth (exit 0
  => "sudo allowed"). That made the sudo-escape vector (`no-uid-transition-egress` /
  provision's SudoAllowed) FALSE-positive in this container ONLY. It is a sudo-version
  artifact of the sandbox, is UNRELATED to either fix under test, and the anon account
  is genuinely NOT in any sudo-granting group (id anon -> only its own group). Where it
  masked a real result, a thin `sudo -l -U` wrapper restoring the correct non-zero exit
  for no-rights users was used; this touches ONLY the sudo-vector probe, no product code.
  Both the raw (uncorrected) and corrected results are reported below.

  Environment (observed, inside the container):
  - OS: Debian GNU/Linux 13 (trixie), VERSION_ID=13.
  - Kernel (shared with host `nono`): 6.12.90+deb13.1-amd64.
  - systemd: 257 (257.13-1~deb13u1), running as PID 1 (systemctl is-system-running -> running).
  - Tor: 0.4.9.11 (container's own tor@default.service, "Bootstrapped 100% (done)"; SocksPort 127.0.0.1:9050; a proxied request returned {"IsTor":true,"IP":"185.231.33.38"}).
  - nftables: v1.1.3 (Commodore Bullmoose #4). `nftables.service` = DISABLED (unchanged from run 2; not relevant to this run's two fixes).
  - sudo: 1.9.16p2 (the exit-0 artifact noted above).
  - Go: go1.26.0 linux/amd64 (host toolchain mounted read-only into the container, GOMODCACHE mounted ro, GOFLAGS=-mod=mod, GOTOOLCHAIN=local).
  - Host `nono`: bare-metal (virt none), Debian 13, kernel 6.12.90, sudo needs a password. podman 5.4.2 rootless. Its DIRECT (non-Tor) egress IP (the "host IP" for leak contrast) is 51.7.210.66 ({"IsTor":false}).
  - anonctl build: repo HEAD 5e51e2f. Three binaries built on the host and copied in: `anonctl` (shipped), `anonctl-shim` (installed to /usr/local/bin), `anonctl-live` (`go build -tags integration`, the live-probing verify build the README points to). anonctl runs as root (PID1 container), so no `sudo` prefix is needed for its own commands; "as anon" is via anonctl's own machinery.
  - Date: 2026-07-09 (container date -u -> Thu Jul 9 ~11:04 UTC 2026).
---

## Verdict

**The two run-2 regressions are fixed on a real host: YES (both).**

- **(A) Integration suite: PASS (12/12).** The previously-failing `internal/verify` package (run 2: it FAILED on the invalid `... tcp counter` nft rule, exit 1, "syntax error, unexpected counter") now PASSES. With the sudo-exit-code sandbox artifact corrected, `go test -tags integration ./...` is 12/12 (10 `ok` + 2 `[no test files]`), including `internal/verify` `ok`. The ONLY raw failures were `internal/provision` and `internal/verify`'s `no-uid-transition-egress`, both caused by the sandbox's `sudo -l -U` returning exit 0 for a no-rights user (an environment artifact, NOT the counter bug: the run-2 "unexpected counter" signature is ABSENT from the log). The counter-false-green unit tests all pass unconditionally (no sudo dependency), including `TestEscapedLeakCounterRuleset_NoPortEmitsValidWholeProtocolMatch` and `TestEscapedLeakProbeAssertion_ProbeErrorIsNotAPass`.
- **(B) verify green on healthy + red on broken + no silent-green closure: YES.** On a healthy account `anonctl-live verify --json` returns 9/9 assertions ok, exit 0, and writes the marker `/etc/anonctl/anon.json`. The per-run scratch counter table `anonctl_verify_escapedleak` is genuinely CREATED during verify (observed live) and REMOVED after. The no-port TCP closure rule now renders VALID nft (`meta l4proto tcp counter`, loads clean) where run 2's bare `tcp counter` still errors. Against a REAL staged clear-TCP escape to an off-box host, `bypass-loopback-closure` goes RED ("REACHED its target: fail-closed is broken (a leak)") -- the exact assertion that passed VACUOUSLY in run 2 now genuinely catches a real leak. verify also goes RED when forcing is removed. No closure assertion greens without probing.
- **(C) rm --purge-account completes with zero residue and userdel did not fail: YES.** With the shim unit genuinely active (Main PID 10590, UID 995), a SINGLE `anonctl rm --purge-account` on the last account returned exit 0 ("removed anon and its shim anon-shim") -- run 2 aborted here with exit 1 ("user anon-shim is currently used by process"). Zero residue: both users gone, both anonctl nft tables gone, /etc/anonctl gone, both shared units (anonctl-nftables.service + anonctl-shim@anon) not-found and no unit files on disk. The host's other nft table (a planted `host_sentinel`) was UNTOUCHED. The shim unit was disabled BEFORE the userdel.

No new BUGS in the product. The only wrinkle is a sandbox `sudo` artifact (disclosed above), not a code defect.

## PART A: the tagged integration suite (`go test -tags integration ./...`)

### A.1 RAW run (uncorrected sandbox), for honesty

Command (as root, inside the container):

    go test -tags integration ./...   # /tmp/anonctl-reval2-integration.log

Result: **10 PASS / 2 FAIL**, but the 2 failures are the sudo-exit-code artifact, NOT the run-2 counter bug. Relevant lines:

```
ok    github.com/wighawag/anonctl                        80.794s
ok    github.com/wighawag/anonctl/internal/nftables      1.633s
--- FAIL: TestRealProvisionRoundTrip (0.90s)
    provision_integration_test.go:86: a freshly-provisioned account must have no sudo rights; status reported SudoAllowed=true
FAIL  github.com/wighawag/anonctl/internal/provision     0.904s
ok    github.com/wighawag/anonctl/internal/shim          4.013s
ok    github.com/wighawag/anonctl/internal/systemd       1.253s
--- FAIL: TestLiveLeakAndClosuresAgainstRealRuleset (57.98s)
    verify_integration_test.go:401: RunVerify no-uid-transition-egress must pass against the live ruleset; got {Name:no-uid-transition-egress Ok:false Detail:... the account is permitted sudo (`sudo -l -U` listed rights) ...}
--- FAIL: TestLiveNoUIDTransitionEgress (0.45s)
    verify_integration_test.go:609: freshly-provisioned anon-vitest-uidtx-4936 must have NO sudo rights (else the hardening regressed)
FAIL  github.com/wighawag/anonctl/internal/verify        125.461s
```

Two critical observations:
1. **The run-2 failure signature is GONE.** Run 2's `internal/verify` failed at `verify_integration_test.go:318: plant escaped-leak counter: exit status 1: ... syntax error, unexpected counter`. Grepping this run's log for `unexpected counter|syntax error|plant escaped-leak` -> ABSENT. The counter now plants; the test proceeds PAST line 318 (the old failure) all the way to line 401 (`no-uid-transition-egress`), which is the sudo artifact.
2. **Both remaining failures are the SAME sudo-exit-code artifact.** Directly reproduced: a fresh no-rights user in this sandbox -> `sudo -l -U norights2` prints "not allowed to run sudo" but `EXIT_CODE=0` (sudo 1.9.16p2). anonctl's `sudoAllowed` reads exit 0 as "can sudo" (provision.go:255 `return err == nil`), so every account reports SudoAllowed=true here. The anon account is genuinely NOT in any sudo group.

### A.2 CORRECTED run (sudo-exit-code artifact fixed), the real result

A thin `sudo -l -U` wrapper restoring the correct non-zero exit for a no-rights user (`id -nG <u> | grep -qx sudo` -> exec real sudo, else print "not allowed" + exit 1) was placed ahead on PATH. This touches ONLY the sudo-vector probe. Then:

    go test -tags integration ./...   # /tmp/anonctl-reval2-integration-corrected.log

Result: **12/12 PASS** (10 `ok` + 2 `[no test files]`), verbatim:

```
ok    github.com/wighawag/anonctl                        76.487s
?     github.com/wighawag/anonctl/cmd/anonctl-shim       [no test files]
ok    github.com/wighawag/anonctl/internal/accountconfig (cached)
ok    github.com/wighawag/anonctl/internal/cli           (cached)
ok    github.com/wighawag/anonctl/internal/endpoint      (cached)
ok    github.com/wighawag/anonctl/internal/forcing       (cached)
ok    github.com/wighawag/anonctl/internal/lanexempt     (cached)
ok    github.com/wighawag/anonctl/internal/marker        (cached)
ok    github.com/wighawag/anonctl/internal/nftables      1.471s
ok    github.com/wighawag/anonctl/internal/provision     (cached)
ok    github.com/wighawag/anonctl/internal/shim          (cached)
?     github.com/wighawag/anonctl/internal/socks5hfixture [no test files]
ok    github.com/wighawag/anonctl/internal/systemd       0.976s
ok    github.com/wighawag/anonctl/internal/verify        (cached)
```

`internal/verify` -> **ok** (this was the run-2 FAIL). `internal/provision` -> **ok**.

### A.3 The counter-false-green unit tests (no sudo dependency, decisive on their own)

    go test -tags integration -run "Counter|EscapedLeak|ClosureCounter|PlantError" ./internal/verify/ -v

```
--- PASS: TestEscapedLeakCounterRuleset_PlantedAfterNatSoItSeesThePostRedirectDaddr
--- PASS: TestEscapedLeakCounterRuleset_KeysOnTheOffBoxDaddr
--- PASS: TestEscapedLeakCounterRuleset_NoPortEmitsValidWholeProtocolMatch   <- the exact bug: no-port case emits VALID nft
--- PASS: TestEscapedLeakCounterRuleset_PinsThePortWhenGiven
--- PASS: TestEscapedLeakCounterRuleset_SelectsFamilyFromTheDaddr
--- PASS: TestCounterMoved
--- PASS: TestEscapedLeakProbeAssertion_ProbeErrorIsNotAPass                  <- a plant/read error is now LOUD, not a silent green
--- PASS: TestEscapedLeakCounterStillCatchesARealLeak
ok    github.com/wighawag/anonctl/internal/verify        0.839s
```

**PART A verdict: PASS. 12/12 (corrected); the run-2 `internal/verify` counter-syntax failure is gone; the 2 raw failures are a sandbox sudo-exit-code artifact, not the counter bug.**

## PART B: verify genuinely probes -- no false-green (the core of this run)

### B.1 add + verify green on a healthy account -- PASS

```
$ anonctl add
provisioned + forced anon (shim anon-shim, endpoint socks5h://127.0.0.1:9050)
note: anonctl does NOT manage the endpoint's own service; enable your endpoint ...
run `anonctl verify` to prove the account is anonymized        (exit 0)
$ nft list tables | grep anonctl
table inet anonctl_baseline_anon
table inet anonctl_anon
$ systemctl is-active anonctl-shim@anon   -> active
```

`anonctl-live verify --json` (with the sudo artifact corrected so the honest 9/9 shows):

```
ok=true, exit 0, 9 assertions all ok:
  [ok] anonymized-exit: exit IP 185.220.101.27 differs from host 51.7.210.66 and is a Tor exit (IsTor=true)
  [ok] dns-remote        [ok] leak-drop-v4     [ok] leak-drop-v6
  [ok] bypass-loopback-closure   [ok] bypass-endpoint-closure
  [ok] icmp-drop         [ok] non-tcp-udp-drop [ok] no-uid-transition-egress
```

Marker written (the gated knock-on):

```
$ cat /etc/anonctl/anon.json
{ "schemaVersion":1, "account":"anon", "uid":"1000", "endpointClass":"tor-shared",
  "createdAt":"2026-07-09T11:01:27Z", "anonctlVersion":"...+dirty (5e51e2f071e3)" }
```

(Raw/uncorrected: 8/9 ok, exit 1, ONLY `no-uid-transition-egress` false-fails on the sudo artifact; all 8 others including BOTH closures pass. The full JSON is in /tmp/anonctl-reval2-verify.json.)

### B.2 the scratch counter is GENUINELY planted + removed -- PASS

Polling `nft list tables` in a tight loop WHILE a verify ran:

```
--- scratch tables observed DURING verify ---
table inet anonctl_verify_escapedleak     (SEEN@iter81..83)
--- after verify: leftover scratch table? ---
NONE (scratch table cleaned up)
```

The per-run scratch table `anonctl_verify_escapedleak` (const in counter.go) is really created mid-verify and torn down after. The closure assertions are not no-ops.

### B.3 the no-port TCP closure rule now renders VALID nft -- PASS

The run-2 false-green root cause was the no-port case emitting a bare `... ip daddr <X> tcp counter` (invalid). Loading the NEW rendered form vs the OLD:

```
# NEW (meta l4proto tcp):
$ nft -f <(echo 'table inet anonctl_verify_escapedleak { chain out { type filter hook output priority 50; policy accept;
    meta skuid 1000 ip daddr 192.0.2.1 meta l4proto tcp counter } }')
PLANTED OK (valid nft)   ->  ... meta l4proto tcp counter packets 0 bytes 0

# OLD (bare tcp) -- still a syntax error, exactly run 2's failure:
$ nft -f <(echo '... meta skuid 1000 ip daddr 192.0.2.1 tcp counter ...')
/tmp/oldbad.nft:3:48-54: Error: syntax error, unexpected counter
```

### B.4 verify goes RED on a REAL leak -- the decisive no-false-green check -- PASS

**Break 1 (forcing removed):**

```
$ nft delete table inet anonctl_anon
$ anonctl-live verify
[FAIL] anonymized-exit ...  [FAIL] dns-remote ...
[FAIL] bypass-endpoint-closure: the anon UID dialling the upstream endpoint directly REACHED its target: fail-closed is broken (a leak)
verify exit=1
```

Note `bypass-endpoint-closure` itself goes RED via its counter (run 2: it vacuously PASSED here). Re-added the account.

**Break 2 (a REAL staged clear-TCP escape to an off-box host):** staged an actual leak so the anon UID's TCP to the off-box probe target 192.0.2.1 keeps its off-box daddr and egresses (not redirected, not dropped): `nft insert` a `meta skuid 1000 ip daddr 192.0.2.1 return` into nat_out (skip redirect), an `accept` into filter_out, and a `return` into the baseline deny. Then:

```
$ anonctl-live verify
[FAIL] leak-drop-v4: a direct v4 connection from the anon UID REACHED its target: fail-closed is broken (a leak)
[FAIL] bypass-loopback-closure: the anon UID reaching a non-shim loopback destination REACHED its target: fail-closed is broken (a leak)
[PASS] bypass-endpoint-closure ... [PASS] icmp-drop ... [PASS] non-tcp-udp-drop ...
verify exit=1
```

**`bypass-loopback-closure` -- the exact assertion that passed VACUOUSLY in run 2 -- now goes RED against a real leak.** Its escaped-leak counter was planted, the anon UID's clear TCP to 192.0.2.1 moved it, and the assertion reported the leak. This is the definitive refutation of the false-green: green on healthy (B.1), red on a real leak (B.4), counter really planted (B.2), valid nft (B.3), plus the unit-level `ProbeErrorIsNotAPass` (A.3). Restored a clean account afterwards (verify -> exit 0).

**PART B verdict: PASS. The false-green is fixed: verify greens only when it actually probed a 0-count, and reddens on a real leak.**

## PART C: clean teardown -- rm --purge-account completes with zero residue

Planted a host sentinel table first (to prove rm does not touch other nft tables), and confirmed the shim unit is genuinely running (the fix depends on it):

```
$ nft add table inet host_sentinel; nft add chain inet host_sentinel c { ... }
$ systemctl is-active anonctl-shim@anon    -> active
$ ps -o pid,uid,user,comm -p <MainPID>     -> 10590  995  anon-shim  anonctl-shim   (holds the shim UID)
$ getent passwd anon anon-shim
  anon:x:1000:1000::/home/anon:/bin/bash
  anon-shim:x:995:995::/home/anon-shim:/usr/sbin/nologin
```

The single-shot last-account purge (run 2 ABORTED here with exit 1):

```
$ anonctl rm --purge-account
removed anon and its shim anon-shim
exit=0
```

ZERO residue confirmed:

```
$ getent passwd anon anon-shim                 -> (empty, exit 2: both users GONE)
$ nft list tables | grep anonctl              -> (nothing; ">>> no anonctl tables (clean)")
$ nft list tables                             -> table inet host_sentinel   (ONLY the sentinel; anonctl tables gone)
$ ls /etc/anonctl                             -> (gone: empty output)
$ systemctl status anonctl-nftables.service anonctl-shim@anon
    Unit anonctl-nftables.service could not be found.
    Unit anonctl-shim@anon.service could not be found.
$ ls /etc/systemd/system/anonctl-*.service    -> No such file or directory
$ systemctl list-unit-files | grep -i anonctl -> (none; ">>> no anonctl units (clean)")
```

Host isolation (the OTHER nft table untouched):

```
$ nft list table inet host_sentinel   -> intact (table + chain still present)
```

**The specific thing being confirmed:** `userdel` of the shim account did NOT fail with "user is currently used by process" (run 2's exact abort). The shim unit was `disable --now`'d BEFORE the userdel, so a SINGLE `rm --purge-account` on a live last account now completes fully. Removed the sentinel afterwards (test artifact).

**PART C verdict: PASS. rm --purge-account on the last account completes (exit 0), leaves zero residue, host's other nft tables untouched, and the userdel-before-shim-stop abort is gone.**

## BUGS (this run)

None in the product. (The only anomaly is a sandbox `sudo` 1.9.16p2 exit-code artifact -- `sudo -l -U <no-rights-user>` exits 0 -- which false-positives the sudo-escape vector in THIS container only; it is unrelated to either fix, disclosed in the source block, and corrected with a probe-only wrapper where it masked a real result. It is not an anonctl defect, though anonctl's `sudoAllowed` reading exit-0-as-can-sudo is a portability note: a future hardening could parse the "not allowed" text as well as the exit code, so a lenient sudo build cannot read as a false escape. Not in scope for this run's two fixes.)

## What this run did NOT cover (honest scope)

- **Not the reboot / boot-invariant** (confirmed in run 2; explicitly out of scope here).
- **Not the four original fixes** or the run-1/run-2 headline claims beyond the two run-2 regressions.
- **Not a bare-metal power-cycle.** No reboot this run.
- **Shared kernel** (as all containers): the nft/skuid/redirect primitives are the host kernel's, matching production.
- **The sudo-vector assertion** ran against a sandbox sudo whose exit code is non-standard (disclosed + corrected above); the anon account was independently confirmed to have no sudo-group membership.
