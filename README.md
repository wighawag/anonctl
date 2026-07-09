# anonctl

Force **all of a Unix account's egress through an anonymizer, at the kernel level, fail-closed**, so anything that account runs (a shell, arbitrary tools, an editor, a script) cannot leak your real IP or DNS. anonctl provisions a dedicated account, installs per-UID kernel forcing that redirects the account's TCP into a per-account SOCKS relay (or drops it), and ships a `verify` leak-test that PROVES the account is anonymized rather than asking you to trust it.

The forcing is done by the **kernel**, not by each tool's own proxy awareness. This is the opposite of app-level `HTTP_PROXY`/`ALL_PROXY` (which raw sockets and DNS ignore, and which therefore leaks). If the anonymizer is unreachable, the account's traffic is **dropped, never sent in the clear** (fail-closed). That is the whole point of the tool, and `verify` exists to prove it.

anonctl is a Linux-only **setup-and-verify manager** (like ufw/firewalld, specialized to per-UID anonymized egress), NOT a runtime wrapper: it is not in the data path. The kernel nftables rules plus the per-account shim plus your (unmanaged) anonymizer endpoint ARE the data path; anonctl installs, verifies, and manages them. Day-to-day you `sudo -iu anon` / `su - anon` and the kernel anonymizes everything that account does; anonctl is out of the loop at runtime. Because its whole job is root-level egress policy, anonctl APPLIES the rules itself when run as root (the ufw stance), rather than printing commands for you to paste.

## Requirements

- A **Linux kernel** with `nftables` (per-UID `meta skuid` matching and transparent redirect via `SO_ORIGINAL_DST`). anonctl is Linux-only; these primitives do not transfer to other platforms.
- **Root**, for the verbs that mutate the system (`add`, `rm`, `update`/`reconfigure`). `list` and `status` are read-only and need no privilege.
- A **socks5h endpoint** to anonymize through. The default is a local **Tor** SOCKS port (`socks5h://127.0.0.1:9050`), so `anonctl add` works out of the box if you run Tor; any other socks5h endpoint (Mullvad local SOCKS, wireproxy, `ssh -D`, wireproxy chained with gost) works too via `--endpoint`. **anonctl does NOT manage the endpoint's lifecycle**: it assumes the endpoint already exists and stays up. Enabling it at boot (e.g. `systemctl enable --now tor.service`) is your job (see [Operating notes](#operating-notes)).

## Usage

```
anonctl add    [--endpoint <socks5h://host:port>] [<name>]   provision + force an account (root)
anonctl rm     [--purge-account] [<name>]                    remove forcing; --purge-account also deletes the account (root)
anonctl list   [--json]                                      list the anon accounts on the box
anonctl status [<name>] [--json]                             show one account's state
anonctl verify [<name>] [--json]                             PROVE the account is anonymized (non-zero exit on failure)
anonctl update|reconfigure --endpoint <socks5h://host:port> [<name>]   re-point an account, re-applied fail-closed (root)
anonctl --version | version                                  print the version
```

A **bare verb** targets the default account `anon`; `<name>` targets `anon-<name>`, so you can run several independently-anonymized accounts (`anonctl add work` provisions `anon-work`). Each account gets its OWN dedicated shim service account (`<account>-shim`), the only UID allowed to reach the upstream endpoint. The forcing survives reboots (an anonctl-owned nftables ruleset loaded at boot by anonctl's OWN early unit `anonctl-nftables.service`, independent of the host's `nftables.service`, plus a per-account `anonctl-shim@<account>.service`) and re-applies fail-closed at boot. The account's RESTING STATE is a standing default-deny, so an anon UID with no forcing loaded is DROPPED, not free: there is never a window where the account has un-anonymized egress.

```sh
sudo anonctl add                    # provision + force `anon` through the local Tor SOCKS port
sudo anonctl verify                 # prove it: anonymized exit, DNS remote, a direct dial DROPPED
sudo anonctl add --endpoint socks5h://127.0.0.1:1080 work   # a second account through another endpoint
```

## verify is the trust anchor

`verify` is the signature ONGOING verb: it does not assume anonymization, it PROVES it, and you re-run it **after setup, after a reboot, and after any Tor/kernel/nftables change**. It emits **named assertions**, exits **non-zero on any failure**, and supports `--json` (a versioned envelope with a derived top-level `ok`) so you can gate CI/automation on it. The assertions cover: the exit IP differs from the host's (and, for a Tor endpoint, is a Tor exit); DNS resolves remotely via the endpoint, never a plaintext local query; a direct (non-anonymized) connection from the account is actually DROPPED, for **both** IPv4 and IPv6, reported separately; the two bypass closures hold (the account can reach only its own shim's loopback port, and only the shim UID can reach the upstream endpoint); an ICMP echo (`ping`) from the account is DROPPED (no real-source-IP packet leaves); raw non-53 UDP from the account, **including UDP/443 (QUIC / HTTP-3)**, is DROPPED (SOCKS carries TCP only, so it is unrelayable); the concretely enumerable UID-transition escape vectors (sudo, the documented setuid network paths) do not leak, reported **honestly as best-effort, not exhaustive**; and, when a LAN split-tunnel is active, that it stays tight.

The live probes stand up real connections as the anon UID and therefore need root and a provisioned host; they are compiled only under the `integration` build tag. The **default binary cannot silently "pass"**: without the integration build its `verify` returns one honest failing assertion telling you to run the integration build on the host, and exits non-zero. Fail-closed extends to the verifier itself: it never reports green unless it actually proved green.

## What anonctl guarantees and what it does NOT

anonctl's one **guarantee** is **per-UID fail-closed anonymized egress**: every TCP and DNS packet from the forced account is pushed through the anonymizer, fail-closed, and `verify` proves it. Knowing the boundary of that guarantee means the residual risk is documented, not surprising. anonctl is as candid here as its sibling netcage is in "What netcage hides and what it does NOT". The full rationale for each decision below lives in [`docs/adr/`](docs/adr/) (cross-referenced throughout), so this section states the boundary rather than re-arguing it.

### Defended (this is the guarantee)

- **An app choosing a wrong proxy, or no proxy at all.** The forcing is at the **kernel**, keyed on the account's UID, so a proxy-unaware or misconfigured tool cannot escape it: its raw sockets are redirected into the shim regardless of what it thinks its proxy is.
- **A DNS leak.** DNS from the account is resolved **remotely over the endpoint** (DNS-over-SOCKS-TCP, socks5h), never as a plaintext query, so you do not leak via DNS. `verify` tests this, it is not merely configured.
- **An anonymizer-down leak.** The account's default egress policy is **DROP** (fail-closed). If the endpoint is unreachable, the account's traffic is dropped, never quietly falling back to the direct route. This holds at boot too, by INVERSION: the anon UID's resting state is a standing per-UID default-deny loaded by anonctl's own early unit, and forcing only ever OPENS the shim path. So the worst case is dropped-until-the-shim-and-endpoint-are-up, and even forcing-absent (the rules never loaded) is dropped-not-free, never leaking.
- **Cross-identification of two accounts on a shared endpoint** (see [The cross-identification boundary](#the-cross-identification-boundary) for the exact, share-class-bounded shape of this one).

### NOT defended (accepted residual)

Per-UID forcing binds the policy to the **UID**. That is precisely what makes these three out of scope: the policy is only as strong as the UID boundary and the kernel enforcing it.

- **Root on the box.** Root can undo the nftables rules, stop the shim, or read anything. anonctl's rules protect against a compromised or careless *tool running as the anon account*, not against an adversary who already has root. If root is compromised, so is everything.
- **A process changing its own UID away from the forced one (the UID-transition escape).** The forcing matches the anon UID; a socket owned by a DIFFERENT uid (a setuid binary, `sudo`, or a triggerable daemon acting on the account's behalf) does not match `meta skuid == anon`, so it egresses in the clear. anonctl binds egress to a UID; it hardens what it can at `add`-time and proves the enumerable vectors, but the per-UID model cannot close an arbitrary differently-owned daemon. This is anonctl's sharpest structural boundary versus a whole-OS model like Tails, so it gets [its own subsection below](#the-uid-transition-escape-what-anonctl-does-and-does-not-close).
- **Kernel compromise.** The redirect and the drop are enforced by the kernel; a compromised kernel can lie about all of it. anonctl trusts the kernel it runs on.

Defending against this last category is explicitly out of scope for anonctl (it would need a different isolation model, a VM or a sandboxed kernel). Being **honest** about it is in scope; that is what this section is.

### The UID-transition escape: what anonctl does and does NOT close

This is the one residual worth spelling out concretely, because it is where "one account, not the whole OS" is structurally weaker than a whole-OS transparent-Tor system.

**The mechanism.** anonctl forces egress with a kernel rule keyed on the socket-OWNING uid. The literal first rule of each account's `filter_out` chain is:

```
meta skuid != <anonUID> meta skuid != <shimUID> accept
```

That is correct for anonctl's scope: it governs only the two anonctl UIDs and must not break the rest of a shared host, so every OTHER uid egresses freely. But it means that if the anon account can cause a socket to be owned by a **different** uid, that socket does not match `skuid == anonUID` and egresses **in the clear**, bypassing all the forcing. The vectors are a **setuid** binary the account can run (its socket is owned by the target uid), **`sudo`** (if the account has any sudo rights), and a **triggerable system daemon** (a dbus-activatable service, a print/scan/avahi/MTA daemon, a local service that fetches a URL) that makes an outbound connection on the account's behalf under its own non-anon uid.

**What anonctl DOES about it (harden-what-we-can + prove-the-enumerable).**

- **No sudo at `add`-time.** `anonctl add` provisions the account with **no sudoers entry and no `sudo`/`wheel` group membership**, so it has no sudo path. `anonctl status` **positively reports** this (a `sudo: none` line, backed by a `sudo -l -U <account>` probe and a `sudoAllowed:false` field in `status --json`), so the invariant is a checkable fact, not a silent assumption. If the box ever grants the account sudo, `status` warns instead of staying quiet.
- **A minimal login PATH.** The account is provisioned with a minimal login `PATH` (`/usr/local/bin:/usr/bin:/bin`) that **omits the `sbin` directories** carrying the setuid network binaries an audit of a real host flagged (`exim4`, `pppd`, `mount.nfs`). This shrinks what the account can gratuitously *name*; it does **not** remove those binaries from disk (they are system-wide and still reachable by absolute path), so it is a partial hardening, not a barrier.
- **A best-effort `verify` probe (`no-uid-transition-egress`).** `verify` re-asserts the concretely enumerable transition vectors do not yield an off-box socket owned by a non-anon, non-shim uid: the account has no sudo path (`sudo -l -U <account>`), and the documented setuid "run a command as another uid" network wrappers a real-host audit flagged (e.g. `pkexec`, `mullvad-exclude`) do not hand the account a process running as a non-anon, non-shim uid. It is reported **honestly as best-effort, not exhaustive**: it proves only the CHECKED vectors, and it **cannot** enumerate every daemon on every host, so an arbitrary triggerable daemon may still escape (see the honest residual below). It is a named assertion pinned in the [`verify` JSON contract](docs/adr/0003-verify-assertion-names-and-json-contract.md).

**What anonctl does NOT do (the honest residual).** anonctl deliberately does **not** grow a second, namespace-based confinement layer to chase this. The per-UID model cannot force an arbitrary triggerable daemon: if the anon account can make any of the dozens of system daemons (each running as its own non-anon uid) open one outbound connection on its behalf, that connection matches the `accept` first rule and leaves in the clear. On a busy shared host this class of escape is real and remains open. Closing it requires **network-namespace-strength confinement**, which is a different tool: **[netcage](https://github.com/wighawag/netcage)** confines by network namespace, not by uid, so a differently-owned process inside the jail is still on the namespace's forced network path and the whole "a daemon owned by another uid egresses for me" class does not apply. If you need that, run netcage (inside the anon account, or directly); do not expect anonctl's per-UID forcing to substitute for it.

**Recommended host hardening: mount reachable filesystems `nosuid`.** anonctl cannot own the host's mount policy (remounting a shared host's `/` `nosuid` would break the machine and is out of scope), but where the account's reachable filesystem CAN be `nosuid` (a dedicated mount, or a `nosuid` `/home`), mount it so: **a setuid binary on a `nosuid` mount does not gain its owner's uid**, which closes the whole "setuid transition" half of this escape for anything under that mount. On a typical host the scratch mounts (`/tmp`, `/dev/shm`, `/run`) are already `nosuid`; the win is making the account's own reachable filesystems `nosuid` too where practical.

### Precision: "kernel-forced" but userspace-relayed

"Kernel-forced" is precise about **the kernel doing the REDIRECT and the DROP**: the nftables rules that redirect the account's TCP into the shim, and that drop everything else, run in the kernel. The relay the traffic is redirected *into*, the per-account shim (a transparent TCP-to-SOCKS relay plus a DNS-over-SOCKS-TCP forwarder), is a **userspace** process. So do not over-read "kernel": the enforcement (redirect/drop) is kernel-enforced and cannot be bypassed by a tool in the account, but the actual anonymizing relay is an ordinary userspace program running under a dedicated shim UID. See [ADR-0002](docs/adr/0002-per-account-inet-table-and-rule-ordering.md) for the ruleset and its two closures.

### ICMP, PMTU, and non-TCP UDP (QUIC/HTTP-3)

The account's non-TCP egress is closed the same fail-closed way its direct TCP is: it falls through to the anon UID's default DROP, and `verify` PROVES it (the `icmp-drop` and `non-tcp-udp-drop` assertions), rather than assuming the policy handles it.

- **ICMP is dropped, and anonctl deliberately does NOT tune PMTU.** An ICMP echo (`ping`) or any raw ICMP from the account is dropped, so it cannot leak your real source IP. Whole-OS transparent-Tor systems (Tails) drop ALL ICMP system-wide and therefore mirror it with a global `net.ipv4.tcp_mtu_probing` sysctl to keep Path-MTU discovery working. anonctl does **not** set that sysctl: it drops ICMP for **one UID only**, so the rest of the machine's PMTU discovery is untouched, and a per-account tool flipping a global kernel knob would be a surprising, out-of-scope system mutation. The anon UID's forced TCP also rides the shim to a SOCKS proxy, so the classic direct-path ICMP-PMTU black-holing that motivates the Tails sysctl does not apply to the anonymized path the way it does to a direct Tor transport. The residual is a documented caveat, not a tuned mutation.
- **Non-53 UDP (including UDP/443, QUIC / HTTP-3) is dropped.** The forced path is a SOCKS relay, which carries **TCP only**, so any UDP that is not the redirected DNS (53) is unrelayable and is dropped fail-closed, never sent in the clear. In practice a modern client that prefers QUIC/HTTP-3 over UDP/443 is **expected to degrade to TCP** rather than leak (standard client behaviour: HTTP-3 falls back to HTTP/2-over-TCP when UDP/443 does not work). anonctl proves the **drop**; the TCP fallback is the client's job, not a tested anonctl assertion.

## The cross-identification boundary

On a shared multi-user host you may want a second guarantee: two anonymized accounts must not be **cross-identifiable** (must not be observable as exiting through the same identity). This guarantee is **share-class-bounded**, safe in exactly one configuration:

- **`tor-shared` + `<account>@` (safe).** A host-wide Tor daemon is safe to share across accounts because anonctl dials it with a per-account SOCKS username (`<account>@`), and Tor's `IsolateSOCKSAuth` gives each username a separate circuit and exit. Two accounts on one Tor are therefore NOT cross-identifiable.
- **Shared `socks-peruser` (unsafe, and REFUSED).** A plain socks endpoint has no per-username isolation: it is a single identity. Sharing one across accounts would make them exit identically and become cross-identifiable, so anonctl treats a `socks-peruser` endpoint as usable by AT MOST ONE account and refuses/flags sharing it.

anonctl classifies an endpoint's share-class (`tor-shared` vs `socks-peruser`) by a conservative, operator-overridable heuristic on the address, and fails SAFE: an unrecognised endpoint is `socks-peruser` (single identity, one account), never a false `tor-shared` sharing guarantee. The endpoint is credential-free at rest by construction. See [ADR-0001](docs/adr/0001-endpoint-share-class-heuristic-and-credential-free-at-rest.md).

The cross-identification defense is therefore real but **bounded**: it holds for `tor-shared` accounts via the `<account>@` isolation username, and it is enforced by refusal (not silence) for the unsafe `socks-peruser` case. It is NOT a claim that any two anonctl accounts are always unlinkable regardless of endpoint.

## Tor-over-Tor (double-anonymization) caveat

If the anon account is ALREADY anonymized, forcing it through a SECOND anonymizer (Tor over Tor) degrades anonymity and breaks connectivity. anonctl makes this caveat both **documented** (here) and **detectable**: after `verify` passes, anonctl writes a marker at `/etc/anonctl/<account>.json`, a versioned, credential-free JSON record that a sibling tool (anon-pi, netcage) reads to detect "this account is already kernel-anonymized" and SKIP re-forcing. The marker is a dependency-free signal (no anonctl binary needed to read it), it is written strictly AFTER `verify` passes (it is a coordination claim, not a live security proof), and it deliberately excludes the endpoint URL and any credentials because it is world-readable under `/etc`. `anonctl status --json` is a convenience reader of the same truth. See [ADR-0004](docs/adr/0004-marker-contract-schema-precedence-and-trust.md).

## Operating notes

- **anonctl does not manage your endpoint.** It anonymizes through an endpoint you run; it does not install, start, or supervise Tor or a per-user proxy (it can scan for and suggest one). **Enable your endpoint at boot yourself** (e.g. `systemctl enable --now tor.service`), so it is up when the account needs it. anonctl's own artifacts (the ruleset and the per-account shim unit) do persist across reboots and re-apply fail-closed; the endpoint is the one piece that is yours to keep running. Because the rules fail closed, an endpoint that is not yet up at boot means the account is dropped, never leaking, so there is no ordering hazard to design around. See [ADR-0005](docs/adr/0005-reboot-persistence-and-boot-invariant.md).
- **Re-run `verify` as the trust anchor.** After the initial setup, after every reboot, and after any Tor/kernel/nftables change, run `anonctl verify [<name>]`. anonctl is a persistent-policy manager, not a one-shot tool; `verify` is how you catch a setup that silently stopped forcing.
- **`update`/`reconfigure` has no leak window.** Changing an account's endpoint re-applies the nft rules as an atomic table replace (the default-DROP is never absent) BEFORE restarting the shim, so egress is dropped-or-forced throughout, never un-anonymized.

## Decisions (ADRs)

The rationale behind anonctl's load-bearing choices lives in [`docs/adr/`](docs/adr/) and is cross-referenced above rather than restated. The ADRs record, with a real why: applying the rules as root (the ufw stance, the deliberate divergence from anon-pi's paste-the-commands stance); the uniform socks5h-forcing mechanism (Tor is just the default endpoint, not a separate backend); the endpoint share-class and the `<account>@` isolation; the per-account static-Go shim, one per account under its own shim UID; the fail-closed `inet` ruleset with its rule ordering and its two bypass closures; the narrow private-only LAN exemption; the `verify` assertion names and `--json` contract; the world-readable, credential-free marker contract; and the reboot persistence with its boot invariant. Consult that folder for the "why" behind any behaviour described here.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
