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

A **bare verb** targets the default account `anon`; `<name>` targets `anon-<name>`, so you can run several independently-anonymized accounts (`anonctl add work` provisions `anon-work`). Each account gets its OWN dedicated shim service account (`<account>-shim`), the only UID allowed to reach the upstream endpoint. The forcing survives reboots (an anonctl-owned nftables ruleset loaded via `nftables.service`, plus a per-account `anonctl-shim@<account>.service`) and re-applies fail-closed at boot, so there is never a window where the account has un-anonymized egress.

```sh
sudo anonctl add                    # provision + force `anon` through the local Tor SOCKS port
sudo anonctl verify                 # prove it: anonymized exit, DNS remote, a direct dial DROPPED
sudo anonctl add --endpoint socks5h://127.0.0.1:1080 work   # a second account through another endpoint
```

## verify is the trust anchor

`verify` is the signature ONGOING verb: it does not assume anonymization, it PROVES it, and you re-run it **after setup, after a reboot, and after any Tor/kernel/nftables change**. It emits **named assertions**, exits **non-zero on any failure**, and supports `--json` (a versioned envelope with a derived top-level `ok`) so you can gate CI/automation on it. The assertions cover: the exit IP differs from the host's (and, for a Tor endpoint, is a Tor exit); DNS resolves remotely via the endpoint, never a plaintext local query; a direct (non-anonymized) connection from the account is actually DROPPED, for **both** IPv4 and IPv6, reported separately; the two bypass closures hold (the account can reach only its own shim's loopback port, and only the shim UID can reach the upstream endpoint); and, when a LAN split-tunnel is active, that it stays tight.

The live probes stand up real connections as the anon UID and therefore need root and a provisioned host; they are compiled only under the `integration` build tag. The **default binary cannot silently "pass"**: without the integration build its `verify` returns one honest failing assertion telling you to run the integration build on the host, and exits non-zero. Fail-closed extends to the verifier itself: it never reports green unless it actually proved green.

## What anonctl guarantees and what it does NOT

anonctl's one **guarantee** is **per-UID fail-closed anonymized egress**: every TCP and DNS packet from the forced account is pushed through the anonymizer, fail-closed, and `verify` proves it. Knowing the boundary of that guarantee means the residual risk is documented, not surprising. anonctl is as candid here as its sibling netcage is in "What netcage hides and what it does NOT". The full rationale for each decision below lives in [`docs/adr/`](docs/adr/) (cross-referenced throughout), so this section states the boundary rather than re-arguing it.

### Defended (this is the guarantee)

- **An app choosing a wrong proxy, or no proxy at all.** The forcing is at the **kernel**, keyed on the account's UID, so a proxy-unaware or misconfigured tool cannot escape it: its raw sockets are redirected into the shim regardless of what it thinks its proxy is.
- **A DNS leak.** DNS from the account is resolved **remotely over the endpoint** (DNS-over-SOCKS-TCP, socks5h), never as a plaintext query, so you do not leak via DNS. `verify` tests this, it is not merely configured.
- **An anonymizer-down leak.** The account's default egress policy is **DROP** (fail-closed). If the endpoint is unreachable, the account's traffic is dropped, never quietly falling back to the direct route. This holds at boot too: the default-DROP loads early, so the worst case is dropped-until-the-shim-and-endpoint-are-up, never leaking-until-forcing-is-applied.
- **Cross-identification of two accounts on a shared endpoint** (see [The cross-identification boundary](#the-cross-identification-boundary) for the exact, share-class-bounded shape of this one).

### NOT defended (accepted residual)

Per-UID forcing binds the policy to the **UID**. That is precisely what makes these three out of scope: the policy is only as strong as the UID boundary and the kernel enforcing it.

- **Root on the box.** Root can undo the nftables rules, stop the shim, or read anything. anonctl's rules protect against a compromised or careless *tool running as the anon account*, not against an adversary who already has root. If root is compromised, so is everything.
- **A process changing its own UID away from the forced one.** The forcing matches the anon UID; a process that legitimately leaves that UID (for example via a setuid path root granted it) leaves the policy with it. anonctl binds egress to a UID, it does not prevent a privileged transition off that UID.
- **Kernel compromise.** The redirect and the drop are enforced by the kernel; a compromised kernel can lie about all of it. anonctl trusts the kernel it runs on.

Defending against this last category is explicitly out of scope for anonctl (it would need a different isolation model, a VM or a sandboxed kernel). Being **honest** about it is in scope; that is what this section is.

### Precision: "kernel-forced" but userspace-relayed

"Kernel-forced" is precise about **the kernel doing the REDIRECT and the DROP**: the nftables rules that redirect the account's TCP into the shim, and that drop everything else, run in the kernel. The relay the traffic is redirected *into*, the per-account shim (a transparent TCP-to-SOCKS relay plus a DNS-over-SOCKS-TCP forwarder), is a **userspace** process. So do not over-read "kernel": the enforcement (redirect/drop) is kernel-enforced and cannot be bypassed by a tool in the account, but the actual anonymizing relay is an ordinary userspace program running under a dedicated shim UID. See [ADR-0002](docs/adr/0002-per-account-inet-table-and-rule-ordering.md) for the ruleset and its two closures.

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
