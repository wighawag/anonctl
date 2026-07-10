# The LAN exemption requires an explicit port; the all-ports form is removed, and the flag is `--allow`

Status: accepted

## Context

The narrow LAN exemption (story 23-25, first shipped per ADR-0005/0006) let the operator carve one private destination out of the forced path so the anon account can reach a trusted local service (e.g. a LAN LLM) directly while everything else stays forced fail-closed. As first shipped it accepted a port-omitted value: `--allow-direct 192.168.1.150` (or a bare CIDR `10.0.0.0/24`) opened `ip daddr <host> tcp dport != 53 accept`, i.e. EVERY TCP port except 53, direct and un-anonymized. The 53-exclusion (ADR-0003's `lan-exemption-not-a-dns-hole`) patched the clear-DNS symptom, but the underlying grant was still "all ports".

For an anonymity tool that is a real deanonymization vector, not merely a wide hole. If the exempted LAN host happens to run ANY forwarding proxy on some other port (an `ssh -D` SOCKS on 1080, a squid/HTTP proxy on 3128, a Tor SocksPort on 9050, a socat/reverse tunnel), the anon account can dial that proxy directly and egress to the WHOLE internet from the operator's real IP, around the forced path. A forwarding-proxy port deanonymizes MORE than a DNS port: it carries arbitrary traffic, not just name lookups. The disease was "all ports"; the 53-exclusion only treated one symptom.

This is a prerequisite for the loopback exemption (`loopback-exemption`): once "exact host:port only" is the invariant, both LAN and loopback holes are the same shape (differing only in the per-class guardrail), so landing this first makes that a clean addition rather than a tangle.

The project does not care about backward compatibility at this stage, so this is taken as a deliberate BACKWARD-INCOMPATIBLE clean break: no compat aliases, no migration shims.

## Decisions

- **A port is MANDATORY; the all-ports (bare-IP / port-omitted) form is removed.** `internal/lanexempt.Parse` now REJECTS a port-omitted value LOUDLY, naming the value and instructing the operator to add `:port`. An exemption is therefore always an exact `IP:port` or `CIDR:port`. The only defensible granularity for an anonymity tool is "reach exactly THIS service", so "reach every port on this host" is no longer expressible. The explicit-`:53` rejection and the private-range (RFC1918 / link-local, IP/CIDR-only) guardrail are unchanged.

- **The now-unreachable `tcp dport != 53` nft path is deleted, not left dead.** With no port-omitted value able to reach the generator, `internal/nftables.exemptMatch`'s `Port == 0` branch (which emitted `tcp dport != 53`) is removed; every exemption emits an exact `tcp dport <port>` in both the nat `return` and the filter `accept`. There is no code path that can ever open more than one exact TCP port. The 53-exclusion is thereby subsumed: an exemption cannot name `:53` (guardrail) and cannot span all ports (removed), so clear tcp/53 to the exempted host still hits the DNS redirect into the shim, and `lan-exemption-not-a-dns-hole` still holds, re-expressed for an exact-port exemption.

- **The flag is renamed `--allow-direct` -> `--allow`, and the box-wide default key `allowDirect` -> `allow`.** With the port always explicit (and, in the sibling task, loopback added), one flag covers all direct-destination classes: `--allow` reads as "allow this exact destination directly, whatever its class", and the tool dispatches on the address the operator already typed. The rename is a clean break across the operator-facing surface: the CLI flag (space and `=` forms, the dangling-value error, the reject message), the `defaults.json` key, the usage/operating-notes text, and the README. anonctl mirrors netcage's `--allow` vocabulary so the two tools stay aligned. The anonctl-internal `accountconfig` `exemptions` key is anonctl-private and keeps its name (a rename there is optional tidiness, not operator-facing).

## Consequences

- An operator who was relying on the all-ports form must now name each exact `host:port` they want reachable. That is intended: the all-ports grant was a leak, so its removal is a security fix, not a regression to smooth over. The reject is loud and names the value, so the failure is self-explaining at config time (including for a `defaults.json` default, which is Parse-gated exactly like the flag).
- `verify`'s `split-tunnel-tight` and `lan-exemption-not-a-dns-hole` assertions are unchanged in name and meaning; their integration probes are re-expressed to exercise an exact-port exemption (the exempted `host:port` reachable directly, a same-/24 sibling and tcp/udp 53 still redirected-or-dropped).
- Because the exemption is now always exactly one port, the verify probe no longer needs a "pick a default port for the all-ports case" fallback: `Exempt.HostPort` always renders the exemption's own concrete port.
