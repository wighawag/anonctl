# A second forced account collides on the fixed shim ports (19050/19053) and its shim crash-loops, so `verify` times out (curl exit 28)

## Symptom

`sudo anonctl verify anon-cultivator` reports:

```
[FAIL] anonymized-exit (error: forced-path curl as anon UID failed: exit status 28 ())
```

`--skip-tor-exit-check` (already added for this account because its Mullvad-style exit IP is not listed on check.torproject.org / onionoo) does NOT help: exit 28 is curl's OPERATION TIMEOUT (it hit `--max-time 25` in `curlAsAnon`, `internal/verify/probes_live.go`), i.e. the forced-path fetch never returned a body at all. The Tor-exit corroboration is downstream of a successful fetch, so a skip of that check cannot rescue a fetch that times out first. Contrast the earlier findings' exit-6 ("couldn't resolve host") case, which is the forcing-absent shape; exit 28 is a different failure: the connection was accepted and redirected but the round-trip stalled.

## Root cause: two accounts, one pair of shim ports

Two forced accounts exist on this host, and BOTH were assigned the same fixed relay/DNS loopback ports:

| account | RELAY_ADDR | DNS_ADDR | endpoint (PROXY_ADDR) |
|---|---|---|---|
| `anon` | `127.0.0.1:19050` | `127.0.0.1:19053` | `127.0.0.1:1080` (wireproxy / Mullvad) |
| `anon-cultivator` | `127.0.0.1:19050` | `127.0.0.1:19053` | `127.0.0.1:9050` (Tor) |

(From `/etc/anonctl/shim/anon.env` and `/etc/anonctl/shim/anon-cultivator.env`.)

`anonctl-shim@anon.service` started first (20h uptime) and owns `19050`/`19053`. When `anonctl-shim@anon-cultivator.service` starts, its DNS forwarder cannot bind:

```
anonctl-shim: shim: start dns forwarder: dns forwarder: listen udp 127.0.0.1:19053: bind: address already in use
systemd[1]: anonctl-shim@anon-cultivator.service: Main process exited, code=exited, status=1/FAILURE
... Scheduled restart job, restart counter is at 206.
```

So there is NO shim serving `anon-cultivator`. Its nft forcing redirects the anon-cultivator UID's TCP to `127.0.0.1:19050`, which nothing (for that account) is listening on in a way that serves it, so the forced-path curl stalls to the 25s timeout -> curl exit 28 -> the `anonymized-exit` (and `dns-remote`) FAIL.

Note a second, quieter hazard even if the second shim somehow bound: because both accounts share `:19050`, the anon-cultivator UID's redirected TCP would be serviced by `anon`'s shim and egress via Mullvad/wireproxy, NOT Tor. The port collision is a correctness bug, not only an availability bug.

## Why the ports collide

`accountconfig.DefaultRelayPort = 19050` / `DefaultDNSPort = 19053` are fixed constants (anoncore `accountconfig/accountconfig.go`). `add`/`verifyParams` fall back to these defaults and there is NO distinct-per-account port allocation. The anoncore comment is explicit that this is a known gap:

> distinct-per-account port ALLOCATION for many accounts is left to a later task (the ports are stored per-account here so that allocation has a place to land without a schema change).

The per-account config schema already CARRIES `RelayPort`/`DNSPort`, so the fix has a landing spot without a schema change: `add` must allocate a free, unused pair per account (and persist it) instead of taking the constant default whenever another account already holds it.

## The environment itself is healthy right now

- Upstream endpoints both reach the internet: wireproxy `:1080` -> `185.201.188.42`, Tor `:9050` -> `185.220.101.109`, host direct -> `51.7.210.6` (all distinct, so anonymization is intact for `anon`).
- `anonctl-shim@anon.service` is active (20h). Only the second account's shim is broken.

So this is purely the multi-account port-allocation gap, not a Tor/Mullvad outage and not a forcing/nft break.

## Immediate remediation (operator, no code change)

Give `anon-cultivator` its own free relay/DNS ports (e.g. `19060`/`19063`), so its shim can bind and its forcing redirects to its own shim:

1. Update the account config to name distinct ports (via `anonctl update` if it exposes them, or by editing `/etc/anonctl/accounts/anon-cultivator.json` and re-running `add`/regenerating the shim env + forcing so the nft redirect, the shim env, and the config agree).
2. Regenerate + reload the nft forcing and the shim env for `anon-cultivator` so relay/DNS point at the new ports.
3. `systemctl reset-failed anonctl-shim@anon-cultivator.service` then `systemctl restart` it, confirm it binds (no more `address already in use`).
4. Re-run `sudo anonctl verify --skip-tor-exit-check anon-cultivator`.

The mismatch to watch: the nft forcing redirect port, the shim env RELAY/DNS port, and the account config port must all be the SAME new pair, or the fetch still stalls.

## The real fix (IMPLEMENTED)

`add` now allocates a free, per-account relay/DNS port pair before persisting the config, so a second (third, ...) forced account never lands on another account's shim ports.

- `portalloc.go` (new): `allocatePortPair` is a PURE function over the existing account configs. It walks a documented, contiguous anonctl range (base 19050, stride 10 per account slot: slot n = relay 19050+10n, dns +3) and returns the first slot whose relay AND dns are both unclaimed by any sibling. Slot 0 is the historical default pair (19050/19053), so a single-account box is byte-identical to before. An exhausted range is a LOUD error (never a silent colliding default), so `add` refuses rather than producing a crash-looping shim.
- `buildConfig` (main.go) calls `allocatePortsFor(account)`, which reads the on-disk config set through the existing `configListStore` seam (the same one `claimEndpoint` uses), excludes the account's OWN record, and hands the siblings to the allocator. The allocated ports are set on the Config, persisted by `forcing.Install` -> `ConfigStore.Write`, and flow into the shim env + nft forcing.
- Allocation reads the config LEDGER, not live sockets (a shim may be momentarily down during an `add`, but its config still holds the reservation).
- Tests: `portalloc_test.go` covers first-account-defaults, second-account-avoids-first (the exact regression), dense packing, gap refill after `rm`, either-port collision, fail-loud-on-exhaustion, zero-port siblings, and the store-wiring (reads the ledger, excludes own record). Full suite + `go vet` green.

## Still TODO (operator, one-time): fix the ALREADY-broken anon-cultivator

The allocator fixes FUTURE adds. The existing `anon-cultivator` record is still on the colliding default 19050/19053 on disk, and `update` deliberately preserves stored ports (it must not move a working account's ports out from under it). So the already-broken account is remediated by RECREATE, which is the codebase's stated recovery path (`runAdd`: "recreating is `rm` then `add`"):

```
sudo anonctl rm anon-cultivator      # tears down the crash-looping shim + its config
sudo anonctl add anon-cultivator ...  # re-adds; now allocates a free pair (slot 1: 19060/19063)
sudo anonctl verify --skip-tor-exit-check anon-cultivator
```

After the re-add, confirm `systemctl status anonctl-shim@anon-cultivator.service` is `active (running)` (no more `bind: address already in use`) before verifying. This one-time recreate is left to the operator (it mutates the live account); the code change prevents the collision from ever recurring on a fresh add.
