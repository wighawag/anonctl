package main

import (
	"fmt"
	"sort"

	"github.com/wighawag/anoncore/accountconfig"
)

// Per-account shim loopback ports are a PERMANENT, boot-time reservation: the
// account's `anonctl-shim@<account>.service` binds its relay + DNS ports at every
// boot and holds them for the machine's uptime (WantedBy=multi-user.target). So the
// second forced account on a box MUST get a DIFFERENT pair from the first, or its
// shim crash-loops on `bind: address already in use` and `verify` times out (curl
// exit 28) with no shim to relay its traffic. The default constants
// (accountconfig.DefaultRelayPort 19050 / DefaultDNSPort 19053) are only ever right
// for ONE account; every additional account needs an allocated pair.
//
// The allocation is a DOCUMENTED, contiguous range walked in a fixed stride, so a
// sysadmin can see "anonctl owns 19050.. in steps of portStride" and steer their
// own services clear. Because the reservation is a permanent boot-time hold, a
// user service that later tries to bind an anonctl port fails LOUDLY on its own
// side (the normal "address already in use" contract), never a silent leak; the
// only dangerous collision is shim-vs-shim, which is exactly what this allocator
// prevents. Allocation reads the on-disk config set (the reservation LEDGER), NOT
// live sockets: a shim may be momentarily down during an `add`, but its config
// still holds the reservation.

const (
	// portBase is the first account's relay port, matching the validated recipe and
	// accountconfig.DefaultRelayPort (19050). The first slot's ports are therefore the
	// historical defaults (relay 19050, dns 19053), so a single-account box is
	// byte-identical to before this allocator existed.
	portBase = accountconfig.DefaultRelayPort
	// dnsOffset is the DNS port's offset from the slot's relay port (19053 - 19050 = 3),
	// mirroring the default pair's gap so slot 0 reproduces the historical 19050/19053.
	dnsOffset = accountconfig.DefaultDNSPort - accountconfig.DefaultRelayPort
	// portStride is the spacing between consecutive account slots. It is > dnsOffset so a
	// slot's relay+DNS ports never overlap the next slot's, leaving headroom in each slot.
	// slot n uses relay = portBase + n*portStride, dns = relay + dnsOffset.
	portStride = 10
	// maxPortSlots bounds the walk so allocation FAILS LOUD on an absurd account count
	// rather than wandering toward 65535. 4000 slots (19050..~59050) is far past any real
	// deployment (<10 accounts) yet still inside the ephemeral range's lower reaches.
	maxPortSlots = 4000
)

// portPair is one account's allocated shim loopback ports.
type portPair struct {
	relay int
	dns   int
}

// slotPorts returns the relay/DNS pair for slot n (0-based). Slot 0 is the
// historical default pair (19050/19053).
func slotPorts(n int) portPair {
	relay := portBase + n*portStride
	return portPair{relay: relay, dns: relay + dnsOffset}
}

// allocatePortPair picks the first port slot whose relay AND DNS ports are BOTH
// unclaimed by any existing account config, so a new account never lands on a
// sibling's shim ports. `existing` is the current on-disk config set (every OTHER
// account's persisted reservation); a claimed port is any relay OR dns value any
// sibling already holds (an old default-19050/19053 account, or a previously
// allocated slot). It returns an error (never a colliding default) when the
// bounded range is exhausted, so `add` fails loud instead of silently producing a
// crash-looping shim.
//
// It is PURE over the supplied configs (no filesystem, no live sockets), so it is
// unit-testable, and it is deterministic (lowest free slot first) so repeated adds
// pack densely and predictably from the documented base.
func allocatePortPair(existing []accountconfig.Config) (portPair, error) {
	claimed := make(map[int]bool, len(existing)*2)
	for _, c := range existing {
		if c.RelayPort != 0 {
			claimed[c.RelayPort] = true
		}
		if c.DNSPort != 0 {
			claimed[c.DNSPort] = true
		}
	}
	for n := 0; n < maxPortSlots; n++ {
		p := slotPorts(n)
		if p.dns > 65535 {
			break
		}
		if !claimed[p.relay] && !claimed[p.dns] {
			return p, nil
		}
	}
	return portPair{}, fmt.Errorf(
		"no free shim port slot in the anonctl range (base %d, stride %d, %d slots): %d account(s) already configured, ports in use: %v; free one with `anonctl rm` or widen the range",
		portBase, portStride, maxPortSlots, len(existing), claimedPortsSummary(existing))
}

// claimedPortsSummary renders the sorted set of relay/DNS ports already reserved by
// the given configs, for a diagnostic message when allocation is tight. It is a
// pure helper used only to make a failure legible.
func claimedPortsSummary(existing []accountconfig.Config) []int {
	seen := map[int]bool{}
	var ports []int
	for _, c := range existing {
		for _, p := range []int{c.RelayPort, c.DNSPort} {
			if p != 0 && !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	sort.Ints(ports)
	return ports
}
