package main

import (
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
)

// cfgWithPorts is a minimal Config carrying only the ports the allocator reads.
func cfgWithPorts(account string, relay, dns int) accountconfig.Config {
	return accountconfig.Config{Account: account, RelayPort: relay, DNSPort: dns}
}

// TestAllocateFirstAccountGetsHistoricalDefaults proves the very first account (no
// siblings) lands on the historical default pair (19050/19053), so a single-account
// box is byte-identical to before the allocator existed.
func TestAllocateFirstAccountGetsHistoricalDefaults(t *testing.T) {
	p, err := allocatePortPair(nil)
	if err != nil {
		t.Fatalf("allocatePortPair(nil): %v", err)
	}
	if p.relay != accountconfig.DefaultRelayPort || p.dns != accountconfig.DefaultDNSPort {
		t.Fatalf("first slot = %d/%d, want the historical defaults %d/%d",
			p.relay, p.dns, accountconfig.DefaultRelayPort, accountconfig.DefaultDNSPort)
	}
}

// TestAllocateSecondAccountAvoidsFirst is the core regression: a second account
// with the first already on the defaults MUST get a different, non-overlapping pair
// (the exact collision that crash-looped anon-cultivator's shim).
func TestAllocateSecondAccountAvoidsFirst(t *testing.T) {
	first := cfgWithPorts("anon", accountconfig.DefaultRelayPort, accountconfig.DefaultDNSPort)
	p, err := allocatePortPair([]accountconfig.Config{first})
	if err != nil {
		t.Fatalf("allocatePortPair: %v", err)
	}
	if p.relay == first.RelayPort || p.dns == first.DNSPort ||
		p.relay == first.DNSPort || p.dns == first.RelayPort {
		t.Fatalf("second slot %d/%d overlaps the first account's ports %d/%d",
			p.relay, p.dns, first.RelayPort, first.DNSPort)
	}
	// It should be the next slot down the range (deterministic, densest-first).
	want := slotPorts(1)
	if p != want {
		t.Fatalf("second slot = %d/%d, want the next range slot %d/%d", p.relay, p.dns, want.relay, want.dns)
	}
}

// TestAllocatePacksDenselyFromBase proves N sequential adds pack into consecutive
// slots with no overlap, so the range is used predictably and contiguously.
func TestAllocatePacksDenselyFromBase(t *testing.T) {
	var existing []accountconfig.Config
	seen := map[int]bool{}
	for i := 0; i < 12; i++ {
		p, err := allocatePortPair(existing)
		if err != nil {
			t.Fatalf("alloc #%d: %v", i, err)
		}
		for _, port := range []int{p.relay, p.dns} {
			if seen[port] {
				t.Fatalf("alloc #%d reused port %d (overlap)", i, port)
			}
			seen[port] = true
		}
		if p != slotPorts(i) {
			t.Fatalf("alloc #%d = %d/%d, want slot %d = %d/%d", i, p.relay, p.dns, i, slotPorts(i).relay, slotPorts(i).dns)
		}
		existing = append(existing, cfgWithPorts("a", p.relay, p.dns))
	}
}

// TestAllocateFillsAGapLeftByAnRemovedAccount proves allocation is lowest-free-slot,
// so removing a middle account frees its slot for the next add (no monotonic drift).
func TestAllocateFillsAGapLeftByAnRemovedAccount(t *testing.T) {
	// Slots 0 and 2 taken, slot 1 free (its account was rm'd).
	existing := []accountconfig.Config{
		cfgWithPorts("a", slotPorts(0).relay, slotPorts(0).dns),
		cfgWithPorts("c", slotPorts(2).relay, slotPorts(2).dns),
	}
	p, err := allocatePortPair(existing)
	if err != nil {
		t.Fatalf("allocatePortPair: %v", err)
	}
	if p != slotPorts(1) {
		t.Fatalf("allocated %d/%d, want the freed middle slot 1 %d/%d", p.relay, p.dns, slotPorts(1).relay, slotPorts(1).dns)
	}
}

// TestAllocateAvoidsAnEitherPortCollision proves BOTH the relay and DNS values are
// treated as claimed: a sibling whose DNS happens to equal a slot's relay (or vice
// versa) blocks that slot, so the allocator never double-books a single number.
func TestAllocateAvoidsAnEitherPortCollision(t *testing.T) {
	// A synthetic sibling that occupies slot 1's RELAY port as its DNS port.
	existing := []accountconfig.Config{
		cfgWithPorts("a", slotPorts(0).relay, slotPorts(0).dns),
		cfgWithPorts("weird", 40000, slotPorts(1).relay),
	}
	p, err := allocatePortPair(existing)
	if err != nil {
		t.Fatalf("allocatePortPair: %v", err)
	}
	if p.relay == slotPorts(1).relay || p.dns == slotPorts(1).relay {
		t.Fatalf("allocated %d/%d collides with the claimed port %d", p.relay, p.dns, slotPorts(1).relay)
	}
	if p.relay == 40000 || p.dns == 40000 {
		t.Fatalf("allocated %d/%d collides with the claimed port 40000", p.relay, p.dns)
	}
}

// TestAllocateFailsLoudWhenExhausted proves an exhausted range is a LOUD error, not
// a silent colliding default: every slot claimed => an error naming the range, so
// `add` refuses rather than crash-looping a shim.
func TestAllocateFailsLoudWhenExhausted(t *testing.T) {
	var existing []accountconfig.Config
	for n := 0; n < maxPortSlots; n++ {
		p := slotPorts(n)
		if p.dns > 65535 {
			break
		}
		existing = append(existing, cfgWithPorts("a", p.relay, p.dns))
	}
	if _, err := allocatePortPair(existing); err == nil {
		t.Fatal("allocatePortPair on a fully-claimed range returned nil error (must fail loud, never a colliding default)")
	}
}

// TestAllocateIgnoresZeroPorts proves a sibling config with unset (zero) ports does
// not spuriously claim port 0, so a partial/legacy record cannot block allocation.
func TestAllocateIgnoresZeroPorts(t *testing.T) {
	existing := []accountconfig.Config{cfgWithPorts("legacy", 0, 0)}
	p, err := allocatePortPair(existing)
	if err != nil {
		t.Fatalf("allocatePortPair: %v", err)
	}
	if p != slotPorts(0) {
		t.Fatalf("a zero-port sibling blocked slot 0; got %d/%d", p.relay, p.dns)
	}
}

// TestAllocatePortsForReadsLedgerAndAvoidsSibling proves the store-wiring
// (allocatePortsFor) reads the on-disk config set through the configListStore seam
// and hands the allocator the SIBLINGS, so a second account never re-derives the
// first's ports. It uses the same scratch-store swap the claim tests use, so it
// never touches the real /etc/anonctl/accounts.
func TestAllocatePortsForReadsLedgerAndAvoidsSibling(t *testing.T) {
	s := swapConfigListStore(t)
	// Seed the first account; Store.Write fills its ports with the defaults (slot 0).
	writeConfig(t, s, "anon", 9050, endpoint.ClassTorShared)
	got, err := allocatePortsFor("anon-cultivator")
	if err != nil {
		t.Fatalf("allocatePortsFor: %v", err)
	}
	if got == slotPorts(0) {
		t.Fatalf("second account got the first's slot-0 ports %d/%d (collision)", got.relay, got.dns)
	}
	if got != slotPorts(1) {
		t.Fatalf("second account got %d/%d, want the next free slot %d/%d", got.relay, got.dns, slotPorts(1).relay, slotPorts(1).dns)
	}
}

// TestAllocatePortsForExcludesOwnRecord proves a re-derivation for an account that
// ALREADY has a record excludes its own reservation, so it does not spuriously
// treat its own ports as taken and skip past its slot.
func TestAllocatePortsForExcludesOwnRecord(t *testing.T) {
	s := swapConfigListStore(t)
	writeConfig(t, s, "anon", 9050, endpoint.ClassTorShared) // slot 0
	got, err := allocatePortsFor("anon")
	if err != nil {
		t.Fatalf("allocatePortsFor: %v", err)
	}
	if got != slotPorts(0) {
		t.Fatalf("re-deriving anon got %d/%d, want its own slot 0 %d/%d (own record must be excluded)", got.relay, got.dns, slotPorts(0).relay, slotPorts(0).dns)
	}
}
