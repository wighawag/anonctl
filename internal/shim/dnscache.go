package shim

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

// The forwarder's answer cache: in-memory, TTL-respecting, bounded, and PER
// ACCOUNT by construction.
//
// WHY. Every miss costs a DNS exchange over the endpoint: a circuit round trip at
// best, and whatever a slow or cold circuit costs at worst. Most of a real workload's
// lookups are repeats of names it has just resolved: a
// page load re-resolves the same handful of hosts, a `git fetch` the same forge, and
// glibc asks A and AAAA for each of them. Answering those from the last answer's own
// TTL is the difference between a forced account feeling usable and feeling broken.
//
// WHY IT CANNOT LEAK BETWEEN ACCOUNTS. The cache is a field of one Forwarder, the
// forwarder is one per shim process, and the shim is one process per account under
// its own dedicated uid. There is no shared store, no file on disk, and nothing that
// outlives the process: a restart of the shim starts empty. That is a property to
// KEEP, not an implementation detail, and it is why this is not a box-wide resolver
// cache however much cheaper that would be.
//
// THE ONE HONEST CAVEAT, stated here rather than in a commit message because this
// is where someone will read it: A LOCAL CACHE IS A TIMING SIDE CHANNEL. Anyone who
// can send a query to this forwarder's DNS port can time the answer and learn
// whether the account has recently resolved a given name, without resolving it
// themselves. That port is a loopback port with no uid filter on its input path
// (the forcing governs EGRESS from the account, not who may talk to the shim), so
// on a shared box the observer is not only root: any local uid can ask. What it
// buys them is a recency oracle over names, bounded by the TTLs below; what it
// costs to remove is every repeat lookup going back over the circuit. Root and the
// operator can already see more than this by other means (the shim's own
// connections, conntrack, the account's processes), so the exposure that is new is
// to an unprivileged local uid on a multi-user host. If that matters for a
// deployment, the answer is a uid-filtered input rule on the shim's DNS port, which
// would also close the pre-existing ability of any local uid to use the account's
// circuit for its own lookups; the cache did not create that.

const (
	// dnsCacheMaxEntries bounds the cache. Answers are small (a few hundred bytes),
	// so this is a small memory ceiling, and it exists so a hostile or runaway client
	// cannot grow the shim's footprint without limit by asking for endless names.
	dnsCacheMaxEntries = 1024
	// dnsCacheMaxTTL caps how long ANY answer is held, however generous its own TTL.
	// A forced account's names are looked up over a circuit that may be replaced
	// underneath it; holding an answer for a day would outlive the world it was
	// resolved in.
	dnsCacheMaxTTL = time.Hour
	// dnsCacheMaxNegativeTTL caps negative answers more tightly than positive ones
	// (RFC 2308's negative caching, bounded): a wrongly held NXDOMAIN is a name the
	// account cannot reach at all, which is a worse failure than one extra lookup.
	dnsCacheMaxNegativeTTL = 5 * time.Minute
	// dnsCacheMaxResponse skips caching answers larger than this. A big answer is
	// rare, and the cache exists for the common repeat.
	dnsCacheMaxResponse = 4096
)

// dnsCache is a bounded map from a query's identity to the last answer for it.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	// resp is the upstream's response bytes, stored as they arrived apart from the
	// message ID, which is per-client and is rewritten on the way out.
	resp []byte
	// stored/expires bound the entry; ttlOffsets are the byte offsets of every RR TTL
	// field in resp, so what is served back carries the REMAINING TTL rather than the
	// original one. A cache that hands out the full TTL every time makes downstream
	// caches hold an answer for as long as it likes, which is how a five-minute record
	// becomes an hour-old one.
	stored     time.Time
	expires    time.Time
	ttlOffsets []int
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

// get returns a response for query, with the client's own message ID and TTLs
// counted down, or ok=false when there is nothing usable.
func (c *dnsCache) get(query []byte) (resp []byte, ok bool) {
	key, cacheable := dnsCacheKey(query)
	if !cacheable {
		return nil, false
	}
	now := time.Now()
	c.mu.Lock()
	e, found := c.entries[key]
	if found && now.After(e.expires) {
		delete(c.entries, key)
		found = false
	}
	c.mu.Unlock()
	if !found {
		return nil, false
	}
	out := make([]byte, len(e.resp))
	copy(out, e.resp)
	copy(out[:2], query[:2]) // the asker's own ID, not the one the answer arrived with
	// And the asker's own QUESTION, byte for byte, so the answer always matches what was
	// asked even in letter case (a stub resolver using 0x20 randomisation compares it).
	// The key guarantees the two questions are the same name; only their spelling of it
	// may differ, and only when neither is compressed are they the same length.
	if qend, ok := questionEnd(query); ok {
		if _, rend, err := dnsName(out, 12); err == nil && rend+4 == qend {
			copy(out[12:qend], query[12:qend])
		}
	}
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	for _, off := range e.ttlOffsets {
		orig := binary.BigEndian.Uint32(out[off : off+4])
		remaining := uint32(1)
		if orig > elapsed {
			remaining = orig - elapsed
		}
		binary.BigEndian.PutUint32(out[off:off+4], remaining)
	}
	return out, true
}

// put stores an answer under the query's identity, if it is one worth storing.
func (c *dnsCache) put(query, resp []byte) {
	key, cacheable := dnsCacheKey(query)
	if !cacheable || len(resp) > dnsCacheMaxResponse {
		return
	}
	ttl, offsets, ok := dnsResponseTTL(resp)
	if !ok || ttl <= 0 {
		return
	}
	stored := make([]byte, len(resp))
	copy(stored, resp)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= dnsCacheMaxEntries {
		c.evictLocked(now)
	}
	c.entries[key] = dnsCacheEntry{resp: stored, stored: now, expires: now.Add(ttl), ttlOffsets: offsets}
}

// evictLocked makes room: expired entries first, and if there are none, the entry
// closest to expiry. Nothing here is an LRU: the cache's job is to hold the names a
// workload is using right now, and those are re-inserted on their next miss.
func (c *dnsCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < dnsCacheMaxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, e := range c.entries {
		if oldestKey == "" || e.expires.Before(oldest) {
			oldestKey, oldest = k, e.expires
		}
	}
	delete(c.entries, oldestKey)
}

// len reports the number of entries (for tests and for reasoning about the bound).
func (c *dnsCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// dnsCacheKey renders the identity of a query: its single question plus the bits of
// the header and of EDNS that change what a correct answer IS.
//
// The profile bits are not decoration. DO (DNSSEC OK) and CD (checking disabled)
// change what the resolver returns, and whether the query carried an OPT RR at all
// changes whether the answer may exceed 512 bytes, so an answer fetched for one
// profile must not be served to a client that asked with another. Anything with more
// than one question, a non-zero opcode, or an unparseable question is NOT cacheable
// and is simply forwarded.
func dnsCacheKey(query []byte) (string, bool) {
	if len(query) < 12 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&0x7800 != 0 { // QR must be 0 here and opcode must be QUERY
		return "", false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 {
		return "", false
	}
	wire, off, err := dnsWireName(query, 12)
	if err != nil || off+4 > len(query) {
		return "", false
	}
	qtype := binary.BigEndian.Uint16(query[off : off+2])
	qclass := binary.BigEndian.Uint16(query[off+2 : off+4])
	cd := flags & 0x0010
	edns, do := ednsProfile(query, off+4)
	return fmt.Sprintf("%x|%d|%d|%d|%t|%t", wire, qtype, qclass, cd, edns, do), true
}

// dnsWireName renders the name at off in its canonical WIRE form (length-prefixed
// labels, ASCII letters lowercased, compression pointers followed) for use as a cache
// key, and returns the offset just past the name in the message.
//
// WHY THE WIRE FORM AND NOT THE DOTTED STRING. A label may legally contain a dot, so
// the single label `example.com` and the two labels `example` + `com` render to the
// same dotted string and would share an entry. Anyone who can reach the forwarder's
// DNS port (any local uid, measured) could then plant the NXDOMAIN for the one-label
// name, capped at five minutes and renewable at will, under the key the account's
// real lookups use, and the account could not resolve that name at all. The wire
// form cannot collide: two names share a key only if they ARE the same name.
func dnsWireName(msg []byte, off int) ([]byte, int, error) {
	var wire []byte
	jumps := 0
	cur := off
	end := -1
	for {
		if cur >= len(msg) {
			return nil, 0, fmt.Errorf("dns: name runs past the message")
		}
		l := int(msg[cur])
		switch {
		case l == 0:
			if end < 0 {
				end = cur + 1
			}
			return append(wire, 0), end, nil
		case l&0xC0 == 0xC0:
			if cur+1 >= len(msg) {
				return nil, 0, fmt.Errorf("dns: truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3FFF)
			if end < 0 {
				end = cur + 2
			}
			jumps++
			if jumps > 16 || ptr >= len(msg) {
				return nil, 0, fmt.Errorf("dns: bad compression pointer")
			}
			cur = ptr
		case l&0xC0 != 0:
			return nil, 0, fmt.Errorf("dns: reserved label type")
		default:
			if cur+1+l > len(msg) {
				return nil, 0, fmt.Errorf("dns: label runs past the message")
			}
			wire = append(wire, byte(l))
			for _, b := range msg[cur+1 : cur+1+l] {
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				wire = append(wire, b)
			}
			cur += 1 + l
		}
	}
}

// ednsProfile reports whether the query carried an OPT RR and whether DO is set.
// It reads the ADDITIONAL section conservatively: anything it cannot parse is
// reported as "no EDNS", which only ever means a separate cache entry, never a
// wrong answer served to the wrong asker.
func ednsProfile(query []byte, off int) (edns bool, do bool) {
	extra := int(binary.BigEndian.Uint16(query[10:12]))
	// Skip the answer and authority sections; a query normally has none.
	for _, count := range []int{int(binary.BigEndian.Uint16(query[6:8])), int(binary.BigEndian.Uint16(query[8:10]))} {
		for i := 0; i < count; i++ {
			next, _, _, err := dnsRR(query, off)
			if err != nil {
				return false, false
			}
			off = next
		}
	}
	for i := 0; i < extra; i++ {
		next, rrType, ttlOff, err := dnsRR(query, off)
		if err != nil {
			return false, false
		}
		if rrType == 41 { // OPT
			// In an OPT RR the TTL field carries extended rcode and flags; DO is its top bit.
			flags := binary.BigEndian.Uint32(query[ttlOff : ttlOff+4])
			return true, flags&0x00008000 != 0
		}
		off = next
	}
	return false, false
}

// dnsResponseTTL decides how long a response may be held and where its TTL fields
// are. It returns ok=false for anything that must not be cached.
func dnsResponseTTL(resp []byte) (time.Duration, []int, bool) {
	if len(resp) < 12 {
		return 0, nil, false
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 { // not a response
		return 0, nil, false
	}
	if flags&0x0200 != 0 {
		// TRUNCATED. Caching a truncated answer would serve an incomplete answer set for
		// the whole TTL, and the client that gets it cannot tell it was ours.
		return 0, nil, false
	}
	rcode := flags & 0x000F
	if rcode == 2 {
		// SERVFAIL IS NEVER CACHED, in either direction. Not an UPSTREAM SERVFAIL (the
		// resolver's failure is a statement about that moment, and holding it would turn one
		// bad second into minutes of an account that cannot resolve a name), and not the
		// forwarder's OWN SERVFAIL either, which structurally never reaches put: it is made
		// after resolveViaSOCKS returns an error, and only answers that came back through the
		// endpoint are stored. Named here, ahead of the general rule below that also excludes
		// it, because this is the one exclusion whose absence would be a fail-closed bug
		// dressed as a performance one: a cached "could not resolve" outlives the outage.
		return 0, nil, false
	}
	if rcode != 0 && rcode != 3 { // otherwise NOERROR and NXDOMAIN only
		return 0, nil, false
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		return 0, nil, false
	}
	_, off, err := dnsName(resp, 12)
	if err != nil || off+4 > len(resp) {
		return 0, nil, false
	}
	qtype := binary.BigEndian.Uint16(resp[off : off+2])
	off += 4

	answers := int(binary.BigEndian.Uint16(resp[6:8]))
	authority := int(binary.BigEndian.Uint16(resp[8:10]))
	additional := int(binary.BigEndian.Uint16(resp[10:12]))

	var offsets []int
	minTTL := uint32(0)
	haveTTL := false
	// answersQuestion: some answer record is of the type ASKED (or the question asked
	// for the CNAME itself, or for everything). Without one, the answer section is at
	// most a CNAME chain to a name with no such record, which RFC 2308 treats as a
	// NEGATIVE answer, and an earlier version held for the CNAME's TTL, up to an hour.
	answersQuestion := false
	// ANSWER section: the TTL is the smallest TTL in it (RFC 2181's reading of a
	// record set's lifetime), and every TTL is remembered so it can be counted down.
	for i := 0; i < answers; i++ {
		next, rrType, ttlOff, err := dnsRR(resp, off)
		if err != nil {
			return 0, nil, false
		}
		if rrType != 41 {
			ttl := binary.BigEndian.Uint32(resp[ttlOff : ttlOff+4])
			if !haveTTL || ttl < minTTL {
				minTTL, haveTTL = ttl, true
			}
			offsets = append(offsets, ttlOff)
			if rrType == qtype || qtype == 5 || qtype == 255 {
				answersQuestion = true
			}
		}
		off = next
	}
	// AUTHORITY section: for a negative answer this is where the lifetime comes from
	// (RFC 2308: min(SOA.TTL, SOA.MINIMUM)). Its TTLs are counted down too.
	negTTL := uint32(0)
	haveNeg := false
	for i := 0; i < authority; i++ {
		next, rrType, ttlOff, err := dnsRR(resp, off)
		if err != nil {
			return 0, nil, false
		}
		if rrType != 41 {
			offsets = append(offsets, ttlOff)
		}
		if rrType == 6 { // SOA
			rdLen := int(binary.BigEndian.Uint16(resp[ttlOff+4 : ttlOff+6]))
			rdStart := ttlOff + 6
			if rdLen >= 4 && rdStart+rdLen <= len(resp) {
				soaMinimum := binary.BigEndian.Uint32(resp[rdStart+rdLen-4 : rdStart+rdLen])
				soaTTL := binary.BigEndian.Uint32(resp[ttlOff : ttlOff+4])
				ttl := soaMinimum
				if soaTTL < ttl {
					ttl = soaTTL
				}
				if !haveNeg || ttl < negTTL {
					negTTL, haveNeg = ttl, true
				}
			}
		}
		off = next
	}
	for i := 0; i < additional; i++ {
		next, rrType, ttlOff, err := dnsRR(resp, off)
		if err != nil {
			return 0, nil, false
		}
		if rrType != 41 { // an OPT RR's "TTL" is flags, not a lifetime: never touched
			offsets = append(offsets, ttlOff)
		}
		off = next
	}

	var ttl time.Duration
	switch {
	case rcode == 0 && answersQuestion:
		ttl = time.Duration(minTTL) * time.Second
		if ttl > dnsCacheMaxTTL {
			ttl = dnsCacheMaxTTL
		}
	case haveNeg:
		// A NEGATIVE answer (NXDOMAIN, or NOERROR with no record of the asked type, with or
		// without a CNAME chain in front) is held only as far as the zone's own SOA allows,
		// never longer than any CNAME in the chain, and never longer than the negative cap.
		ttl = time.Duration(negTTL) * time.Second
		if haveTTL && time.Duration(minTTL)*time.Second < ttl {
			ttl = time.Duration(minTTL) * time.Second
		}
		if ttl > dnsCacheMaxNegativeTTL {
			ttl = dnsCacheMaxNegativeTTL
		}
	default:
		// No record of the asked type and no SOA to authorise negative caching: nothing
		// says how long this may be held, so it is not held at all.
		return 0, nil, false
	}
	return ttl, offsets, true
}

// dnsName reads a (possibly compressed) name at off and returns it plus the offset
// just past it. Compression pointers are followed for READING the name, and a
// pointer ends the name in the wire stream, which is what the returned offset
// reflects.
func dnsName(msg []byte, off int) (string, int, error) {
	var parts []string
	jumps := 0
	cur := off
	end := -1
	for {
		if cur >= len(msg) {
			return "", 0, fmt.Errorf("dns: name runs past the message")
		}
		l := int(msg[cur])
		switch {
		case l == 0:
			cur++
			if end < 0 {
				end = cur
			}
			return strings.Join(parts, "."), end, nil
		case l&0xC0 == 0xC0:
			if cur+1 >= len(msg) {
				return "", 0, fmt.Errorf("dns: truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3FFF)
			if end < 0 {
				end = cur + 2
			}
			jumps++
			if jumps > 16 || ptr >= len(msg) {
				return "", 0, fmt.Errorf("dns: bad compression pointer")
			}
			cur = ptr
		case l&0xC0 != 0:
			return "", 0, fmt.Errorf("dns: reserved label type")
		default:
			if cur+1+l > len(msg) {
				return "", 0, fmt.Errorf("dns: label runs past the message")
			}
			parts = append(parts, string(msg[cur+1:cur+1+l]))
			cur += 1 + l
		}
	}
}

// dnsRR steps over one resource record at off, returning the offset after it, its
// type, and the offset of its 4-byte TTL field.
func dnsRR(msg []byte, off int) (next int, rrType uint16, ttlOff int, err error) {
	_, after, err := dnsName(msg, off)
	if err != nil {
		return 0, 0, 0, err
	}
	if after+10 > len(msg) {
		return 0, 0, 0, fmt.Errorf("dns: record header runs past the message")
	}
	rrType = binary.BigEndian.Uint16(msg[after : after+2])
	ttlOff = after + 4
	rdLen := int(binary.BigEndian.Uint16(msg[after+8 : after+10]))
	next = after + 10 + rdLen
	if next > len(msg) {
		return 0, 0, 0, fmt.Errorf("dns: record data runs past the message")
	}
	return next, rrType, ttlOff, nil
}
