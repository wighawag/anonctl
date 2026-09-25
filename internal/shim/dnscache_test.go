package shim

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/socks5hfixture"
)

// The cache's unit level: what it stores, for how long, and what it refuses to
// store. The properties asserted here are the ones a wrong answer would come from
// (a TTL that outlives the record, a negative answer held past its SOA, a query
// profile that changes what a correct answer is), plus the bound that keeps a
// runaway client from growing the shim.

// TestDNSCache_HitRespectsTTLAndCountsItDown: an answer is served back from the
// cache with the ASKER's message id and a REMAINING TTL, not the original one. A
// cache that replayed the full TTL every time would let a downstream resolver hold a
// 60-second record indefinitely.
func TestDNSCache_HitRespectsTTLAndCountsItDown(t *testing.T) {
	c := newDNSCache()
	q := buildAQuery(uniqueName)
	resp := aResponse(q, uniqueName, answerIP, 60)
	c.put(q, resp)

	// A second client asks the same question with a DIFFERENT message id.
	q2 := buildAQuery(uniqueName)
	binary.BigEndian.PutUint16(q2[:2], 0xBEEF)
	got, ok := c.get(q2)
	if !ok {
		t.Fatal("the same question missed the cache")
	}
	if id := binary.BigEndian.Uint16(got[:2]); id != 0xBEEF {
		t.Errorf("cached answer carried id %#04x, want the asker's own %#04x", id, 0xBEEF)
	}
	if ip := parseFirstA(got); ip != answerIP {
		t.Errorf("cached answer resolved to %q, want %q", ip, answerIP)
	}
	if ttl := firstAnswerTTL(t, got); ttl > 60 || ttl == 0 {
		t.Errorf("served TTL %d, want a remaining TTL in (0,60]", ttl)
	}

	// Backdate the entry past its TTL: the entry must be gone, not merely stale.
	for k, e := range c.entries {
		e.stored = e.stored.Add(-90 * time.Second)
		e.expires = e.expires.Add(-90 * time.Second)
		c.entries[k] = e
	}
	if _, ok := c.get(q2); ok {
		t.Error("an answer past its own TTL was served from the cache")
	}
	if c.len() != 0 {
		t.Error("the expired entry was not dropped")
	}
}

// TestDNSCache_KeyedOnQuestionAndProfile: the key is the question, not the name
// alone, and it includes the bits of the query that change what a correct answer IS.
// Serving an A answer to an AAAA question, or a non-EDNS answer to an EDNS asker,
// would be a wrong answer that no client could detect.
func TestDNSCache_KeyedOnQuestionAndProfile(t *testing.T) {
	c := newDNSCache()
	q := buildAQuery(uniqueName)
	c.put(q, aResponse(q, uniqueName, answerIP, 60))

	if _, ok := c.get(buildAQuery("other.anonctl.test")); ok {
		t.Error("a different name hit the cache")
	}
	aaaa := buildAQuery(uniqueName)
	aaaa[len(aaaa)-3] = 28 // qtype AAAA
	if _, ok := c.get(aaaa); ok {
		t.Error("a different qtype hit the cache")
	}
	if _, ok := c.get(withEDNS(buildAQuery(uniqueName), true)); ok {
		t.Error("an EDNS/DO query hit an entry fetched without EDNS")
	}
	// Case-insensitivity is required: DNS names are case-insensitive, and a client
	// that varies case (0x20 encoding) must not miss every time.
	if _, ok := c.get(buildAQuery(strings.ToUpper(uniqueName))); !ok {
		t.Error("the same name in different case missed the cache")
	}
}

// TestDNSCache_NegativeAnswerHeldOnlyAsFarAsTheSOAAllows: NXDOMAIN is cacheable, but
// only for min(SOA.TTL, SOA.MINIMUM) (RFC 2308) and never past the negative cap,
// because a wrongly held NXDOMAIN is a name the account cannot reach at all.
func TestDNSCache_NegativeAnswerHeldOnlyAsFarAsTheSOAAllows(t *testing.T) {
	q := buildAQuery(uniqueName)

	// SOA MINIMUM of 30s with a larger record TTL: the smaller wins.
	ttl, _, ok := dnsResponseTTL(nxdomainResponse(q, uniqueName, 3600, 30))
	if !ok {
		t.Fatal("an NXDOMAIN with an SOA must be cacheable")
	}
	if ttl != 30*time.Second {
		t.Errorf("negative TTL %s, want 30s (min of SOA TTL and SOA MINIMUM)", ttl)
	}

	// A huge SOA MINIMUM is capped.
	ttl, _, ok = dnsResponseTTL(nxdomainResponse(q, uniqueName, 86400, 86400))
	if !ok {
		t.Fatal("an NXDOMAIN with a large SOA must still be cacheable")
	}
	if ttl != dnsCacheMaxNegativeTTL {
		t.Errorf("negative TTL %s, want the %s cap", ttl, dnsCacheMaxNegativeTTL)
	}

	// No SOA: nothing authorises holding it, so it is not held.
	bare := nxdomainResponse(q, uniqueName, 0, 0)
	binary.BigEndian.PutUint16(bare[8:10], 0) // drop the authority section count
	if _, _, ok := dnsResponseTTL(bare[:len(bare)-1]); ok {
		t.Error("an NXDOMAIN with no SOA was treated as cacheable")
	}
}

// TestDNSCache_RefusesWhatMustNotBeCached covers the responses where caching would
// be actively wrong rather than merely unhelpful.
func TestDNSCache_RefusesWhatMustNotBeCached(t *testing.T) {
	q := buildAQuery(uniqueName)
	cases := []struct {
		name string
		resp []byte
	}{
		{"TTL 0", aResponse(q, uniqueName, answerIP, 0)},
		{"truncated (TC set)", withFlag(aResponse(q, uniqueName, answerIP, 60), 0x0200)},
		{"SERVFAIL", withRcode(aResponse(q, uniqueName, answerIP, 60), 2)},
		{"REFUSED", withRcode(aResponse(q, uniqueName, answerIP, 60), 5)},
		{"not a response", withoutFlag(aResponse(q, uniqueName, answerIP, 60), 0x8000)},
	}
	for _, tc := range cases {
		c := newDNSCache()
		c.put(q, tc.resp)
		if c.len() != 0 {
			t.Errorf("%s was cached; it must not be", tc.name)
		}
	}
}

// TestDNSCache_IsBounded: a client asking for endless distinct names cannot grow the
// shim without limit.
func TestDNSCache_IsBounded(t *testing.T) {
	c := newDNSCache()
	for i := 0; i < dnsCacheMaxEntries+50; i++ {
		name := "n" + itoa(i) + ".anonctl.test"
		q := buildAQuery(name)
		c.put(q, aResponse(q, name, answerIP, 600))
	}
	if n := c.len(); n > dnsCacheMaxEntries {
		t.Errorf("cache holds %d entries, over the %d bound", n, dnsCacheMaxEntries)
	}
}

// TestForwarder_CacheHitNeverReachesTheUpstream is the cache's reason to exist: the
// second lookup of a name the account has just resolved costs no exchange over the
// endpoint at all. The observable is the UPSTREAM's own query count, not a timing,
// so the assertion cannot pass by accident on a fast machine.
func TestForwarder_CacheHitNeverReachesTheUpstream(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{answers: map[string]string{uniqueName: answerIP}, ttl: 600})
	fwd := startForwarderVia(t, res, ForwarderConfig{})

	for i := 0; i < 3; i++ {
		if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
			t.Fatalf("lookup %d resolved to %q, want %q", i+1, ip, answerIP)
		}
	}
	if n := res.queryCount(); n != 1 {
		t.Fatalf("the upstream saw %d queries for 3 identical lookups; want 1 (the rest served from this account's cache)", n)
	}
}

// TestForwarder_CacheExpiryGoesUpstreamAgain is the other half of the same property:
// the cache respects the ANSWER'S OWN TTL, so a name whose record has expired is
// re-resolved over the endpoint rather than served stale forever.
func TestForwarder_CacheExpiryGoesUpstreamAgain(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{answers: map[string]string{uniqueName: answerIP}, ttl: 1})
	fwd := startForwarderVia(t, res, ForwarderConfig{})

	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("first lookup resolved to %q, want %q", ip, answerIP)
	}
	if n := res.queryCount(); n != 1 {
		t.Fatalf("the upstream saw %d queries, want 1", n)
	}
	time.Sleep(1100 * time.Millisecond) // past the record's 1s TTL
	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("lookup after TTL expiry resolved to %q, want %q", ip, answerIP)
	}
	if n := res.queryCount(); n != 2 {
		t.Fatalf("the upstream saw %d queries; want 2 (the expired entry must be re-resolved)", n)
	}
}

// TestForwarder_FailsClosedOnACacheMissWithTheEndpointDown is the property the cache
// could most plausibly have broken: a MISS must still fail closed. There is no host
// resolver in this picture and there must never be one, however cheap it would be to
// ask it when the endpoint is gone.
//
// It also asserts the converse, which is correct rather than a leak: an answer
// already in the cache CAME from the endpoint, so serving it after the endpoint dies
// discloses nothing new and is exactly what a TTL is for.
func TestForwarder_FailsClosedOnACacheMissWithTheEndpointDown(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{answers: map[string]string{uniqueName: answerIP}, ttl: 600})
	fx := socks5hfixture.New(socks5hfixture.Options{
		KnownHosts:     map[string]string{upstreamName: hostOf(res.addr())},
		RedirectTarget: res.addr(),
	})
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:          "127.0.0.1:0",
		ProxyAddr:       fx.Addr(),
		Upstream:        upstreamName + ":53",
		ExchangeTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("priming lookup resolved to %q, want %q", ip, answerIP)
	}
	fx.Close() // the endpoint is gone

	// A MISS: nothing may answer it, and in particular nothing may answer it with an
	// address, which is what a host-resolver fallback would look like.
	if resp, ok := rawQuery(t, fwd.Addr(), "never-asked-before.anonctl.test", 2*time.Second); ok {
		if ip := parseFirstA(resp); ip != "" {
			t.Fatalf("a cache MISS with the endpoint down was answered with %q: that can only have come from somewhere other than the endpoint", ip)
		}
		if rcode := resp[3] & 0x0F; rcode == 0 {
			t.Fatalf("a cache miss with the endpoint down got a NOERROR answer; want no answer or a failure rcode")
		}
	}
	// A HIT: still served, from an answer that came over the endpoint while it was up.
	if ip := queryAWithTimeout(t, fwd.Addr(), uniqueName, 5*time.Second); ip != answerIP {
		t.Fatalf("a cached answer resolved to %q after the endpoint died, want %q", ip, answerIP)
	}
}

// TestForwarder_UpstreamServfailIsNeverCached: an upstream resolver that answers
// SERVFAIL is asked again next time. Its failure is a statement about that moment;
// holding it would turn one bad second into an account that cannot resolve a name
// for as long as the entry lived.
func TestForwarder_UpstreamServfailIsNeverCached(t *testing.T) {
	res := startPipelinedResolver(t, resolverOptions{servfail: true})
	fwd := startForwarderVia(t, res, ForwarderConfig{})

	for i := 0; i < 2; i++ {
		resp, ok := rawQuery(t, fwd.Addr(), uniqueName, 5*time.Second)
		if !ok {
			t.Fatalf("lookup %d: no answer; the upstream's SERVFAIL should have been passed through", i+1)
		}
		if rcode := resp[3] & 0x0F; rcode != 2 {
			t.Fatalf("lookup %d: rcode %d, want the upstream's SERVFAIL (2)", i+1, rcode)
		}
	}
	if n := res.queryCount(); n != 2 {
		t.Fatalf("the upstream saw %d queries for 2 lookups; want 2 (a SERVFAIL must never be served from the cache)", n)
	}
}

// ---- wire helpers for cache tests ----

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// aResponse renders a response to query with one A record at the given TTL.
func aResponse(query []byte, name, ip string, ttl uint32) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(resp[6:8], 1)
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1}
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], ttl)
	rr = append(rr, t[:]...)
	rr = append(rr, 0, 4)
	rr = append(rr, net.ParseIP(ip).To4()...)
	return append(resp, rr...)
}

// nxdomainResponse renders an NXDOMAIN with one SOA in the authority section.
func nxdomainResponse(query []byte, name string, soaTTL, soaMinimum uint32) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2], resp[3] = 0x81, 0x83 // response, NXDOMAIN
	binary.BigEndian.PutUint16(resp[8:10], 1)
	rr := []byte{0xc0, 0x0c, 0, 6, 0, 1} // SOA/IN, owner compressed to the question
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], soaTTL)
	rr = append(rr, t[:]...)
	// rdata: MNAME, RNAME, then SERIAL REFRESH RETRY EXPIRE MINIMUM
	rdata := append(encodeName("ns.anonctl.test"), encodeName("hostmaster.anonctl.test")...)
	var nums [20]byte
	binary.BigEndian.PutUint32(nums[16:20], soaMinimum)
	rdata = append(rdata, nums[:]...)
	var rdLen [2]byte
	binary.BigEndian.PutUint16(rdLen[:], uint16(len(rdata)))
	rr = append(rr, rdLen[:]...)
	rr = append(rr, rdata...)
	return append(resp, rr...)
}

// withEDNS appends an OPT RR, optionally with the DO bit set.
func withEDNS(query []byte, do bool) []byte {
	out := make([]byte, len(query))
	copy(out, query)
	binary.BigEndian.PutUint16(out[10:12], 1) // ARCOUNT
	opt := []byte{0, 0, 41, 0x10, 0x00}       // root owner, type OPT, class 4096
	var ttl [4]byte
	if do {
		binary.BigEndian.PutUint32(ttl[:], 0x00008000)
	}
	opt = append(opt, ttl[:]...)
	return append(append(out, opt...), 0, 0) // rdlength 0
}

func withFlag(resp []byte, flag uint16) []byte {
	out := make([]byte, len(resp))
	copy(out, resp)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|flag)
	return out
}

func withoutFlag(resp []byte, flag uint16) []byte {
	out := make([]byte, len(resp))
	copy(out, resp)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])&^flag)
	return out
}

func withRcode(resp []byte, rcode uint16) []byte {
	out := make([]byte, len(resp))
	copy(out, resp)
	flags := binary.BigEndian.Uint16(out[2:4])&^0x000F | rcode
	binary.BigEndian.PutUint16(out[2:4], flags)
	return out
}

// firstAnswerTTL reads the TTL of the first answer record.
func firstAnswerTTL(t *testing.T, resp []byte) uint32 {
	t.Helper()
	_, off, err := dnsName(resp, 12)
	if err != nil {
		t.Fatalf("parse question: %v", err)
	}
	_, _, ttlOff, err := dnsRR(resp, off+4)
	if err != nil {
		t.Fatalf("parse answer: %v", err)
	}
	return binary.BigEndian.Uint32(resp[ttlOff : ttlOff+4])
}
