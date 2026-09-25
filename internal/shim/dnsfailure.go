package shim

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

// WHY A FAILED RESOLUTION CARRIES A REASON. The forwarder answers SERVFAIL when it
// cannot resolve over the endpoint, instead of dropping the query in silence (a
// silent drop is what sent two people to conntrack and nft for an event inside this
// forwarder). But "SERVFAIL" alone still leaves the operator guessing, and the two
// common causes call for OPPOSITE next moves: ENDPOINT UNREACHABLE means the
// anonymizer is not running or not listening where the account says ("your Tor is
// down"), while DEADLINE EXPIRED means the endpoint is up and the circuit was slow
// ("your circuit was slow", usually a cold one after idle, and re-running is the
// right response). So the reason is classified once, here, and reported twice: in
// the shim's log for the operator, and as an RFC 8914 Extended DNS Error on the
// SERVFAIL itself, which is how `anonctl verify` (a DNS client on the far side of
// the redirect, with no access to this log) can name the right one.

// dnsFailureKind is WHY an upstream attempt produced no answer.
type dnsFailureKind int

const (
	// dnsFailOther is a failure none of the others describes. It is reported as such
	// rather than guessed into one of them.
	dnsFailOther dnsFailureKind = iota
	// dnsFailEndpointUnreachable: nothing accepted a TCP connection at the SOCKS
	// endpoint's own address. The anonymizer is down or not listening there.
	dnsFailEndpointUnreachable
	// dnsFailEndpointRefused: the endpoint accepted the connection and then failed
	// the CONNECT to the upstream resolver. The endpoint is up; for Tor this is a
	// circuit or exit that could not reach the resolver.
	dnsFailEndpointRefused
	// dnsFailDeadline: the attempt (dial, SOCKS handshake and exchange together) ran
	// out of time. The endpoint accepted us; the circuit was too slow.
	dnsFailDeadline
	// dnsFailStreamBroken: the upstream stream died mid-exchange and the one re-dial
	// did not rescue the query.
	dnsFailStreamBroken
)

// token is the stable, machine-readable name of a failure kind. It is the contract
// between the shim and `anonctl verify` (carried as EDE extra text), in the same way
// ANSWERED:/NOANSWER: is the contract for the probe's output, so it is a fixed
// vocabulary and never prose.
func (k dnsFailureKind) token() string {
	switch k {
	case dnsFailEndpointUnreachable:
		return "anonctl:endpoint-unreachable"
	case dnsFailEndpointRefused:
		return "anonctl:endpoint-refused"
	case dnsFailDeadline:
		return "anonctl:deadline-expired"
	case dnsFailStreamBroken:
		return "anonctl:stream-broken"
	}
	return "anonctl:other"
}

// edeInfoCode maps a failure onto the closest RFC 8914 info code. The code is for
// generic clients; anonctl itself reads the token, because no registered code says
// "the anonymizer is down" as distinct from "the anonymizer is slow".
func (k dnsFailureKind) edeInfoCode() uint16 {
	if k == dnsFailDeadline {
		return 22 // No Reachable Authority: nothing answered in time
	}
	return 23 // Network Error: communication with the next hop failed
}

// logReason renders the operator-facing log text: the classification first, then
// what it means, then the raw error, because the raw error alone is what used to be
// missing entirely.
func (k dnsFailureKind) logReason(proxyAddr, upstream string, err error) string {
	switch k {
	case dnsFailEndpointUnreachable:
		return fmt.Sprintf("endpoint unreachable: nothing accepted a connection at %s (is the anonymizer, e.g. Tor, running and listening there?): %v", proxyAddr, err)
	case dnsFailEndpointRefused:
		return fmt.Sprintf("endpoint refused: %s accepted the connection but could not reach the upstream resolver %s (a circuit or exit failure; the endpoint itself is up): %v", proxyAddr, upstream, err)
	case dnsFailDeadline:
		return fmt.Sprintf("deadline expired: no answer from %s via %s in time (the endpoint is up and the circuit was slow, typically a cold one after idle): %v", upstream, proxyAddr, err)
	case dnsFailStreamBroken:
		return fmt.Sprintf("upstream stream broken: the connection to %s via %s died mid-exchange and a re-dial did not recover it: %v", upstream, proxyAddr, err)
	}
	return fmt.Sprintf("upstream failure via %s: %v", proxyAddr, err)
}

// errEndpointUnreachable tags a failure to open the TCP connection to the SOCKS
// endpoint ITSELF. It is attached where that dial happens (reachabilityDialer),
// because by the time the error has come back through the SOCKS client it is one
// net.OpError among many and a message string is the only other way to tell them
// apart.
type errEndpointUnreachable struct{ err error }

func (e *errEndpointUnreachable) Error() string { return e.err.Error() }
func (e *errEndpointUnreachable) Unwrap() error { return e.err }

// reachabilityDialer is the SOCKS client's forward dialer: a plain TCP dial to the
// endpoint whose failures are tagged as unreachable. A dial cut short by the
// caller's deadline is NOT tagged, because that is a slow path and not a dead one.
type reachabilityDialer struct{}

var _ proxy.ContextDialer = reachabilityDialer{}

func (reachabilityDialer) Dial(network, addr string) (net.Conn, error) {
	return reachabilityDialer{}.DialContext(context.Background(), network, addr)
}

func (reachabilityDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, addr)
	if err != nil && ctx.Err() == nil {
		return nil, &errEndpointUnreachable{err: err}
	}
	return c, err
}

// classifyDNSFailure turns an upstream error into its kind. The order matters: a
// deadline is checked first, since a timed-out dial is also a failed dial.
func classifyDNSFailure(err error) dnsFailureKind {
	var unreachable *errEndpointUnreachable
	var opErr *net.OpError
	switch {
	case errors.Is(err, errUpstreamTimeout), errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return dnsFailDeadline
	case errors.As(err, &unreachable):
		return dnsFailEndpointUnreachable
	case errors.Is(err, errUpstreamBroken):
		return dnsFailStreamBroken
	case errors.As(err, &opErr) && strings.Contains(opErr.Op, "socks"):
		// x/net's SOCKS client names its own operations "socks connect" (and documents
		// that an Op containing "socks" is its own). Reaching this case means the endpoint
		// was reached, since a failed forward dial is tagged above, and the CONNECT failed.
		// Matching the exact string "connect" was the first version, and a test with a real
		// refusing endpoint caught it filing every refusal under "other".
		return dnsFailEndpointRefused
	}
	return dnsFailOther
}

// servfail renders the failure a client can SEE: the question echoed back as a
// response with rcode SERVFAIL and no records, under the client's own message ID.
// When the query carried EDNS the response carries an OPT RR with an Extended DNS
// Error naming the failure kind; when it did not, it carries no OPT at all (RFC
// 6891 forbids an OPT in a response to a query without one). It reports ok=false
// for a message too short to answer at all, which is dropped.
//
// Why SERVFAIL rather than REFUSED or a close: it is the rcode that means "this
// server could not complete your query", which is exactly true, it carries no
// resolution, and nothing caches it as a negative answer. glibc treats it as a
// failure for that server and moves on instead of waiting out its own timeout, and
// moving on loses nothing, because every nameserver the account could try is
// redirected into this same forwarder by the nft rule (the
// lan-exemption-not-a-dns-hole assertion holds exactly that).
func servfail(query []byte, kind dnsFailureKind) ([]byte, bool) {
	if len(query) < 12 {
		return nil, false
	}
	end := len(query)
	edns := false
	if qend, ok := questionEnd(query); ok {
		end = qend
		edns, _ = ednsProfile(query, qend)
	}
	resp := make([]byte, end)
	copy(resp, query[:end])
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000             // QR: this is a response
	flags = flags&^0x000F | 0x2 // rcode 2, SERVFAIL
	flags &^= 0x0200            // not truncated
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT, set below if an OPT goes back
	if edns {
		resp = append(resp, edeOPT(kind)...)
		binary.BigEndian.PutUint16(resp[10:12], 1)
	}
	return resp, true
}

// edeOPT renders an OPT RR carrying one Extended DNS Error option (RFC 8914).
func edeOPT(kind dnsFailureKind) []byte {
	text := kind.token()
	opt := []byte{0}                               // owner: root
	opt = binary.BigEndian.AppendUint16(opt, 41)   // TYPE OPT
	opt = binary.BigEndian.AppendUint16(opt, 1232) // CLASS: UDP payload size
	opt = binary.BigEndian.AppendUint32(opt, 0)    // extended rcode, version, flags
	optLen := 4 + 2 + len(text)                    // option header + info code + text
	opt = binary.BigEndian.AppendUint16(opt, uint16(optLen))
	opt = binary.BigEndian.AppendUint16(opt, 15) // OPTION-CODE: Extended DNS Error
	opt = binary.BigEndian.AppendUint16(opt, uint16(2+len(text)))
	opt = binary.BigEndian.AppendUint16(opt, kind.edeInfoCode())
	return append(opt, text...)
}

// questionEnd returns the offset just past a single question, so the SERVFAIL
// echoes the question and nothing else. A query with no parseable question is
// echoed whole, header flags corrected, which is still a well-formed failure.
func questionEnd(query []byte) (int, bool) {
	if binary.BigEndian.Uint16(query[4:6]) != 1 {
		return 0, false
	}
	_, off, err := dnsName(query, 12)
	if err != nil || off+4 > len(query) {
		return 0, false
	}
	return off + 4, true
}

// ExtendedDNSError reads the first RFC 8914 Extended DNS Error from a response: its
// info code and extra text. ok=false means the response carries none (no OPT RR, or
// an OPT with no EDE option), which is the ordinary case for any answer that is not
// one of the forwarder's own failures. It is PURE, and it is exported because it is
// the reading half of the contract whose writing half is servfail: it is what lets a
// client on the far side of the redirect (`anonctl verify`'s probe) tell an
// unreachable endpoint from a slow circuit.
func ExtendedDNSError(resp []byte) (code uint16, text string, ok bool) {
	if len(resp) < 12 {
		return 0, "", false
	}
	off := 12
	for i := 0; i < int(binary.BigEndian.Uint16(resp[4:6])); i++ {
		_, next, err := dnsName(resp, off)
		if err != nil || next+4 > len(resp) {
			return 0, "", false
		}
		off = next + 4
	}
	skip := int(binary.BigEndian.Uint16(resp[6:8])) + int(binary.BigEndian.Uint16(resp[8:10]))
	for i := 0; i < skip; i++ {
		next, _, _, err := dnsRR(resp, off)
		if err != nil {
			return 0, "", false
		}
		off = next
	}
	for i := 0; i < int(binary.BigEndian.Uint16(resp[10:12])); i++ {
		next, rrType, ttlOff, err := dnsRR(resp, off)
		if err != nil {
			return 0, "", false
		}
		if rrType == 41 {
			rd := resp[ttlOff+6 : next]
			for len(rd) >= 4 {
				optCode := binary.BigEndian.Uint16(rd[0:2])
				optLen := int(binary.BigEndian.Uint16(rd[2:4]))
				if 4+optLen > len(rd) {
					return 0, "", false
				}
				if optCode == 15 && optLen >= 2 {
					data := rd[4 : 4+optLen]
					return binary.BigEndian.Uint16(data[0:2]), string(data[2:]), true
				}
				rd = rd[4+optLen:]
			}
		}
		off = next
	}
	return 0, "", false
}
