package shim

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// The DNS ROUND-TRIP probe: a minimal, dependency-free DNS client `anonctl verify`
// execs AS the anon UID (`anonctl-shim -dns-probe <server> <name>`, under setpriv)
// to measure whether the account's DNS actually WORKS through the forced path,
// rather than inferring it from the rules being installed.
//
// It must NOT use the Go resolver (net.LookupHost) and it must NOT use NSS: both
// would answer from whatever resolves for the account, which is precisely the
// thing under test (an out-of-process NSS provider such as nscd/nsncd or
// systemd-resolved resolves in ANOTHER process under ANOTHER uid, so its answer
// says nothing about the account's own sockets). This sends one A query from a
// socket owned by the calling uid to a NAMED server, so the packet traverses the
// account's own `meta skuid` rules and the answer, if any, comes back on the same
// socket.
//
// WHY THE ROUND TRIP IS THE MEASUREMENT, not the query leaving. Measured on a
// NixOS + Tailscale host (work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md):
// the redirect fired, the query reached the shim, and the shim answered over Tor,
// yet the account got nothing, because the reply is un-NATed back to the
// NAMESERVER's address before it is delivered and a host-owned input filter
// dropped it on that source address. Every packet-level signal said "working".
// Only asking for the ANSWER catches it.

// DNSProbeTimeout is the total deadline for one probe query. It is deliberately
// far longer than ProbeTimeout, and the size is derived rather than picked: a
// healthy forced path here is a full DNS round trip over the endpoint, not a
// loopback dial.
//
// IT MUST EXCEED THE SHIM'S OWN BUDGET FOR THE SAME QUERY, which is an UNBOUNDED
// SOCKS dial (dnsforwarder.go builds its dialer over proxy.Direct, which has no
// timeout, and a COLD Tor circuit build is seconds) PLUS the forwarder's own 5s
// deadline on the upstream exchange. At 5s the client gave up no later than the
// server's first leg, so the first `verify` after a reboot could report a
// perfectly healthy path as "the shim never answered" -- a wrong diagnosis, and a
// red that makes `use`/`exec` refuse a shell. Measured on a warm circuit the whole
// round trip is ~0.5s; the margin here is for the cold one. It mirrors the
// generous window the other Tor-round-trip probes take (curlAsAnon's 25s) and the
// same margin rule probeExecBudget states for the dial probes. A genuinely dropped
// answer burns the whole window, which is why `verify` runs its checks
// concurrently.
const DNSProbeTimeout = 20 * time.Second

// dnsProbeDeadline is the deadline DNSProbe actually applies. It is a package var
// ONLY so the unit suite can prove the silent-server path (the measured failure
// shape: the shim answered and the answer never arrived) without burning the full
// production window in every test run. Production never changes it.
var dnsProbeDeadline = DNSProbeTimeout

// dnsProbeQType is the query type the probe sends: A (1). The probe's subject is
// WHETHER AN ANSWER COMES BACK, never what the answer is, so the cheapest,
// most universally served type is the right one.
const dnsProbeQType = 1

// BuildDNSQuery renders a minimal RFC 1035 query message for one name: a header
// with RD set and a single A/IN question. It is PURE so the wire format is
// unit-tested without a socket. It refuses a name that cannot be encoded (an empty
// or over-long label, or an over-long name) rather than emit a malformed packet
// that would fail in a way indistinguishable from a dropped answer.
func BuildDNSQuery(id uint16, name string) ([]byte, error) {
	msg := make([]byte, 0, 64)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD (recursion desired)
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	msg = append(msg, hdr[:]...)

	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return nil, fmt.Errorf("dns probe: empty name")
	}
	if len(trimmed) > 253 {
		return nil, fmt.Errorf("dns probe: name %q is longer than 253 bytes", name)
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" {
			return nil, fmt.Errorf("dns probe: name %q has an empty label", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("dns probe: name %q has a label longer than 63 bytes", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // root label
	var qtail [4]byte
	binary.BigEndian.PutUint16(qtail[0:2], dnsProbeQType)
	binary.BigEndian.PutUint16(qtail[2:4], 1) // IN
	return append(msg, qtail[:]...), nil
}

// ParseDNSResponse reads the response header and reports the RCODE and answer
// count, or an error when the message is not a response to wantID. It is PURE.
//
// An NXDOMAIN (rcode 3) is a perfectly good ANSWER for this probe's purpose: the
// probe asks whether the resolver on the far side of the forced path can be
// reached and can reply, not whether the name exists. The probe name is
// deliberately one that cannot exist, so NXDOMAIN is the EXPECTED pass.
func ParseDNSResponse(resp []byte, wantID uint16) (rcode int, answers int, err error) {
	if len(resp) < 12 {
		return 0, 0, fmt.Errorf("dns probe: short response (%d bytes)", len(resp))
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != wantID {
		return 0, 0, fmt.Errorf("dns probe: response id %d does not match query id %d", got, wantID)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		return 0, 0, fmt.Errorf("dns probe: message is not a response")
	}
	return int(flags & 0x000F), int(binary.BigEndian.Uint16(resp[6:8])), nil
}

// dnsProbeID is the query id the probe uses. It is FIXED rather than random on
// purpose: the probe opens a fresh unconnected socket per run and reads exactly
// one datagram from it, the id is echoed by the responder, and ParseDNSResponse
// checks it, so its only job is to reject a stray datagram. A fixed id keeps the
// whole probe deterministic and unit-testable end to end.
const dnsProbeID = 0x4131

// DNSProbe sends one A query for name to server (host:port, an IP literal so the
// probe itself never needs to resolve anything) from the CALLING uid, and reports
// whether an answer came back. It is the measurement behind the
// `dns-forced-path-answers` assertion.
//
// Polarity: an answer of ANY rcode is ANSWERED (the forced path carried a query
// and returned a reply). A timeout, an EPERM on the send (the fail-closed drop),
// or a malformed reply is NOT answered, and the detail carries the reason so the
// caller can tell "nothing came back" from "the kernel refused to send it".
func DNSProbe(server, name string) (answered bool, detail string) {
	if server == "" || name == "" {
		return false, "usage: -dns-probe <server-ip:port> <name>"
	}
	query, err := BuildDNSQuery(dnsProbeID, name)
	if err != nil {
		return false, err.Error()
	}
	c, err := (&net.Dialer{Timeout: dnsProbeDeadline}).Dial("udp", server)
	if err != nil {
		return false, err.Error()
	}
	defer c.Close()
	deadline := time.Now().Add(dnsProbeDeadline)
	_ = c.SetDeadline(deadline)
	if _, werr := c.Write(query); werr != nil {
		// An EPERM here is the fail-closed drop on the SEND side: the kernel refused to
		// emit the query at all. Distinct from a silent timeout, so say so.
		return false, "send failed: " + werr.Error()
	}
	buf := make([]byte, 1500)
	n, rerr := c.Read(buf)
	if rerr != nil {
		return false, "no answer: " + rerr.Error()
	}
	rcode, answers, perr := ParseDNSResponse(buf[:n], dnsProbeID)
	if perr != nil {
		return false, perr.Error()
	}
	return true, fmt.Sprintf("rcode=%d answers=%d", rcode, answers)
}

// DNSProbeResult renders a DNSProbe outcome as the single-line token the caller
// (`anonctl verify`'s runSetprivDNSProbe) greps for, mirroring ProbeResult's
// REACHED/DROPPED shape. It is a pure formatter so the exact wire string is
// unit-tested; the caller treats output matching NEITHER token as "the probe could
// not run", which is a LOUD failure, never a pass.
func DNSProbeResult(answered bool, detail string) string {
	if answered {
		return "ANSWERED:" + detail
	}
	return "NOANSWER:" + detail
}
