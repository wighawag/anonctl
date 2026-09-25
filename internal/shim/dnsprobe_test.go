package shim

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// The DNS round-trip probe. Its wire format is unit-proven here, and the probe
// itself is exercised against a real local UDP responder, so the one measurement
// `dns-forced-path-answers` rests on is not taken on trust.

func TestBuildDNSQuery_EncodesOneARecordQuestion(t *testing.T) {
	msg, err := BuildDNSQuery(0x4131, "probe.invalid")
	if err != nil {
		t.Fatalf("BuildDNSQuery: %v", err)
	}
	if got := binary.BigEndian.Uint16(msg[0:2]); got != 0x4131 {
		t.Errorf("id = %#x, want 0x4131", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0x0100 {
		t.Errorf("flags = %#x, want RD set (0x0100)", got)
	}
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 1 {
		t.Errorf("qdcount = %d, want 1", got)
	}
	// The question: length-prefixed labels, root label, then QTYPE=A QCLASS=IN.
	want := append([]byte{5}, "probe"...)
	want = append(want, 7)
	want = append(want, "invalid"...)
	want = append(want, 0, 0, 1, 0, 1)
	if got := msg[12:]; string(got) != string(want) {
		t.Errorf("question = %v, want %v", got, want)
	}
}

func TestBuildDNSQuery_RefusesUnencodableNames(t *testing.T) {
	for _, name := range []string{"", "a..b", strings.Repeat("x", 64) + ".invalid", strings.Repeat("x.", 200) + "invalid"} {
		if _, err := BuildDNSQuery(1, name); err == nil {
			t.Errorf("name %q must be refused rather than emitted malformed (a malformed packet fails in a way indistinguishable from a dropped answer)", name)
		}
	}
	// A trailing dot is the ordinary fully-qualified spelling, not an error.
	if _, err := BuildDNSQuery(1, "probe.invalid."); err != nil {
		t.Errorf("a fully-qualified name must be accepted: %v", err)
	}
}

// NXDOMAIN is the EXPECTED healthy answer for this probe (the name cannot exist),
// so it must parse as an answer, not as a failure. Getting this backwards would
// fail the assertion on every correctly working host.
func TestParseDNSResponse_NXDomainIsAnAnswer(t *testing.T) {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], 0x4131)
	binary.BigEndian.PutUint16(resp[2:4], 0x8183) // QR set, rcode 3 (NXDOMAIN)
	rcode, answers, err := ParseDNSResponse(resp, 0x4131)
	if err != nil {
		t.Fatalf("an NXDOMAIN response must parse: %v", err)
	}
	if rcode != 3 || answers != 0 {
		t.Errorf("rcode=%d answers=%d, want 3/0", rcode, answers)
	}
}

func TestParseDNSResponse_RejectsStrayAndMalformedDatagrams(t *testing.T) {
	ok := make([]byte, 12)
	binary.BigEndian.PutUint16(ok[0:2], 0x4131)
	binary.BigEndian.PutUint16(ok[2:4], 0x8180)

	if _, _, err := ParseDNSResponse(ok[:8], 0x4131); err == nil {
		t.Errorf("a short datagram must be rejected")
	}
	if _, _, err := ParseDNSResponse(ok, 0x9999); err == nil {
		t.Errorf("a datagram answering a DIFFERENT query id must be rejected (it is somebody else's)")
	}
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x4131)
	if _, _, err := ParseDNSResponse(query, 0x4131); err == nil {
		t.Errorf("a message without QR set is not a response")
	}
}

// End to end against a real responder: a probe that gets an answer reports
// ANSWERED with the rcode, which is the signal `dns-forced-path-answers` passes on.
func TestDNSProbe_AnsweredAgainstARealResponder(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		resp := make([]byte, 12)
		copy(resp[0:2], buf[0:2])                     // echo the query id
		binary.BigEndian.PutUint16(resp[2:4], 0x8183) // QR + NXDOMAIN
		_, _ = pc.WriteTo(resp, addr)
	}()

	answered, detail := DNSProbe(pc.LocalAddr().String(), "probe.invalid")
	if !answered {
		t.Fatalf("a responder that answers must read as ANSWERED; got %q", detail)
	}
	if !strings.Contains(detail, "rcode=3") {
		t.Errorf("the detail must carry the rcode; got %q", detail)
	}
	if got := DNSProbeResult(answered, detail); !strings.HasPrefix(got, "ANSWERED:") {
		t.Errorf("wire token = %q, want an ANSWERED: prefix", got)
	}
}

// A silent server is the measured failure shape (the shim answered, the reply was
// dropped on the way back): the probe must report NOANSWER rather than hang, and
// the token must be the one the caller greps for.
func TestDNSProbe_SilentServerReadsAsNoAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close() // bound but never answering

	orig := dnsProbeDeadline
	dnsProbeDeadline = 300 * time.Millisecond
	defer func() { dnsProbeDeadline = orig }()

	start := time.Now()
	answered, detail := DNSProbe(pc.LocalAddr().String(), "probe.invalid")
	if answered {
		t.Fatalf("a server that never answers must read as NOANSWER; got %q", detail)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the probe must bound its own wait; took %v", elapsed)
	}
	if got := DNSProbeResult(answered, detail); !strings.HasPrefix(got, "NOANSWER:") {
		t.Errorf("wire token = %q, want a NOANSWER: prefix", got)
	}
}

func TestDNSProbe_UsageErrorIsNotAnAnswer(t *testing.T) {
	if answered, detail := DNSProbe("", ""); answered || !strings.Contains(detail, "usage") {
		t.Errorf("missing args must report usage and NOT an answer; got %v %q", answered, detail)
	}
}

// THE REASON CONTRACT, end to end: a probe that reaches a forwarder whose endpoint is
// down gets an ANSWER (the path works) whose rcode is SERVFAIL and whose detail names
// the reason in the token `anonctl verify` reads. Proven against the real forwarder,
// not a hand-built reply, because the probe and the shim are two halves of one
// contract and a unit test of either half alone cannot catch them drifting apart.
func TestDNSProbe_ReportsTheShimsFailureReason(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    "127.0.0.1:0",
		ProxyAddr: "127.0.0.1:1", // nothing listening: the endpoint is DOWN
		Upstream:  upstreamName + ":53",
	})
	if err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Close()

	answered, detail := DNSProbe(fwd.Addr(), "probe.invalid.")
	if !answered {
		t.Fatalf("the forwarder answered SERVFAIL, which the probe must report as ANSWERED (the path works); got %q", detail)
	}
	for _, want := range []string{"rcode=2", "anonctl:endpoint-unreachable"} {
		if !strings.Contains(detail, want) {
			t.Errorf("probe detail %q lacks %q", detail, want)
		}
	}
}

func TestEDETextToken_IsOneBoundedToken(t *testing.T) {
	got := edeTextToken("upstream said: no \n thanks" + strings.Repeat("x", 200))
	if strings.ContainsAny(got, " \n\t") || len([]rune(got)) > 80 {
		t.Errorf("edeTextToken produced %q: it must be one whitespace-free token of at most 80 runes", got)
	}
}
