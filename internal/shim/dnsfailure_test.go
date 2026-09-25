package shim

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/socks5hfixture"
)

// The failure REASON, which is what separates "your Tor is down" from "your circuit
// was slow". Each case below is produced by a real endpoint shape rather than a
// hand-built error, because the classification rests on how x/net's SOCKS client
// wraps errors, and that is exactly the kind of thing that changes under a version
// bump without failing a build.

func TestClassifyDNSFailure_NamesEachKindFromARealEndpoint(t *testing.T) {
	silent := startSilentDNSOverTCP(t)
	up := &socks5hfixture.Options{KnownHosts: map[string]string{upstreamName: hostOf(silent)}, RedirectTarget: silent}
	fx := socks5hfixture.New(*up)
	if err := fx.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start fixture: %v", err)
	}
	defer fx.Close()
	// A fixture that knows no name for the upstream: it is UP and refuses the CONNECT.
	refusing := socks5hfixture.New(socks5hfixture.Options{DisallowIPConnect: true})
	if err := refusing.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("start refusing fixture: %v", err)
	}
	defer refusing.Close()
	// A listener that accepts TCP and never speaks SOCKS: the handshake itself stalls,
	// which for Tor is where a circuit build waits.
	mute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mute.Close()
	go func() {
		for {
			c, err := mute.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	for _, tc := range []struct {
		name  string
		proxy string
		want  dnsFailureKind
	}{
		{"nothing listening at the endpoint", "127.0.0.1:1", dnsFailEndpointUnreachable},
		{"endpoint up, CONNECT refused", refusing.Addr(), dnsFailEndpointRefused},
		{"endpoint up, handshake never completes", mute.Addr().String(), dnsFailDeadline},
		{"endpoint up, CONNECT ok, upstream never answers", fx.Addr(), dnsFailDeadline},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fwd, err := StartForwarder(ctx, ForwarderConfig{
				Listen: "127.0.0.1:0", ProxyAddr: tc.proxy, Upstream: upstreamName + ":53",
				ExchangeTimeout: 300 * time.Millisecond, NoCache: true,
			})
			if err != nil {
				t.Fatalf("start forwarder: %v", err)
			}
			defer fwd.Close()
			_, rerr := fwd.resolveViaSOCKS(buildAQuery(uniqueName))
			if rerr == nil {
				t.Fatal("resolved through an endpoint that cannot resolve anything")
			}
			if got := classifyDNSFailure(rerr); got != tc.want {
				t.Fatalf("classified %v as %s, want %s", rerr, got.token(), tc.want.token())
			}
		})
	}
}

func TestClassifyDNSFailure_BrokenAndOther(t *testing.T) {
	if got := classifyDNSFailure(fmt.Errorf("%w: read length: EOF", errUpstreamBroken)); got != dnsFailStreamBroken {
		t.Errorf("a broken stream classified as %s", got.token())
	}
	if got := classifyDNSFailure(errors.New("something nobody anticipated")); got != dnsFailOther {
		t.Errorf("an unknown error classified as %s; it must be reported as unknown, not guessed", got.token())
	}
}

// servfail's wire shape: the question echoed, SERVFAIL, no records, and an EDE ONLY
// when the query carried EDNS (RFC 6891 forbids an OPT in reply to a query without).
func TestServfail_CarriesTheReasonOnlyToAnEDNSClient(t *testing.T) {
	plain, ok := servfail(buildAQuery(uniqueName), dnsFailDeadline)
	if !ok {
		t.Fatal("no SERVFAIL for a well-formed query")
	}
	if rcode := plain[3] & 0x0F; rcode != 2 || plain[2]&0x80 == 0 {
		t.Fatalf("flags %#02x%02x: want a response with rcode 2", plain[2], plain[3])
	}
	if ar := binary.BigEndian.Uint16(plain[10:12]); ar != 0 {
		t.Fatalf("a query without EDNS got %d additional records; it must get no OPT", ar)
	}
	if _, _, ok := ExtendedDNSError(plain); ok {
		t.Fatal("an EDE was attached for a client that did not use EDNS")
	}

	for _, kind := range []dnsFailureKind{dnsFailEndpointUnreachable, dnsFailEndpointRefused, dnsFailDeadline, dnsFailStreamBroken, dnsFailOther} {
		resp, ok := servfail(withEDNS(buildAQuery(uniqueName), false), kind)
		if !ok {
			t.Fatal("no SERVFAIL for a well-formed EDNS query")
		}
		code, text, ok := ExtendedDNSError(resp)
		if !ok {
			t.Fatalf("%s: an EDNS client got no Extended DNS Error", kind.token())
		}
		if text != kind.token() || code != kind.edeInfoCode() {
			t.Errorf("EDE = (%d, %q), want (%d, %q)", code, text, kind.edeInfoCode(), kind.token())
		}
		if an := binary.BigEndian.Uint16(resp[6:8]); an != 0 {
			t.Errorf("%s: the failure carried %d answer records", kind.token(), an)
		}
	}
	if _, ok := servfail([]byte{1, 2, 3}, dnsFailOther); ok {
		t.Error("a message shorter than a header cannot be answered and must be dropped")
	}

	// A query without exactly one question (here two, with trailing record bytes) gets
	// a bare header: no undeclared trailing bytes, and counts that describe the message.
	two := buildAQuery(uniqueName)
	binary.BigEndian.PutUint16(two[4:6], 2)
	two = append(two, 0xde, 0xad, 0xbe, 0xef)
	bare, ok := servfail(two, dnsFailOther)
	if !ok {
		t.Fatal("a query with a header is answerable")
	}
	if len(bare) != 12 {
		t.Errorf("SERVFAIL for an unparseable question is %d bytes; want a bare 12-byte header", len(bare))
	}
	for i, name := range []string{"QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"} {
		if n := binary.BigEndian.Uint16(bare[4+2*i : 6+2*i]); n != 0 {
			t.Errorf("%s = %d in a bare SERVFAIL; want 0", name, n)
		}
	}
}

// The operator-facing reason names the NEXT MOVE, which is the point of splitting
// the kinds: an unreachable endpoint and a slow circuit must not read alike.
func TestDNSFailureLogReason_TellsDownFromSlow(t *testing.T) {
	down := dnsFailEndpointUnreachable.logReason("127.0.0.1:9050", "1.1.1.1:53", errors.New("connection refused"))
	slow := dnsFailDeadline.logReason("127.0.0.1:9050", "1.1.1.1:53", errUpstreamTimeout)
	if down == slow {
		t.Fatal("two different failures produced the same log text")
	}
	for _, want := range []string{"endpoint unreachable", "127.0.0.1:9050", "running"} {
		if !strings.Contains(down, want) {
			t.Errorf("unreachable reason %q lacks %q", down, want)
		}
	}
	for _, want := range []string{"deadline expired", "circuit was slow"} {
		if !strings.Contains(slow, want) {
			t.Errorf("deadline reason %q lacks %q", slow, want)
		}
	}
}
