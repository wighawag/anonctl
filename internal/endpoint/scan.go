package endpoint

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Scan-and-offer (story 6): detect the plausible local socks5h endpoints so the
// operator need not hand-type an endpoint they already run. It mirrors netcage's
// internal/detectproxy pattern: walk the canonical local SOCKS ports, CONFIRM each
// open port actually speaks SOCKS5 via a minimal RFC1928 handshake (an open port
// alone is NOT enough), and OFFER only the confirmed ones as socks5h candidates,
// each with a suggested share-class (a Tor-conventional port suggests tor-shared).
// The decision layer (Scan) is PURE and injectable (a Prober), so the enumeration
// is unit-testable with no real socket; the impure DialProber is a thin shell.
//
// Like detect-proxy, this NEVER labels the exit provider: the suggested class is a
// weak, port-conventional prior (9050/9150 => Tor per convention), not a claim
// that the exit IS Tor. The operator confirms/overrides the class.

// ScanPorts is the canonical, ORDERED list of common local SOCKS ports anonctl
// probes when scanning for an endpoint, mirroring netcage detect-proxy's
// DefaultPorts: the two Tor-conventional ports plus the generic SOCKS port.
var ScanPorts = []int{
	9050, // Tor default SocksPort
	9150, // Tor Browser default SocksPort
	1080, // generic SOCKS (wireproxy / ssh -D / other)
}

// ProbeResult is one port's probe outcome as observed by a Prober: whether the
// port was open and whether it CONFIRMED SOCKS5 (an open port alone is not a
// proxy). It mirrors detect-proxy's PortResult.
type ProbeResult struct {
	Open   bool
	SOCKS5 bool
}

// Prober performs the impure per-port probe (dial the loopback port, and if open
// run the SOCKS5 handshake). It is an interface so the pure Scan decision is
// testable with an injected result and no real socket.
type Prober interface {
	Probe(port int) ProbeResult
}

// Scan is the PURE scan-and-offer decision: it walks ScanPorts in order, asks the
// Prober for each port's result, and OFFERS an Endpoint candidate for every port
// that CONFIRMED SOCKS5, with the share-class Classify assigns to that loopback
// port (Tor-conventional ports => tor-shared, else socks-peruser). It performs no
// I/O itself, so it is deterministic and unit-testable against a fake Prober. An
// open-but-unconfirmed port is skipped (an open port is not a proxy); a scan that
// confirms nothing offers an empty slice, not a false candidate.
func Scan(p Prober) []Endpoint {
	var offers []Endpoint
	for _, port := range ScanPorts {
		if !p.Probe(port).SOCKS5 {
			continue
		}
		ps := fmt.Sprintf("%d", port)
		offers = append(offers, Endpoint{
			Host:  DefaultHost,
			Port:  ps,
			Class: Classify("socks5h://" + net.JoinHostPort(DefaultHost, ps)),
		})
	}
	return offers
}

// SOCKS5 protocol constants (RFC 1928), for the confirmation handshake.
const (
	socksVer     = 0x05
	methodNoAuth = 0x00
)

// Handshake performs a MINIMAL RFC1928 SOCKS5 method negotiation over rw and
// reports whether the peer really speaks SOCKS5 (an open port is not enough). It
// offers the no-auth method and requires a version-5 method-selection reply. It
// issues NO CONNECT (that would egress); confirming the peer speaks SOCKS5 is the
// whole job. Mirrors detect-proxy's Handshake.
func Handshake(rw io.ReadWriter) (bool, error) {
	if _, err := rw.Write([]byte{socksVer, 0x01, methodNoAuth}); err != nil {
		return false, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(rw, resp); err != nil {
		return false, err
	}
	if resp[0] != socksVer {
		return false, nil // a non-SOCKS5 speaker answered on an open port
	}
	return true, nil
}

// DialProber is the thin, IMPURE socket I/O behind Scan: it dials
// 127.0.0.1:<port>, and if open runs the RFC1928 Handshake to confirm SOCKS5. All
// decisions live in the pure Scan layer above. Mirrors detect-proxy's DialProber.
type DialProber struct {
	// Timeout bounds each dial + handshake so a probe of a dead port is fast.
	Timeout time.Duration
}

// Probe dials the loopback port and, if open, confirms SOCKS5 via the handshake.
func (d DialProber) Probe(port int) ProbeResult {
	to := d.Timeout
	if to <= 0 {
		to = 2 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(DefaultHost, fmt.Sprintf("%d", port)), to)
	if err != nil {
		return ProbeResult{} // closed / unreachable
	}
	defer conn.Close()
	res := ProbeResult{Open: true}
	_ = conn.SetDeadline(time.Now().Add(to))
	if ok, _ := Handshake(conn); ok {
		res.SOCKS5 = true
	}
	return res
}
