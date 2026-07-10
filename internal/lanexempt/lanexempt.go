// Package lanexempt is anonctl's PURE guardrail for the narrow LAN exemption: the
// parse+validate that turns an operator-supplied `IP|CIDR:port` into a
// validated, private-only exemption the nftables ruleset punches a direct hole
// for. It is all pure logic (no root, no sockets, no system mutation) so the
// guardrail is exhaustively unit-testable everywhere (the default `go test ./...`).
//
// It mirrors netcage's `--allow` guardrail VERBATIM (netcage
// internal/cli/allowdirect.go, ADR-0005): the ONLY destinations accepted are
// RFC1918 private space plus link-local; a hostname or any non-IP/CIDR literal is
// refused (a LAN name cannot resolve through the forced path, and a local-resolver
// hole would be another leak); a value not FULLY contained in a private range
// (public, or a too-wide prefix that straddles public space) is refused LOUDLY,
// naming the value. A PORT IS MANDATORY: a port-omitted (bare-IP / all-ports)
// value is refused LOUDLY too, because the old all-ports form opened every TCP
// port except 53 and is a deanonymization leak when the exempted host runs a
// forwarding proxy on some other port (see docs/adr/0007); the only defensible
// granularity is "reach exactly this service". This is the
// fail-loud-at-config-time security gate: a user cannot accidentally punch an
// anonymity leak (story 24).
//
// The MECHANISM anonctl builds on top of this is simpler than netcage's two-half
// TUN split: there is no TUN here, so a single nft `accept`-before-drop suffices
// and the fail-closed default-DROP gives netcage's defense-in-depth RFC1918 drops
// for FREE (internal/nftables consumes an Exempt and emits the accept). This
// package only decides WHAT is a valid exemption; it never emits nft text.
package lanexempt

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Exempt is one validated LAN-exemption entry: a private LAN destination the anon
// account may reach DIRECTLY (over the real NIC) instead of through the forced
// path. It is the parse+validate output this package produces; internal/nftables
// consumes it (emits `meta skuid <anon> ip[6] daddr <net> tcp dport <port> accept`
// before the anon-UID drops, plus a nat `return` so it is not redirected).
//
// Network is always non-nil. A bare IP is normalised to a host route (/32 for
// IPv4, /128 for IPv6). Port is the exact TCP destination port and is always
// > 0: a port is mandatory (Parse rejects a port-omitted value), so an exemption
// always names EXACTLY one service. The entry is TCP-only by construction (the
// forced path carries TCP; UDP other than DNS is dropped), enforced at the nft
// layer, not encoded per entry.
type Exempt struct {
	Network *net.IPNet // the exempted destination network (a /32 or /128 for a bare IP)
	Port    int        // exact TCP port (always > 0; a port is mandatory)
	Raw     string     // the original value, preserved for diagnostics
}

// dnsPort is the clear-DNS port (53). It is UN-EXEMPTABLE: Parse rejects an
// explicit `:53` exemption, so the LAN hole can never carry clear DNS (Tails
// leak-catalogue row 2). Exported so the nft generator names the SAME port rather
// than spelling a bare 53, keeping the guardrail and the generation consistent.
const DNSPort = 53

const dnsPort = DNSPort

// HostPort renders the exemption as a dialable `host:port` for a live verify
// probe (the split-tunnel probe dials the exempted destination and expects it
// reachable, so it needs a concrete host+port). The host is the network's base
// address (the exact host for a bare-IP /32 or /128) and the port is the
// exemption's own TCP port, always present (a port is mandatory). It never renders
// 53 (un-exemptable).
func (e Exempt) HostPort() string {
	if e.Network == nil {
		return ""
	}
	return net.JoinHostPort(e.Network.IP.String(), strconv.Itoa(e.Port))
}

// IsV4 reports whether the exemption is an IPv4 destination, so the nft layer can
// pick the matching `ip`/`ip6` family (a v6 exemption must not emit a v4-family
// rule and vice versa).
func (e Exempt) IsV4() bool { return e.Network != nil && e.Network.IP.To4() != nil }

// privateRanges is the ONLY set of destination ranges the exemption accepts:
// RFC1918 private space plus link-local. Restricting exemptions to these ranges is
// the security gate (story 24): a user cannot accidentally exempt a PUBLIC address
// that would become a real anonymity leak around the forced egress. A public
// exemption, if ever wanted, is a separate louder opt-in, NOT part of this
// feature. An exempted network must be FULLY contained in one of these (a prefix
// that straddles public space is refused). Mirrors netcage's privateRanges.
var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local (RFC3927)
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("lanexempt: bad built-in private range " + c) // unreachable: constants
		}
		nets = append(nets, n)
	}
	return nets
}()

// Parse parses one exemption value into a validated Exempt. It accepts an IP or a
// CIDR, each suffixed with a MANDATORY `:port`, and REJECTS (loudly, naming the
// value + reason): a hostname or otherwise non-IP/CIDR literal; a malformed value;
// a port-omitted (all-ports) value; an out-of-range or non-numeric port; an
// explicit `:53`; and any address/network NOT fully within the private/link-local
// ranges (a public destination that would leak). This is the
// fail-loud-at-config-time security gate. Mirrors netcage's parseAllow.
func Parse(raw string) (Exempt, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Exempt{}, fmt.Errorf("empty LAN exemption value: expected an RFC1918/link-local IP or CIDR, optionally with :port")
	}

	hostPart, port, err := splitPort(value)
	if err != nil {
		return Exempt{}, err
	}

	// Reject a port-omitted value: a port is MANDATORY. The old all-ports form
	// (`192.168.1.150`, no `:port`) opened every TCP port except 53, which is a
	// deanonymization leak if the exempted host runs a forwarding proxy on some
	// other port (ssh -D SOCKS, squid, a Tor SocksPort, a socat tunnel): the anon
	// account could dial that proxy directly and egress the whole internet from the
	// real IP. The only defensible granularity is "reach exactly this service", so
	// the exemption must always name an exact port (see docs/adr/0007).
	if port == 0 {
		return Exempt{}, fmt.Errorf(
			"LAN exemption %q has no port: a port is mandatory (an all-ports hole to a host running a forwarding proxy would leak your real IP); add :port for the exact service, e.g. %s:8080",
			raw, hostPart)
	}

	// Reject an explicit clear-DNS port (53). A LAN DNS hole (`@192.168.x.x`) can
	// reveal the local network's public IP (Tails leak-catalogue row 2), so 53 is
	// UN-EXEMPTABLE by construction: DNS must go through the anonymizer, never a
	// direct LAN query. With the all-ports form removed, an exemption always names
	// exactly one port, so rejecting :53 here is the whole DNS-hole guard. 853 (DoT)
	// is encrypted DNS and does not leak the public IP the
	// same way, and mDNS/5353 is UDP (never carried by the TCP-only exemption), so
	// only 53 is rejected here.
	if port == dnsPort {
		return Exempt{}, fmt.Errorf(
			"LAN exemption %q targets DNS port 53: a direct clear-DNS query to a LAN resolver can reveal your local network's public IP (a deanonymization vector); DNS must go through the anonymizer, so port 53 cannot be exempted",
			raw)
	}

	network, err := parseHostToNetwork(hostPart, value)
	if err != nil {
		return Exempt{}, err
	}

	if !networkWithinPrivateRanges(network) {
		return Exempt{}, fmt.Errorf(
			"LAN exemption %q is not a private address: only RFC1918 / link-local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) may be exempted for direct egress; a public destination would leak your real IP around the forced path",
			raw)
	}

	return Exempt{Network: network, Port: port, Raw: raw}, nil
}

// splitPort separates an optional trailing `:port` from the host (IP or CIDR)
// part. It disambiguates the `:` that separates a port from the `:` inside an IPv6
// literal by treating an unbracketed multi-colon token as a possible IPv6 with no
// port rather than mis-splitting it. A present-but-invalid port is rejected here
// (naming the value). Mirrors netcage's splitAllowDirectPort.
func splitPort(value string) (host string, port int, err error) {
	idx := strings.LastIndexByte(value, ':')
	if idx < 0 {
		return value, 0, nil // no port
	}

	// An unbracketed multi-colon token is a possible IPv6 literal with no port,
	// not a host:port; let network parsing decide. A bracketed IPv6 with a port
	// ("[fe80::1]:80") is out of scope for v1 (the exemption targets IPv4
	// RFC1918/link-local in practice), so it is left to fail network parsing.
	if strings.Count(value, ":") > 1 && !strings.Contains(value, "]") {
		return value, 0, nil
	}

	host = value[:idx]
	portStr := value[idx+1:]
	if portStr == "" {
		return "", 0, fmt.Errorf("LAN exemption %q has an empty port after ':': expected :<1-65535>", value)
	}
	p, perr := strconv.Atoi(portStr)
	if perr != nil {
		return "", 0, fmt.Errorf("LAN exemption %q has a non-numeric port %q: expected :<1-65535>", value, portStr)
	}
	if p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("LAN exemption %q has an out-of-range port %d: expected :<1-65535>", value, p)
	}
	return host, p, nil
}

// parseHostToNetwork turns the host part (an IP or a CIDR) into a normalised
// *net.IPNet: a bare IP becomes a host route (/32 for IPv4, /128 for IPv6). A
// value that is neither a valid IP nor a valid CIDR literal (e.g. a hostname) is
// rejected, naming the original value and that hostnames are unsupported. Mirrors
// netcage's parseHostToNetwork.
func parseHostToNetwork(host, value string) (*net.IPNet, error) {
	if strings.Contains(host, "/") {
		_, network, err := net.ParseCIDR(host)
		if err != nil {
			return nil, fmt.Errorf("LAN exemption %q is not a valid CIDR: %v (IP/CIDR literals only; hostnames are unsupported)", value, err)
		}
		return network, nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("LAN exemption %q is not a valid IP or CIDR literal (hostnames are unsupported: a LAN name cannot resolve through the forced path)", value)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// networkWithinPrivateRanges reports whether the whole network is contained in one
// of the accepted private/link-local ranges. Both the network address AND the last
// address must fall inside the same range, so a too-wide prefix that straddles
// public space (e.g. 10.0.0.0/7) is refused. Mirrors netcage's function.
func networkWithinPrivateRanges(n *net.IPNet) bool {
	for _, r := range privateRanges {
		if rangeContainsNetwork(r, n) {
			return true
		}
	}
	return false
}

// rangeContainsNetwork reports whether accepted range r fully contains network n
// (both endpoints of n lie in r). Mirrors netcage's function.
func rangeContainsNetwork(r, n *net.IPNet) bool {
	first := n.IP
	last := lastAddr(n)
	if first == nil || last == nil {
		return false
	}
	return r.Contains(first) && r.Contains(last)
}

// lastAddr returns the last address of a network (network address OR'd with the
// inverted mask), used to prove the whole prefix is within an accepted range.
// Mirrors netcage's lastAddr.
func lastAddr(n *net.IPNet) net.IP {
	ip := n.IP
	mask := n.Mask
	if len(ip) != len(mask) {
		if v4 := ip.To4(); v4 != nil && len(mask) == net.IPv4len {
			ip = v4
		} else {
			return nil
		}
	}
	last := make(net.IP, len(ip))
	for i := range ip {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}
