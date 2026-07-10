// Package lanexempt is anonctl's PURE guardrail for the narrow direct-egress
// exemption (the unified `--allow` flag): the parse+validate that turns an
// operator-supplied `IP|CIDR:port` into a validated exemption the nftables ruleset
// punches a direct hole for. It is all pure logic (no root, no sockets, no system
// mutation) so the guardrail is exhaustively unit-testable everywhere (the default
// `go test ./...`).
//
// It DISPATCHES on the address class the operator typed (loopback vs
// RFC1918/link-local LAN), because the user made the class obvious by typing
// 127.0.0.1 vs 192.168.x.x, so no separate flag is needed. A PORT IS MANDATORY for
// both classes, and a hostname or any non-IP/CIDR literal is refused (a LAN name
// cannot resolve through the forced path, and a local-resolver hole would be
// another leak).
//
// The LAN branch mirrors netcage's `--allow` guardrail VERBATIM (netcage
// internal/cli/allowdirect.go, ADR-0005): the ONLY destinations accepted are
// RFC1918 private space plus link-local; a value not FULLY contained in a private
// range (public, or a too-wide prefix that straddles public space) is refused
// LOUDLY, naming the value; an explicit `:53` is refused (a clear-DNS hole). The
// port-omitted (bare-IP / all-ports) form is refused because the old all-ports form
// opened every TCP port except 53 and is a deanonymization leak when the exempted
// host runs a forwarding proxy on some other port (see docs/adr/0007); the only
// defensible granularity is "reach exactly this service".
//
// The LOOPBACK branch is STRICTER (docs/adr/0008): loopback (127.0.0.0/8, ::1) is
// the anonymizer's OWN control surface, so a loopback exemption additionally
// rejects the well-known anonymizer control/SOCKS/DNS ports (53, 9050, 9150, 9051,
// 1080). The ACCOUNT-specific ports (the shim relay/DNS ports, the endpoint port)
// are host-dependent and not known here, so they are rejected at the nft generate
// layer (internal/nftables), which knows them; together they keep a loopback hole
// from ever re-opening the anonymizer's own control surface.
//
// This is the fail-loud-at-config-time security gate: a user cannot accidentally
// punch an anonymity leak (story 24).
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

// Exempt is one validated direct-egress exemption entry: a private LAN or loopback
// destination the anon account may reach DIRECTLY (over the real NIC, or on
// loopback for a same-host service) instead of through the forced path. It is the
// parse+validate output this package produces; internal/nftables consumes it (emits
// `meta skuid <anon> ip[6] daddr <net> tcp dport <port> accept` before the anon-UID
// drops, plus a nat `return` so it is not redirected). IsLoopback() reports which
// class it is, so the nft layer emits the right rule pair.
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

// IsLoopback reports whether the exemption is a LOOPBACK-class destination
// (127.0.0.0/8 for v4, ::1 for v6), as opposed to an RFC1918/link-local LAN
// destination. This is the class the unified --allow flag DISPATCHES on: the user
// made the class obvious by typing 127.0.0.1 vs 192.168.x.x, so it is self-evident
// from the parsed literal, no separate flag needed. The nft generator emits the
// STRICTER loopback rule pair (a scoped nat return + a filter accept before the
// 127.0.0.0/8 drop) for a loopback exemption, and the LAN rule pair for a LAN one.
func (e Exempt) IsLoopback() bool {
	return e.Network != nil && e.Network.IP.IsLoopback()
}

// privateRanges is the set of RFC1918 / link-local destination ranges the LAN
// branch accepts. The loopback branch accepts 127.0.0.0/8 (and ::1) instead,
// guarded by its own STRICTER port blocklist (loopbackAnonymizerPorts). Restricting
// LAN exemptions to these ranges is the security gate (story 24): a user cannot
// accidentally exempt a PUBLIC address that would become a real anonymity leak
// around the forced egress. A public
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

// loopbackAnonymizerPorts is the STATIC part of the loopback branch's port
// blocklist: the conventional, host-independent anonymizer control/SOCKS/DNS ports
// a loopback exemption must NEVER name, because loopback is the anonymizer's OWN
// control surface. Allowing a SOCKS/control port would let the anon UID dial the
// forced path's own upstream directly (defeating closure (b) and the <account>@
// isolation); allowing 9051 (Tor control) is a self-deanonymization vector; 53 is
// clear DNS. The ACCOUNT-specific ports (the shim relay/DNS ports, the configured
// endpoint port) are not host-independent, so they are rejected at the nft generate
// layer (internal/nftables), which knows them; this set is the load-bearing
// well-known blocklist enumerated in docs/adr/0008. The value is the human-readable
// reason, named in the reject.
var loopbackAnonymizerPorts = map[int]string{
	53:   "clear DNS (must go through the anonymizer, never a direct query)",
	9050: "the conventional Tor SOCKS port (dialling it directly would skip the forced path and its <account>@ isolation)",
	9150: "the conventional Tor Browser SOCKS port (dialling it directly would skip the forced path)",
	9051: "the conventional Tor CONTROL port (reachable from the account it is a self-deanonymization vector)",
	1080: "the conventional generic SOCKS port (dialling it directly would skip the forced path)",
}

// Parse parses one exemption value into a validated Exempt and DISPATCHES on the
// address class the operator typed: a loopback literal (127.0.0.0/8, ::1) routes to
// the STRICTER loopback guardrail; an RFC1918/link-local literal routes to the LAN
// guardrail. Both require a MANDATORY `:port` and reject a hostname, a malformed
// value, and an out-of-range/non-numeric port. The LAN branch rejects anything not
// fully within the private/link-local ranges; the loopback branch additionally
// rejects the well-known anonymizer control/SOCKS/DNS ports (loopbackAnonymizerPorts)
// so a loopback hole can never re-open the anonymizer's own control surface. This
// is the fail-loud-at-config-time security gate. Mirrors netcage's parseAllow.
func Parse(raw string) (Exempt, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Exempt{}, fmt.Errorf("empty --allow value: expected an RFC1918/link-local or 127.0.0.1 IP or CIDR, with a mandatory :port")
	}

	hostPart, port, err := splitPort(value)
	if err != nil {
		return Exempt{}, err
	}

	// Reject a port-omitted value: a port is MANDATORY for BOTH classes. The old
	// all-ports form (`192.168.1.150`, no `:port`) opened every TCP port except 53,
	// which is a deanonymization leak if the exempted host runs a forwarding proxy on
	// some other port (ssh -D SOCKS, squid, a Tor SocksPort, a socat tunnel): the anon
	// account could dial that proxy directly and egress the whole internet from the
	// real IP. The only defensible granularity is "reach exactly this service", so the
	// exemption must always name an exact port (see docs/adr/0007). Loopback is even
	// stricter: it has NO all-ports form under any circumstance (docs/adr/0008).
	if port == 0 {
		return Exempt{}, fmt.Errorf(
			"--allow %q has no port: a port is mandatory (an all-ports hole to a host running a forwarding proxy would leak your real IP); add :port for the exact service, e.g. %s:8080",
			raw, hostPart)
	}

	network, err := parseHostToNetwork(hostPart, value)
	if err != nil {
		return Exempt{}, err
	}

	e := Exempt{Network: network, Port: port, Raw: raw}

	// Class-dispatch on the address the user typed. A loopback literal is the
	// anonymizer's OWN control surface, so it goes through the stricter loopback
	// guardrail; everything else must be a private/link-local LAN destination.
	if e.IsLoopback() {
		if reason, blocked := loopbackAnonymizerPorts[port]; blocked {
			return Exempt{}, fmt.Errorf(
				"--allow %q targets loopback port %d: %s; loopback is the anonymizer's own control surface, so port %d cannot be exempted",
				raw, port, reason, port)
		}
		return e, nil
	}

	// Reject an explicit clear-DNS port (53) on a LAN destination. A LAN DNS hole
	// (`@192.168.x.x`) can reveal the local network's public IP (Tails leak-catalogue
	// row 2), so 53 is UN-EXEMPTABLE by construction: DNS must go through the
	// anonymizer, never a direct LAN query. (Loopback 53 is already rejected above by
	// loopbackAnonymizerPorts.) With the all-ports form removed, an exemption always
	// names exactly one port, so rejecting :53 here is the whole DNS-hole guard. 853
	// (DoT) is encrypted DNS and does not leak the public IP the same way, and
	// mDNS/5353 is UDP (never carried by the TCP-only exemption), so only 53 is
	// rejected here.
	if port == dnsPort {
		return Exempt{}, fmt.Errorf(
			"--allow %q targets DNS port 53: a direct clear-DNS query to a LAN resolver can reveal your local network's public IP (a deanonymization vector); DNS must go through the anonymizer, so port 53 cannot be exempted",
			raw)
	}

	if !networkWithinPrivateRanges(network) {
		return Exempt{}, fmt.Errorf(
			"--allow %q is not a private or loopback address: only RFC1918 / link-local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16) or loopback (127.0.0.1) may be exempted for direct egress; a public destination would leak your real IP around the forced path",
			raw)
	}

	return e, nil
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
		return "", 0, fmt.Errorf("--allow %q has an empty port after ':': expected :<1-65535>", value)
	}
	p, perr := strconv.Atoi(portStr)
	if perr != nil {
		return "", 0, fmt.Errorf("--allow %q has a non-numeric port %q: expected :<1-65535>", value, portStr)
	}
	if p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("--allow %q has an out-of-range port %d: expected :<1-65535>", value, p)
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
			return nil, fmt.Errorf("--allow %q is not a valid CIDR: %v (IP/CIDR literals only; hostnames are unsupported)", value, err)
		}
		return network, nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("--allow %q is not a valid IP or CIDR literal (hostnames are unsupported: a LAN or loopback name cannot resolve through the forced path)", value)
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
