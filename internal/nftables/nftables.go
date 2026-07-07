// Package nftables is the KERNEL half of anonctl's per-UID forced anonymized
// egress: it GENERATES (pure) and APPLIES (as root, the ufw stance) the
// fail-closed `inet` nftables ruleset that redirects an anon account's egress
// into its per-account shim and default-DROPs everything else for that UID. It
// encodes the hand-validated recipe verbatim
// (work/notes/findings/manual-per-uid-tor-recipe.md), parameterised by the
// account's UID, its dedicated shim UID, its shim loopback ports, and its
// endpoint; it does NOT invent a fresh ruleset.
//
// The split mirrors provision's Runner seam: Generate is pure text (unit-tested
// everywhere, no root) and Apply/Delete flow every mutation through a Runner so
// the wiring is unit-testable against a fake and the real `nft` shell-out lives
// in ONE place, behind the `integration` build tag for the tests that touch a
// real ruleset.
//
// The security shape (all from the recipe, all load-bearing):
//
//   - ONE `inet` table so IPv4 and IPv6 share a single ruleset: the
//     v4-rules-while-v6-leaks trap is closed by construction.
//   - a nat/output chain (priority dstnat, so it runs BEFORE filter) that, for the
//     anon UID only, redirects DNS (udp+tcp 53) to the shim DNS port and all other
//     TCP to the shim relay port; a REDIRECTed packet re-enters the filter hook
//     with its dst already rewritten to the shim port, so the filter accepts match
//     the SHIM ports, not the original destination.
//   - a filter/output chain with policy DROP (fail-closed) that governs ONLY the
//     anon + shim UIDs and enforces the two bypass closures:
//     (a) the anon UID reaches ONLY its own shim ports; all other loopback
//     (127.0.0.0/8 and ::1) and all IPv6 is dropped (never leaked);
//     (b) ONLY the shim UID may reach the upstream endpoint; the anon UID's dial of
//     the endpoint is dropped so it can never skip the shim or its `<account>@`
//     isolation username.
//
// The table is named per-account (`anonctl_<account>`) so two accounts never
// clobber each other's ruleset and Delete removes exactly one account's table,
// leaving the rest of the host's nftables untouched (ADR 0002).
package nftables

import (
	"fmt"
	"net"
	"strings"

	"github.com/wighawag/anonctl/internal/lanexempt"
)

// Params is everything the generator needs to emit one account's ruleset. It is
// the "given UID/ports/endpoint" input the task's acceptance names: the anon UID
// (from provisioning), the dedicated shim UID (from provisioning), the shim's
// per-account relay + DNS loopback ports (from the shim binary), and the upstream
// endpoint host:port (from the endpoint model). anonctl resolves the account/shim
// NAMES to these numeric UIDs and emits the numbers, exactly as the recipe notes
// `meta skuid` matches by numeric UID.
type Params struct {
	// Account is the anon login account name; it names the per-account table
	// (`anonctl_<account>`) so accounts never share a table.
	Account string
	// AnonUID is the login account's numeric UID (the UID whose egress is forced).
	AnonUID int
	// ShimUID is the dedicated shim service account's numeric UID (the ONLY UID
	// allowed to reach the endpoint).
	ShimUID int
	// RelayPort is the shim's transparent TCP relay loopback port (all other TCP is
	// redirected here).
	RelayPort int
	// DNSPort is the shim's DNS-over-SOCKS-TCP loopback port (DNS is redirected
	// here).
	DNSPort int
	// EndpointHost/EndpointPort is the upstream socks5h endpoint (e.g. the Tor
	// SocksPort). Only the shim UID may reach it; the anon UID's dial of it is
	// dropped (closure b). The host may be v4 or v6; the emitted closure rules use
	// the matching family so closure (b) is never silently v4-only.
	EndpointHost string
	EndpointPort int
	// Exemptions are the narrow LAN exemptions: private-only, exact host:port (or
	// whole-host / CIDR) destinations the anon UID may reach DIRECTLY over the real
	// NIC instead of through the forced path. Each is already guardrail-validated by
	// internal/lanexempt (RFC1918/link-local only, IP/CIDR not hostnames); Generate
	// trusts that and emits, for the anon UID and before the redirect/drop, a nat
	// `return` (so it is not redirected into the shim) and a filter `accept` (so the
	// default-DROP does not drop it). Empty (the default) is byte-identical to the
	// pre-exemption fail-closed ruleset: the hole is opt-in and never widens the
	// forced egress. Because the default is already DROP-for-the-UID, a non-exempt
	// LAN host is dropped by construction, so NO separate defense-in-depth RFC1918
	// drop rules are needed (netcage's two-half TUN mechanism does not apply here).
	Exemptions []lanexempt.Exempt
}

// TableName is the per-account nft table name (`anonctl_<account>`). nft
// identifiers cannot contain '-', so a named account's '-' becomes '_'
// (`anon-work` -> `anonctl_anon_work`); this only names the table, never the Unix
// account.
func TableName(account string) string {
	return "anonctl_" + strings.ReplaceAll(account, "-", "_")
}

// Generate produces the fail-closed `inet` nftables ruleset text for one account,
// ready to feed to `nft -f -`. It is pure (no root, no I/O) so it is unit-tested
// everywhere. It validates its inputs and refuses a nonsensical Params (a zero
// UID/port, equal UIDs, or an unparseable endpoint host) rather than emit a
// ruleset that would silently mis-force or lock out the account.
//
// The emitted ruleset is self-contained and idempotent: it create-if-absent then
// DELETEs the account's own table, then defines it fresh, so a re-Apply is a
// clean atomic replace (never an append of stale rules) and it touches no other
// table on the host.
func Generate(p Params) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	table := TableName(p.Account)

	// Endpoint closure (b) must match the endpoint's actual address family so it is
	// not silently v4-only for a v6 endpoint.
	endpointFamily := "ip"
	if ip := net.ParseIP(p.EndpointHost); ip != nil && ip.To4() == nil {
		endpointFamily = "ip6"
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# anonctl per-UID forced anonymized egress for account %q - inet table (IPv4 + IPv6), fail-closed.", p.Account)
	w("# Generated from the validated recipe (work/notes/findings/manual-per-uid-tor-recipe.md).")
	w("# Governs ONLY uid %d (anon) and uid %d (shim); every other uid is untouched.", p.AnonUID, p.ShimUID)
	// Create-if-absent then delete makes the -f load atomic and idempotent: a
	// re-Apply cleanly REPLACES this account's table and never touches another.
	w("table inet %s {}", table)
	w("delete table inet %s", table)
	w("table inet %s {", table)

	// nat/output (priority dstnat = -100, runs BEFORE filter): rewrite only the
	// anon UID; leave its own shim ports as-is; DNS -> shim DNS port; all other TCP
	// -> shim relay port.
	w("    chain nat_out {")
	w("        type nat hook output priority dstnat; policy accept;")
	w("        meta skuid != %d return", p.AnonUID)
	w("        ip daddr 127.0.0.1 tcp dport { %d, %d } return", p.RelayPort, p.DNSPort)
	w("        ip daddr 127.0.0.1 udp dport %d return", p.DNSPort)
	// LAN exemptions (enabler half): RETURN the anon UID's traffic to an exempted
	// private destination so it is NOT redirected into the shim and egresses the
	// real NIC directly. Emitted BEFORE the DNS and catch-all TCP redirects so the
	// exempt packet is never swallowed by them. The exemption NEVER carries clear
	// DNS: an explicit :53 is rejected at the guardrail (internal/lanexempt) and a
	// port-omitted (all-TCP) exemption excludes 53 (`tcp dport != 53`), so tcp/53 to
	// the exempted host is NOT returned here and still hits the DNS redirect below
	// (Tails leak-catalogue row 2).
	for _, e := range p.Exemptions {
		w("        # LAN exemption (direct, not forced): %s", e.Raw)
		w("        meta skuid %d %s return", p.AnonUID, exemptMatch(e))
	}
	w("        udp dport 53 redirect to :%d", p.DNSPort)
	w("        tcp dport 53 redirect to :%d", p.DNSPort)
	w("        meta l4proto tcp redirect to :%d", p.RelayPort)
	w("    }")

	// filter/output (policy DROP = fail-closed): governs only anon + shim UIDs.
	w("    chain filter_out {")
	w("        type filter hook output priority filter; policy drop;")
	w("        meta skuid != %d meta skuid != %d accept", p.AnonUID, p.ShimUID)
	w("")
	// SHIM UID: the ONLY UID allowed to reach the endpoint, then the world.
	w("        meta skuid %d %s daddr %s tcp dport %d accept", p.ShimUID, endpointFamily, p.EndpointHost, p.EndpointPort)
	w("        meta skuid %d oifname \"lo\" accept", p.ShimUID)
	w("        meta skuid %d accept", p.ShimUID)
	w("")
	// ANON UID: closure (b) DROP first (so a 9050-style dial can never be
	// accepted), then closure (a) accept-own-shim-ports, then drop all other
	// loopback + all IPv6 (leak-free), then policy DROP catches the rest.
	w("        meta skuid %d %s daddr %s tcp dport %d drop", p.AnonUID, endpointFamily, p.EndpointHost, p.EndpointPort)
	// LAN exemptions (narrowing half): ACCEPT the anon UID's traffic to an exempted
	// private destination, before the fail-closed drops, so it leaves directly. It
	// is scoped to EXACTLY the named daddr(+port): everything else (including the
	// rest of that host's subnet) still hits the drops or the policy DROP, so the
	// exemption cannot silently widen (story 25). No separate RFC1918 drop rules:
	// the default-DROP gives netcage's defense-in-depth for free.
	for _, e := range p.Exemptions {
		w("        # LAN exemption (direct, not forced): %s", e.Raw)
		w("        meta skuid %d %s accept", p.AnonUID, exemptMatch(e))
	}
	w("        meta skuid %d ip daddr 127.0.0.1 tcp dport { %d, %d } accept", p.AnonUID, p.RelayPort, p.DNSPort)
	w("        meta skuid %d ip daddr 127.0.0.1 udp dport %d accept", p.AnonUID, p.DNSPort)
	w("        meta skuid %d ip daddr 127.0.0.0/8 drop", p.AnonUID)
	w("        meta skuid %d ip6 daddr ::1 drop", p.AnonUID)
	w("        meta skuid %d ip6 daddr ::/0 drop", p.AnonUID)
	w("    }")
	w("}")

	return b.String(), nil
}

// exemptMatch builds the nft match clause for one exemption's destination,
// SHARED by the nat `return` and the filter `accept` so the two halves can never
// diverge (the enabler and the narrowing must target the exact same traffic). It
// picks the ip/ip6 family from the exemption's address family, and either pins
// the exact `tcp dport` or, for a port-omitted exemption, matches all TCP ports
// EXCEPT the clear-DNS port 53 (`tcp dport != 53`). Excluding 53 is the nft half
// of the row-2 fix: an all-ports exemption can never carry clear TCP/53 to a LAN
// resolver (which would reveal the local network's public IP); 53 stays
// redirected to the shim. An exact-port exemption cannot be :53 (the guardrail
// rejects that), so the exact case needs no exclusion. It never matches UDP (the
// forced path carries TCP; the exemption is TCP-only by construction).
func exemptMatch(e lanexempt.Exempt) string {
	family := "ip6"
	if e.IsV4() {
		family = "ip"
	}
	if e.Port == 0 {
		// All TCP EXCEPT 53: an all-ports exemption must not open clear DNS to the LAN.
		return fmt.Sprintf("%s daddr %s tcp dport != %d", family, exemptDst(e.Network), lanexempt.DNSPort)
	}
	return fmt.Sprintf("%s daddr %s tcp dport %d", family, exemptDst(e.Network), e.Port)
}

// exemptDst renders an exemption's destination for nft: a host route (a /32 for
// v4 or /128 for v6, the bare-IP case) is printed as the bare address (nft's own
// idiom, and how the recipe writes single hosts), while a real subnet keeps its
// CIDR. This is purely how the exact same destination is spelled; it never widens
// the match.
func exemptDst(n *net.IPNet) string {
	ones, bits := n.Mask.Size()
	if ones == bits {
		return n.IP.String()
	}
	return n.String()
}

// validate rejects a Params that would produce a dangerous or nonsensical
// ruleset: a zero UID (uid 0 is root, never a forced anon account), equal
// anon/shim UIDs (closure b collapses), a zero port, an empty account, or an
// endpoint host that is neither an IP literal. It fails LOUD rather than emit a
// ruleset that silently mis-forces or locks out the account (this is the
// highest-stakes code path).
func (p Params) validate() error {
	switch {
	case p.Account == "":
		return fmt.Errorf("nftables: empty account")
	case p.AnonUID <= 0:
		return fmt.Errorf("nftables: anon uid must be > 0 (got %d)", p.AnonUID)
	case p.ShimUID <= 0:
		return fmt.Errorf("nftables: shim uid must be > 0 (got %d)", p.ShimUID)
	case p.AnonUID == p.ShimUID:
		return fmt.Errorf("nftables: anon uid and shim uid must differ (both %d): bypass closure (b) requires a distinct shim UID", p.AnonUID)
	case p.RelayPort <= 0 || p.RelayPort > 65535:
		return fmt.Errorf("nftables: relay port out of range (got %d)", p.RelayPort)
	case p.DNSPort <= 0 || p.DNSPort > 65535:
		return fmt.Errorf("nftables: dns port out of range (got %d)", p.DNSPort)
	case p.EndpointHost == "":
		return fmt.Errorf("nftables: empty endpoint host")
	case p.EndpointPort <= 0 || p.EndpointPort > 65535:
		return fmt.Errorf("nftables: endpoint port out of range (got %d)", p.EndpointPort)
	}
	if net.ParseIP(p.EndpointHost) == nil {
		// The closure (b) rule needs a literal IP to pick the ip/ip6 family and to
		// match exactly; a hostname would be ambiguous (and a DNS lookup in a
		// firewall rule is itself a leak vector).
		return fmt.Errorf("nftables: endpoint host %q must be an IP literal (v4 or v6), not a hostname", p.EndpointHost)
	}
	return nil
}
