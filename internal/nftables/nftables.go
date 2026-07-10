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
	// Exemptions are the narrow direct-egress exemptions: exact host:port (or
	// whole-host / CIDR) LAN destinations OR same-host loopback destinations the anon
	// UID may reach DIRECTLY instead of through the forced path. Each is already
	// guardrail-validated by internal/lanexempt (RFC1918/link-local or loopback only,
	// IP/CIDR not hostnames, and the loopback class rejects the well-known anonymizer
	// ports); Generate additionally rejects a loopback exemption on the account's OWN
	// shim relay/DNS or endpoint port (validate, ADR-0008), then emits, for the anon
	// UID and before the redirect/drop, a nat `return` (so it is not redirected into
	// the shim) and a filter `accept` (so the default-DROP does not drop it). A
	// loopback accept sits before the broad `127.0.0.0/8 drop`, so closure (a) still
	// drops every OTHER loopback port. Empty (the default) is byte-identical to the
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
	// Direct exemptions (enabler half): RETURN the anon UID's traffic to an exempted
	// LAN or loopback destination so it is NOT redirected into the shim and reaches
	// the target directly (the real NIC for a LAN host, loopback for a same-host
	// service). Emitted BEFORE the DNS and catch-all TCP redirects so the exempt
	// packet is never swallowed by them (a loopback return in particular MUST precede
	// the catch-all `redirect to :relay`, ADR-0008). Each exemption names EXACTLY one
	// safe TCP port (a port is mandatory; :53 and the anonymizer control/SOCKS/DNS
	// ports are rejected at the guardrail), so it can never carry clear DNS: tcp/53 to
	// the exempted host is NOT returned here and still hits the DNS redirect below
	// (Tails leak-catalogue row 2). There is no all-ports form to widen it (ADR-0007).
	for _, e := range p.Exemptions {
		w("        # direct exemption (%s, not forced): %s", exemptClass(e), e.Raw)
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
	// Direct exemptions (narrowing half): ACCEPT the anon UID's traffic to an
	// exempted LAN or loopback destination, before the fail-closed drops, so it leaves
	// directly. It is scoped to EXACTLY the named daddr(+port): everything else
	// (including the rest of that host's subnet, and for loopback every OTHER 127.x
	// port via the broad drop below) still hits the drops or the policy DROP, so the
	// exemption cannot silently widen (story 25) and closure (a) survives (ADR-0008).
	// No separate RFC1918 drop rules: the default-DROP gives netcage's defense-in-depth
	// for free.
	for _, e := range p.Exemptions {
		w("        # direct exemption (%s, not forced): %s", exemptClass(e), e.Raw)
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
// picks the ip/ip6 family from the exemption's address family and pins the exact
// `tcp dport`. A port is mandatory and the anonymizer control/SOCKS/DNS ports are
// rejected at the guardrail (internal/lanexempt for the well-known set, and
// Generate's validate for the account's shim/endpoint ports), so the port here is
// always a single safe TCP port: there is no all-ports (`tcp dport != 53`) form any
// more, because an all-ports hole to a host running a forwarding proxy is a
// deanonymization vector (ADR-0007). It never matches UDP (the forced path carries
// TCP; the exemption is TCP-only by construction).
//
// The LOOPBACK and LAN classes emit the SAME clause shape (`<family> daddr <dst>
// tcp dport <port>`): a loopback /32 renders as the bare `127.0.0.1`, which lands
// the nat `return` and the filter `accept` before the broad `127.0.0.0/8 drop`, so
// closure (a) still drops every OTHER loopback port. The two classes DIVERGE at the
// guardrail (which ports each may name, ADR-0008), not in the emitted rule, so this
// stays one shared helper (the loopback branch is a comment about intent, not a
// separate code path, because the nft match is identical once the port is validated).
func exemptMatch(e lanexempt.Exempt) string {
	family := "ip6"
	if e.IsV4() {
		family = "ip"
	}
	return fmt.Sprintf("%s daddr %s tcp dport %d", family, exemptDst(e.Network), e.Port)
}

// exemptDst renders an exemption's destination for nft: a host route (a /32 for
// v4 or /128 for v6, the bare-IP case) is printed as the bare address (nft's own
// idiom, and how the recipe writes single hosts), while a real subnet keeps its
// CIDR. This is purely how the exact same destination is spelled; it never widens
// the match.
// exemptClass names an exemption's address class for the emitted nft comment, so a
// reader of the ruleset can see at a glance whether a direct hole is a LAN host or
// a same-host loopback service (the two go through different guardrails, ADR-0008).
func exemptClass(e lanexempt.Exempt) string {
	if e.IsLoopback() {
		return "loopback"
	}
	return "LAN"
}

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
	// The ACCOUNT-specific half of the loopback exemption port blocklist (docs/adr/0008):
	// a loopback exemption must NOT name the account's OWN shim relay/DNS ports or the
	// configured endpoint port. Those are host-dependent, so lanexempt.Parse (which is
	// context-free) cannot reject them; it rejects the well-known static set
	// (9050/9150/9051/1080/53). Here, where the account's ports are known, we complete
	// the guardrail: allowing the anon UID a DIRECT loopback hole to the shim's own
	// relay/DNS ports would let it bypass the shim's SO_ORIGINAL_DST framing, and a hole
	// to the endpoint port would re-open closure (b). LAN exemptions are exempt from
	// this check: a LAN host's :19050 is a different socket than the loopback shim.
	for _, e := range p.Exemptions {
		if !e.IsLoopback() {
			continue
		}
		var reason string
		switch e.Port {
		case p.RelayPort:
			reason = "the account's shim relay port (a direct hole would bypass the shim)"
		case p.DNSPort:
			reason = "the account's shim DNS port (a direct hole would bypass the shim)"
		case p.EndpointPort:
			reason = "the configured endpoint port (a direct hole would re-open bypass closure (b))"
		}
		if reason != "" {
			return fmt.Errorf("nftables: loopback exemption %q targets port %d: %s; it cannot be exempted", e.Raw, e.Port, reason)
		}
	}
	return nil
}
