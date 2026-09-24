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
//   - a filter/output chain with policy ACCEPT whose base chain only ever JUMPS,
//     on a POSITIVE `meta skuid` match, into a per-UID closure chain; the anon
//     closure chain is fail-closed and ends in an unconditional terminal DROP. It
//     governs ONLY the anon + shim UIDs and enforces the two bypass closures:
//     (a) the anon UID reaches ONLY its own shim ports; all other loopback
//     (127.0.0.0/8 and ::1) and all IPv6 is dropped (never leaked);
//     (b) ONLY the shim UID may reach the upstream endpoint; the anon UID's dial of
//     the endpoint is dropped so it can never skip the shim or its `<account>@`
//     isolation username.
//
// WHY THE BASE CHAINS ONLY EVER MATCH A UID POSITIVELY (the box-wide invariant).
// Both output base chains are evaluated for EVERY packet the host sends, so the
// ONE thing they must never do is adjudicate a packet they cannot attribute. Not
// every locally generated packet carries a socket UID: `meta skuid` reads
// `sk->sk_socket->file`, and a large share of ordinary TCP output is emitted from
// a deferred context where that is unavailable (measured on loopback, kernel
// 6.18: bulk data super-packets, pure ACKs, the FIN, and data retransmissions on
// an ESTABLISHED socket). Such a packet matches NEITHER `skuid == u` NOR
// `skuid != u`.
//
// A SYN is NOT in that class, INCLUDING a retransmitted one, and that distinction
// is what the whole design rests on so it was measured rather than assumed: a
// dropped off-box dial retransmits its SYN from TIMER context, which is where
// attribution is normally lost, yet all 9 SYNs of a 20-second dial (the original
// plus 8 retransmissions) carried the socket UID, for v4 and v6 alike. A control
// run with no tables loaded saw the same 9 escape, proving the probe really does
// emit retransmissions and that they would leak if nothing matched them.
//
// An earlier shape opened this chain with `policy drop` plus a NEGATIVE
// pass-through (`meta skuid != anon meta skuid != shim accept`). An unattributable
// packet took no accept, fell through, and was killed by the policy drop, in a
// chain whose own header promised it touched no other UID. Because a `drop` is
// TERMINAL across every base chain at a hook, that silently broke larger TCP
// transfers for EVERY uid on the box, root included. The shape below cannot have
// that class of bug by construction: an unattributable packet takes no jump,
// reaches the end of the base chain, and is accepted by policy, while the anon
// UID's closures are unchanged in effect. Dropping is done ONLY inside a chain
// that is entered by a positive UID match, so anonctl can only ever drop a packet
// it has positively attributed to an account it governs.
//
// This does NOT weaken the fail-closed property, because the property rests on
// the FIRST packet of a flow: a new connection's SYN always carries a socket UID
// (every retransmission of it too, measured above), so it is always adjudicated by
// these rules, and an unattributable follow-on packet necessarily belongs to a flow
// whose SYN was already judged (and, for the anon UID, already REDIRECTED to the
// shim loopback port by nat_out, which the conntrack entry then applies to every
// later packet of that flow regardless of attributability). See docs/adr/0002 and
// docs/adr/0005.
//
// The SYN-retransmission case is worth stating explicitly because it is the one
// that would matter if it went the other way: a dropped SYN is not confirmed in
// conntrack, so its retransmission arrives as a FRESH connection and re-traverses
// nat_out. Were it unattributable it would take no jump, keep its real off-box
// destination, and escape both tables. Measured end to end with the forcing and
// baseline tables loaded together: zero packets left with an off-box destination
// over a 20-second v4 and v6 dial.
//
// The table is named per-account (`anonctl_<account>`) so two accounts never
// clobber each other's ruleset and Delete removes exactly one account's table,
// leaving the rest of the host's nftables untouched (ADR 0002).
package nftables

import (
	"fmt"
	"github.com/wighawag/anoncore/account"
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
//
// The mapping is injective ONLY over account names that have no underscore of
// their own: `anon-a_b` and `anon-a-b` both render `anonctl_anon_a_b`, and since
// the ruleset is loaded as an atomic table REPLACE, the second account's forcing
// would silently overwrite the first's while every kernel query about one answered
// about the other. Injectivity is therefore enforced UPSTREAM, at name resolution
// (anoncore/account.ValidateName), and again here in Params.validate so that a
// caller bypassing the CLI still cannot install a colliding table. This function
// stays a total, pure string mapping so it can be used on already-validated names
// (including in teardown paths that must work for whatever is on the box).
func TableName(account string) string {
	return "anonctl_" + strings.ReplaceAll(account, "-", "_")
}

// GoverningRule is the ONE rule whose presence in a LOADED table means the anon
// UID's packets are actually attributed to this account's forcing: the positive
// `meta skuid` jump from the filter base chain into the fail-closed closure chain.
// Without it the table can be loaded and the account still completely ungoverned.
//
// It is exported because `anonctl probe` matches it against a live `nft list
// table` dump, and it is BUILT HERE, by the same package that generates the
// ruleset, so the live matcher cannot drift away from what is actually emitted
// (the generator calls this function too). The kernel re-renders a loaded ruleset
// when printing it, and this exact spelling is what it prints back - pinned by the
// boot-invariant integration test against a real `nft list table` on a real box.
func GoverningRule(anonUID int) string {
	return fmt.Sprintf("meta skuid %d jump %s", anonUID, anonFilterChain)
}

// The per-UID CLOSURE chains. These are REGULAR (non-base) chains: they are
// reachable ONLY by an explicit `jump` from a base chain that has already matched
// the UID POSITIVELY, which is what guarantees anonctl never adjudicates a packet
// it cannot attribute (see the package doc). They are named per-ROLE, not
// per-account, because they already live inside the per-account table.
const (
	// anonNatChain holds the anon UID's destination rewrites (jumped to from nat_out).
	anonNatChain = "anon_nat"
	// anonFilterChain holds the anon UID's fail-closed closures and ENDS in the
	// unconditional terminal drop (jumped to from filter_out).
	anonFilterChain = "anon_filter"
	// shimFilterChain holds the shim UID's endpoint + world accepts (jumped to from
	// filter_out).
	shimFilterChain = "shim_filter"
)

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
	w("# That claim is enforced STRUCTURALLY: both base chains are policy ACCEPT and hold")
	w("# nothing but POSITIVE `meta skuid` jumps, so a packet belonging to another uid --")
	w("# or to no attributable socket at all, which much of ordinary TCP output is --")
	w("# takes no jump and is never adjudicated here. Every drop lives inside a chain")
	w("# entered only by a positive UID match.")
	// Create-if-absent then delete makes the -f load atomic and idempotent: a
	// re-Apply cleanly REPLACES this account's table and never touches another.
	w("table inet %s {}", table)
	w("delete table inet %s", table)
	w("table inet %s {", table)

	// nat/output (priority dstnat = -100, runs BEFORE filter): rewrite only the
	// anon UID; leave its own shim ports as-is; DNS -> shim DNS port; all other TCP
	// -> shim relay port.
	//
	// The base chain ONLY jumps, on a POSITIVE `meta skuid` match, into the anon
	// UID's rewrite chain. The previous negative form (`meta skuid != anon return`)
	// had the same unattributable-packet hole as the filter chain did, in the more
	// dangerous direction: a packet with no socket owner matched neither form, took
	// no `return`, and fell through to `meta l4proto tcp redirect to :<relay>`, so an
	// UNINVOLVED uid's traffic could be redirected INTO the anon shim. In practice a
	// nat base chain is only evaluated for the first packet of a conntrack flow and a
	// new flow's SYN is always attributable, so the hole was masked (measured; see
	// the task's evidence) -- but "masked by conntrack" is not a closure, and the
	// positive form removes it outright.
	w("    chain nat_out {")
	w("        type nat hook output priority dstnat; policy accept;")
	w("        meta skuid %d jump %s", p.AnonUID, anonNatChain)
	w("    }")

	// The anon UID's rewrite chain. Entered ONLY via the positive-skuid jump above,
	// so every packet in it is positively attributed to the anon UID. A `return` here
	// returns to nat_out, which has no rule after the jump, so its policy accept
	// applies: the packet is NOT redirected. That is the same effect the `return`s had
	// as base-chain rules, which is why the rule bodies are unchanged.
	w("    chain %s {", anonNatChain)
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

	// filter/output: the base chain is policy ACCEPT and contains NOTHING but two
	// POSITIVE-skuid jumps, so a packet anonctl cannot attribute (and every packet
	// belonging to an uninvolved uid) takes no jump, reaches the end, and is accepted
	// by policy. Fail-closed lives in the anon closure chain below, which ends in an
	// unconditional terminal DROP. See the package doc for why the negative-match
	// form this replaces was a box-wide bug.
	w("    chain filter_out {")
	w("        type filter hook output priority filter; policy accept;")
	w("        meta skuid %d jump %s", p.ShimUID, shimFilterChain)
	w("        %s", GoverningRule(p.AnonUID))
	w("    }")
	w("")
	// SHIM UID: the ONLY UID allowed to reach the endpoint, then the world. Entered
	// only by the positive-skuid jump, so falling off its end would return to
	// filter_out and be accepted by policy -- the same verdict its own catch-all
	// `accept` gives, so the shim chain needs no terminal rule to be correct.
	w("    chain %s {", shimFilterChain)
	w("        meta skuid %d %s daddr %s tcp dport %d accept", p.ShimUID, endpointFamily, p.EndpointHost, p.EndpointPort)
	w("        meta skuid %d oifname \"lo\" accept", p.ShimUID)
	w("        meta skuid %d accept", p.ShimUID)
	w("    }")
	w("")
	// ANON UID: closure (b) DROP first (so a 9050-style dial can never be
	// accepted), then closure (a) accept-own-shim-ports, then drop all other
	// loopback + all IPv6 (leak-free), then the TERMINAL DROP catches the rest.
	//
	// The rules keep their `meta skuid <anon>` qualifier even though the jump has
	// already established the UID: it costs nothing, keeps each rule self-describing,
	// and keeps the exemption `accept` SPELLED IDENTICALLY to the nat `return` and the
	// baseline `return` (all three are built from the shared exemptMatch, and the
	// split-tunnel finding is what happens when those three diverge).
	//
	// The final `drop` is the ONE rule that MUST stay unqualified, unconditional and
	// LAST. It is what the base chain's old `policy drop` used to do for this UID, and
	// it carries real weight: the anon UID's ICMP and its non-53 UDP are never
	// redirected, so they arrive here with their real off-box destination and are
	// caught by nothing above (the `verify` assertions icmp-drop and non-tcp-udp-drop
	// are exactly these). Without it the chain would fall back to filter_out's policy
	// ACCEPT and the anon UID's ordinary egress would leave IN THE CLEAR -- masked, in
	// a casual test, by the standing baseline table dropping it instead. That is why
	// TestAnonClosureChainEndsInAnUnconditionalTerminalDrop exists.
	w("    chain %s {", anonFilterChain)
	// Closure (b). NOTE for whoever next edits the nat chain's ordering: for TCP this
	// rule is belt-and-braces, not the thing that closes (b). anon_nat's catch-all
	// `meta l4proto tcp redirect` runs at dstnat (-100), so by the time this chain
	// sees an anon dial of the endpoint its destination has ALREADY been rewritten to
	// the shim relay port and this match cannot fire. The closure genuinely holds --
	// the anon UID cannot reach the endpoint because its dial has been forced into the
	// shim -- but it holds by the REDIRECT. This rule is what catches the dial if the
	// nat chain is ever bypassed, reordered, or absent, which is exactly why it stays.
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
	// THE terminal drop. Unconditional and last: see the comment above this chain.
	w("        drop")
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
	// The account name must be one TableName can render UNAMBIGUOUSLY. This repeats
	// the check name resolution already made, deliberately: it is the last gate before
	// a ruleset is generated, and generating a table whose name another account also
	// maps onto would silently replace that account's forcing.
	if err := account.ValidateName(p.Account); err != nil {
		return fmt.Errorf("nftables: %w", err)
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
