package nftables

import (
	"fmt"
	"strings"

	"github.com/wighawag/anonctl/internal/lanexempt"
)

// The BASELINE default-deny is the security INVERSION at the heart of the boot
// invariant: the anon UID's RESTING STATE is DROP, and forcing is what OPENS a path
// (only through the shim). It is a tiny, standalone `inet` table, SEPARATE from the
// per-account forcing table, persisted as its own always-loaded artifact and loaded
// by anonctl's OWN early-boot unit. So "the anon UID has no anonctl forcing loaded"
// means DROPPED, not free: if the forcing rules fail to load, the shim is down, or
// the endpoint is down, the account is STILL dropped, by construction. This is
// strictly safer than the shipped "load the allow-through-shim rules early enough"
// approach, whose gap (the rules were not loaded at boot at all) leaked the host's
// real IP after a reboot (work/notes/findings/e2e-binary-validation.md, BUG 1).
//
// How it layers with forcing WITHOUT dropping forced traffic (the load-bearing
// nftables semantics): a `drop` verdict is terminal across ALL base chains at a
// hook; an `accept` is NOT (a later chain can still drop). So the baseline canNOT
// unconditionally drop the anon UID (that would kill forced traffic too). Instead:
//
//   - Forcing's nat/output chain runs at `priority dstnat` (-100), BEFORE every
//     filter/output chain, and REDIRECTS the anon UID's egress to a LOOPBACK shim
//     port (rewriting the destination). By the time any filter chain sees a forced
//     packet, its dst is 127.0.0.1:<shim-port>.
//   - The baseline is a filter/output chain (policy ACCEPT, so it never touches
//     another UID) that, for the anon UID, RETURNs loopback destinations (handing
//     forced/shim traffic on to the forcing table's own closures) and DROPs
//     everything else (the anon UID's real, non-loopback egress).
//
// Result: forcing PRESENT => the anon UID's traffic is redirected to loopback, the
// baseline returns it, the forcing table governs it (shim path works). Forcing
// ABSENT => no redirect, the anon UID's real egress stays non-loopback, the
// baseline DROPS it. Un-forced = dropped, by construction, at any boot ordering.
//
// WHY THE RESTING DROPS MATCH THE UID POSITIVELY, AND WHAT THAT LEAVES OPEN.
// `meta skuid <anon> ip daddr != 127.0.0.0/8 drop` is a POSITIVE skuid match, so a
// locally generated packet carrying NO attributable socket owner (much of ordinary
// bulk TCP output is such a packet: see the forcing generator's package doc)
// ESCAPES this drop rather than being caught by it. That asymmetry is deliberate
// and it is the SAFE direction for a base chain: the alternative, catching those
// packets with a negative match, is exactly the construct that made the forcing
// filter chain drop every other uid's traffic box-wide. A base chain at the output
// hook must only ever adjudicate what it can attribute; the cost is this residual,
// and the residual is not reachable:
//
//   - Forcing ABSENT: the anon UID cannot get a flow off the ground, because a
//     new connection's SYN always carries a socket UID and is therefore always
//     caught by the positive match above. The SYN RETRANSMISSION is the case to
//     check here, not the established-flow case, and it is the one that was
//     measured: a dropped SYN is never confirmed in conntrack, so it is
//     retransmitted from TIMER context as a fresh connection, and if THAT were
//     unattributable it would escape this drop and leave with the host's real
//     address. It is not. Measured in a namespace with ONLY the baseline loaded,
//     over a 20-second dial: 9 v4 SYNs and 9 v6 SYNs (each one original plus 8
//     retransmissions), ALL attributable, ALL dropped, and zero packets escaping
//     with an off-box destination. The same run with no tables loaded saw all 9
//     escape, which is what makes the zero meaningful rather than accidental.
//   - Forcing PRESENT: the anon UID's flows have already had their destination
//     rewritten to a loopback shim port by the forcing nat chain, on the SYN, and
//     conntrack applies that same rewrite to every later packet of the flow whether
//     or not it is attributable. So an unattributable follow-on packet carries a
//     LOOPBACK destination, which this chain returns by design. The one class that
//     is deliberately not rewritten is a LAN/loopback exemption, and an
//     unattributable packet of an exempted flow leaving directly is precisely what
//     the exemption is for.
//
// For FOLLOW-ON packets the protection that carries the weight is therefore the
// DESTINATION REWRITE, not the filter match; for the FIRST packet of a flow (and
// every retransmission of it) the filter match carries it, because those are
// always attributable. This residual is irreducible at the nftables layer
// (identifying an unattributable packet as the anon UID's is impossible by
// definition), so it is documented and pinned by a test rather than "fixed".
// Pinned by TestBaselineDropsMatchTheAnonUIDPositively.

// BaselineTableName is the baseline default-deny table for an account
// (`anonctl_baseline_<account>`). It derives from the forcing TableName so the two
// artifacts share the account's identifier-safe spelling ('-' -> '_'); it is a
// DISTINCT table so it loads/removes independently of the forcing rules.
func BaselineTableName(account string) string {
	return "anonctl_baseline_" + strings.ReplaceAll(account, "-", "_")
}

// GenerateBaseline produces the standing per-UID default-deny ruleset text for one
// account's anon UID, ready to feed to `nft -f -`. It is pure (no root, no I/O) so
// it is unit-tested everywhere. It refuses an empty account or a non-positive UID
// (uid 0 is root, never a forced anon account) rather than emit a ruleset that
// would mis-target or lock out the wrong UID.
//
// The emitted table is self-contained and idempotent: create-if-absent then DELETE
// then define fresh, so a re-load cleanly replaces ONLY this account's baseline
// table and never touches the forcing table or any other table on the host.
//
// exemptions are the SAME narrow direct exemptions the forcing table opens (LAN or
// loopback, story 25).
// The baseline must RETURN them, exactly as it returns loopback, BEFORE its broad
// non-loopback drop: an exempted destination is deliberately NOT redirected into the
// shim (forcing's nat chain `return`s it), so it reaches this baseline chain still
// carrying its real LAN daddr. Without a matching baseline `return`, the baseline's
// `ip daddr != 127.0.0.0/8 drop` (a TERMINAL verdict, and the baseline shares the
// output/filter hook with the forcing chain) KILLS the exempted flow before the
// forcing chain's exemption `accept` (non-terminal) can take effect: the split hole
// is generated correctly yet never completes. Returning the exemptions here hands
// them on to the forcing table's `accept`, so the direct LAN hole actually works,
// and it is consistent with the exemption's contract (a private-only, guardrail-
// restricted destination that is reachable DIRECTLY regardless of the anonymizer's
// state, since it is explicitly carved out of the forced path).
func GenerateBaseline(account string, anonUID int, exemptions []lanexempt.Exempt) (string, error) {
	if strings.TrimSpace(account) == "" {
		return "", fmt.Errorf("nftables: empty account for baseline")
	}
	if anonUID <= 0 {
		return "", fmt.Errorf("nftables: baseline anon uid must be > 0 (got %d)", anonUID)
	}
	table := BaselineTableName(account)

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# anonctl standing per-UID default-deny (baseline) for account %q - inet table (IPv4 + IPv6).", account)
	w("# The anon UID's RESTING STATE: real (non-loopback) egress is DROPPED; forcing")
	w("# layers on top (its nat redirect rewrites the anon UID's dst to a loopback shim")
	w("# port BEFORE any filter chain), so forcing-present => shim path, forcing-absent")
	w("# => dropped. Loaded by anonctl's OWN early-boot unit, independent of the host's")
	w("# nftables.service. Governs ONLY uid %d; every other uid is untouched.", anonUID)
	// Create-if-absent then delete makes the -f load atomic and idempotent.
	w("table inet %s {}", table)
	w("delete table inet %s", table)
	w("table inet %s {", table)

	// filter/output, policy ACCEPT: an accept is non-terminal, so the baseline never
	// affects another UID or the host's own traffic. Only the anon UID's real egress
	// is DROPPED (terminal), and loopback (forcing's redirect target) is RETURNed so
	// forced traffic is handed on to the forcing table's own closures.
	w("    chain baseline_out {")
	w("        type filter hook output priority filter; policy accept;")
	// CLEAR DNS TO A LOOPBACK RESOLVER IS DROPPED, and it must be dropped HERE,
	// before the loopback return below, or the resting state has a hole in it.
	//
	// The rest of this chain rests on "loopback means forced": forcing rewrites the
	// anon UID's destination to a loopback shim port, so a loopback dst is the
	// signature of a packet the forcing table is about to govern, and returning it is
	// correct. That reasoning holds for every destination EXCEPT a local resolver.
	//
	// A host whose `/etc/resolv.conf` names a LOOPBACK nameserver (127.0.0.53 with
	// systemd-resolved, 127.0.0.1 with dnsmasq/unbound, or glibc's own 127.0.0.1
	// default when no nameserver is declared) makes an UN-forced DNS query look
	// exactly like a forced one to this chain: loopback dst, returned, delivered to
	// the host's resolver, which forwards it and leaks the name with the host's real
	// identity. With an OFF-BOX nameserver the broad drop below caught that query;
	// with a loopback one it did not. So the boot invariant ("forcing absent means
	// DROPPED, not free") silently stopped holding for DNS on exactly the hosts
	// anonctl now RECOMMENDS configuring that way, because a loopback resolver is the
	// remedy for the un-NATed-reply defect (docs/nixos.md, ADR-0011).
	//
	// The asymmetry that makes this safe is the same one the whole design uses: a
	// FORCED query has already had its destination port rewritten to the shim's DNS
	// port by `anon_nat` at dstnat (-100), and this chain runs at filter priority (0),
	// so a forced query arrives here as `127.0.0.1:<dnsPort>` and does NOT match. Only
	// an UNFORCED query still carries :53. Matching without a daddr covers every
	// loopback address and both families in one rule; the off-box case was already
	// covered by the drop below, so this widens nothing.
	//
	// It cannot collide with a loopback exemption either: `lanexempt` rejects :53
	// outright (ADR-0008), so no exemption can ever name the port this drops.
	w("        meta skuid %d udp dport 53 drop", anonUID)
	w("        meta skuid %d tcp dport 53 drop", anonUID)
	// Loopback RETURN first: forcing redirects the anon UID's egress to a loopback
	// shim port, so its forced packets arrive here with a loopback dst; return them
	// (do not drop) so the forcing table governs them. With forcing ABSENT there is
	// no such loopback traffic, so this simply does not match the real egress below.
	w("        meta skuid %d ip daddr 127.0.0.0/8 return", anonUID)
	w("        meta skuid %d ip6 daddr ::1 return", anonUID)
	// Direct exemptions: RETURN each exempted destination BEFORE the broad drop,
	// exactly as loopback is returned, so the forcing chain's exemption `accept`
	// governs it (the baseline's terminal drop would otherwise kill the un-redirected
	// LAN flow). The match is exemptMatch (SHARED with the forcing return+accept) so
	// all three target byte-identical traffic and can never diverge. A LOOPBACK
	// exemption is already covered by the `ip daddr 127.0.0.0/8 return` above (its
	// daddr is loopback), so its per-exemption return here is a harmless no-op; it is
	// still emitted for uniformity (the shared loop) and never widens the baseline
	// (the resting DROP only ever hits NON-loopback egress).
	for _, e := range exemptions {
		w("        # direct exemption (%s, not forced): %s", exemptClass(e), e.Raw)
		w("        meta skuid %d %s return", anonUID, exemptMatch(e))
	}
	// The resting-state DROP: every NON-loopback destination for the anon UID (v4
	// AND v6) is dropped. This is the whole point: un-forced = dropped. The match is
	// POSITIVE on the anon UID (never `skuid != ...`), so this chain can only ever
	// drop a packet it has positively attributed to the account it governs; see the
	// residual analysis in this file's header for what that deliberately leaves open
	// and why it is not reachable.
	w("        meta skuid %d ip daddr != 127.0.0.0/8 drop", anonUID)
	w("        meta skuid %d ip6 daddr != ::1 drop", anonUID)
	w("    }")
	w("}")

	return b.String(), nil
}
