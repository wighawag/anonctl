package nftables

import (
	"fmt"
	"strings"
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
func GenerateBaseline(account string, anonUID int) (string, error) {
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
	// Loopback RETURN first: forcing redirects the anon UID's egress to a loopback
	// shim port, so its forced packets arrive here with a loopback dst; return them
	// (do not drop) so the forcing table governs them. With forcing ABSENT there is
	// no such loopback traffic, so this simply does not match the real egress below.
	w("        meta skuid %d ip daddr 127.0.0.0/8 return", anonUID)
	w("        meta skuid %d ip6 daddr ::1 return", anonUID)
	// The resting-state DROP: every NON-loopback destination for the anon UID (v4
	// AND v6) is dropped. This is the whole point: un-forced = dropped.
	w("        meta skuid %d ip daddr != 127.0.0.0/8 drop", anonUID)
	w("        meta skuid %d ip6 daddr != ::1 drop", anonUID)
	w("    }")
	w("}")

	return b.String(), nil
}
