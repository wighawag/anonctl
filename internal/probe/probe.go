// Package probe answers the one question that sat between anonctl's two existing
// answers and that every automated consumer needs on every trigger: IS THIS
// ACCOUNT JAILED RIGHT NOW?
//
// The two existing answers do not cover it:
//
//   - `verify` is a live, network-touching, tens-of-seconds PROOF. It stands up
//     real probes as the anon UID against a real endpoint. It is the trust anchor,
//     and it is far too expensive to run on every trigger of a reconciliation loop.
//   - the MARKER is a durable CLAIM that verify passed at SOME point. It is free to
//     read, and it outlives the thing it claims: rules are re-loaded (or silently
//     not) at every boot, and nothing re-verifies. A marker can read green while the
//     account is completely unforced.
//
// So consumers built the in-between check themselves, inline: marker present,
// marker uid equal to the account's live uid, and `nft list table inet
// anonctl_<account>` actually matching `skuid <uid>` right now. That is the right
// check, and it is the wrong place for it. The table naming is anonctl's PRIVATE
// convention (`anonctl_<account>`, with `-` rewritten to `_`), so a consumer
// grepping the ruleset couples itself to an internal detail anonctl cannot then
// refactor; and the shape of the mistake is predictable - most integrators will
// stop at "the marker is present", which is the UNSAFE SUBSET (it is exactly the
// case that survives a failed rule load).
//
// probe is therefore three cheap checks, no network and no Tor exit check:
//
//   - marker-present: anonctl has a proven-forcing claim for this account at all.
//   - uid-agreement: the uid the marker names is the uid the account has RIGHT NOW.
//     (An account deleted and recreated - the NixOS `users.mutableUsers = false`
//     activation case - keeps the marker and the loaded rules while the rules now
//     govern a uid that belongs to somebody else, or to nobody.)
//   - rules-loaded: the account's nft table exists AND actually funnels that uid
//     into the fail-closed chain. This is the check the marker cannot make, and the
//     one that catches a boot where the loader failed.
//
// Every failure carries a NAMED, stable reason code, and the verb exits non-zero
// when the account is not jailed, so a shell consumer can gate on the exit status
// and a JSON consumer can switch on the reason.
//
// What probe is NOT: a replacement for `verify`. It proves the rules are LOADED and
// ATTRIBUTED, not that the forced path actually carries traffic anonymously and
// leak-free. A green probe on a box whose endpoint is dead is an account that is
// dropping, not leaking (the ruleset is fail-closed), which is the safe failure -
// but it is still not the proof `verify` gives. The report says so in its own
// output rather than leaving a consumer to infer it.
package probe

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wighawag/anoncore/marker"
)

// SchemaVersion is the version of the `probe --json` CONTRACT. Additive evolution
// only (new optional fields, new checks appended); a breaking reshape bumps it. It
// mirrors verify.SchemaVersion and the marker's.
const SchemaVersion = 1

// The CHECK NAMES. They are stable public identifiers a machine consumer keys on,
// declared once here and never spelled inline (the same discipline as verify's
// assertion names).
const (
	// CheckMarkerPresent: anonctl has a marker for the account, i.e. it has proven
	// this account forced at some point.
	CheckMarkerPresent = "marker-present"
	// CheckUIDAgreement: the marker's recorded uid IS the account's live uid.
	CheckUIDAgreement = "uid-agreement"
	// CheckRulesLoaded: the account's nft table is loaded and governs that uid.
	CheckRulesLoaded = "rules-loaded"
)

// The REASON CODES. A failing check always names one, so a consumer switches on a
// stable string instead of matching prose. They are deliberately fine-grained:
// "we could not look" and "we looked and it is not there" are different conditions
// with different operator responses, and collapsing them is the exact mistake this
// whole change set is about.
const (
	// ReasonNoMarker: no marker file. anonctl has never proven this account forced,
	// or `rm` removed the claim. NOT an error - a determined negative.
	ReasonNoMarker = "no-marker"
	// ReasonMarkerUnreadable: the marker could not be read or parsed (permission,
	// corruption). UNDETERMINED, never treated as absent.
	ReasonMarkerUnreadable = "marker-unreadable"
	// ReasonAccountMissing: no passwd entry for the account, so there is no live uid
	// to agree with. The rules may still be loaded, governing a freed uid.
	ReasonAccountMissing = "account-missing"
	// ReasonUIDDrift: the marker names a different uid than the account has now (the
	// account was deleted and recreated under a new uid). The loaded rules govern the
	// OLD uid, so this account is unforced while every durable record says otherwise.
	ReasonUIDDrift = "uid-drift"
	// ReasonRulesUnreadable: the ruleset could not be read at all (`nft` needs root).
	// UNDETERMINED: probe refuses to call an account jailed on an unread ruleset.
	ReasonRulesUnreadable = "rules-unreadable"
	// ReasonTableMissing: the account's nft table is not loaded. This is the
	// post-reboot failure mode the marker cannot see: rules gone, claim still green.
	ReasonTableMissing = "table-missing"
	// ReasonUIDNotGoverned: the table is loaded but contains no rule funnelling this
	// uid into the fail-closed chain, so the account's packets are not attributed to
	// the forcing at all.
	ReasonUIDNotGoverned = "uid-not-governed"
)

// The BOOT states. The boot id answers "was this proven during the boot that is
// running now?", which is the difference between a claim that has survived a
// reboot untested and one made since.
const (
	// BootThisBoot: the marker was written during the RUNNING boot.
	BootThisBoot = "this-boot"
	// BootEarlierBoot: the marker was written during an EARLIER boot. The rules were
	// re-loaded since (or were not), and nothing re-verified: a consumer that needs a
	// proof rather than loaded rules should run `verify`.
	BootEarlierBoot = "earlier-boot"
	// BootUnknown: no boot id to compare - an older marker that predates the field, a
	// host with no /proc/sys/kernel/random/boot_id, or an unreadable marker. Never
	// read this as a mismatch.
	BootUnknown = "unknown"
)

// Check is one probe check: its stable name, its verdict, the named reason when it
// did not pass, and a human evidence line. Detail is diagnostic prose and is NOT a
// contract; Name and Reason are.
type Check struct {
	Name   string `json:"name"`
	Ok     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail"`
}

// Boot reports whether the forcing claim was proven during the RUNNING boot.
type Boot struct {
	State         string `json:"state"`
	CurrentBootID string `json:"currentBootId,omitempty"`
	MarkerBootID  string `json:"markerBootId,omitempty"`
}

// Report is the `probe --json` document.
type Report struct {
	SchemaVersion int    `json:"schemaVersion"`
	Account       string `json:"account"`
	// Jailed is the single verdict a consumer gates on: every check passed. It is
	// false whenever ANY check failed, INCLUDING the undetermined ones - probe never
	// answers "jailed" from a question it could not ask.
	Jailed bool `json:"jailed"`
	// UID is the account's live uid; MarkerUID is the uid the marker recorded. Both
	// are reported so a consumer sees the two sides of the uid comparison rather than
	// just its verdict.
	UID       string  `json:"uid,omitempty"`
	MarkerUID string  `json:"markerUid,omitempty"`
	Checks    []Check `json:"checks"`
	Boot      Boot    `json:"boot"`
}

// FirstFailure returns the named reason of the first check that did not pass, or
// "" when the account is jailed. It is the one-line answer a shell consumer wants.
func (r Report) FirstFailure() string {
	for _, c := range r.Checks {
		if !c.Ok {
			return c.Reason
		}
	}
	return ""
}

// Input is everything probe needs, GATHERED BY THE CALLER. Keeping the gathering
// out means Decide is pure - no root, no /etc, no nft - so every verdict path
// (including the undetermined ones, which are the hard ones to stage for real) is
// unit-tested directly.
type Input struct {
	// Account is the resolved account name.
	Account string
	// AccountExists / LiveUID are the account's passwd truth, read from the box.
	AccountExists bool
	LiveUID       string
	// Marker is the parsed marker; MarkerErr is the read error. A marker.ErrNotFound
	// is a determined ABSENCE; any other error is UNDETERMINED.
	Marker    *marker.Marker
	MarkerErr error
	// Ruleset is the output of `nft list table inet anonctl_<account>`; RulesetErr is
	// the failure to OBTAIN it (the ruleset could not be read at all - typically not
	// root). TableName is carried so the report can name it in its evidence.
	TableName  string
	Ruleset    string
	RulesetErr error
	// TableAbsent reports that the ruleset WAS readable and the account's table is
	// simply not loaded.
	//
	// It is a separate field because `nft list table` EXITS NON-ZERO for a table that
	// does not exist, exactly as it does for a permission failure, so the two
	// conditions are indistinguishable at this layer and collapsing them would report
	// the most important failure this verb has - the rules are gone after a reboot -
	// as "could not read; re-run as root", which is the wrong instruction for a root
	// operator and a reason no consumer would ever see. The gatherer, which knows
	// whether it is root, does the classification; see main.go probeNftRun.
	TableAbsent bool
	// GoverningRule is the exact rule text that must be present in the loaded table
	// for the live uid to be governed (built by the nftables package, so the matcher
	// and the generator cannot drift apart).
	GoverningRule string
	// CurrentBootID is the running kernel's boot id, or "" when it could not be read.
	CurrentBootID string
}

// Decide runs the three checks and produces the report. Every check runs (no
// short-circuit) so the report is COMPLETE: an operator sees the uid drift AND the
// missing table, not just whichever failed first. That mirrors verify's
// run-every-assertion discipline.
func Decide(in Input) Report {
	rep := Report{
		SchemaVersion: SchemaVersion,
		Account:       in.Account,
		UID:           in.LiveUID,
	}
	if in.Marker != nil {
		rep.MarkerUID = in.Marker.UID
	}

	markerCheck := decideMarker(in)
	uidCheck := decideUID(in)
	rulesCheck := decideRules(in)
	rep.Checks = []Check{markerCheck, uidCheck, rulesCheck}

	rep.Jailed = markerCheck.Ok && uidCheck.Ok && rulesCheck.Ok
	rep.Boot = decideBoot(in)
	return rep
}

// decideMarker classifies the marker read. The three outcomes are kept apart on
// purpose: present, positively-absent, and unreadable.
func decideMarker(in Input) Check {
	c := Check{Name: CheckMarkerPresent}
	switch {
	case in.MarkerErr != nil && errors.Is(in.MarkerErr, marker.ErrNotFound):
		c.Reason = ReasonNoMarker
		c.Detail = "no marker for this account: anonctl has never proven it forced (or `anonctl rm` removed the claim)"
	case in.MarkerErr != nil:
		c.Reason = ReasonMarkerUnreadable
		c.Detail = fmt.Sprintf("the marker could not be read, so its claim is UNDETERMINED (not absent): %v", in.MarkerErr)
	case in.Marker == nil:
		c.Reason = ReasonMarkerUnreadable
		c.Detail = "no marker record and no read error: the caller gathered neither, so the claim is undetermined"
	default:
		c.Ok = true
		c.Detail = fmt.Sprintf("marker present: %s claimed forced at %s by anonctl %s (endpoint class %s)",
			in.Marker.Account, in.Marker.CreatedAt, in.Marker.AnonctlVersion, in.Marker.EndpointClass)
	}
	return c
}

// decideUID compares the marker's recorded uid against the account's live uid.
// This is the check that catches an account deleted and recreated underneath a
// still-loaded ruleset: the rules govern the OLD uid, so the account is completely
// unforced while the marker and the ledger both still read green.
func decideUID(in Input) Check {
	c := Check{Name: CheckUIDAgreement}
	switch {
	case !in.AccountExists:
		c.Reason = ReasonAccountMissing
		c.Detail = "no passwd entry for this account, so there is no live uid to agree with (any loaded rules now govern a uid that is free or belongs to somebody else)"
	case in.Marker == nil && in.MarkerErr != nil && !errors.Is(in.MarkerErr, marker.ErrNotFound):
		// The marker was UNREADABLE, not absent. Reporting "no-marker" here would tell an
		// operator the account has no claim when in fact we could not look - the same
		// undetermined-reads-as-negative mistake this whole verb exists to avoid.
		c.Reason = ReasonMarkerUnreadable
		c.Detail = "the marker could not be read, so there is no recorded uid to compare the live uid against (UNDETERMINED, not absent)"
	case in.Marker == nil:
		c.Reason = ReasonNoMarker
		c.Detail = "no marker uid to compare the live uid against"
	case strings.TrimSpace(in.Marker.UID) == "":
		c.Reason = ReasonMarkerUnreadable
		c.Detail = "the marker records no uid, so agreement cannot be established"
	case in.Marker.UID != in.LiveUID:
		c.Reason = ReasonUIDDrift
		c.Detail = fmt.Sprintf("uid DRIFT: the marker claims uid %s, the account now has uid %s. The loaded rules govern %s, so this account is UNFORCED while every durable record still says otherwise",
			in.Marker.UID, in.LiveUID, in.Marker.UID)
	default:
		c.Ok = true
		c.Detail = fmt.Sprintf("the marker's uid and the account's live uid agree (%s)", in.LiveUID)
	}
	return c
}

// decideRules is the check no durable record can make: are the rules ACTUALLY
// LOADED right now, and do they govern this uid? An unreadable ruleset is
// undetermined, never a pass - probe must not certify an account from a question it
// could not ask.
func decideRules(in Input) Check {
	c := Check{Name: CheckRulesLoaded}
	switch {
	case in.RulesetErr != nil:
		c.Reason = ReasonRulesUnreadable
		c.Detail = fmt.Sprintf("the nft table %q could not be read, so whether the forcing is loaded is UNDETERMINED: %v. Reading the ruleset needs root; re-run as root",
			in.TableName, in.RulesetErr)
	case in.TableAbsent, strings.TrimSpace(in.Ruleset) == "":
		c.Reason = ReasonTableMissing
		c.Detail = fmt.Sprintf("the nft table %q is not loaded: the account's forcing is NOT installed right now (after a reboot this is a loader that did not run or failed)", in.TableName)
	case in.GoverningRule == "":
		// No rule to look for means the live uid could not be determined (no passwd
		// entry), so whether the ruleset governs this account is UNDETERMINED, not a
		// determined "not governed". The guard is also load-bearing against
		// strings.Contains(x, "") being unconditionally true, which would report this
		// check OK on an empty rule.
		c.Reason = ReasonRulesUnreadable
		c.Detail = fmt.Sprintf("the account has no live uid, so there is no `meta skuid` rule to look for in %q: whether the loaded ruleset governs this account cannot be determined", in.TableName)
	case !strings.Contains(in.Ruleset, in.GoverningRule):
		c.Reason = ReasonUIDNotGoverned
		c.Detail = fmt.Sprintf("the nft table %q is loaded but contains no rule funnelling uid %s into the fail-closed chain (%q), so this account's packets are not attributed to the forcing",
			in.TableName, in.LiveUID, in.GoverningRule)
	default:
		c.Ok = true
		c.Detail = fmt.Sprintf("the nft table %q is loaded and funnels uid %s into the fail-closed chain", in.TableName, in.LiveUID)
	}
	return c
}

// decideBoot compares the marker's recorded boot id against the running one. It is
// REPORTED, not gated on: rules-loaded is checked live, so an account proven in an
// earlier boot whose rules are loaded now IS jailed now. What the boot id adds is
// the knowledge that nothing has re-PROVEN it since the machine came up, which is
// the difference between "the rules are there" and "the rules were shown to work".
func decideBoot(in Input) Boot {
	b := Boot{State: BootUnknown, CurrentBootID: in.CurrentBootID}
	if in.Marker != nil {
		b.MarkerBootID = in.Marker.BootID
	}
	if b.CurrentBootID == "" || b.MarkerBootID == "" {
		return b
	}
	if b.CurrentBootID == b.MarkerBootID {
		b.State = BootThisBoot
	} else {
		b.State = BootEarlierBoot
	}
	return b
}
