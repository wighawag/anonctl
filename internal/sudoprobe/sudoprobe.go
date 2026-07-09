// Package sudoprobe is anonctl's PURE classifier for the sudo UID-transition
// vector: it turns the OUTPUT of `sudo -l -U <account>` (list the account's
// permitted sudo commands) into a three-valued verdict, WITHOUT trusting the exit
// code. It is shared by both sides of the sudo vector: provision's sudo-absence
// probe (the PROVE side, `status`) and verify's sudoVector (the no-uid-transition
// -egress assertion), so the not-allowed / may-run signal matching lives in ONE
// spot rather than being duplicated per package.
//
// sudo-absence cannot be read from the exit code alone: some sudo builds
// (observed: 1.9.16p2, work/notes/findings/e2e-binary-revalidation-2.md) print the
// not-allowed text yet exit 0 for a no-rights account, so an exit-code-only read
// false-alarms "can sudo". We read the OUTPUT instead, and honestly report Unknown
// when it is neither a clear grant nor a clear denial rather than guessing either
// way. It is pure logic (no exec, no root) so the classification is exhaustively
// unit-testable everywhere (the default `go test ./...`); each package owns the
// exec seam that FEEDS this parse.
package sudoprobe

import "strings"

// Verdict is the three-valued result of classifying `sudo -l -U <account>`
// output. sudo-absence cannot be read from the exit code alone (a lenient build
// may exit 0 for a no-rights account), so the verdict is decided from the OUTPUT,
// and an unrecognisable output is honestly Unknown rather than a guess in either
// dangerous direction.
type Verdict int

const (
	// Unknown: the probe could not be classified (empty/ambiguous/unparseable
	// output, or the probe could not run). Surfaced honestly as not-conclusive,
	// NEVER as a false "has sudo" or a false "no sudo".
	Unknown Verdict = iota
	// Denied: the output carries the decisive "not allowed to run sudo" negative.
	// The account has no sudo rights (the hardened state), whatever the exit code.
	Denied
	// Granted: the output lists permitted commands (a real grant). The account CAN
	// sudo (a uid-transition escape), whatever the exit code.
	Granted
)

// ParseOutput classifies `sudo -l -U <account>` OUTPUT into the three-valued
// verdict WITHOUT trusting the exit code. It is a pure function so the parse is
// unit-testable against real-shaped fixtures. Precedence is DENY-first: if the
// decisive "not allowed to run sudo" negative is present the account has no rights
// even on a build that also prints noise; else a permitted-commands listing ("may
// run the following commands") is a grant; anything else is Unknown (we do not
// guess). Matching is case-insensitive to tolerate build/locale casing drift.
func ParseOutput(out string) Verdict {
	lower := strings.ToLower(out)
	if strings.Contains(lower, "not allowed to run sudo") {
		return Denied
	}
	if strings.Contains(lower, "may run the following commands") {
		return Granted
	}
	return Unknown
}
