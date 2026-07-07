//go:build !integration
// +build !integration

package verify

import "context"

// LiveChecks (default build) returns a single honest FAIL: the live assertion set
// stands up real probes AS the anon UID against a real fail-closed ruleset and a
// live endpoint (setpriv + nft + root), which per ADR 0003 is compiled ONLY under
// the `integration` build tag (checks_integration.go). A binary built WITHOUT that
// tag must never silently "pass" verification, so verify reports one failing
// assertion explaining how to run the real proof, and exits non-zero (the
// fail-closed / CI-gating contract holds: a check that could not run is not a
// pass).
//
// The pure assertion DECISIONS (AnonymizedExitAssertion, DNSRemoteAssertion,
// LeakDropAssertion, the two closures, SplitTunnelTightAssertion) live in
// verify.go and are proven by the unit suite against the socks5h fixture with no
// privilege; only the LIVE probing that feeds them is gated here.
func LiveChecks(_ context.Context, _ LiveParams) []Check {
	return []Check{{
		Name: "live-verify-available",
		Run: func(context.Context) Assertion {
			return Assertion{
				Name:   "live-verify-available",
				Ok:     false,
				Detail: "this anonctl binary was built WITHOUT the live-verify probes; the leak/closure/exit/DNS assertions run only in the `integration` build (need root + setpriv + a live endpoint). Rebuild with `-tags integration` and run on the provisioned host, or run `go test -tags integration ./internal/verify/...`.",
			}
		},
	}}
}
