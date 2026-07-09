package sudoprobe_test

import (
	"testing"

	"github.com/wighawag/anonctl/internal/sudoprobe"
)

// ParseOutput reads the sudo vector from the OUTPUT, not the exit code: a lenient
// build that prints "not allowed to run sudo" (whatever its exit code) is a
// decisive Denied, never a false Granted. This is the shared classifier both the
// provision (status) and verify (sudoVector) sides route through.
func TestParseOutput_NotAllowedIsDenied(t *testing.T) {
	cases := []string{
		"User anon is not allowed to run sudo on host.\n",
		// case-insensitive: tolerate build/locale casing drift
		"user anon is NOT ALLOWED TO RUN SUDO on host.\n",
		// exit code is irrelevant here: even mixed with noise, the negative wins
		"Matching Defaults entries for anon on host:\n    env_reset\n\nUser anon is not allowed to run sudo on host.\n",
	}
	for _, out := range cases {
		if got := sudoprobe.ParseOutput(out); got != sudoprobe.Denied {
			t.Errorf("ParseOutput(%q) = %v, want Denied", out, got)
		}
	}
}

// A real permitted-commands listing is Granted (a genuine sudo grant), so the
// parse never hides a real uid-transition escape.
func TestParseOutput_MayRunIsGranted(t *testing.T) {
	out := "Matching Defaults entries for anon on host:\n    env_reset\n\n" +
		"User anon may run the following commands on host:\n    (ALL : ALL) ALL\n"
	if got := sudoprobe.ParseOutput(out); got != sudoprobe.Granted {
		t.Errorf("ParseOutput(%q) = %v, want Granted", out, got)
	}
}

// DENY-first precedence: if a build prints BOTH the not-allowed negative and some
// listing-shaped noise, the decisive negative wins (no rights), never a false
// grant.
func TestParseOutput_DenyFirstPrecedence(t *testing.T) {
	out := "User anon may run the following commands on host:\n(none)\n" +
		"User anon is not allowed to run sudo on host.\n"
	if got := sudoprobe.ParseOutput(out); got != sudoprobe.Denied {
		t.Errorf("deny-first: ParseOutput(%q) = %v, want Denied", out, got)
	}
}

// Anything that is neither a clear denial nor a clear grant is Unknown: we do NOT
// guess in either dangerous direction. Surfaced honestly by the caller.
func TestParseOutput_AmbiguousIsUnknown(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"password prompt": "sudo: a password is required\n",
		"garbled":         "something happened but not a recognisable verdict\n",
	}
	for name, out := range cases {
		if got := sudoprobe.ParseOutput(out); got != sudoprobe.Unknown {
			t.Errorf("%s: ParseOutput(%q) = %v, want Unknown", name, out, got)
		}
	}
}
