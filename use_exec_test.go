package main

import "testing"

// TestLoginWorkingDirPrefersHome proves the dropped login shell starts in the
// account's HOME when it is a usable absolute path: this is what keeps `anonctl use`
// from leaving the anon session in the operator's own (unwritable) CWD, the split
// environment that made tools like `pi` hit EACCES (a session dir named after the
// caller's path while HOME points at /home/anon).
func TestLoginWorkingDirPrefersHome(t *testing.T) {
	if got := loginWorkingDir("/home/anon"); got != "/home/anon" {
		t.Errorf("loginWorkingDir(/home/anon) = %q, want /home/anon", got)
	}
}

// TestLoginWorkingDirFallsBackToRootNotCaller proves an unusable home (empty or a
// relative path) falls back to `/`, NEVER to the caller's inherited CWD: a login
// must not sit in the operator's home. The important property is "not the caller's
// dir"; `/` is the safe, always-present fallback.
func TestLoginWorkingDirFallsBackToRootNotCaller(t *testing.T) {
	for _, home := range []string{"", "relative/home", "./x", "home/anon"} {
		if got := loginWorkingDir(home); got != "/" {
			t.Errorf("loginWorkingDir(%q) = %q, want the / fallback (never the caller's CWD)", home, got)
		}
	}
}
