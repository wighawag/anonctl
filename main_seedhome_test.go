package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/defaults"
	"github.com/wighawag/anonctl/internal/seedhome"
)

// seedFakeRunner answers the `getent passwd` probes runSeedHome/runAdd make so the
// wiring runs without a real account. present maps account -> home dir; an absent
// account reports not-found. Every other command (chown, etc.) is a recorded no-op.
type seedFakeRunner struct {
	present map[string]string // account -> home
	calls   [][]string
}

func (r *seedFakeRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if name == "getent" && len(args) == 2 && args[0] == "passwd" {
		acct := args[1]
		if home, ok := r.present[acct]; ok {
			// name:x:uid:gid:gecos:home:shell
			return acct + ":x:30034:30034::" + home + ":/bin/bash", "", nil
		}
		return "", "", &exitErr{code: 2}
	}
	return "", "", nil
}

// exitErr is a minimal non-zero exit error for the fake getent (mirrors provision's
// own fake). Its presence + empty stdout is read as "account absent".
type exitErr struct{ code int }

func (e *exitErr) Error() string { return "exit " + string(rune('0'+e.code)) }

// swapSeedSeams points defaultsStore at a scratch base dir and lets a test capture
// the seedHomeSeed call, restoring both on cleanup. It NEVER lets the real
// /etc/anonctl be read or a real home be written.
func swapSeedSeams(t *testing.T, base string) *[]string {
	t.Helper()
	origStore, origSeed := defaultsStore, seedHomeSeed
	defaultsStore = defaults.Store{BaseDir: base}
	var seeded []string
	seedHomeSeed = func(_ context.Context, _ seedhome.Runner, templateDir, home, account string, force bool) (seedhome.Result, error) {
		seeded = append(seeded, templateDir+" -> "+home+" (account "+account+")")
		return seedhome.Result{Copied: 1}, nil
	}
	t.Cleanup(func() { defaultsStore, seedHomeSeed = origStore, origSeed })
	return &seeded
}

// seed-home refuses on a non-existent account: it seeds a home, it does not create
// one. Exit non-zero, and the seed seam is never called.
func TestSeedHomeRefusesMissingAccount(t *testing.T) {
	seeded := swapSeedSeams(t, t.TempDir())
	r := &seedFakeRunner{present: map[string]string{}} // account absent
	code := runSeedHome(context.Background(), r, mustParse(t, []string{"seed-home", "work"}))
	if code == 0 {
		t.Errorf("seed-home on a missing account = 0, want non-zero")
	}
	if len(*seeded) != 0 {
		t.Errorf("seed seam was called for a missing account: %v", *seeded)
	}
}

// seed-home with no --from and no default-home dir is a loud error (nothing to
// seed), not a silent success.
func TestSeedHomeNoSourceErrors(t *testing.T) {
	seeded := swapSeedSeams(t, t.TempDir()) // scratch base has no default-home dir
	r := &seedFakeRunner{present: map[string]string{"anon-work": "/home/anon-work"}}
	code := runSeedHome(context.Background(), r, mustParse(t, []string{"seed-home", "work"}))
	if code == 0 {
		t.Errorf("seed-home with no source = 0, want non-zero")
	}
	if len(*seeded) != 0 {
		t.Errorf("seed seam called with no source: %v", *seeded)
	}
}

// seed-home --from copies the named template into the EXISTING account's home.
func TestSeedHomeFromExplicitTemplate(t *testing.T) {
	seeded := swapSeedSeams(t, t.TempDir())
	tmpl := t.TempDir()
	r := &seedFakeRunner{present: map[string]string{"anon-work": "/home/anon-work"}}
	code := runSeedHome(context.Background(), r, mustParse(t, []string{"seed-home", "--from", tmpl, "work"}))
	if code != 0 {
		t.Errorf("seed-home --from = %d, want 0", code)
	}
	if len(*seeded) != 1 {
		t.Fatalf("expected 1 seed call, got %v", *seeded)
	}
	if want := tmpl + " -> /home/anon-work (account anon-work)"; (*seeded)[0] != want {
		t.Errorf("seed call = %q, want %q", (*seeded)[0], want)
	}
}

// seed-home with no --from falls back to the directory-exists default-home when it
// is present.
func TestSeedHomeFallsBackToDefaultHome(t *testing.T) {
	base := t.TempDir()
	seeded := swapSeedSeams(t, base)
	if err := os.Mkdir(filepath.Join(base, "default-home"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &seedFakeRunner{present: map[string]string{"anon": "/home/anon"}}
	code := runSeedHome(context.Background(), r, mustParse(t, []string{"seed-home"}))
	if code != 0 {
		t.Errorf("seed-home (default-home present) = %d, want 0", code)
	}
	if len(*seeded) != 1 {
		t.Fatalf("expected 1 seed call, got %v", *seeded)
	}
}

// seedDefaultHome (add's fresh-creation helper) is a clean no-op when there is no
// default-home dir: it returns 0 copied, no error.
func TestSeedDefaultHomeNoOpWithoutDir(t *testing.T) {
	swapSeedSeams(t, t.TempDir()) // no default-home dir
	r := &seedFakeRunner{present: map[string]string{"anon": "/home/anon"}}
	n, err := seedDefaultHome(context.Background(), r, "anon")
	if err != nil {
		t.Fatalf("seedDefaultHome no-op errored: %v", err)
	}
	if n != 0 {
		t.Errorf("seedDefaultHome copied %d files with no default-home dir, want 0", n)
	}
}

// mustParse is a tiny helper to build a *cli.Command for the run* handlers under
// test (the parse itself is covered in internal/cli).
func mustParse(t *testing.T, args []string) *cli.Command {
	t.Helper()
	cmd, err := cli.Parse(args)
	if err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return cmd
}
