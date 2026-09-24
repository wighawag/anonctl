package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/systemd"
)

// This file holds the load-bearing test of the unit-export feature: that the text a
// HOST declares is byte-for-byte the text `anonctl add` would have written.
//
// Single-sourcing is the entire point of exporting the units at all. A host declares
// them so the two unit files stop being out-of-band state that no rebuild reproduces
// and no rollback undoes; if the exported copy could DRIFT from the installed one
// across a version, the host would have swapped invisible state for state that is
// visible and WRONG, which is worse. So the property is asserted against what the
// install path actually writes to disk, not against a golden file: a fixture copy of
// the template in testdata would satisfy a comparison while quietly being the second
// definition this feature exists to prevent.

// exportPaths are the host-supplied paths used throughout this file. They are
// deliberately /nix/store-shaped: that is the coherent thing for a host to declare
// (the unit and the binary roll forward and back together from one pin), and it is
// the case `verify`'s volatileBakedPaths must keep accepting.
const (
	exportSetpriv = "/nix/store/0000000000000000000000000000000-util-linux-2.41/bin/setpriv"
	exportShim    = "/nix/store/1111111111111111111111111111111-anonctl-0.9.0/bin/anonctl-shim"
	exportNft     = "/nix/store/2222222222222222222222222222222-nftables-1.1.6/bin/nft"
	// The two DIRECTORIES are scratch-shaped rather than the real /etc/anonctl paths.
	// Nothing here writes to them today (InstallCommon only creates the unit dir), but a
	// test store naming a real shared location is the one thing this suite's isolation
	// discipline forbids, and it would become a real /etc write the day the install path
	// touched its env or rules dir.
	exportEnvDir   = "/scratch/anonctl/shim"
	exportRulesDir = "/scratch/anonctl/nftables"
)

// installedUnits runs the REAL install path (Store.InstallCommon, the function
// `anonctl add` calls) against a scratch unit dir and returns the two files it
// wrote, keyed by unit file name.
func installedUnits(t *testing.T) map[string]string {
	t.Helper()
	root := t.TempDir()
	store := systemd.Store{
		UnitDir:       filepath.Join(root, "systemd"),
		EnvDir:        exportEnvDir,
		RulesDir:      exportRulesDir,
		LegacyUnitDir: filepath.Join(root, "legacy"),
		// No marker: this is the ordinary anonctl-owned mode, i.e. exactly what a host
		// that says nothing gets.
		HostOwnedMarker: filepath.Join(root, "absent-marker"),
	}
	if err := store.InstallCommon(
		systemd.TemplateParams{ShimBinaryPath: exportShim, SetprivPath: exportSetpriv},
		systemd.LoaderParams{NftPath: exportNft},
	); err != nil {
		t.Fatalf("InstallCommon: %v", err)
	}
	out := map[string]string{}
	for _, name := range systemd.SharedUnitNames() {
		body, err := os.ReadFile(filepath.Join(store.UnitDir, name))
		if err != nil {
			t.Fatalf("read installed unit %s: %v", name, err)
		}
		out[name] = string(body)
	}
	return out
}

// printUnits runs the CLI exactly as a host's build system would (through run(), the
// real argv entry point) and returns stdout.
func printUnits(t *testing.T, args ...string) string {
	t.Helper()
	var code int
	out := captureStdout(t, func() { code = run(args) })
	if code != 0 {
		t.Fatalf("`anonctl %s` exited %d", strings.Join(args, " "), code)
	}
	return out
}

// TestExportedUnitTextIsByteIdenticalToWhatAddWrites is the whole contract in one
// assertion, for BOTH units: `anonctl units print` must emit exactly the bytes the
// install path writes for the same paths. If this ever fails, a host declaring the
// units is running a different definition from the one anonctl believes it
// installed, which is precisely the drift the export exists to remove.
func TestExportedUnitTextIsByteIdenticalToWhatAddWrites(t *testing.T) {
	installed := installedUnits(t)

	for _, tc := range []struct {
		kind systemd.Kind
		args []string
	}{
		{systemd.KindShim, []string{"units", "print", "--kind", "shim",
			"--setpriv", exportSetpriv, "--shim", exportShim, "--env-dir", exportEnvDir}},
		{systemd.KindNftables, []string{"units", "print", "--kind", "nftables",
			"--nft", exportNft, "--rules-dir", exportRulesDir}},
	} {
		name, err := tc.kind.UnitFileName()
		if err != nil {
			t.Fatalf("UnitFileName(%s): %v", tc.kind, err)
		}
		printed := printUnits(t, tc.args...)
		if printed != installed[name] {
			t.Errorf("`anonctl units print --kind %s` does NOT match what add writes to %s.\n--- printed ---\n%s\n--- installed ---\n%s",
				tc.kind, name, printed, installed[name])
		}
		if printed == "" {
			t.Errorf("`anonctl units print --kind %s` printed nothing", tc.kind)
		}
	}
}

// TestPackagedUnitFilesMatchTheEmitter holds the OTHER export shape to the same
// standard: the `.in` data files shipped in the package are generated output, not a
// hand-maintained copy. Editing them by hand, or changing the generator without
// re-running `go generate ./...`, fails here rather than shipping two definitions
// that agree today and drift at the next release.
//
// It ranges over systemd.Kinds rather than a hand-written table, so a THIRD unit
// kind cannot ship with no packaged file and no failure: adding a kind without
// regenerating fails here.
func TestPackagedUnitFilesMatchTheEmitter(t *testing.T) {
	for _, kind := range systemd.Kinds {
		name, err := kind.UnitFileName()
		if err != nil {
			t.Fatalf("UnitFileName(%s): %v", kind, err)
		}
		file := filepath.Join("share", "anonctl", "units", name+".in")
		want, err := systemd.ExportPlaceholders(kind)
		if err != nil {
			t.Fatalf("ExportPlaceholders(%s): %v", kind, err)
		}
		got, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read packaged unit %s: %v (run `go generate ./...`)", file, err)
		}
		if string(got) != want {
			t.Errorf("%s is stale: it does not match the emitter. Run `go generate ./...` and commit the result.\n--- file ---\n%s\n--- emitter ---\n%s", file, got, want)
		}
	}
}

// TestPlaceholderSubstitutionEqualsConcreteEmission closes the loop for the shape a
// packager actually uses: substituting every `@name@` token in the shipped `.in`
// file must yield exactly what `add` would have written with those paths.
//
// It is the assertion that makes the `.in` files SAFE to use rather than merely
// present: it proves the placeholders cover EVERY host-varying value in the text, so
// a host that substitutes them all is left with no residue of the build machine and
// no stale default that a future generator change might introduce.
func TestPlaceholderSubstitutionEqualsConcreteEmission(t *testing.T) {
	installed := installedUnits(t)
	substitute := strings.NewReplacer(
		systemd.PlaceholderSetpriv, exportSetpriv,
		systemd.PlaceholderShim, exportShim,
		systemd.PlaceholderEnvDir, exportEnvDir,
		systemd.PlaceholderNft, exportNft,
		systemd.PlaceholderRulesDir, exportRulesDir,
	)
	for _, kind := range systemd.Kinds {
		name, err := kind.UnitFileName()
		if err != nil {
			t.Fatalf("UnitFileName(%s): %v", kind, err)
		}
		in, err := systemd.ExportPlaceholders(kind)
		if err != nil {
			t.Fatalf("ExportPlaceholders(%s): %v", kind, err)
		}
		got := substitute.Replace(in)
		if got != installed[name] {
			t.Errorf("substituting the placeholders in %s.in does not reproduce what add writes.\n--- substituted ---\n%s\n--- installed ---\n%s", name, got, installed[name])
		}
		// And no token survives: a placeholder left in a unit file is a path that does not
		// exist, i.e. a 203/EXEC at the next boot.
		for _, token := range []string{
			systemd.PlaceholderSetpriv, systemd.PlaceholderShim, systemd.PlaceholderEnvDir,
			systemd.PlaceholderNft, systemd.PlaceholderRulesDir,
		} {
			if strings.Contains(got, token) {
				t.Errorf("%s still contains the unsubstituted placeholder %s after substituting every token: %s", name, token, got)
			}
		}
	}
}

// TestUnitsPrintIsPureOfTheHost pins the property a Nix derivation depends on: the
// emitter is a function of its FLAGS alone. Same flags, same bytes, no matter what
// this host's $PATH says, what its unit dir override is, or how many times it runs.
//
// This is not a style preference. A derivation that calls `anonctl units print` is
// reproducible only while it holds, and the tempting future "improvement" -- falling
// back to resolving setpriv on $PATH when the flag is omitted -- would silently break
// it by making the output depend on the build machine. The missing flag is an error
// instead, which this also asserts.
func TestUnitsPrintIsPureOfTheHost(t *testing.T) {
	args := []string{"units", "print", "--kind", "shim",
		"--setpriv", exportSetpriv, "--shim", exportShim, "--env-dir", exportEnvDir}

	first := printUnits(t, args...)
	t.Setenv(systemd.UnitDirEnv, "/run/systemd/system")
	t.Setenv("PATH", "/nonexistent")
	second := printUnits(t, args...)
	if first != second {
		t.Errorf("units print is NOT pure: the same flags produced different text after changing PATH/%s\n--- first ---\n%s\n--- second ---\n%s", systemd.UnitDirEnv, first, second)
	}

	// A path that is not supplied is a REFUSAL, never a lookup and never a default: a
	// unit naming a path that is merely plausible fails at the next boot, long after
	// whoever ran this saw it succeed.
	for _, missing := range [][]string{
		{"units", "print", "--kind", "shim", "--shim", exportShim, "--env-dir", exportEnvDir},
		{"units", "print", "--kind", "shim", "--setpriv", exportSetpriv, "--env-dir", exportEnvDir},
		{"units", "print", "--kind", "shim", "--setpriv", exportSetpriv, "--shim", exportShim},
		{"units", "print", "--kind", "nftables", "--rules-dir", exportRulesDir},
		{"units", "print", "--kind", "nftables", "--nft", exportNft},
		{"units", "print"},
	} {
		if code := run(missing); code == 0 {
			t.Errorf("`anonctl %s` succeeded; a missing path flag must be refused, not defaulted", strings.Join(missing, " "))
		}
	}

	// A flag belonging to the OTHER unit is refused rather than ignored, so a host can
	// never believe it pinned a path that is not in the file it got.
	for _, wrong := range [][]string{
		{"units", "print", "--kind", "shim", "--setpriv", exportSetpriv, "--shim", exportShim, "--env-dir", exportEnvDir, "--nft", exportNft},
		{"units", "print", "--kind", "nftables", "--nft", exportNft, "--rules-dir", exportRulesDir, "--setpriv", exportSetpriv},
		{"units", "print", "--kind", "shim", "--placeholders", "--setpriv", exportSetpriv},
		{"units", "print", "--kind", "banana"},
	} {
		if code := run(wrong); code == 0 {
			t.Errorf("`anonctl %s` succeeded; a flag that does not belong to the kind must be refused, not dropped", strings.Join(wrong, " "))
		}
	}
}

// TestUnitsPrintNeedsNoRootAndEmitsOnlyTheUnitOnStdout pins the two properties that
// make the emitter usable from a build: it does not self-elevate (the test process is
// not root, and a sudo re-exec would hang or fail), and stdout carries the unit and
// NOTHING else, so `anonctl units print ... > file` writes a valid unit file.
func TestUnitsPrintNeedsNoRootAndEmitsOnlyTheUnitOnStdout(t *testing.T) {
	out := printUnits(t, "units", "print", "--kind", "nftables", "--nft", exportNft, "--rules-dir", exportRulesDir)
	if !strings.HasPrefix(out, "# anonctl early-boot nftables loader") {
		t.Errorf("stdout does not start with the unit text (something else is being printed to stdout):\n%s", out)
	}
	if strings.Contains(out, "install this text as") {
		t.Error("the advisory file NAME leaked into stdout; it belongs on stderr, or it lands inside a redirected unit file")
	}
	if !strings.HasSuffix(out, "WantedBy=sysinit.target\n") {
		t.Errorf("stdout does not end with the unit's last line:\n%s", out)
	}
}

// TestAddRefusesBeforeTouchingTheBoxWhenTheUnitPreflightFails pins WHERE the
// host-owned preflight sits in `add`: before the account is created or adopted.
//
// That placement is the whole safety of the mode. The failure it guards against is
// a host that declares the marker but not the units, and the state it must never
// produce is an account that exists, is enabled, and has NO unit to load at the next
// boot -- which for the early loader means no standing default-deny at all, so the
// anon UID egresses with the host's real IP. Fail-open and silent, discovered at a
// reboot nobody is watching.
func TestAddRefusesBeforeTouchingTheBoxWhenTheUnitPreflightFails(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	restore := swapUnitPreflight(systemd.UnitOwnership{HostOwned: true, MarkerPath: "/etc/anonctl/units.host-owned"},
		errors.New("anonctl-nftables.service is not present in any of systemd's unit directories"))
	defer restore()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	code := runAdd(context.Background(), r,
		mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	if code == 0 {
		t.Fatal("add succeeded although the unit preflight refused")
	}
	if len(r.created) != 0 {
		t.Errorf("add created %v before/despite the refusal: the guard exists so a refusal leaves the box UNTOUCHED", r.created)
	}
	if len(install.calls) != 0 {
		t.Errorf("add installed forcing despite the refusal: %+v", install.calls)
	}
}

// TestUnitsNeverElevatesAndIsDispatchedBeforeAnyHostAccess pins the ORDERING that
// makes the emitter pure, which no assertion about its output can pin on its own.
//
// Two things sit between Parse and a verb in run(): self-elevation, and the
// root-only chmod chokepoint that asserts the modes of the operator-placed files
// under /etc/anonctl. `units` must be dispatched before BOTH. If it were not, then
// running it as root -- which a build system plausibly does -- would write to /etc,
// and a `sudo` re-exec would turn a pure text emitter into an interactive password
// prompt in the middle of a derivation.
func TestUnitsNeverElevatesAndIsDispatchedBeforeAnyHostAccess(t *testing.T) {
	if rootRequiringVerbs["units"] {
		t.Error("units is listed as root-requiring: it would self-elevate, and it needs no root at all")
	}
	// The dispatch must come before the elevation seam. Assert it by making elevation
	// FATAL if it is ever reached: a units run that touched it would fail here rather
	// than silently acquiring the habit.
	orig := elevateLookSudo
	t.Cleanup(func() { elevateLookSudo = orig })
	elevateLookSudo = func() (string, error) {
		t.Error("units reached the self-elevation seam; it is dispatched too late in run()")
		return "", errSudoNotFound
	}
	if code := run([]string{"units", "print", "--kind", "nftables", "--nft", exportNft, "--rules-dir", exportRulesDir}); code != 0 {
		t.Fatalf("units print exited %d", code)
	}
}

// TestUnitsPrintRefusesARelativeBinaryPath pins the refusal at the moment the text
// is GENERATED, on the machine of the person who can still fix it.
//
// A systemd unit inherits no useful $PATH, so `--nft nft` is not "resolved later":
// it is exit 127 at the next boot, with nothing loaded. For the loader that means no
// standing baseline default-deny, so the account egresses with the host's real IP,
// silently, and only after a reboot that nobody is watching. It is a natural thing
// to write for anyone with a working shell, which is exactly why the emitter must
// not produce it. The preflight refuses it too, for a unit that arrives by some
// other route.
func TestUnitsPrintRefusesARelativeBinaryPath(t *testing.T) {
	for _, args := range [][]string{
		{"units", "print", "--kind", "nftables", "--nft", "nft", "--rules-dir", exportRulesDir},
		{"units", "print", "--kind", "nftables", "--nft", exportNft, "--rules-dir", "anonctl/nftables"},
		{"units", "print", "--kind", "shim", "--setpriv", "setpriv", "--shim", exportShim, "--env-dir", exportEnvDir},
		{"units", "print", "--kind", "shim", "--setpriv", exportSetpriv, "--shim", "anonctl-shim", "--env-dir", exportEnvDir},
		{"units", "print", "--kind", "shim", "--setpriv", exportSetpriv, "--shim", exportShim, "--env-dir", "anonctl/shim"},
	} {
		if code := run(args); code == 0 {
			t.Errorf("`anonctl %s` succeeded: a relative path in a unit is 203/EXEC or 127 at the next boot, not a lookup", strings.Join(args, " "))
		}
	}

	// The placeholders are NOT paths yet, so they must still be emitted. Refusing them
	// would make the packaged .in files ungenerateable by the very tool that ships them.
	for _, kind := range systemd.Kinds {
		if code := run([]string{"units", "print", "--kind", string(kind), "--placeholders"}); code != 0 {
			t.Errorf("`units print --kind %s --placeholders` was refused; @name@ tokens are substituted by the host, not resolved by anonctl", kind)
		}
	}
}
