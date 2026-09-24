package systemd

import (
	"fmt"
	"path/filepath"
	"strings"
)

// This file is the EXPORT surface: it lets a HOST declare anonctl's two unit files
// in its own configuration instead of depending on files `add` wrote into
// /usr/local/lib/systemd/system that no rebuild reproduces and no rollback undoes.
//
// It adds NO second copy of the unit text. Export calls the SAME TemplateUnit /
// LoaderUnit generators `add` installs through, with the paths taken as PARAMETERS
// rather than resolved, so the exported text and the written text cannot drift
// across a version: they are the same function. That is the whole point of the
// feature, and `TestExportedUnitTextIsByteIdenticalToWhatAddWrites` is what holds
// it (a fixture copy of the template in testdata would quietly defeat it).
//
// PURITY IS A CONTRACT, NOT A STYLE. Export is a pure function of its arguments:
// it reads no file, probes no host, resolves nothing against $PATH, and embeds no
// timestamp, so the same arguments give byte-identical output on every host and
// every run. A Nix derivation that calls `anonctl units print` is only reproducible
// while that holds, so it is asserted by test rather than left as an intention.

// Kind selects WHICH of anonctl's two shared units to emit. They are the only two
// files `add` installs that are account-AGNOSTIC: the per-account artifacts (the
// env file, the rule files, and above all the per-account enablement symlink) are
// deliberately NOT exportable, because the symlink's NAME is the one artifact that
// says which account slot is in use, and that is exactly the fact a declarative
// host would publish to a git repository. See ADR-0012.
type Kind string

const (
	// KindShim is the per-account shim @-template (`anonctl-shim@.service`). It is
	// name-free by construction: the account is the `%i` instance and every
	// per-account value arrives through the EnvironmentFile, so ONE static file
	// serves every account and it can be declared by a host without naming any.
	KindShim Kind = "shim"
	// KindNftables is anonctl's early-boot nftables loader (`anonctl-nftables.service`).
	KindNftables Kind = "nftables"
)

// Kinds are the accepted --kind values, in the order they are printed in errors and
// usage.
var Kinds = []Kind{KindShim, KindNftables}

// UnitFileName returns the file name a kind is installed as, so a host declaring
// the text knows which name it must land under. The names are load-bearing: the
// per-account enablement symlinks anonctl writes name the shim TEMPLATE, and a host
// that declared the same text under a different name would leave those symlinks
// pointing at nothing.
func (k Kind) UnitFileName() (string, error) {
	switch k {
	case KindShim:
		return UnitName, nil
	case KindNftables:
		return LoaderUnitName, nil
	default:
		return "", fmt.Errorf("systemd: unknown unit kind %q (want one of: %s)", k, kindList())
	}
}

func kindList() string {
	names := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// Placeholder values for the packaged `.in` files: the text with every host-varying
// path left as a substitutable token, in Nix's `substituteAll` spelling (`@name@`)
// so a derivation can consume it with no extra tooling.
//
// They are ORDINARY PARAMETER VALUES, not a special mode of the generator: the
// `.in` files are produced by calling the same Export with these strings, so a
// packaged `.in` file cannot drift from the emitter either. A host that substitutes
// all of them gets byte-for-byte what `anonctl units print` would have emitted with
// the same paths, which TestPlaceholderSubstitutionEqualsConcreteEmission asserts.
const (
	PlaceholderSetpriv  = "@setpriv@"
	PlaceholderShim     = "@shim@"
	PlaceholderEnvDir   = "@envDir@"
	PlaceholderNft      = "@nft@"
	PlaceholderRulesDir = "@rulesDir@"
)

// ExportParams are the paths a host supplies for the unit it is declaring. They are
// PARAMETERS rather than resolved values on purpose: a host that declares the unit
// points ExecStart at an immutable store path from the same pin as the binary, so
// the unit and the binary roll forward and BACK together, which is more coherent
// than a stable alias that the next rebuild can repoint under a unit nobody edited.
//
// Nothing here is validated for existence, and that is deliberate too: the paths
// being described may not exist on the machine doing the describing (a build host
// emitting a unit for a target closure), and a generator that stat()ed them would
// not be a pure function of its arguments.
type ExportParams struct {
	// Kind selects the unit to emit. Required.
	Kind Kind
	// SetprivPath / ShimBinaryPath / EnvDir parameterise KindShim.
	SetprivPath    string
	ShimBinaryPath string
	EnvDir         string
	// NftPath / RulesDir parameterise KindNftables. RulesDir is the DIRECTORY, not the
	// glob: the `*.nft` suffix is appended by the generator exactly as InstallCommon
	// appends it, so a host cannot accidentally declare a glob that misses the
	// `<account>.baseline.nft` files and thereby drop the standing default-deny.
	NftPath  string
	RulesDir string
}

// Export renders one shared unit as text. It is the single entry point behind both
// export shapes (the packaged `.in` data files and `anonctl units print`), and it
// delegates to the very generators `add` installs through.
//
// It REFUSES a parameter that belongs to the other kind rather than ignoring it. A
// silently dropped `--nft` on the shim unit would let a host believe it had pinned a
// path that is not in the file, and the loader naming a wrong `nft` is the
// fail-OPEN failure in this whole design (no loader means no standing default-deny
// at boot), so the one thing this must never do is accept a flag and discard it.
func Export(p ExportParams) (string, error) {
	switch p.Kind {
	case KindShim:
		if err := rejectForeign(p.Kind, map[string]string{"--nft": p.NftPath, "--rules-dir": p.RulesDir}); err != nil {
			return "", err
		}
		if strings.TrimSpace(p.EnvDir) == "" {
			return "", fmt.Errorf("systemd: unit kind %q needs --env-dir (the directory holding the per-account EnvironmentFiles; anonctl's own default is %s)", p.Kind, DefaultEnvDir)
		}
		if err := mustBeAbsolute(map[string]string{"--setpriv": p.SetprivPath, "--shim": p.ShimBinaryPath, "--env-dir": p.EnvDir}); err != nil {
			return "", err
		}
		return TemplateUnit(TemplateParams{
			ShimBinaryPath: p.ShimBinaryPath,
			SetprivPath:    p.SetprivPath,
			EnvDir:         p.EnvDir,
		})
	case KindNftables:
		if err := rejectForeign(p.Kind, map[string]string{"--setpriv": p.SetprivPath, "--shim": p.ShimBinaryPath, "--env-dir": p.EnvDir}); err != nil {
			return "", err
		}
		if strings.TrimSpace(p.RulesDir) == "" {
			return "", fmt.Errorf("systemd: unit kind %q needs --rules-dir (the directory holding the persisted per-account .nft files; anonctl's own default is %s)", p.Kind, DefaultRulesDir)
		}
		if err := mustBeAbsolute(map[string]string{"--nft": p.NftPath, "--rules-dir": p.RulesDir}); err != nil {
			return "", err
		}
		// The SAME join InstallCommon performs, so the exported loader and the installed
		// loader carry the identical glob.
		return LoaderUnit(LoaderParams{
			NftPath:   p.NftPath,
			RulesGlob: filepath.Join(p.RulesDir, "*.nft"),
		})
	default:
		return "", fmt.Errorf("systemd: unknown unit kind %q (want one of: %s)", p.Kind, kindList())
	}
}

// mustBeAbsolute refuses a path that is neither absolute nor one of anonctl's own
// `@name@` placeholder tokens.
//
// A SYSTEMD UNIT HAS NO USEFUL INHERITED $PATH, so a relative command in ExecStart
// is not "resolved later", it is `203/EXEC` or `127` at the next boot. For the
// loader that is the fail-OPEN failure this whole feature is built around: no rules
// load, so there is no standing baseline default-deny, so the anon UID egresses with
// the host's real IP, silently and only after a reboot. `--nft nft` looks entirely
// reasonable to someone who has a working shell, which is exactly why it has to be
// refused HERE, at the moment the text is generated, on the machine of the person
// who can still fix it.
//
// The placeholder tokens are permitted because they are not paths yet: they are
// substituted with one. The host-side check that they were all substituted, and
// substituted with something absolute, lives in PreflightHostUnits.
func mustBeAbsolute(paths map[string]string) error {
	placeholders := map[string]bool{
		PlaceholderSetpriv: true, PlaceholderShim: true, PlaceholderEnvDir: true,
		PlaceholderNft: true, PlaceholderRulesDir: true,
	}
	var bad []string
	for flag, value := range paths {
		v := strings.TrimSpace(value)
		if placeholders[v] || strings.HasPrefix(v, "/") {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s %q", flag, value))
	}
	if len(bad) == 0 {
		return nil
	}
	sortStrings(bad)
	return fmt.Errorf("systemd: %s must be ABSOLUTE. A systemd unit inherits no useful $PATH, so a bare name is not resolved at boot: the unit fails (203/EXEC or 127) the first time it runs, which for %s means no rules are loaded at all -- no standing baseline default-deny -- and the account egresses with this host's real IP. Give the full path, e.g. the one your package manager pins",
		strings.Join(bad, ", "), LoaderUnitName)
}

// rejectForeign fails when a parameter belonging to the OTHER kind was supplied, so
// a mis-flagged invocation is a loud error instead of a quietly ignored pin.
func rejectForeign(kind Kind, foreign map[string]string) error {
	var named []string
	for flag, value := range foreign {
		if strings.TrimSpace(value) != "" {
			named = append(named, flag)
		}
	}
	if len(named) == 0 {
		return nil
	}
	sortStrings(named)
	return fmt.Errorf("systemd: unit kind %q does not take %s (that path is baked into the other unit; emit it with --kind %s)", kind, strings.Join(named, " or "), otherKind(kind))
}

func otherKind(k Kind) Kind {
	if k == KindShim {
		return KindNftables
	}
	return KindShim
}

// sortStrings is a tiny insertion sort so error text is deterministic (map iteration
// order is not). Deterministic messages matter here: a host's build log is the only
// place these errors are read.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ExportPlaceholders renders a kind with every host-varying path left as its `@name@`
// placeholder: the packaged `.in` file. It exists so the data files anonctl ships and
// the emitter can never disagree, because the files ARE the emitter's output.
func ExportPlaceholders(kind Kind) (string, error) {
	return Export(ExportParams{
		Kind:           kind,
		SetprivPath:    PlaceholderSetpriv,
		ShimBinaryPath: PlaceholderShim,
		EnvDir:         PlaceholderEnvDir,
		NftPath:        PlaceholderNft,
		RulesDir:       PlaceholderRulesDir,
	}.forKind(kind))
}

// forKind blanks the parameters that belong to the other kind, so ExportPlaceholders
// can pass one filled struct without tripping Export's reject-foreign guard.
func (p ExportParams) forKind(kind Kind) ExportParams {
	out := ExportParams{Kind: kind}
	switch kind {
	case KindShim:
		out.SetprivPath, out.ShimBinaryPath, out.EnvDir = p.SetprivPath, p.ShimBinaryPath, p.EnvDir
	case KindNftables:
		out.NftPath, out.RulesDir = p.NftPath, p.RulesDir
	}
	return out
}
