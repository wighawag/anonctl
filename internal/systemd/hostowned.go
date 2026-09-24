package systemd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/wighawag/anoncore/configroot"
)

// This file implements HOST-OWNED UNITS: the mode in which the two shared unit
// FILES are declared by the host's own configuration (a NixOS module, a package, a
// config-management manifest) and anonctl must therefore NOT write, rewrite or
// delete them.
//
// It exists because a host that declares its accounts declaratively still had to
// depend, at boot, on two unit files that `anonctl add` wrote out of band: nothing
// in the host's configuration knew they existed, no rebuild reproduced them, no
// rollback undid them, and a reinstall of the machine restored the declared
// accounts and the declared binary but NOT the units -- so the accounts came back
// with nothing installing their forcing at boot. See ADR-0012.
//
// The bit is a MARKER FILE rather than a flag or an environment variable, and that
// choice is load-bearing:
//
//   - a flag on `add` cannot protect `update`, which ALSO rewrites both unit files
//     (it re-bakes the binary paths); one forgotten flag on one later invocation
//     re-creates the very second definition this mode exists to prevent;
//   - an environment variable has to be present in every context anonctl is invoked
//     from -- an operator's interactive `sudo`, a reconcile oneshot, a rescue shell --
//     and it is invisible to anyone inspecting the box afterwards;
//   - a marker file is DECLARED like everything else the host owns, so it arrives and
//     departs with the configuration that declares the units, it applies to every
//     invocation by every caller automatically, and `ls /etc/anonctl` shows it.
//
// The marker governs the two SHARED unit files only. The per-account enablement
// symlinks stay anonctl's in every mode: `multi-user.target.wants/anonctl-shim@<account>.service`
// is the one artifact whose NAME says which account slot is in use, and a host that
// declared it would publish that fact to its configuration repository. That is the
// exact privacy property anonctl's slot-pool guidance exists to protect
// (docs/nixos.md section 4), so those symlinks are never exported and never
// host-declarable.

// HostOwnedUnitsMarkerName is the marker file, under the shared config root
// (`/etc/anonctl/units.host-owned`). Its PRESENCE is the entire signal; its content
// is ignored by anonctl and is a good place for the host to record which module
// declares the units, for whoever reads the box later.
const HostOwnedUnitsMarkerName = "units.host-owned"

// DefaultHostOwnedUnitsMarker is that marker at its production path.
const DefaultHostOwnedUnitsMarker = configroot.DefaultDir + "/" + HostOwnedUnitsMarkerName

// UnitOwnership is the answer to "who owns the two shared unit files here", carried
// as a value so every caller renders the SAME answer rather than re-deciding it.
type UnitOwnership struct {
	// HostOwned is true when the host declares the unit files and anonctl must not
	// write or delete them.
	HostOwned bool
	// MarkerPath is where the decision was read from, so an operator can be told
	// exactly which file put anonctl into this mode (or which file to create to ask
	// for it). Empty for a store that is not rooted in a config root at all (a test
	// store), which always reads as anonctl-owned.
	MarkerPath string
	// Units maps each shared unit name to the file the preflight actually VALIDATED,
	// set only on the host-owned path (PreflightUnits). It exists so the caller can name
	// those files to the operator: in this mode anonctl is vouching for text it did not
	// write, and with two copies in the search path systemd picks one without saying so,
	// which makes "anonctl checked the units" useful only if it says WHICH.
	Units map[string]string
}

// hostOwnedMarkerPath resolves the marker for THIS store, or "" when the store does
// not name a config root at all.
//
// The fallback is deliberately narrow: an EXPLICITLY named RootDir, and nothing
// else. It does NOT go through configroot.RootFor like the env/rules dirs do,
// because that helper treats an EMPTY directory as "production" -- correct for a dir
// that has a production default, and wrong here, since it would make a store that
// merely forgot a field read the real /etc/anonctl marker and silently run in a
// different mode than its author believed. Production names the marker outright
// (DefaultStore), so the fallback only has to serve a caller that named a root, and
// anything else reads as "anonctl owns the units", which is the pre-existing
// behaviour.
func (s Store) hostOwnedMarkerPath() string {
	if m := strings.TrimSpace(s.HostOwnedMarker); m != "" {
		return m
	}
	root := strings.TrimSpace(s.RootDir)
	if root == "" {
		return ""
	}
	return filepath.Join(root, HostOwnedUnitsMarkerName)
}

// UnitOwnership reports whether the host owns the two shared unit files.
//
// An unreadable marker (present but un-stat-able) is reported as an ERROR rather
// than as "anonctl owns them", because guessing wrong in that direction is what
// makes `rm` delete a file the host declares.
func (s Store) UnitOwnership() (UnitOwnership, error) {
	path := s.hostOwnedMarkerPath()
	if path == "" {
		return UnitOwnership{}, nil
	}
	switch _, err := os.Stat(path); {
	case err == nil:
		return UnitOwnership{HostOwned: true, MarkerPath: path}, nil
	case errors.Is(err, os.ErrNotExist):
		return UnitOwnership{MarkerPath: path}, nil
	default:
		return UnitOwnership{}, fmt.Errorf("systemd: cannot read the host-owned-units marker %q: %w (refusing to guess: treating it as absent would let anonctl overwrite or delete a unit file the host declares)", path, err)
	}
}

// searchDirs is the list of directories a unit file is looked for in, in systemd's
// own PRECEDENCE order (highest first), which is what makes "which definition will
// actually load" answerable without shelling out to systemctl.
//
// It ends with this store's own unit dir when that is not already one of the known
// dirs, so an ANONCTL_UNIT_DIR override still resolves. It goes LAST because its
// true precedence is unknown -- systemd would not read it at all unless the host
// added it to UnitPath -- and claiming a rank for it would be inventing an answer.
func (s Store) searchDirs() []string {
	if len(s.SearchDirs) > 0 {
		return s.SearchDirs
	}
	dirs := append([]string(nil), knownUnitSearchDirs...)
	if !isKnownUnitSearchDir(s.unitDir()) {
		dirs = append(dirs, s.unitDir())
	}
	return dirs
}

// FindUnitFiles returns EVERY copy of a unit name in the search path, in precedence
// order, so "which definition loads" and "is there more than one" are answerable
// from the same walk. systemd itself answers neither out loud: with two copies it
// simply uses the higher-ranked one and says nothing (measured on systemd 260).
func (s Store) FindUnitFiles(unitName string) ([]string, error) {
	var out []string
	for _, dir := range s.searchDirs() {
		path := filepath.Join(dir, unitName)
		switch _, err := os.Stat(path); {
		case err == nil:
			out = append(out, path)
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return nil, fmt.Errorf("systemd: inspect %q: %w", path, err)
		}
	}
	return out, nil
}

// FindUnitFile returns the path systemd would LOAD for a unit name: the first match
// walking the search dirs in precedence order. It is how anonctl checks a
// host-declared unit is really there, and how it detects its own copy being
// shadowed by a higher-ranked one.
//
// Measured on systemd 260 (NixOS): with the same unit name present in two search
// dirs, FragmentPath is the higher-precedence one and NOTHING warns -- the lower
// copy simply sits there looking authoritative. That silent shadowing is the hazard
// this whole mode exists to avoid, so it is detected explicitly rather than assumed
// away.
//
// A returned ("", nil) means "no definition anywhere in the search path", which is
// a real and important answer, distinct from an error.
func (s Store) FindUnitFile(unitName string) (string, error) {
	all, err := s.FindUnitFiles(unitName)
	if err != nil || len(all) == 0 {
		return "", err
	}
	return all[0], nil
}

// SharedUnitNames are the two account-agnostic unit files, in install order.
func SharedUnitNames() []string { return []string{UnitName, LoaderUnitName} }

// PreflightHostUnits asserts that a host claiming to own the units has actually
// provided BOTH of them AND that the binaries those units name really exist. It
// returns the resolved unit paths for reporting.
//
// IT IS A PRECONDITION, NOT A COURTESY, and it runs before `add` creates or adopts
// anything. Without it, the marker becomes the most dangerous footgun in the tool:
// declare the marker, forget the units, and `add` would enable an account, apply
// live rules, report success -- and at the next boot load NEITHER the shim NOR the
// early loader. Missing the loader means the standing baseline default-deny is
// absent, so the anon UID egresses FREELY with the host's real IP. That is
// fail-OPEN and silent, which is the one outcome this codebase refuses to ship, so
// the check is mandatory and the failure is a refusal with the box untouched.
//
// The BINARY half is the same assertion `verify` makes (unit-binaries-present),
// pulled forward to install time: on this path anonctl does not resolve the paths
// itself, so the host's ExecStart is the only thing standing between the account
// and a 203/EXEC at the next boot, and a typo in a declared store path must be
// caught while the box is still untouched rather than at 03:00 after a reboot.
func (s Store) PreflightHostUnits() (map[string]string, error) {
	found := map[string]string{}
	var missing []string
	for _, name := range SharedUnitNames() {
		path, err := s.FindUnitFile(name)
		if err != nil {
			return nil, err
		}
		if path == "" {
			missing = append(missing, name)
			continue
		}
		found[name] = path
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("systemd: the host-owned-units marker %s is present, so anonctl will not install its own unit files, but %s %s in any of systemd's unit directories (%s). Declare %s in the host configuration (`anonctl units print --kind shim|nftables ...`, or the packaged share/anonctl/units/*.service.in files), or remove the marker to let anonctl install them again. Refusing now, with nothing changed: proceeding would enable an account whose shim and whose early-boot default-deny simply do not exist at the next boot",
			s.hostOwnedMarkerPath(), strings.Join(missing, " and "), plural(len(missing), "is not present", "are not present"), strings.Join(s.searchDirs(), ", "), plural(len(missing), "it", "them"))
	}
	if err := s.assertDeclaredUnitsAgree(found); err != nil {
		return nil, err
	}
	baked, err := s.BakedBinaries()
	if err != nil {
		return nil, err
	}
	// NOTHING PARSED IS NOT A PASS. `verify` already refuses an empty baked list on the
	// grounds that "nothing was checked" must never read as "everything is fine"; this
	// preflight must answer the same way about the same files, or a host gets a green
	// install and a red verify for one unchanged configuration.
	//
	// Belt and braces as things stand: a loader that survived the agreement check above
	// names an ABSOLUTE nft, which this sweep picks up, so an empty list is not
	// reachable through that path today. It is kept because it is a property of the
	// answer rather than of today's parser, and the parser is what would change.
	if len(baked) == 0 {
		return nil, fmt.Errorf("systemd: no absolute binary path could be read out of the host-declared units (%s), so what they will exec was NOT checked. Emit them with `anonctl units print` (or substitute the packaged *.service.in files) rather than hand-writing them: anonctl parses the ExecStart it generates, and cannot vouch for a shape it did not produce",
			strings.Join(sortedValues(found), ", "))
	}
	var absent []string
	for _, bin := range baked {
		if _, serr := os.Stat(bin); serr != nil {
			absent = append(absent, bin)
		}
	}
	if len(absent) > 0 {
		return nil, fmt.Errorf("systemd: the host-declared units name %s, which %s not exist on this host. The unit would fail at its next start with 203/EXEC, and for %s that means no standing default-deny at boot (fail-OPEN). Fix the path in the host configuration that declares these units; anonctl does not resolve them itself in this mode, by design, so that they can be pinned to the same closure as the binary",
			strings.Join(absent, ", "), plural(len(absent), "does", "do"), LoaderUnitName)
	}
	return found, nil
}

// assertDeclaredUnitsAgree checks the one thing a host CAN get wrong that nothing
// else would ever catch: the declared units must point at the directories anonctl
// actually writes into.
//
// THIS IS THE FAIL-OPEN CASE OF THE WHOLE MODE, and it is silent in a way the others
// are not. anonctl pins both couplings itself when it owns the units (InstallCommon
// passes its own env dir and its own `<rulesdir>/*.nft` glob); handing the files to
// the host removes that pin, and nothing downstream replaces it:
//
//   - a loader whose glob names the WRONG directory -- or still carries an
//     unsubstituted `@rulesDir@` from a half-finished `.in` substitution -- loads NOTHING
//     at boot. No baseline default-deny, so ADR-0005's inversion stops holding and the
//     anon UID egresses directly with the host's real IP.
//   - nothing exercises it before that boot. `add` deliberately ENABLES the loader
//     without starting it (the live rules are already applied via nft), so the only
//     time the glob is ever evaluated is the boot it exists to protect.
//   - the binary check cannot see it: the glob token is skipped precisely because it
//     is not a binary, so a wrong directory leaves `/bin/sh` as the only path checked
//     and everything reports green, including `verify`.
//
// The shim's EnvironmentFile is checked for the same reason, though its failure is
// merely fail-CLOSED (the instance does not start, the baseline still drops).
//
// The expected values MIRROR the two places that construct them (TemplateUnit's
// EnvironmentFile line and InstallCommon's rules glob). That duplication is tied
// down by test: a unit exported with this store's directories must pass this check,
// so a change to either generator that broke the agreement would fail there.
func (s Store) assertDeclaredUnitsAgree(found map[string]string) error {
	// Iterate the NAMES, not the map: when both units disagree the operator must get
	// the same message on every run (a build log is where this is read).
	for _, name := range SharedUnitNames() {
		path, ok := found[name]
		if !ok {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("systemd: read host-declared unit %q: %w", path, err)
		}
		text := string(body)
		// A surviving placeholder is a half-substituted `.in` file. Catch the whole class
		// in one place, because the same mistake in the shim is loud and in the loader is
		// silent, and an operator should not have to learn which is which.
		for _, token := range []string{PlaceholderSetpriv, PlaceholderShim, PlaceholderEnvDir, PlaceholderNft, PlaceholderRulesDir} {
			if strings.Contains(text, token) {
				return fmt.Errorf("systemd: the host-declared %s still contains the placeholder %s at %q: the packaged *.service.in template was installed without substituting every token. Substitute them all (see `anonctl units print --placeholders` for the list), or emit the final text with `anonctl units print`", name, token, path)
			}
		}
		switch name {
		case UnitName:
			// Mirrors TemplateUnit's `EnvironmentFile=<envdir>/%i.env`.
			want := s.envDir() + "/%i.env"
			got := directiveValue(text, "EnvironmentFile=")
			if got != want {
				return fmt.Errorf("systemd: the host-declared %s reads its per-account parameters from %q, but anonctl writes them to %q (%s). Every account's shim would start with no endpoint, no shim uid and no ports. Re-emit the unit with --env-dir %s",
					name, got, want, path, s.envDir())
			}
		case LoaderUnitName:
			// Mirrors InstallCommon's `filepath.Join(s.rulesDir(), "*.nft")`.
			want := filepath.Join(s.rulesDir(), "*.nft")
			got := loaderRulesGlob(text)
			if got != want {
				return fmt.Errorf("systemd: the host-declared %s loads %q at boot, but anonctl persists its rule files to %q (%s). At the next boot that unit would load NOTHING: no forcing, and -- the part that matters -- no standing baseline default-deny, so the account would egress directly with this host's real IP. Re-emit the unit with --rules-dir %s",
					name, got, want, path, s.rulesDir())
			}
			// The command the loader actually runs must be ABSOLUTE, and this is the only
			// check that looks at it. The generated `/bin/sh` is absolute and exists, so the
			// binary sweep is satisfied by it alone and never notices that the `nft` after the
			// `&&` is a bare name -- which a unit, inheriting no useful $PATH, cannot run. The
			// result at boot is exit 127, no rules loaded, no standing default-deny, real-IP
			// egress, silent. `--nft nft` is a perfectly natural thing for someone with a
			// working shell to write, so it is refused at BOTH ends: here, and in Export.
			if nft := loaderNftCommand(text); !strings.HasPrefix(nft, "/") {
				return fmt.Errorf("systemd: the host-declared %s runs %q to load the rules (%s), which is not an absolute path. A systemd unit inherits no useful $PATH, so at boot that is exit 127 and NOTHING is loaded: no forcing, and no standing baseline default-deny, so the account egresses with this host's real IP. Re-emit the unit with --nft pointing at the full path",
					name, nft, path)
			}
		}
	}
	return nil
}

// directiveValue returns the value of the first `<directive>` line in a unit, or ""
// when the directive is absent (which is itself a disagreement worth reporting).
//
// The name match is CASE-INSENSITIVE because systemd's is: a hand-written
// `execstart=` is a valid unit, and refusing it would be a false alarm about a
// declaration that is actually fine.
func directiveValue(text, directive string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= len(directive) && strings.EqualFold(line[:len(directive)], directive) {
			return line[len(directive):]
		}
	}
	return ""
}

// loaderNftCommand extracts the command the loader's ExecStart runs on each rule
// file (`... && <nft> -f "$f"; ...`), or "" when the line does not have the shape
// anonctl generates. "" reads as a disagreement, which is the safe direction.
func loaderNftCommand(text string) string {
	line := directiveValue(text, "ExecStart=")
	i := strings.Index(line, "&& ")
	if i < 0 {
		return ""
	}
	fields := strings.Fields(line[i+len("&& "):])
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// loaderRulesGlob extracts the glob the loader's ExecStart iterates (`for f in
// <glob>; do ...`), or "" when the line does not have the shape anonctl generates.
// An unrecognised shape reads as a disagreement, which is the safe direction: this
// check exists precisely because a loader that loads nothing is silent.
func loaderRulesGlob(text string) string {
	const marker = "for f in "
	line := directiveValue(text, "ExecStart=")
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(marker):]
	j := strings.Index(rest, ";")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// sortedValues returns a map's values in a deterministic order, for error text.
func sortedValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sortStrings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// PreflightUnits is the ONE unit preflight both `add` (before the account is created
// or adopted) and the orchestration (before any mutation) run, so the two can never
// disagree about what a host must satisfy. It returns the ownership it decided, for
// reporting.
//
// What it asserts depends on who owns the unit files, and the difference is the
// point of the mode:
//
//   - anonctl-owned: every binary the GENERATED units will name (the shim, setpriv,
//     nft) must resolve now, because anonctl is about to bake them in.
//   - host-owned: nothing is resolved locally -- the host's units carry the host's own
//     pin, and demanding a local `setpriv` or shim on $PATH would refuse a correct
//     host over text that is discarded. Instead both declared units must be present
//     in systemd's search path and the binaries THEY name must exist.
//
// The unit dir's writability is asserted in the HOST-OWNED mode only, and that
// asymmetry is deliberate rather than an oversight. In the default mode nothing
// about this host's behaviour changes: InstallCommon creates the dir and fails
// loudly exactly as it always has. In host-owned mode there is no unit write left to
// fail, so the only thing that would ever touch that directory is the per-account
// enablement symlink -- and an `add` that could not write it would otherwise report
// success over an account whose forcing silently does not come back after a reboot.
func PreflightUnits(s Store, r Resolver) (UnitOwnership, error) {
	own, err := s.UnitOwnership()
	if err != nil {
		return own, err
	}
	if own.HostOwned {
		if err := s.PreflightUnitDirWritable(); err != nil {
			return own, err
		}
		found, err := s.PreflightHostUnits()
		own.Units = found
		return own, err
	}
	return own, PreflightUnitBinaries(r)
}

// ShadowedUnit is one unit file anonctl wrote that is OUTRANKED by another copy
// elsewhere in the search path, so the one systemd loads is not the one anonctl
// maintains.
type ShadowedUnit struct {
	// Name is the unit file name; Ours is anonctl's copy; Loaded is the one systemd
	// will actually use.
	Name   string
	Ours   string
	Loaded string
}

// ShadowedUnits reports anonctl's own unit files that are outranked by a copy in a
// higher-precedence directory. It is the detection half of the shadowing hazard:
// anonctl's copy is inert but looks authoritative, so `update` re-bakes a file
// nothing loads while the definition that IS loaded silently goes stale.
//
// It is a REPORT, not a refusal, and it never deletes the other copy: on a host that
// declares units, the higher-ranked copy is very likely the host's own, and deleting
// a declared file is the worse error of the two (the next boot loses it entirely
// until a rebuild puts it back). The right resolution is for the operator to place
// the marker and remove anonctl's copy, which the message says.
func (s Store) ShadowedUnits() ([]ShadowedUnit, error) {
	own, err := s.UnitOwnership()
	if err != nil {
		return nil, err
	}
	var out []ShadowedUnit
	for _, name := range SharedUnitNames() {
		all, ferr := s.FindUnitFiles(name)
		if ferr != nil {
			return nil, ferr
		}
		if len(all) < 2 {
			continue
		}
		loaded := all[0]
		// In the ordinary mode the interesting case is anonctl's own copy being outranked.
		// In host-owned mode anonctl HAS no copy, so the same walk answers a different and
		// equally silent question: the host declared one definition and a second one
		// (pre-0.4 residue, another package) outranks it, which means the file the operator
		// is maintaining is not the file that boots. Both are "two definitions, one wins,
		// nothing says so", so both are reported through this one report.
		ours := filepath.Join(s.unitDir(), name)
		if !own.HostOwned {
			if _, serr := os.Stat(ours); serr != nil {
				continue // not ours to be shadowed
			}
			if filepath.Clean(loaded) == filepath.Clean(ours) {
				continue
			}
		} else {
			ours = all[len(all)-1] // the outranked definition, whoever wrote it
		}
		out = append(out, ShadowedUnit{Name: name, Ours: ours, Loaded: loaded})
	}
	return out, nil
}

// PreflightUnitDirWritable checks that anonctl can write into its unit dir WITHOUT
// creating anything, so `add` can refuse while the box is still untouched.
//
// It matters in every mode, because the per-account enablement symlink is anonctl's
// in every mode: a host can own the unit FILES, but only anonctl writes
// `<target>.wants/anonctl-shim@<account>.service`, and without it the account's
// forcing does not come back after a reboot. Discovering that after the account is
// created and the live rules are applied would leave exactly the state this
// codebase preflights against: forcing that is live now and absent at the next boot.
//
// It walks up to the nearest EXISTING ancestor and asks for write permission there,
// because the dir itself may legitimately not exist yet (a first install). As root
// the mode bits are bypassed, so what this really catches is the case that matters
// on a declarative host: a read-only filesystem.
func (s Store) PreflightUnitDirWritable() error {
	dir := filepath.Clean(s.unitDir())
	probe := dir
	for {
		if _, err := os.Stat(probe); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("systemd: inspect unit dir %q: %w", probe, err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	if err := syscall.Access(probe, 2 /* W_OK */); err != nil {
		return fmt.Errorf("systemd: cannot write into %q (%q is not writable: %w). anonctl needs this directory even when the host owns the unit files, because the per-account enablement symlink that makes the account's forcing come back after a reboot is anonctl's own artifact and is written here. Point ANONCTL_UNIT_DIR at a writable directory that systemd reads, or make this one writable", dir, probe, err)
	}
	return nil
}
