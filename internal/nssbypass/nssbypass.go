// Package nssbypass detects the host configurations under which the anon
// account's NAME RESOLUTION happens in ANOTHER PROCESS under ANOTHER UID, where
// anonctl's per-UID forcing cannot reach it.
//
// THE PRINCIPLE, and why this package exists at all. anonctl forces egress with
// `meta skuid <anonUID>`, which matches a socket's OWNER. A rule that matches on
// socket ownership cannot see work done in another process. That is the same
// principle behind the v0.4.0 chain fix (a packet the kernel cannot attribute must
// never be adjudicated); this is that principle applied to NSS rather than to
// deferred kernel context.
//
// glibc's getaddrinfo does NOT always resolve in the calling process. Two shapes
// take it elsewhere, and BOTH are invisible to `meta skuid`:
//
//   - the nscd protocol: if an nscd-compatible socket exists, glibc asks it for
//     the `hosts` database BEFORE consulting nsswitch.conf at all. The daemon
//     (real nscd, or NixOS's nsncd) resolves in ITS process under ITS uid. This is
//     not visible anywhere in nsswitch.conf, which is why a detector that reads
//     only that file misses it entirely.
//   - a DELEGATING NSS module in the `hosts` line: nss-resolve hands the query to
//     systemd-resolved over varlink, nss-mdns to avahi-daemon, nss-mymachines to
//     systemd-machined, sss to sssd, winbind to winbindd. Each resolves in that
//     daemon's process under that daemon's uid.
//
// MEASURED CONSEQUENCE (work/notes/findings/dns-confinement-defeated-by-nss-delegation-and-reply-un-nat.md):
// on a NixOS host running nsncd, an anon account resolved a tailnet name that its
// own shim NXDOMAINs, instantly, with the host resolver's answer, while every
// nftables counter for the account's own sockets stayed at zero. The account's DNS
// was being done for it, by uid 998.
//
// WHAT THIS PACKAGE DOES NOT DO. It never "fixes" the host: forcing a system
// daemon's egress is not anonctl's business (the daemon serves every uid on the
// box, not just the account), and there is no per-uid override for
// /etc/nsswitch.conf or /etc/resolv.conf that a setup-and-verify manager could
// install without becoming a runtime wrapper. So the honest responses are to
// REFUSE (add) and to REPORT RED (verify), which is what anonctl does, with the
// per-host remedy named so the operator can act. See docs/adr/0011.
//
// The DETECTOR IS NOT THE AUTHORITY. `verify` measures the bypass directly (a
// unique name resolved as the anon UID while a counter watches the account's own
// sockets), and that measurement stands on its own. This package exists to make
// the refusal and the failure message ACTIONABLE by naming the daemon and the
// remedy, and to catch the case at `add` time BEFORE anything is provisioned.
// A host this package does not know about is caught by the measurement anyway.
package nssbypass

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Scope says how much of the namespace a provider can answer for, which is what
// separates a refusal from a noted residual.
type Scope int

const (
	// ScopeAllNames: the provider answers ARBITRARY hostnames, so every name the
	// account looks up can be resolved out-of-process. This is a leak of the whole
	// browsing history to the host's resolver, and it is what `add` refuses over.
	ScopeAllNames Scope = iota
	// ScopeNameClass: the provider answers only a bounded class of names (`.local`
	// via mDNS, machine names, libvirt guest names). Still out-of-process and still a
	// real leak for those names, but it cannot carry the account's general traffic,
	// so it is REPORTED as a residual rather than being a refusal on every desktop
	// that happens to run avahi.
	ScopeNameClass
)

// Provider is one detected out-of-process resolution path for the `hosts`
// database: what it is, how it was detected, and what the operator can do.
type Provider struct {
	// Name identifies the mechanism ("nscd/nsncd", "nss-resolve", ...).
	Name string
	// Daemon is the process that does the resolving, and whose uid owns the socket
	// that `meta skuid` cannot match.
	Daemon string
	// Scope is how much of the namespace it can answer for.
	Scope Scope
	// Evidence is what was actually observed on this host (a socket path, an
	// nsswitch entry), so the operator can check the claim rather than trust it.
	Evidence string
	// Remedy is the concrete change that removes this bypass, host-specific where
	// that matters. It never promises anonctl will do it.
	Remedy string
}

// Broad reports whether the provider can answer arbitrary hostnames (ScopeAllNames).
func (p Provider) Broad() bool { return p.Scope == ScopeAllNames }

// delegatingModules maps an nsswitch `hosts` module to the daemon it delegates to.
// Only modules that resolve OUT OF PROCESS belong here. `files`, `dns` and
// `myhostname` resolve IN the calling process (the account's own socket, which
// `meta skuid` governs correctly) and are deliberately absent; `nis` likewise
// talks to its server from the calling process. Every entry is a module that hands
// the query to a local daemon over a socket the account does not own.
var delegatingModules = []struct {
	// match is the module name; prefix is true when any module STARTING with it
	// delegates (the mdns family ships as mdns, mdns4, mdns6, mdns4_minimal, ...).
	match  string
	prefix bool
	p      Provider
}{
	{match: "resolve", p: Provider{
		Name:   "nss-resolve",
		Daemon: "systemd-resolved",
		Scope:  ScopeAllNames,
		Remedy: "remove `resolve` from the hosts line in /etc/nsswitch.conf so glibc queries the stub resolver (127.0.0.53) on the ACCOUNT's own socket, which the forcing does govern",
	}},
	{match: "sss", p: Provider{
		Name:   "nss-sss",
		Daemon: "sssd",
		Scope:  ScopeAllNames,
		Remedy: "remove `sss` from the hosts line in /etc/nsswitch.conf (it is normally there for users/groups, not hosts)",
	}},
	{match: "winbind", p: Provider{
		Name:   "nss-winbind",
		Daemon: "winbindd",
		Scope:  ScopeAllNames,
		Remedy: "remove `winbind` from the hosts line in /etc/nsswitch.conf",
	}},
	{match: "mdns", prefix: true, p: Provider{
		Name:   "nss-mdns",
		Daemon: "avahi-daemon",
		Scope:  ScopeNameClass,
		Remedy: "remove the mdns* entries from the hosts line in /etc/nsswitch.conf if the account must not resolve .local names off-path",
	}},
	{match: "mymachines", p: Provider{
		Name:   "nss-mymachines",
		Daemon: "systemd-machined",
		Scope:  ScopeNameClass,
		Remedy: "remove `mymachines` from the hosts line in /etc/nsswitch.conf if the account must not resolve container/machine names off-path",
	}},
	{match: "libvirt", prefix: true, p: Provider{
		Name:   "nss-libvirt",
		Daemon: "libvirtd",
		Scope:  ScopeNameClass,
		Remedy: "remove the libvirt* entries from the hosts line in /etc/nsswitch.conf if the account must not resolve guest names off-path",
	}},
}

// NSCDSocketPaths are the nscd-protocol socket paths glibc tries. Both spellings
// are checked because /var/run is a symlink to /run on most hosts but not all, and
// a missed socket here is a missed leak.
var NSCDSocketPaths = []string{"/var/run/nscd/socket", "/run/nscd/socket"}

// Detect is the PURE decision: given the nsswitch `hosts` line and the path of an
// nscd-compatible socket that EXISTS (empty when none does), it returns every
// out-of-process resolution path, broad ones first so the caller's message leads
// with the one that matters.
//
// The nscd socket is reported FIRST and independently of the hosts line, because
// glibc consults it BEFORE nsswitch: a host can have a perfectly innocent-looking
// `hosts: files dns` and still resolve every name in another process.
func Detect(hostsLine string, nscdSocket string) []Provider {
	var broad, narrow []Provider
	if nscdSocket != "" {
		broad = append(broad, Provider{
			Name:   "nscd/nsncd",
			Daemon: "the nscd-protocol daemon owning " + nscdSocket,
			Scope:  ScopeAllNames,
			Evidence: "the nscd-compatible socket " + nscdSocket + " exists, so glibc asks it for the `hosts` database BEFORE consulting nsswitch.conf; " +
				"the lookup then runs in that daemon's process, under its uid, on sockets `meta skuid` cannot match",
			Remedy: "make the daemon refuse HOSTS requests, so glibc resolves in the calling process on the account's own socket: " +
				"nsncd (the NixOS default since 23.05), set `NSNCD_IGNORE_HOSTS=true` in its environment " +
				"(`systemd.services.nscd.environment.NSNCD_IGNORE_HOSTS = \"true\";`), which keeps passwd/group service intact; " +
				"real nscd, `enable-cache hosts no` in /etc/nscd.conf. Measured: with hosts ignored, glibc falls back to in-process resolution rather than failing",
		})
	}
	// One provider per DAEMON, not per entry: the mdns family alone routinely appears
	// twice on one hosts line (mdns4_minimal early, mdns4 last), and reporting
	// avahi-daemon twice would make a refusal message look like two separate leaks.
	seen := map[string]bool{}
	for _, field := range parseHostsModules(hostsLine) {
		for _, d := range delegatingModules {
			hit := field == d.match
			if d.prefix {
				hit = strings.HasPrefix(field, d.match)
			}
			if !hit {
				continue
			}
			if seen[d.p.Name] {
				break
			}
			seen[d.p.Name] = true
			p := d.p
			p.Evidence = "the nsswitch.conf hosts line lists `" + field + "`, which resolves via " + p.Daemon + " (another process, another uid)"
			if p.Broad() {
				broad = append(broad, p)
			} else {
				narrow = append(narrow, p)
			}
			break
		}
	}
	return append(broad, narrow...)
}

// parseHostsModules splits an nsswitch `hosts:` line into its module names,
// dropping the leading `hosts:` key and the `[STATUS=action]` reaction brackets
// (which are not modules). It tolerates the whole line or just the value.
func parseHostsModules(line string) []string {
	line = strings.TrimSpace(line)
	if i := strings.Index(line, ":"); i >= 0 && strings.HasPrefix(strings.ToLower(line), "hosts") {
		line = line[i+1:]
	}
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	var mods []string
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "[") || strings.HasSuffix(f, "]") {
			continue // a [NOTFOUND=return] style reaction, not a module
		}
		mods = append(mods, strings.ToLower(f))
	}
	return mods
}

// nsswitchPath is the file Inspect reads; a package var so the unit suite can
// point it at a fixture without a real /etc.
var nsswitchPath = "/etc/nsswitch.conf"

// socketPaths is the nscd socket candidate list Inspect stats; a package var for
// the same reason.
var socketPaths = NSCDSocketPaths

// Inspect reads this host and returns every out-of-process resolution path for the
// `hosts` database.
//
// A MISSING or unreadable /etc/nsswitch.conf is NOT an error and NOT a clean
// result: the nscd socket check still runs, and the caller is told what could not
// be read via the returned error, so "we could not look" is never rendered as
// "nothing found". That distinction is the same one the rest of the tool makes
// everywhere: a check that could not run is not a pass.
func Inspect() ([]Provider, error) {
	var socket string
	for _, p := range socketPaths {
		if _, err := os.Stat(p); err == nil {
			socket = p
			break
		}
	}
	hostsLine, err := readHostsLine(nsswitchPath)
	providers := Detect(hostsLine, socket)
	if err != nil {
		return providers, fmt.Errorf("could not read %s (the nsswitch hosts line was NOT checked; the nscd socket check still ran): %w", nsswitchPath, err)
	}
	return providers, nil
}

// readHostsLine returns the `hosts:` line of an nsswitch.conf, or "" when the file
// has none.
func readHostsLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(strings.ToLower(line), "hosts:") {
			return line, nil
		}
	}
	return "", sc.Err()
}

// Broad returns only the providers that can answer ARBITRARY hostnames: the set
// `add` refuses over and `verify` fails over.
func Broad(providers []Provider) []Provider {
	var out []Provider
	for _, p := range providers {
		if p.Broad() {
			out = append(out, p)
		}
	}
	return out
}

// Narrow returns the bounded-namespace providers: reported as a residual, never a
// refusal (see Scope).
func Narrow(providers []Provider) []Provider {
	var out []Provider
	for _, p := range providers {
		if !p.Broad() {
			out = append(out, p)
		}
	}
	return out
}

// Names renders a provider list as a compact "name (daemon)" summary for a
// one-line assertion detail.
func Names(providers []Provider) string {
	parts := make([]string, 0, len(providers))
	for _, p := range providers {
		parts = append(parts, p.Name+" via "+p.Daemon)
	}
	return strings.Join(parts, ", ")
}

// Explain renders the full multi-line operator-facing explanation: what was found,
// why it defeats per-UID forcing, and the per-provider remedy. It is used verbatim
// by `add`'s refusal so the operator is never left with a refusal they cannot act
// on.
func Explain(providers []Provider) string {
	var b strings.Builder
	for _, p := range providers {
		fmt.Fprintf(&b, "  - %s (%s): %s\n", p.Name, p.Daemon, p.Evidence)
		fmt.Fprintf(&b, "    remedy: %s\n", p.Remedy)
	}
	return b.String()
}
