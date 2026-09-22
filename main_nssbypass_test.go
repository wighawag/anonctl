package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/anonctl/internal/nssbypass"
)

// `add`'s DNS-confinement gate. The rule it enforces is the one thing the tool
// cannot enforce with a rule: anonctl forces egress by socket OWNER, so when the
// host's glibc resolves `hosts` in another process under another uid, the
// account's name resolution is outside anonctl's reach entirely. The honest
// responses are to refuse and to report red, and both are proven here.

// broadHost is a host whose resolution is done by an nscd-protocol daemon: the
// measured NixOS/nsncd case.
func broadHost() []nssbypass.Provider {
	return []nssbypass.Provider{{
		Name: "nscd/nsncd", Daemon: "nsncd", Scope: nssbypass.ScopeAllNames,
		Evidence: "the socket /var/run/nscd/socket exists",
		Remedy:   "turn the hosts cache off",
	}}
}

// THE REFUSAL, and it must happen BEFORE anything on the box is touched: refusing
// later would leave an account that exists, is jailed, and leaks its DNS.
func TestAddRefusesAHostThatResolvesOutOfProcess(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	defer swapNSSBypassInspector(broadHost(), nil)()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	var code int
	// The refusal is an ERROR, so it goes to stderr like every other `add` refusal.
	out := captureStderrDuring(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code == 0 {
		t.Fatalf("add on a host that resolves out of process must REFUSE; got exit 0")
	}
	if len(r.created) != 0 {
		t.Errorf("the refusal must come BEFORE provisioning; accounts were created: %v", r.created)
	}
	if len(install.calls) != 0 {
		t.Errorf("no forcing may be installed on a refusal; got %+v", install.calls)
	}
	// The refusal has to be actionable: name the daemon, the evidence and a remedy.
	for _, want := range []string{"nsncd", "/var/run/nscd/socket", "remedy:", "--allow-nss-bypass"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal must mention %q; got:\n%s", want, out)
		}
	}
}

// The escape hatch proceeds, and says plainly what the operator is accepting. It
// must NOT promise a green verify: the measurement keeps failing while the bypass
// is real, which is the whole point of the change.
func TestAddAllowNSSBypassProceedsButStatesTheExposure(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	defer swapNSSBypassInspector(broadHost(), nil)()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "--allow-nss-bypass", "01"}))
	})
	if code != 0 {
		t.Fatalf("--allow-nss-bypass must proceed; got exit %d\n%s", code, out)
	}
	if len(install.calls) != 1 {
		t.Errorf("the forcing must still be installed under the escape hatch; got %+v", install.calls)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "attributable to you") {
		t.Errorf("the escape hatch must state the exposure; got:\n%s", out)
	}
	// The flag must state the FULL price, not just the red assertion: `use`/`exec`
	// gate on a green verify and the marker needs one too, so consenting to the leak
	// buys the forcing and nothing else. An operator who discovers that from
	// behaviour instead of from this message was misled by it.
	for _, want := range []string{
		"dns-nss-not-bypassed RED",
		"REFUSE to open a session",
		"sudo -iu anon-01",
		"marker",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the escape hatch must disclose %q; got:\n%s", want, out)
		}
	}
}

// A bounded-namespace provider (avahi answers .local, machined answers machine
// names) cannot carry the account's general traffic, so refusing on it would
// refuse on most Linux desktops for a narrow leak. It warns and proceeds.
func TestAddWarnsButProceedsForANarrowProvider(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	defer swapNSSBypassInspector([]nssbypass.Provider{{
		Name: "nss-mdns", Daemon: "avahi-daemon", Scope: nssbypass.ScopeNameClass,
	}}, nil)()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("a narrow provider must not refuse the add; got exit %d\n%s", code, out)
	}
	if len(install.calls) != 1 {
		t.Errorf("the forcing must be installed; got %+v", install.calls)
	}
	if !strings.Contains(out, "avahi-daemon") || !strings.Contains(out, "NOTE") {
		t.Errorf("a narrow provider must still be disclosed; got:\n%s", out)
	}
}

// A detector that could not READ the host must warn, never pass silently: a check
// that could not run is not a pass, and here that distinction decides whether the
// operator is told their box may leak.
func TestAddWarnsWhenTheHostCouldNotBeInspected(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	defer swapNSSBypassInspector(nil, errors.New("could not read /etc/nsswitch.conf (the nsswitch hosts line was NOT checked)"))()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("an unreadable host must not block the add by itself; got exit %d", code)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "NOT checked") {
		t.Errorf("an unreadable host must be disclosed, never silently treated as clean; got:\n%s", out)
	}
}

// THE FALSE REFUSAL THE LIVE RUN CAUGHT. The detector reports an nscd-compatible
// socket as a broad provider, because glibc consults such a socket before
// nsswitch.conf. That is the right default reading, and it is what found the
// original leak. But the socket's EXISTENCE does not prove the daemon serves
// hosts: nsncd with NSNCD_IGNORE_HOSTS=true keeps its socket (it still serves
// passwd and group) while refusing hosts, which is the remedy anonctl itself
// recommends. Refusing on the detector alone therefore refuses exactly the
// operator who has just done what the docs told them, with a message telling them
// to do it again. Measured on telemaque after the remedy landed: detector still
// reports nscd/nsncd, and the account's lookups demonstrably use its own sockets.
func TestAddProceedsWhenTheMeasurementShowsInProcessResolution(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	install := swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	defer swapNSSBypassInspector(broadHost(), nil)()
	defer swapHostResolutionMeasurement(true, true, "a lookup of probe.invalid. put a DNS query on this process's own socket")()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("a host whose MEASUREMENT shows in-process resolution must NOT be refused; got exit %d\n%s", code, out)
	}
	if len(install.calls) != 1 {
		t.Errorf("the forcing must be installed; got %+v", install.calls)
	}
	// It must still disclose that the daemon is there, and say why it proceeded.
	if !strings.Contains(out, "nsncd") || !strings.Contains(out, "own socket") {
		t.Errorf("the note must name the daemon and the measurement that overrode it; got:\n%s", out)
	}
}

// When the question cannot be answered here (no root, no nft, or another process
// emitting DNS during the control window), proceed with a loud warning rather than
// refuse: `add` runs `verify` inline moments later and measures it per-account, so
// a wrong guess this way is caught in seconds and reported red, while a wrong
// refusal leaves a correct operator with no route except a flag that costs them
// `use`/`exec` and the marker.
func TestAddProceedsLoudlyWhenTheHostCannotBeMeasured(t *testing.T) {
	disableColorForTest(t)
	swapSeedSeams(t, t.TempDir())
	store := swapConfigStore(t)
	swapAddSeams(t, store)
	swapProvisionSeams(t)
	fakeUnitBinariesOnPath(t)
	defer swapNSSBypassInspector(broadHost(), nil)()
	defer swapHostResolutionMeasurement(false, false, "nft is not on PATH, so the host's resolution path could not be measured")()

	r := &createOnUseraddRunner{
		declaredFakeRunner: declaredFakeRunner{uids: map[string]int{}},
		allocate:           map[string]int{"anon-01": 1002, "anon-01-shim": 992},
	}
	var code int
	out := captureStdout(t, func() {
		code = runAdd(context.Background(), r,
			mustParse(t, []string{"add", "--endpoint", "socks5h://127.0.0.1:9050", "01"}))
	})
	if code != 0 {
		t.Fatalf("an unmeasurable host must not be refused on the detector alone; got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "could not be measured") {
		t.Errorf("it must say loudly that the question was not answered; got:\n%s", out)
	}
	if !strings.Contains(out, "will measure it for real") {
		t.Errorf("it must point at the inline verify that backstops this; got:\n%s", out)
	}
}
