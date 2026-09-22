package nssbypass

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE CASE THIS PACKAGE WAS WRITTEN FOR, taken verbatim from the measured host: an
// nscd-compatible socket exists, so glibc asks it for `hosts` BEFORE nsswitch.conf
// is consulted at all. Nothing in the hosts line hints at it, which is exactly why
// a detector that reads only nsswitch.conf misses the whole leak.
func TestDetect_NscdSocketIsFoundEvenWithAnInnocentHostsLine(t *testing.T) {
	got := Detect("hosts: files dns", "/var/run/nscd/socket")
	if len(got) != 1 {
		t.Fatalf("the nscd socket must be detected on its own; got %+v", got)
	}
	if !got[0].Broad() {
		t.Errorf("an nscd-protocol daemon answers ARBITRARY names, so it must be broad; got %+v", got[0])
	}
	if !strings.Contains(got[0].Evidence, "/var/run/nscd/socket") {
		t.Errorf("the evidence must name the socket the operator can go and look at; got %q", got[0].Evidence)
	}
	if !strings.Contains(got[0].Evidence, "BEFORE consulting nsswitch.conf") {
		t.Errorf("the evidence must state WHY nsswitch.conf does not reveal it; got %q", got[0].Evidence)
	}
	if got[0].Remedy == "" {
		t.Errorf("a refusal the operator cannot act on is not acceptable: every provider needs a remedy")
	}
}

// The measured host's real hosts line, which carries a narrow provider (mdns) and
// a machine-name provider alongside the socket. The broad one must lead, since it
// is the one that decides the refusal.
func TestDetect_OrdersBroadProvidersFirst(t *testing.T) {
	got := Detect("hosts:     mymachines mdns4_minimal [NOTFOUND=return] files myhostname dns mdns4", "/var/run/nscd/socket")
	if len(got) < 2 {
		t.Fatalf("expected the socket plus the delegating modules; got %+v", got)
	}
	if !got[0].Broad() {
		t.Fatalf("the broad provider must come first; got %+v", got)
	}
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"nscd/nsncd", "nss-mymachines", "nss-mdns"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %s among the detected providers; got %s", want, joined)
		}
	}
	// mdns appears TWICE on that line (mdns4_minimal and mdns4); it is one provider.
	if strings.Count(joined, "nss-mdns") != 1 {
		t.Errorf("the mdns family must be reported once, not per entry; got %s", joined)
	}
}

// The stock systemd desktop configuration is the case that makes this a general
// defect rather than a NixOS quirk: nss-resolve hands getaddrinfo to
// systemd-resolved over varlink, under that daemon's uid, on Debian, Ubuntu and
// Fedora out of the box.
func TestDetect_SystemdResolvedIsBroad(t *testing.T) {
	got := Detect("hosts: files resolve [!UNAVAIL=return] myhostname dns", "")
	if len(Broad(got)) != 1 || got[0].Name != "nss-resolve" {
		t.Fatalf("nss-resolve must be detected as a broad provider; got %+v", got)
	}
	if !strings.Contains(got[0].Remedy, "nsswitch.conf") {
		t.Errorf("the remedy must be concrete; got %q", got[0].Remedy)
	}
}

// IN-PROCESS modules must never be reported. `files`, `dns` and `myhostname`
// resolve on the CALLING process's own socket, which is precisely the path
// `meta skuid` governs correctly: reporting them would make the tool refuse on
// every host on earth.
func TestDetect_InProcessModulesAreNotBypasses(t *testing.T) {
	if got := Detect("hosts: files dns myhostname", ""); len(got) != 0 {
		t.Fatalf("a fully in-process hosts line is NOT a bypass; got %+v", got)
	}
	// A reaction bracket is not a module and must never be matched as one.
	if got := Detect("hosts: files [!UNAVAIL=return] dns", ""); len(got) != 0 {
		t.Fatalf("[STATUS=action] brackets are not modules; got %+v", got)
	}
}

func TestDetect_ScopeSeparatesRefusalFromResidual(t *testing.T) {
	got := Detect("hosts: files mdns4_minimal mymachines libvirt dns", "")
	if len(Broad(got)) != 0 {
		t.Fatalf("none of these can answer arbitrary names, so none may force a refusal; got %+v", Broad(got))
	}
	if len(Narrow(got)) != 3 {
		t.Fatalf("expected three bounded-namespace providers; got %+v", Narrow(got))
	}
}

// Inspect must never render "could not look" as "nothing found": the nscd check
// still runs, and the error says plainly which half was not checked.
func TestInspect_UnreadableNsswitchIsAnErrorNotACleanResult(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "socket")
	if err := os.WriteFile(socket, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer swapPaths(filepath.Join(dir, "nsswitch-does-not-exist"), []string{socket})()

	got, err := Inspect()
	if err == nil {
		t.Fatalf("an unreadable nsswitch.conf must be reported, not swallowed")
	}
	if !strings.Contains(err.Error(), "NOT checked") {
		t.Errorf("the error must say which half was not checked; got %v", err)
	}
	if len(got) != 1 || got[0].Name != "nscd/nsncd" {
		t.Fatalf("the nscd check must still have run; got %+v", got)
	}
}

func TestInspect_ReadsTheHostsLineFromTheFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(conf, []byte("passwd: files\n# a comment\nhosts:  files resolve dns\nnetworks: files\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer swapPaths(conf, []string{filepath.Join(dir, "no-socket-here")})()

	got, err := Inspect()
	if err != nil {
		t.Fatalf("a readable nsswitch.conf must not error: %v", err)
	}
	if len(got) != 1 || got[0].Name != "nss-resolve" {
		t.Fatalf("expected nss-resolve from the hosts line; got %+v", got)
	}
	if Explain(got) == "" || !strings.Contains(Explain(got), "remedy:") {
		t.Errorf("Explain must carry the remedy so a refusal is actionable; got %q", Explain(got))
	}
}

// swapPaths points the package's file seams at a fixture and returns the restore.
func swapPaths(nsswitch string, sockets []string) func() {
	origConf, origSockets := nsswitchPath, socketPaths
	nsswitchPath, socketPaths = nsswitch, sockets
	return func() { nsswitchPath, socketPaths = origConf, origSockets }
}
