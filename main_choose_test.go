package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wighawag/anoncore/endpoint"
)

// swapScanSeams installs fake scan/TTY/prompt seams for the endpoint-choice flow
// and restores them on cleanup. offers is the scripted scan result; tty forces the
// interactive/non-interactive branch; input is the scripted prompt line. It returns
// the buffer the menu is rendered into so a test can assert the annotation text.
func swapScanSeams(t *testing.T, offers []endpoint.Endpoint, tty bool, input string) *bytes.Buffer {
	t.Helper()
	origScan, origTTY, origIn, origOut := endpointScan, stdinIsTTY, promptReader, promptWriter
	endpointScan = func() []endpoint.Endpoint { return offers }
	stdinIsTTY = func() bool { return tty }
	promptReader = strings.NewReader(input)
	var out bytes.Buffer
	promptWriter = &out
	t.Cleanup(func() {
		endpointScan, stdinIsTTY, promptReader, promptWriter = origScan, origTTY, origIn, origOut
	})
	return &out
}

func offerEp(port string, class endpoint.ShareClass) endpoint.Endpoint {
	return endpoint.Endpoint{Host: "127.0.0.1", Port: port, Class: class}
}

// Non-interactive with a confirmed Tor endpoint: pick it, no prompt.
func TestChooseEndpointNonInteractivePicksTor(t *testing.T) {
	swapScanSeams(t, []endpoint.Endpoint{offerEp("9050", endpoint.ClassTorShared)}, false, "")
	swapConfigListStore(t) // empty claim set
	got, err := chooseEndpointInteractive(context.Background(), "anon", "add")
	if err != nil {
		t.Fatalf("chooseEndpointForAdd: %v", err)
	}
	if got.Port != "9050" {
		t.Errorf("chose %s, want the Tor default 9050", got.URL())
	}
}

// Non-interactive with NO confirmed Tor (only a peruser, or nothing): FAIL CLOSED,
// never silently configure a dead default.
func TestChooseEndpointNonInteractiveFailsClosed(t *testing.T) {
	swapScanSeams(t, []endpoint.Endpoint{offerEp("1080", endpoint.ClassSocksPeruser)}, false, "")
	swapConfigListStore(t)
	if _, err := chooseEndpointInteractive(context.Background(), "anon", "add"); !errors.Is(err, endpoint.ErrNoEndpointConfirmed) {
		t.Errorf("non-interactive add with no Tor = %v, want ErrNoEndpointConfirmed", err)
	}
}

// The non-interactive refusal names the CALLING verb, so an `update` that cannot
// choose points the operator at `anonctl update` (not `add`) to re-run interactively.
// This is the shared chooser now serving both add and update/reconfigure.
func TestChooseEndpointNonInteractiveRefusalNamesVerb(t *testing.T) {
	swapScanSeams(t, []endpoint.Endpoint{offerEp("1080", endpoint.ClassSocksPeruser)}, false, "")
	swapConfigListStore(t)
	_, err := chooseEndpointInteractive(context.Background(), "anon", "update")
	if err == nil {
		t.Fatalf("expected a fail-closed error for update with no Tor")
	}
	if !strings.Contains(err.Error(), "anonctl update") {
		t.Errorf("the non-interactive refusal must name the calling verb (`anonctl update`); got %q", err.Error())
	}
}

// Interactive, empty enter accepts the Tor default.
func TestChooseEndpointInteractiveDefaultOnEnter(t *testing.T) {
	swapScanSeams(t, []endpoint.Endpoint{
		offerEp("9050", endpoint.ClassTorShared),
		offerEp("1080", endpoint.ClassSocksPeruser),
	}, true, "\n")
	swapConfigListStore(t)
	got, err := chooseEndpointInteractive(context.Background(), "anon", "add")
	if err != nil {
		t.Fatalf("chooseEndpointForAdd: %v", err)
	}
	if got.Port != "9050" {
		t.Errorf("empty enter chose %s, want the Tor default 9050", got.URL())
	}
}

// Interactive, a number selects that offer.
func TestChooseEndpointInteractiveNumberPick(t *testing.T) {
	swapScanSeams(t, []endpoint.Endpoint{
		offerEp("9050", endpoint.ClassTorShared),
		offerEp("1080", endpoint.ClassSocksPeruser),
	}, true, "2\n")
	swapConfigListStore(t)
	got, err := chooseEndpointInteractive(context.Background(), "anon", "add")
	if err != nil {
		t.Fatalf("chooseEndpointForAdd: %v", err)
	}
	if got.Port != "1080" {
		t.Errorf("pick 2 chose %s, want 1080", got.URL())
	}
}

// Interactive, a typed socks5h endpoint is parsed like an explicit --endpoint.
func TestChooseEndpointInteractiveTyped(t *testing.T) {
	swapScanSeams(t, nil, true, "socks5h://127.0.0.1:1234\n")
	swapConfigListStore(t)
	got, err := chooseEndpointInteractive(context.Background(), "anon", "add")
	if err != nil {
		t.Fatalf("chooseEndpointForAdd: %v", err)
	}
	if got.Port != "1234" {
		t.Errorf("typed endpoint chose %s, want 1234", got.URL())
	}
}

// The menu annotates a peruser endpoint already in use by another account, and a
// pick of it is refused.
func TestChooseEndpointAnnotatesAndRefusesTaken(t *testing.T) {
	out := swapScanSeams(t, []endpoint.Endpoint{
		offerEp("9050", endpoint.ClassTorShared),
		offerEp("1080", endpoint.ClassSocksPeruser),
	}, true, "2\n")
	s := swapConfigListStore(t)
	writeConfig(t, s, "anon-a", 1080, endpoint.ClassSocksPeruser) // 1080 taken by anon-a

	_, err := chooseEndpointInteractive(context.Background(), "anon-new", "add")
	if err == nil {
		t.Errorf("picking a taken peruser endpoint must be refused")
	}
	if !strings.Contains(out.String(), "IN USE") || !strings.Contains(out.String(), "anon-a") {
		t.Errorf("menu did not annotate the taken endpoint; got:\n%s", out.String())
	}
}
