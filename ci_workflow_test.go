package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The CI workflow (.github/workflows/ci.yml) is the unit gate that runs on every
// push/PR. Its gate command MUST be the repo's single source of truth: the exact
// `.dorfl.json` verify string (gofmt check + go vet + go build + go test, unit
// only). These tests pin that contract so the workflow cannot silently drift from
// the acceptance gate a human/runner drives locally.

// dorflVerify reads the verify command out of .dorfl.json (the single source of
// truth for the acceptance gate).
func dorflVerify(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(".dorfl.json")
	if err != nil {
		t.Fatalf("read .dorfl.json: %v", err)
	}
	var cfg struct {
		Verify string `json:"verify"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .dorfl.json: %v", err)
	}
	if cfg.Verify == "" {
		t.Fatal(".dorfl.json has an empty verify command")
	}
	return cfg.Verify
}

// ciWorkflow reads the CI workflow file.
func ciWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read .github/workflows/ci.yml: %v", err)
	}
	return string(raw)
}

// The CI workflow must run the EXACT `.dorfl.json` verify command verbatim, so
// the push/PR gate and the local acceptance gate can never diverge (criterion:
// single source of truth). If .dorfl.json changes its verify, this test forces
// ci.yml to be updated too.
func TestCIRunsExactDorflVerifyGate(t *testing.T) {
	verify := dorflVerify(t)
	wf := ciWorkflow(t)
	if !strings.Contains(wf, verify) {
		t.Errorf("ci.yml does not run the exact .dorfl.json verify gate.\nwant to find verbatim:\n\t%s\nin the workflow", verify)
	}
}

// The CI workflow must trigger on push AND pull_request (every push/PR runs the
// unit gate and fails on a regression) and set up Go 1.26.
func TestCITriggersAndGoVersion(t *testing.T) {
	wf := ciWorkflow(t)
	for _, want := range []string{"push:", "pull_request:", "1.26"} {
		if !strings.Contains(wf, want) {
			t.Errorf("ci.yml missing %q (push/PR trigger + Go 1.26 setup)", want)
		}
	}
}

// The CI workflow must honestly document the integration gap: the integration
// suite is behind `-tags integration`, needs a capable host (root + nftables +
// live endpoint + systemd-PID1), and is deliberately NOT run in GitHub CI.
func TestCIDocumentsIntegrationGap(t *testing.T) {
	wf := strings.ToLower(ciWorkflow(t))
	for _, want := range []string{"integration", "nftables", "systemd"} {
		if !strings.Contains(wf, want) {
			t.Errorf("ci.yml must document the integration gap; missing mention of %q", want)
		}
	}
	if !strings.Contains(wf, "-tags integration") {
		t.Error("ci.yml must name the `-tags integration` build tag the integration suite lives behind")
	}
}
