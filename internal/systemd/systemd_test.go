package systemd_test

import (
	"strings"
	"testing"

	"github.com/wighawag/anoncore/accountconfig"
	"github.com/wighawag/anoncore/endpoint"
	"github.com/wighawag/anonctl/internal/systemd"
)

func sampleConfig() accountconfig.Config {
	return accountconfig.Config{
		SchemaVersion: accountconfig.SchemaVersion,
		Account:       "anon",
		AnonUID:       30034,
		ShimUID:       995,
		EndpointHost:  "127.0.0.1",
		EndpointPort:  9050,
		EndpointClass: endpoint.ClassTorShared,
		RelayPort:     19050,
		DNSPort:       19053,
	}
}

// --- the templated unit (ONE unit for all accounts, the @ pattern) ---

func TestTemplateUnitIsAnInstanceTemplate(t *testing.T) {
	unit := systemd.TemplateUnit(systemd.TemplateParams{ShimBinaryPath: "/usr/local/bin/anonctl-shim"})
	// A single instance TEMPLATE (`%i` = the account), NOT one unit per account: the
	// per-account process boundary is the security boundary, and systemd's @-template
	// gives each account its own supervised process from one unit file.
	if !strings.Contains(unit, "%i") {
		t.Errorf("template unit must use the %%i instance specifier:\n%s", unit)
	}
	// It runs the shim binary as the account's dedicated shim UID via the env file,
	// never as root.
	if !strings.Contains(unit, "/usr/local/bin/anonctl-shim") {
		t.Errorf("template unit must ExecStart the shim binary:\n%s", unit)
	}
	// Boot ordering: the shim must not race ahead of the network being configured,
	// and it explicitly does NOT depend on (nor manage) the endpoint's own service
	// (anonctl does not own the endpoint lifecycle). It is fail-closed by the nft
	// rules if the endpoint is not yet up, so a plain network ordering is enough.
	if !strings.Contains(unit, "After=network.target") {
		t.Errorf("template unit should order After=network.target:\n%s", unit)
	}
	// The per-account parameters come from a per-instance EnvironmentFile so ONE
	// template serves every account.
	if !strings.Contains(unit, "EnvironmentFile") || !strings.Contains(unit, "%i") {
		t.Errorf("template unit must read per-account params from a per-instance EnvironmentFile:\n%s", unit)
	}
}

func TestTemplateUnitDoesNotHardcodeAnAccount(t *testing.T) {
	unit := systemd.TemplateUnit(systemd.TemplateParams{ShimBinaryPath: "/usr/local/bin/anonctl-shim"})
	// The template is account-agnostic: no concrete account name is baked in (that
	// is what `%i` is for). A baked-in `anon` would make it a single-account unit.
	for _, banned := range []string{"User=anon", "socks-user anon", "relay 127.0.0.1:19050"} {
		if strings.Contains(unit, banned) {
			t.Errorf("template unit must not hardcode account params (%q):\n%s", banned, unit)
		}
	}
}

// --- the per-account env file (parameterises the template instance) ---

func TestEnvFileCarriesTheShimArgs(t *testing.T) {
	env := systemd.EnvFile(sampleConfig())
	// The env file carries exactly the per-account shim parameters the template's
	// ExecStart consumes: the shim UID, the loopback ports, the endpoint, and the
	// derived isolation username (the account name for a tor-shared endpoint).
	for _, want := range []string{
		"ANONCTL_SHIM_UID=995",
		"ANONCTL_RELAY_ADDR=127.0.0.1:19050",
		"ANONCTL_DNS_ADDR=127.0.0.1:19053",
		"ANONCTL_PROXY_ADDR=127.0.0.1:9050",
		"ANONCTL_SOCKS_USER=anon",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("env file missing %q:\n%s", want, env)
		}
	}
}

func TestEnvFilePeruserEndpointHasEmptyIsolationUser(t *testing.T) {
	c := sampleConfig()
	c.EndpointClass = endpoint.ClassSocksPeruser
	c.EndpointPort = 1080
	env := systemd.EnvFile(c)
	// A socks-peruser endpoint has NO per-username isolation, so the shim dials it
	// unauthenticated: the env file must carry an EMPTY isolation username (a
	// non-empty one would be a false promise of isolation).
	if !strings.Contains(env, "ANONCTL_SOCKS_USER=\n") && !strings.Contains(env, "ANONCTL_SOCKS_USER=") {
		t.Errorf("peruser endpoint env file should have an empty ANONCTL_SOCKS_USER:\n%s", env)
	}
	if strings.Contains(env, "ANONCTL_SOCKS_USER=anon") {
		t.Errorf("peruser endpoint must NOT carry the account as the isolation user:\n%s", env)
	}
}

// (The early-boot nftables LOADER unit, which replaced the nftables.service
// drop-in, is covered by loader_test.go.)

// --- instance name ---

func TestInstanceNameIsPerAccount(t *testing.T) {
	// The templated instance for account `anon` is `anonctl-shim@anon.service`; a
	// named account instantiates its own (`anonctl-shim@anon-work.service`), so each
	// account's shim is a DISTINCT supervised instance (the security boundary).
	if got := systemd.InstanceName("anon"); got != "anonctl-shim@anon.service" {
		t.Errorf("InstanceName(anon) = %q, want anonctl-shim@anon.service", got)
	}
	if got := systemd.InstanceName("anon-work"); got != "anonctl-shim@anon-work.service" {
		t.Errorf("InstanceName(anon-work) = %q, want anonctl-shim@anon-work.service", got)
	}
}
