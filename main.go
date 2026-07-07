// Command anonctl provisions a dedicated Unix account (`anon` by default,
// `anon-<name>` for named ones) plus its own dedicated shim service account, and
// (in later tasks) forces all of that account's egress through an anonymizer at
// the kernel level, fail-closed. This entry point wires the PURE CLI surface
// (internal/cli: verb dispatch + account-name resolution) to the provisioning
// engine (internal/provision) behind the Runner seam, so the four verbs
// (add/rm/list/status) work end-to-end while verify/update/reconfigure dispatch
// as stubs later tasks fill.
//
// This task delivers the account + shim-UID lifecycle only: NO egress forcing
// (that is the nftables/persistence tasks). Provisioning mutates the system as
// root (the ufw stance), so add/rm require privilege; list/status are read-only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/wighawag/anonctl/internal/accountconfig"
	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/forcing"
	"github.com/wighawag/anonctl/internal/marker"
	"github.com/wighawag/anonctl/internal/nftables"
	"github.com/wighawag/anonctl/internal/provision"
	"github.com/wighawag/anonctl/internal/systemd"
	"github.com/wighawag/anonctl/internal/verify"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// `anonctl --version` / `anonctl version` prints and exits before any parse.
	if isVersionArg(args) {
		fmt.Println("anonctl " + resolveVersion())
		return 0
	}

	cmd, err := cli.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %v\n", err)
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	// SIGINT/SIGTERM cancels the context that flows into provisioning, so a
	// long-running useradd is interruptible cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := provision.ExecRunner{}
	switch cmd.Verb {
	case "add":
		return runAdd(ctx, runner, cmd)
	case "rm":
		return runRm(ctx, runner, cmd)
	case "list":
		return runList(ctx, runner, cmd)
	case "status":
		return runStatus(ctx, runner, cmd)
	case "verify":
		return runVerify(ctx, runner, cmd)
	case "update", "reconfigure":
		return runUpdate(ctx, runner, cmd)
	default:
		fmt.Fprintf(os.Stderr, "anonctl: unknown verb %q\n%s\n", cmd.Verb, usage)
		return 2
	}
}

// runAdd provisions the account + its dedicated shim UID, then INSTALLS the forcing
// (nft rules + the persisted systemd shim unit + the nftables.service drop-in), so
// the account is anonymized live AND across a reboot fail-closed. It must run as
// root (useradd/nft/systemctl); a non-root run surfaces the underlying command's
// own permission error. Provisioning is idempotent and the forcing install is an
// atomic replace, so re-running `add` cleanly re-applies.
func runAdd(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	res, err := provision.Add(ctx, r, cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: %v\n", err)
		return 1
	}

	// Build the at-rest config from the just-provisioned UIDs and the chosen
	// endpoint (default Tor SocksPort when none named), then install the forcing.
	cfg, err := buildConfig(ctx, r, cmd.Account, cmd.Endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: %v\n", err)
		return 1
	}
	if err := forcing.Install(ctx, forcingDeps(), cfg, nil); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: installing forcing: %v\n", err)
		return 1
	}

	if res.Created {
		fmt.Printf("provisioned + forced %s (shim %s, endpoint %s)\n", res.Account, res.Shim, cfg.Endpoint().URL())
	} else {
		fmt.Printf("%s already existed; re-applied forcing (shim %s, endpoint %s)\n", res.Account, res.Shim, cfg.Endpoint().URL())
	}
	fmt.Printf("note: anonctl does NOT manage the endpoint's own service; enable your endpoint (e.g. `systemctl enable --now tor.service`) so it is up at boot\n")
	fmt.Printf("run `anonctl verify %s` to prove the account is anonymized\n", accountArg(cmd.Account))
	return 0
}

// runRm removes the account's forcing hooks and, only under --purge-account,
// deletes the account + its shim. A bare rm leaves the home intact. It ALSO
// removes the marker (the double-anonymization claim): teardown must not leave a
// stale `/etc/anonctl/<account>.json` asserting an account is still forced.
func runRm(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	res, err := provision.Rm(ctx, r, cmd.Account, cmd.PurgeAccount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: rm: %v\n", err)
		return 1
	}
	// Remove the forcing (disable the shim, delete the account's nft table, and the
	// persisted env/rule files + at-rest config) BEFORE the marker, so a torn-down
	// account leaves no live forcing and no stale persisted state.
	if err := forcing.Remove(ctx, forcingDeps(), cmd.Account); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: rm: removing forcing: %v\n", err)
		return 1
	}
	// Remove the marker (idempotent: a missing marker is a clean no-op), so a
	// torn-down account never leaves a stale "already forced" claim behind.
	if err := marker.DefaultStore().Remove(cmd.Account); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: rm: removing marker: %v\n", err)
		return 1
	}
	switch {
	case res.AccountRemoved:
		fmt.Printf("removed %s and its shim %s\n", res.Account, res.Shim)
	case cmd.PurgeAccount:
		fmt.Printf("%s did not exist; nothing to remove\n", res.Account)
	default:
		fmt.Printf("removed forcing for %s; account left intact (pass --purge-account to delete it)\n", res.Account)
	}
	return 0
}

// runList enumerates the anon accounts that exist on the box, reading the real
// passwd table (not a maintained index). Read-only: no root needed.
func runList(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	accounts, err := provision.List(ctx, r, provision.ReadPasswd(ctx, r))
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: list: %v\n", err)
		return 1
	}
	if cmd.JSON {
		return emitJSON(accounts)
	}
	if len(accounts) == 0 {
		fmt.Println("no anon accounts")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tUID\tSHIM\tSHIM-UID")
	for _, a := range accounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Account, a.UID, a.Shim, a.ShimUID)
	}
	tw.Flush()
	return 0
}

// runStatus reports one account's state, read from the box. --json emits the
// machine-readable contract; the human form is a short summary. Read-only.
func runStatus(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: status: %v\n", err)
		return 1
	}
	// Read the marker (the same dependency-free truth a sibling tool reads). A
	// missing marker is a clean "not forced", not an error.
	st, err = st.WithMarker(marker.DefaultStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: status: reading marker: %v\n", err)
		return 1
	}
	if cmd.JSON {
		return emitJSON(st)
	}
	if !st.Exists {
		fmt.Printf("%s: not provisioned\n", st.Account)
		return 0
	}
	fmt.Printf("%s: provisioned (uid %s)\n", st.Account, st.UID)
	if st.ShimExists {
		fmt.Printf("  shim %s: present (uid %s)\n", st.Shim, st.ShimUID)
	} else {
		fmt.Printf("  shim %s: MISSING\n", st.Shim)
	}
	if st.Forced && st.Marker != nil {
		fmt.Printf("  forced: yes (endpoint class %s, marked %s)\n", st.Marker.EndpointClass, st.Marker.CreatedAt)
	} else {
		fmt.Printf("  forced: no (no marker)\n")
	}
	return 0
}

// runVerify is the trust anchor (story 15-18, 25): it PROVES the account is
// anonymized rather than assuming it, running the named assertion set with NO
// short-circuit, printing each result, and exiting NON-ZERO on any failure (the
// CI-gating contract). `--json` emits the versioned machine report (the contract
// others may consume) on stdout; the human form goes to stdout too so a plain
// `verify` reads clearly. The live probes need root + a live host and are compiled
// only under the `integration` build tag; the DEFAULT binary's verify therefore
// fails-closed (it cannot PROVE anonymization, so it must not exit 0).
//
// It reads the account's UIDs from the box (the same read-only truth `status`
// uses) and the endpoint + shim loopback ports from the PERSISTED account config
// (written by `add`/`update`), so the live probes dial the account's real endpoint
// and shim ports. When there is no persisted config (an account never forced), it
// falls back to the default Tor endpoint + the default ports, which is enough for
// the default build's fail-closed report and for the integration harness (which
// supplies the live params directly).
func runVerify(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	st, err := provision.Status(ctx, r, cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: verify: %v\n", err)
		return 1
	}
	p := verifyParams(cmd.Account, st)
	rep := verify.RunVerify(ctx, p)

	// WRITE-AFTER-VERIFY: the marker is a coordination CLAIM written strictly AFTER
	// verify proves the account forced. On a passing report we write it (via the
	// gate, so an unverified account can never be claimed); a failing verify writes
	// nothing and leaves any prior claim to be cleared by `rm`. A marker-write
	// failure does NOT flip a passing verify to a failure (the account IS proven
	// forced); it is surfaced on stderr so the operator can retry.
	if rep.Ok() {
		m := marker.New(cmd.Account, st.UID, p.Class, resolveVersion(), time.Now())
		if werr := marker.DefaultStore().WriteVerified(m, true); werr != nil {
			fmt.Fprintf(os.Stderr, "anonctl: verify: writing marker: %v\n", werr)
		}
	}

	if cmd.JSON {
		blob, jerr := rep.JSON()
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "anonctl: verify: %v\n", jerr)
			return 1
		}
		os.Stdout.Write(append(blob, '\n'))
	} else {
		fmt.Print(rep.Human())
	}
	return rep.ExitCode()
}

// verifyParams assembles the LIVE verify params for an account: the endpoint +
// shim loopback ports from the PERSISTED account config (written by add/update)
// when present, else the default Tor endpoint + default ports (an account never
// forced). The UIDs always come from the box (the same read-only truth status
// uses). This is the seam that lets the default build's fail-closed report and the
// integration probes target the account's real endpoint/ports.
func verifyParams(account string, st provision.AccountStatus) verify.LiveParams {
	ep := endpoint.Default()
	relay, dns := accountconfig.DefaultRelayPort, accountconfig.DefaultDNSPort
	if cfg, err := accountconfig.DefaultStore().Read(account); err == nil {
		ep = cfg.Endpoint()
		relay, dns = cfg.RelayPort, cfg.DNSPort
	}
	return verify.LiveParams{
		Account:      account,
		Endpoint:     ep.URL(),
		Class:        ep.Class,
		AnonUID:      atoiOr(st.UID, 0),
		ShimUID:      atoiOr(st.ShimUID, 0),
		RelayPort:    relay,
		DNSPort:      dns,
		EndpointHost: ep.Host,
		EndpointPort: atoiOr(ep.Port, 0),
	}
}

// runUpdate is `update`/`reconfigure`: it changes an already-forced account's
// endpoint and RE-APPLIES the rules fail-closed, with no un-anonymized window
// (story 21). It reads the account's persisted config (it must already be
// provisioned + forced), overlays the new endpoint (required for update), and calls
// forcing.Reconfigure, which re-applies the nft rules (atomic table replace, the
// default-DROP never absent) BEFORE restarting the shim, so egress is
// dropped-or-forced throughout. It runs as root (nft/systemctl).
func runUpdate(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	if cmd.Endpoint == "" {
		fmt.Fprintf(os.Stderr, "anonctl: %s: --endpoint is required (the new socks5h endpoint to point the account at)\n", cmd.Verb)
		return 2
	}
	cfg, err := accountconfig.DefaultStore().Read(cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %s is not provisioned/forced (run `anonctl add %s` first): %v\n", cmd.Verb, cmd.Account, accountArg(cmd.Account), err)
		return 1
	}
	ep, err := resolveEndpoint(cmd.Endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %v\n", cmd.Verb, err)
		return 1
	}
	cfg.EndpointHost = ep.Host
	cfg.EndpointPort = atoiOr(ep.Port, 0)
	cfg.EndpointClass = ep.Class
	if err := forcing.Reconfigure(ctx, forcingDeps(), cfg, nil); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %s: %v\n", cmd.Verb, err)
		return 1
	}
	fmt.Printf("reconfigured %s -> endpoint %s (re-applied fail-closed, no leak window)\n", cfg.Account, cfg.Endpoint().URL())
	fmt.Printf("run `anonctl verify %s` to re-prove the account is anonymized\n", accountArg(cmd.Account))
	return 0
}

// forcingDeps wires the real runners + stores for the forcing orchestration (the
// production seam; tests build fakes). It is the ONE place the ExecRunners + the
// default Stores are assembled.
func forcingDeps() forcing.Deps {
	return forcing.Deps{
		NftRunner:     nftables.ExecRunner{},
		SystemdRunner: systemd.ExecRunner{},
		ConfigStore:   accountconfig.DefaultStore(),
		SystemdStore:  systemd.DefaultStore(),
	}
}

// buildConfig assembles an account's at-rest config from its just-provisioned UIDs
// (read from the box) and the chosen endpoint (the raw --endpoint value, or the
// default Tor SocksPort when empty). It fails loud if the account's UIDs cannot be
// read (a provisioning that did not land) rather than emit a config that would
// mis-force.
func buildConfig(ctx context.Context, r provision.Runner, account, rawEndpoint string) (accountconfig.Config, error) {
	st, err := provision.Status(ctx, r, account)
	if err != nil {
		return accountconfig.Config{}, fmt.Errorf("reading provisioned account: %w", err)
	}
	anonUID := atoiOr(st.UID, 0)
	shimUID := atoiOr(st.ShimUID, 0)
	if anonUID <= 0 || shimUID <= 0 {
		return accountconfig.Config{}, fmt.Errorf("account %q is missing its UID (%q) or shim UID (%q); provisioning did not complete", account, st.UID, st.ShimUID)
	}
	ep, err := resolveEndpoint(rawEndpoint)
	if err != nil {
		return accountconfig.Config{}, err
	}
	return accountconfig.Config{
		Account:       account,
		AnonUID:       anonUID,
		ShimUID:       shimUID,
		EndpointHost:  ep.Host,
		EndpointPort:  atoiOr(ep.Port, 0),
		EndpointClass: ep.Class,
	}, nil
}

// resolveEndpoint turns the raw --endpoint value into a validated, credential-free
// endpoint with its share-class. An empty value is the default Tor SocksPort
// (story 4). A named value is parsed with the heuristic class (Classify), which the
// operator's future --endpoint-class override could refine (out of scope here).
func resolveEndpoint(raw string) (endpoint.Endpoint, error) {
	if raw == "" {
		return endpoint.Default(), nil
	}
	ep, err := endpoint.Parse(raw, endpoint.Classify(raw))
	if err != nil {
		return endpoint.Endpoint{}, fmt.Errorf("endpoint: %w", err)
	}
	return ep, nil
}

// accountArg renders an account name as the CLI argument that targets it: the
// default `anon` is a BARE verb (no name), a named `anon-<name>` is `<name>`. So a
// follow-up hint prints the shortest form the operator would type.
func accountArg(account string) string {
	if account == cli.DefaultAccount {
		return ""
	}
	return strings.TrimPrefix(account, cli.DefaultAccount+"-")
}

// atoiOr parses s as an int, returning def on any error (an empty/absent UID for a
// not-yet-provisioned account maps to the default rather than aborting: verify
// still runs its assertions and reports the fail-closed verdict).
func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// emitJSON writes v as indented JSON to stdout (the machine-readable channel), so
// a caller can capture it cleanly. Diagnostics stay on stderr.
func emitJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: %v\n", err)
		return 1
	}
	return 0
}

const usage = `usage:
  anonctl add    [--endpoint <socks5h://host:port>] [<name>]
                                     provision the account + shim UID, install fail-closed forcing that
                                     survives reboot (default endpoint: the local Tor SocksPort) (root)
  anonctl rm     [--purge-account] [<name>]
                                     remove forcing; --purge-account also deletes the account (root)
  anonctl list   [--json]           list the anon accounts that exist on the box
  anonctl status [<name>] [--json]  show one account's state (machine-readable with --json)
  anonctl verify [<name>] [--json]  prove the account is anonymized (named assertions, non-zero exit on failure)
  anonctl update|reconfigure --endpoint <socks5h://host:port> [<name>]
                                     change the account's endpoint and re-apply fail-closed (no leak window) (root)
  anonctl --version | version       print the anonctl version

A bare verb targets the default account ` + "`anon`" + `; ` + "`<name>`" + ` targets ` + "`anon-<name>`" + `.
Each account gets its OWN dedicated shim service account (` + "`<account>-shim`" + `), the
only UID allowed to reach the upstream endpoint. anonctl does NOT manage the
endpoint's own service: enable your endpoint (e.g. ` + "`tor.service`" + `) at boot yourself.`
