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
	"syscall"
	"text/tabwriter"

	"github.com/wighawag/anonctl/internal/cli"
	"github.com/wighawag/anonctl/internal/provision"
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
	case "verify", "update", "reconfigure":
		// Stubs: the verb DISPATCHES (the surface is end-to-end) but the behaviour
		// is filled by later tasks (nftables/persistence/verify). Fail loud so it is
		// never mistaken for a silent success.
		fmt.Fprintf(os.Stderr, "anonctl: %s is not implemented yet (a later task fills it)\n", cmd.Verb)
		return 3
	default:
		fmt.Fprintf(os.Stderr, "anonctl: unknown verb %q\n%s\n", cmd.Verb, usage)
		return 2
	}
}

// runAdd provisions the account + its dedicated shim UID, idempotently. It must
// run as root (useradd); a non-root run surfaces useradd's own permission error.
func runAdd(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	res, err := provision.Add(ctx, r, cmd.Account)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: add: %v\n", err)
		return 1
	}
	if res.Created {
		fmt.Printf("provisioned %s (shim %s)\n", res.Account, res.Shim)
	} else {
		fmt.Printf("%s already exists (shim %s); nothing to do\n", res.Account, res.Shim)
	}
	return 0
}

// runRm removes the account's forcing hooks and, only under --purge-account,
// deletes the account + its shim. A bare rm leaves the home intact.
func runRm(ctx context.Context, r provision.Runner, cmd *cli.Command) int {
	res, err := provision.Rm(ctx, r, cmd.Account, cmd.PurgeAccount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anonctl: rm: %v\n", err)
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
	return 0
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
  anonctl add    [<name>]            provision the anon / anon-<name> account + its shim UID (root)
  anonctl rm     [--purge-account] [<name>]
                                     remove forcing; --purge-account also deletes the account (root)
  anonctl list   [--json]           list the anon accounts that exist on the box
  anonctl status [<name>] [--json]  show one account's state (machine-readable with --json)
  anonctl verify [<name>]           (later task) prove the account is anonymized
  anonctl update|reconfigure [<name>]
                                     (later task) change an account's endpoint, re-apply fail-closed
  anonctl --version | version       print the anonctl version

A bare verb targets the default account ` + "`anon`" + `; ` + "`<name>`" + ` targets ` + "`anon-<name>`" + `.
Each account gets its OWN dedicated shim service account (` + "`<account>-shim`" + `), the
only UID a later task lets reach the upstream endpoint. This build provisions the
account + shim lifecycle only; it installs NO egress forcing yet.`
