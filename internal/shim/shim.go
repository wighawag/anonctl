// Package shim is the userspace half of anonctl's per-UID forced-egress data
// path: the static Go binary the nft redirect feeds. One instance runs per
// account, on the account's per-account loopback ports, under the account's
// dedicated shim UID. It is two halves in one binary:
//
//   - a transparent TCP-to-SOCKS relay (relay.go): reads each redirected
//     connection's ORIGINAL destination via SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST
//     and relays it to the account's socks5h endpoint; and
//   - a DNS-over-SOCKS-TCP forwarder (dnsforwarder.go, mirrored from netcage):
//     resolves every query REMOTELY over the endpoint via TCP (socks5h), never a
//     local/plaintext lookup.
//
// Both halves dial the endpoint with the per-account `<account>@` isolation
// username (the Tor IsolateSOCKSAuth knob) and both fail closed: if the endpoint
// is unreachable the connection/query is dropped, never sent in the clear. The
// binary builds static (CGO_ENABLED=0) so it runs anywhere the anonctl binary
// does. See work/notes/findings/manual-per-uid-tor-recipe.md for the validated
// invocation and loopback-port scheme this encodes.
package shim

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"
)

// Config is one account's shim configuration. It carries the per-account
// loopback ports, the endpoint, and the isolation username. anonctl's shim UID
// runs one shim per account with its own Config (distinct RelayAddr/DNSAddr per
// account), so account A's forced traffic never rides account B's shim.
type Config struct {
	// RelayAddr is the transparent TCP relay listen address (the account's
	// per-account relay port), e.g. "127.0.0.1:19050".
	RelayAddr string
	// DNSAddr is the DNS forwarder listen address (udp+tcp), the account's
	// per-account DNS port, e.g. "127.0.0.1:19053".
	DNSAddr string
	// ProxyAddr is the socks5h endpoint host:port (e.g. the Tor SocksPort).
	ProxyAddr string
	// SocksUser is the per-account isolation username (`<account>`), carried on
	// BOTH the relay and DNS dials; SocksPass is normally empty (username alone
	// drives Tor IsolateSOCKSAuth). Both empty means an unauthenticated dial (a
	// plain socks-peruser endpoint).
	SocksUser string
	SocksPass string
	// UpstreamDNS is the resolver the DNS forwarder reaches over the endpoint by
	// hostname (socks5h). Empty defaults to a public resolver.
	UpstreamDNS string
}

// Run starts both halves and blocks until ctx is cancelled. The DNS forwarder
// starts first (it binds and serves in the background); then the relay listener
// binds and Serve blocks. A bind failure on either half is a fail-loud error (the
// shim must not run half-open). Cancelling ctx tears both down.
func Run(ctx context.Context, cfg Config) error {
	var auth *proxy.Auth
	if cfg.SocksUser != "" || cfg.SocksPass != "" {
		auth = &proxy.Auth{User: cfg.SocksUser, Password: cfg.SocksPass}
	}

	fwd, err := StartForwarder(ctx, ForwarderConfig{
		Listen:    cfg.DNSAddr,
		ProxyAddr: cfg.ProxyAddr,
		ProxyAuth: auth,
		Upstream:  cfg.UpstreamDNS,
	})
	if err != nil {
		return fmt.Errorf("shim: start dns forwarder: %w", err)
	}
	defer fwd.Close()

	ln, err := net.Listen("tcp", cfg.RelayAddr)
	if err != nil {
		return fmt.Errorf("shim: listen relay %s: %w", cfg.RelayAddr, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	relay := &Relay{
		ProxyAddr: cfg.ProxyAddr,
		SocksUser: cfg.SocksUser,
		SocksPass: cfg.SocksPass,
	}
	if err := relay.Serve(ln); err != nil {
		select {
		case <-ctx.Done():
			return nil // clean shutdown
		default:
			return fmt.Errorf("shim: relay: %w", err)
		}
	}
	return nil
}
