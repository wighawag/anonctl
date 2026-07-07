// Package endpoint is anonctl's PURE endpoint model: the socks5h proxy an account
// is forced through, its cross-user SHARE-CLASS, the per-account isolation
// username derived from that class, and the sharing-refusal that keeps two
// accounts off one single-identity endpoint. It is all pure logic (no root, no
// sockets, no system mutation) so classification, username derivation, and the
// refusal are exhaustively unit-testable everywhere (the default `go test ./...`).
//
// The axis that matters is NOT tor-vs-socks mechanism (the shim dials both the
// same socks5h way); it is whether the endpoint is SAFE TO SHARE across accounts:
//
//   - ClassTorShared: a Tor SocksPort. Per-username SOCKS-auth isolation is
//     available, so anonctl dials it with a per-account `<account>@` SOCKS
//     username and Tor's default IsolateSOCKSAuth gives each account its own
//     circuit/exit (ground truth: work/notes/findings/tor-isolatesocksauth-default.md).
//     Many accounts may share ONE such endpoint safely.
//   - ClassSocksPeruser: a plain socks endpoint (Mullvad local SOCKS, wireproxy,
//     `ssh -D`, ...). It has NO per-username isolation, so it is a SINGLE identity
//     that AT MOST ONE account may use; a second account would exit identically
//     and become cross-identifiable. anonctl refuses/flags sharing it (Registry).
//
// anonctl does NOT manage the endpoint's lifecycle (netcage's stance): it assumes
// the socks5h endpoint already exists and can scan for one (scan.go). The endpoint
// persisted at rest is CREDENTIAL-FREE by construction (mirrors netcage's config
// hygiene): the per-account isolation username is DERIVED here, never embedded.
package endpoint

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ShareClass is the cross-user share-safety axis of an endpoint. It is the
// vocabulary CONTEXT.md defines: tor-shared (per-username isolation, share-safe)
// vs socks-peruser (single identity, at most one account).
type ShareClass string

const (
	// ClassTorShared is a Tor SocksPort: per-account `<account>@` SOCKS-auth
	// isolation is available (Tor IsolateSOCKSAuth), so many accounts may share it.
	ClassTorShared ShareClass = "tor-shared"
	// ClassSocksPeruser is a plain socks endpoint: one identity, no per-username
	// isolation, so AT MOST ONE account may use it (else cross-identifiable).
	ClassSocksPeruser ShareClass = "socks-peruser"
)

// ErrCredentialedEndpoint is returned by Parse when the endpoint URL carries
// embedded user:pass@ credentials. anonctl's endpoint at rest is credential-free
// by construction (mirroring netcage's ErrCredentialedProxyNotPersisted): the
// per-account isolation username is derived by anonctl (IsolationUsername), and a
// real authed proxy's credentials belong in the endpoint's own config, not in an
// anonctl-owned marker/config. A world-readable marker must never hold a secret.
var ErrCredentialedEndpoint = errors.New("refusing an endpoint with embedded credentials: anonctl's endpoint is credential-free at rest (the per-account isolation username is derived, not embedded); keep any real proxy credentials in the endpoint's own config")

// ErrPeruserAlreadyClaimed is returned by Registry.Claim when a SECOND account is
// pointed at a socks-peruser endpoint already claimed by a DIFFERENT account. The
// two accounts would exit identically and become cross-identifiable, which is the
// exact failure the share-class axis exists to prevent (story 8).
var ErrPeruserAlreadyClaimed = errors.New("refusing to share a socks-peruser endpoint across accounts")

// Endpoint is a parsed, validated socks5h endpoint plus its share-class. It is
// credential-free at rest by construction (Parse refuses embedded credentials);
// the Username/Password fields exist only so a scanned/typed value can be
// inspected and rejected, and are always empty on a value that survived Parse.
type Endpoint struct {
	Host     string
	Port     string
	Class    ShareClass
	Username string // always empty on a Parse/Default/Scan result (credential-free at rest)
	Password string // always empty on a Parse/Default/Scan result
}

// DefaultHost and DefaultPort are the local Tor SocksPort anonctl points an
// account at when the operator names no endpoint, so `anonctl add` anonymizes out
// of the box (story 4). They mirror the validated manual recipe's SOCKS_ADDR /
// SOCKS_PORT (work/notes/findings/manual-per-uid-tor-recipe.md).
const (
	DefaultHost = "127.0.0.1"
	DefaultPort = "9050"
)

// torPorts is the set of conventional local Tor SocksPort ports. A loopback
// endpoint on one of these is CLASSIFIED tor-shared by Classify: it is the
// per-username-isolation-available case. Any other port is conservatively
// socks-peruser (a single identity) unless the operator declares otherwise. These
// mirror netcage detect-proxy's DefaultPorts Tor entries (9050 Tor, 9150 Tor
// Browser).
var torPorts = map[string]bool{
	"9050": true, // Tor default SocksPort
	"9150": true, // Tor Browser default SocksPort
}

// Default returns the default endpoint: the local Tor SocksPort, classed
// tor-shared. It is what an account is pointed at when no endpoint is named.
func Default() Endpoint {
	return Endpoint{Host: DefaultHost, Port: DefaultPort, Class: ClassTorShared}
}

// Parse turns a user-supplied endpoint (a full socks5h://host:port URL or a bare
// host:port) into a validated, credential-free Endpoint with the given
// share-class. It mirrors netcage's socks5h hygiene: a bare host:port defaults to
// the socks5h scheme; a socks5:// (local-DNS) or non-socks5h scheme is REFUSED
// (that is a DNS leak by definition); and an endpoint carrying embedded
// user:pass@ credentials is REFUSED (ErrCredentialedEndpoint) so nothing at rest
// holds a secret. The class is supplied by the caller (Classify decides it for a
// bare URL; the operator may override); Parse does not re-derive it.
func Parse(raw string, class ShareClass) (Endpoint, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Endpoint{}, errors.New("empty endpoint: a socks5h://host:port (or a host:port) is required")
	}
	// A bare host:port (no scheme) defaults to socks5h:// (the only scheme anonctl
	// accepts). A value that already carries a scheme is left as-is so a wrong
	// scheme (socks5://, http://) is rejected below, not masked.
	if !strings.Contains(s, "://") {
		s = "socks5h://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "socks5h":
		// ok: remote (proxy-side) name resolution, no host DNS leak.
	case "socks5":
		return Endpoint{}, fmt.Errorf("endpoint uses socks5:// (local DNS) which LEAKS hostnames to the host resolver; use socks5h:// (remote, proxy-side resolution)")
	default:
		return Endpoint{}, fmt.Errorf("endpoint scheme %q unsupported; anonctl requires socks5h://", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q must include host and port (socks5h://host:port)", raw)
	}
	if u.User != nil {
		// Credential-free at rest: an embedded user:pass@ is refused, not silently
		// dropped, so the operator learns their credentials will not be persisted.
		return Endpoint{}, ErrCredentialedEndpoint
	}
	if class == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q needs a share-class (tor-shared or socks-peruser)", raw)
	}
	return Endpoint{Host: host, Port: port, Class: class}, nil
}

// Classify decides the share-class of a socks5h endpoint from its address alone:
// a loopback endpoint on a conventional Tor SocksPort (9050/9150) is tor-shared
// (per-username isolation available); every other endpoint is conservatively
// socks-peruser (a single identity). This is a HEURISTIC prior, not a probe of
// the running proxy: a SOCKS proxy does not announce that it is Tor, so anonctl
// classifies by the operator-conventional port and lets the operator override the
// class explicitly. It never LABELS the exit provider (netcage's honesty
// constraint); it only decides whether per-username isolation is assumed
// available. A malformed input classifies socks-peruser (the safe, no-sharing
// default); Parse is where a malformed URL is actually rejected.
func Classify(raw string) ShareClass {
	ep, err := Parse(raw, ClassSocksPeruser)
	if err != nil {
		return ClassSocksPeruser
	}
	if isLoopback(ep.Host) && torPorts[ep.Port] {
		return ClassTorShared
	}
	return ClassSocksPeruser
}

// URL returns the canonical, credential-free socks5h URL for the endpoint
// (socks5h://host:port). It is the value persisted / offered; it never carries
// the per-account isolation username (that is derived at dial time, per account).
func (e Endpoint) URL() string {
	return "socks5h://" + net.JoinHostPort(e.Host, e.Port)
}

// Address returns "host:port" (the shim's ProxyAddr).
func (e Endpoint) Address() string { return net.JoinHostPort(e.Host, e.Port) }

// IsolationUsername derives the per-account SOCKS username the shim dials with. For
// a tor-shared endpoint it is the account name, so Tor's default IsolateSOCKSAuth
// puts each account on its own circuit/exit (distinct account => distinct username
// => distinct exit; ground truth in tor-isolatesocksauth-default.md). For a
// socks-peruser endpoint it is EMPTY: that class has no per-username isolation, so
// dialling with an account name would be a false promise of isolation; anonctl
// instead enforces one-account-only (Registry).
func (e Endpoint) IsolationUsername(account string) string {
	if e.Class == ClassTorShared {
		return account
	}
	return ""
}

// key identifies an endpoint for the sharing-refusal: same host:port is the same
// single-identity endpoint. The class is not part of the key (a given host:port
// has one class), and the isolation username is per-account, not per-endpoint.
func (e Endpoint) key() string { return e.Address() }

// Registry records which account has CLAIMED which endpoint, and enforces the
// socks-peruser sharing refusal (story 8): a socks-peruser endpoint (one identity)
// may be claimed by AT MOST ONE account; a tor-shared endpoint may be shared by
// many (the `<account>@` username isolates each). The zero value is not usable;
// build one with NewRegistry. It models the account->endpoint decision purely, so
// the refusal is unit-testable without any persistence; the persistence task wires
// the real claim set from the on-disk account configs.
type Registry struct {
	// peruserOwner maps a socks-peruser endpoint key (host:port) to the single
	// account that owns it. tor-shared endpoints are intentionally NOT tracked
	// here: they are share-safe, so there is nothing to refuse.
	peruserOwner map[string]string
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{peruserOwner: map[string]string{}}
}

// Claim records that account is pointed at ep, refusing the cross-identification
// case. For a tor-shared endpoint it always succeeds (sharing is safe). For a
// socks-peruser endpoint it succeeds only if the endpoint is unclaimed or already
// claimed by the SAME account (a reconfigure/re-add is idempotent); a DIFFERENT
// second account is refused with ErrPeruserAlreadyClaimed, naming the conflicting
// account so the operator sees the collision. Claim mutates the Registry only on
// success.
func (r *Registry) Claim(account string, ep Endpoint) error {
	if ep.Class != ClassSocksPeruser {
		return nil // tor-shared (or any non-peruser class) is share-safe: nothing to refuse.
	}
	k := ep.key()
	if owner, ok := r.peruserOwner[k]; ok && owner != account {
		return fmt.Errorf("%w: %s is already claimed by account %q (a socks-peruser endpoint is a single identity; a second account would exit identically and become cross-identifiable)", ErrPeruserAlreadyClaimed, ep.URL(), owner)
	}
	r.peruserOwner[k] = account
	return nil
}

// isLoopback reports whether host is a loopback address (127.0.0.0/8 or ::1). The
// Tor-conventional-port classification only applies to a LOCAL Tor SocksPort; a
// remote 9050 is not assumed to be Tor.
func isLoopback(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}
