#!/bin/sh
# anonctl installer: download the latest release, verify its sha256 checksum, and
# install BOTH binaries (anonctl + its required anonctl-shim helper), with the
# shim landing at the path the systemd unit's ExecStart expects.
#
#   curl -fsSL https://github.com/wighawag/anonctl/releases/latest/download/install.sh | sh
#
# anonctl's whole job is root-level per-UID egress policy, so this installs to
# /usr/local/bin by DEFAULT (root-writable, on a shared system PATH), NOT to
# ~/.local/bin. That default is LOAD-BEARING, not just convention: the per-account
# shim is launched by the `anonctl-shim@<account>.service` systemd unit whose
# ExecStart is a FIXED path (internal/systemd.DefaultShimBinaryPath =
# /usr/local/bin/anonctl-shim). Unlike the sibling netcage (which finds its helper
# as a sibling of its own binary, so "both on PATH" suffices), anonctl's shim MUST
# be reachable at that unit path or `anonctl add` cannot bring an account's shim up.
# So this script places anonctl-shim at $PREFIX/anonctl-shim and warns loudly if
# $PREFIX is not /usr/local/bin (the unit still looks at the fixed path).
#
# Options (environment variables):
#   ANONCTL_VERSION   version tag to install (default: latest, e.g. v0.1.0)
#   PREFIX            install dir (default: /usr/local/bin). Both binaries go here.
#                     Keep it /usr/local/bin unless you know what you are doing:
#                     the shim unit's ExecStart is the fixed path above.
#
# anonctl is Linux-only: per-UID nftables `skuid` matching and the SO_ORIGINAL_DST
# transparent redirect it relies on are Linux kernel primitives that do not exist
# on other platforms. This script refuses to install on a non-Linux uname.
set -eu

REPO="wighawag/anonctl"
BIN="anonctl"
SHIM="anonctl-shim"

# The path the systemd shim unit's ExecStart expects (mirror of
# internal/systemd.DefaultShimBinaryPath). The shim MUST be reachable here or
# `anonctl add` cannot start an account's shim instance.
SHIM_UNIT_PATH="/usr/local/bin/anonctl-shim"

info() { printf '%s\n' "anonctl-install: $*" >&2; }
err() {
	printf '%s\n' "anonctl-install: error: $*" >&2
	exit 1
}

# --- platform ---------------------------------------------------------------
os="$(uname -s)"
[ "$os" = "Linux" ] || err "anonctl is Linux-only (got $os). Its per-UID nftables skuid matching and SO_ORIGINAL_DST transparent redirect are Linux kernel primitives that do not exist on other platforms."

arch="$(uname -m)"
case "$arch" in
x86_64 | amd64) target="linux_amd64" ;;
aarch64 | arm64) target="linux_arm64" ;;
armv7l | armv7) target="linux_armv7" ;;
armv6l | armv6) target="linux_armv6" ;;
arm*)
	# Unqualified arm: prefer armv7, the common 32-bit Raspberry Pi target.
	info "unrecognised arm variant '$arch'; defaulting to armv7 (set the tarball manually if wrong)"
	target="linux_armv7"
	;;
*) err "unsupported architecture '$arch' (supported: amd64, arm64, armv7, armv6)" ;;
esac

# --- tools ------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
	dl() { curl -fsSL "$1" -o "$2"; }
	dlout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	dl() { wget -qO "$2" "$1"; }
	dlout() { wget -qO- "$1"; }
else
	err "need curl or wget on PATH"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	err "need sha256sum or shasum to verify the download"
fi

# --- version ----------------------------------------------------------------
version="${ANONCTL_VERSION:-}"
if [ -z "$version" ]; then
	info "resolving the latest release..."
	version="$(dlout "https://api.github.com/repos/$REPO/releases/latest" |
		grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
	[ -n "$version" ] || err "could not resolve the latest release tag (set ANONCTL_VERSION=vX.Y.Z)"
fi
# The archive uses the version WITHOUT the leading v (e.g. v0.1.0 -> 0.1.0).
ver_noV="${version#v}"

archive="${BIN}_${ver_noV}_${target}.tar.gz"
base="https://github.com/$REPO/releases/download/$version"

info "installing $BIN $version ($target)"

# --- download + verify ------------------------------------------------------
tmp="$(mktemp -d "${TMPDIR:-/tmp}/anonctl-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading $archive"
dl "$base/$archive" "$tmp/$archive" || err "download failed: $base/$archive"
dl "$base/checksums.txt" "$tmp/checksums.txt" || err "download failed: $base/checksums.txt"

# NEVER install an unverified anonymity tool: the checksum must be present AND
# match, or we abort before touching the filesystem.
want="$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}')"
[ -n "$want" ] || err "no checksum for $archive in checksums.txt"
got="$(sha256 "$tmp/$archive")"
[ "$want" = "$got" ] || err "checksum mismatch for $archive
  expected: $want
  got:      $got"
info "checksum ok"

tar -xzf "$tmp/$archive" -C "$tmp" "$BIN" "$SHIM" || err "failed to extract $BIN and $SHIM"

# --- install dir ------------------------------------------------------------
# Default to /usr/local/bin (root-writable, on a shared system PATH, and the dir
# the shim unit's fixed ExecStart path lives in). anonctl needs root anyway, so
# unlike netcage we do NOT prefer a per-user ~/.local/bin: a per-user shim would
# be invisible to the shim unit's fixed path.
dest="${PREFIX:-/usr/local/bin}"
mkdir -p "$dest" || err "cannot create install dir $dest (anonctl needs root; try: sudo sh, or PREFIX=/usr/local/bin sudo sh)"

install_one() {
	if mv "$tmp/$1" "$dest/$1" 2>/dev/null; then :; else
		cp "$tmp/$1" "$dest/$1" || err "cannot write $dest/$1 (anonctl needs root; re-run with sudo)"
	fi
	chmod +x "$dest/$1"
}
install_one "$BIN"
install_one "$SHIM"

info "installed:"
info "  $dest/$BIN"
info "  $dest/$SHIM"

# --- shim path check --------------------------------------------------------
# The shim unit's ExecStart is a FIXED path. If PREFIX moved the shim off it, the
# install is INCOMPLETE: `anonctl add` will fail to start the shim. Symlink the
# fixed path to where we put it, or tell the user how.
if [ "$dest/$SHIM" != "$SHIM_UNIT_PATH" ]; then
	if ln -sf "$dest/$SHIM" "$SHIM_UNIT_PATH" 2>/dev/null; then
		info "symlinked $SHIM_UNIT_PATH -> $dest/$SHIM (the shim unit's ExecStart path)"
	else
		info ""
		info "WARNING: the shim is at $dest/$SHIM but the systemd shim unit's ExecStart"
		info "expects it at $SHIM_UNIT_PATH. \`anonctl add\` will NOT start the shim until"
		info "the shim is reachable there. Fix it (as root), e.g.:"
		info "  ln -sf $dest/$SHIM $SHIM_UNIT_PATH"
	fi
fi

# --- PATH hint --------------------------------------------------------------
case ":$PATH:" in
*":$dest:"*) ;;
*)
	info ""
	info "NOTE: $dest is not on your PATH. Add it, e.g.:"
	info "  echo 'export PATH=\"$dest:\$PATH\"' >> ~/.profile && . ~/.profile"
	;;
esac

info ""
info "done. anonctl needs root; provision + prove an account with:"
info "  sudo $BIN add"
info "  sudo $BIN verify"
