#!/bin/sh
# anonctl installer: download the latest release, verify its sha256 checksum, and
# install BOTH binaries (anonctl + its required anonctl-shim helper) SIDE BY SIDE.
#
#   curl -fsSL https://github.com/wighawag/anonctl/releases/latest/download/install.sh | sh
#
# anonctl's whole job is root-level per-UID egress policy, so this installs to
# /usr/local/bin by DEFAULT (root-writable, on a shared system PATH), NOT to
# ~/.local/bin.
#
# BOTH binaries MUST land in the SAME directory, and that is the one rule here that
# is load-bearing. The per-account shim is launched by the
# `anonctl-shim@<account>.service` unit, whose ExecStart must be an absolute path
# (a systemd unit has no useful inherited $PATH). anonctl resolves that path when it
# WRITES the unit, preferring the anonctl-shim sitting NEXT TO the running anonctl.
# So a custom $PREFIX now works by itself: the unit is rendered with wherever the
# shim actually is, and no symlink into /usr/local/bin is needed. (Before 0.4 the
# unit hard-coded /usr/local/bin/anonctl-shim regardless of $PREFIX, which is why
# this script used to symlink that path.)
#
# Options (environment variables):
#   ANONCTL_VERSION   version tag to install (default: latest, e.g. v0.1.0)
#   PREFIX            install dir (default: /usr/local/bin). Both binaries go here,
#                     and they must stay together: anonctl finds the shim as its
#                     own sibling when it renders the unit.
#
# anonctl is Linux-only: per-UID nftables `skuid` matching and the SO_ORIGINAL_DST
# transparent redirect it relies on are Linux kernel primitives that do not exist
# on other platforms. This script refuses to install on a non-Linux uname.
set -eu

REPO="wighawag/anonctl"
BIN="anonctl"
SHIM="anonctl-shim"

# The conventional shim location (mirror of internal/systemd.DefaultShimBinaryPath).
# It is now only anonctl's LAST-RESORT fallback when resolving the shim, not a path
# the install must hit: anonctl prefers the shim sitting next to its own binary.
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
# Default to /usr/local/bin (root-writable, on a shared system PATH). anonctl needs
# root anyway, so unlike netcage we do NOT prefer a per-user ~/.local/bin: a per-user
# shim would be unreadable by the root-launched system unit.
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

# --- shim co-location check -------------------------------------------------
# No symlink into $SHIM_UNIT_PATH is created anymore: anonctl renders the unit with
# the shim's ACTUAL path, preferring its own sibling. The only thing that must hold
# is that the two binaries stayed together, so say so if they did not.
if [ ! -x "$dest/$SHIM" ]; then
	info ""
	info "WARNING: $dest/$SHIM is missing or not executable. \`anonctl add\` resolves the"
	info "shim as a sibling of the anonctl binary and will refuse to force an account"
	info "until it can find it."
fi

# --- runtime prerequisites --------------------------------------------------
# anonctl bakes the ABSOLUTE paths of nft and setpriv into the units it generates,
# and REFUSES to force an account if it cannot resolve them (a unit naming a missing
# binary would fail at the next boot, and for the nftables loader that failure is
# fail-OPEN: no baseline default-deny, so the anon UID egresses freely). Flag a
# missing prerequisite now rather than at `anonctl add` time.
for req in nft setpriv; do
	if ! command -v "$req" >/dev/null 2>&1; then
		info ""
		info "WARNING: \`$req\` was not found on PATH. \`anonctl add\` needs it and will refuse"
		info "to force an account until it is installed."
	fi
done

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
