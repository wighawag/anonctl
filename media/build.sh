#!/usr/bin/env bash
# Regenerates every generated asset in this directory from the authored sources.
# Authored: logo.svg, icon.svg, preview.src.svg, fonts/
# Generated: preview.svg, preview.png, icon.png
set -euo pipefail
cd "$(dirname "$0")"

command -v inkscape >/dev/null || { echo "error: inkscape is required (rasteriser + text-to-path)" >&2; exit 1; }
MAGICK=$(command -v magick || command -v convert) || { echo "error: ImageMagick is required" >&2; exit 1; }

# The mark's geometry is duplicated across three files because each needs a
# different ink and framing. Compare the load-bearing path data and fail loudly
# rather than shipping three marks that no longer match.
geom() { grep -o 'd="M120 180[^"]*"\|d="M138 140 V96[^"]*"\|d="M138 140 V204[^"]*"' "$1" | tr -d ' ' | sort -u; }
for f in icon.svg preview.src.svg; do
	if [ "$(geom logo.svg)" != "$(geom "$f")" ]; then
		echo "error: mark geometry in $f has drifted from logo.svg" >&2
		diff <(geom logo.svg) <(geom "$f") >&2 || true
		exit 1
	fi
done

# Vendored font, found without installing it system-wide.
mkdir -p .fc
cat > .fc/fonts.conf <<EOF
<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig><dir>$(pwd)/fonts</dir><dir>/usr/share/fonts</dir><cachedir>$(pwd)/.fc/cache</cachedir></fontconfig>
EOF
export FONTCONFIG_FILE="$(pwd)/.fc/fonts.conf"

# Card: outline the two strings so no build needs the font installed.
inkscape preview.src.svg --export-text-to-path --export-plain-svg -o preview.svg >/dev/null 2>&1

# Render at 2x and downsample: hard-edged arcs stairstep when rasterised to size.
inkscape preview.svg -o /tmp/anonctl-preview@2x.png -w 2560 >/dev/null 2>&1
"$MAGICK" /tmp/anonctl-preview@2x.png -resize 1280x640 -strip preview.png
inkscape icon.svg -o /tmp/anonctl-icon@2x.png -w 1024 >/dev/null 2>&1
"$MAGICK" /tmp/anonctl-icon@2x.png -resize 512x512 -strip icon.png

echo "built: preview.svg preview.png icon.png"
