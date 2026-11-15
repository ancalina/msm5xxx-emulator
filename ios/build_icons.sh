#!/bin/sh
# Generate the asset catalog and layered Icon Composer resources for this checkout.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
if [ -z "${INKSCAPE:-}" ] && ! command -v inkscape >/dev/null 2>&1; then
    export INKSCAPE="/Applications/Inkscape.app/Contents/MacOS/inkscape"
fi
python3 "$ROOT/branding/mobile_icons.py" ios "$ROOT/ios/app/build/icons"
