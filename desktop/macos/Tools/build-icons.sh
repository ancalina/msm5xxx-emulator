#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
icon_python=${MSM5XXX_PYTHON:-python3}
output="$PWD/.build/Branding"
"$icon_python" Tools/build_branding.py --out "$output"
mkdir -p "$output/raster"
for style in full small; do
    # Quick Look preserves SVG grain filters that the sips SVG importer omits.
    qlmanage -t -s 1024 -o "$output/raster" "$output/$style.svg" > "$output/raster/$style.log" 2>&1
    cp "$output/raster/$style.svg.png" "$output/$style.png"
    iconset="$output/$style.iconset"
    mkdir -p "$iconset"
    for points in 16 32 128 256 512; do
        for scale in 1 2; do
            pixels=$((points * scale))
            suffix=""
            if [ "$scale" = 2 ]; then suffix="@2x"; fi
            sips -z "$pixels" "$pixels" "$output/$style.png" --out "$iconset/icon_${points}x${points}${suffix}.png" >/dev/null
        done
    done
    iconutil -c icns "$iconset" -o "$output/$style.icns"
done
mkdir -p "$output/AppIcon.icon/Assets"
cp "$output/plate.svg" "$output/marking.svg" "$output/AppIcon.icon/Assets/"
cat > "$output/AppIcon.icon/icon.json" <<'JSON'
{
  "groups": [{"name": "Chip", "layers": [
    {"name": "Marking", "image-name": "marking.svg"},
    {"name": "Plate", "image-name": "plate.svg"}
  ]}],
  "supported-platforms": {"squares": ["macOS"]}
}
JSON
# Compile the layered document into the asset catalog used on macOS 26.
mkdir -p "$output/compiled"
xcrun actool --compile "$output/compiled" --platform macosx --minimum-deployment-target 15.0 --app-icon AppIcon --output-partial-info-plist "$output/icon-info.plist" "$output/AppIcon.icon" > "$output/asset-build.log"
