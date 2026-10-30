#!/bin/sh
# Relink a finished build_qemu_ios.sh tree as QEMU.framework with entry point qemu_entry(argc, argv).
# usage: build_qemu_framework.sh QEMU_BUILD_DIR OUTPUT_DIR
set -eu
[ "$#" -eq 2 ] || { sed -n 3p "$0" >&2; exit 2; }
BUILD=$(cd "$1" && pwd)
mkdir -p "$2"; OUT=$(cd "$2" && pwd)/QEMU.framework
rm -rf "$OUT"; mkdir -p "$OUT"

# Reuse QEMU's own final link step; only the output kind and the entry symbol change.
LINK=$(ninja -C "$BUILD" -t commands qemu-system-arm-unsigned | tail -1)
case $LINK in *" -o qemu-system-arm-unsigned "*) ;; *) echo "unexpected link command" >&2; exit 1 ;; esac
LINK=$(printf '%s' "$LINK" | sed "s| -o qemu-system-arm-unsigned | -dynamiclib -install_name @rpath/QEMU.framework/QEMU -Wl,-alias,_main,_qemu_entry -o $OUT/QEMU |")
(cd "$BUILD" && eval "$LINK")
nm -gU "$OUT/QEMU" | grep -q ' _qemu_entry$'

MIN_IOS=$(otool -l "$OUT/QEMU" | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $2; exit}')
cat > "$OUT/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>QEMU</string>
  <key>CFBundleIdentifier</key><string>me.ancal.msm5xemu.qemu</string>
  <key>CFBundleName</key><string>QEMU</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>10.2.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>MinimumOSVersion</key><string>$MIN_IOS</string>
</dict></plist>
PLIST
echo "built $OUT"
