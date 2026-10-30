#!/bin/sh
# Relink a finished build_qemu_ios.sh tree as NAME.framework with entry point qemu_entry(argc, argv).
# usage: build_qemu_framework.sh QEMU_BUILD_DIR OUTPUT_DIR [NAME]   (QEMU for tcg, QEMUTCI for tci)
set -eu
[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || { sed -n 3p "$0" >&2; exit 2; }
NAME=${3:-QEMU}
BUILD=$(cd "$1" && pwd)
mkdir -p "$2"; OUT=$(cd "$2" && pwd)/$NAME.framework
rm -rf "$OUT"; mkdir -p "$OUT"

# Reuse QEMU's own final link step; only the output kind and the entry symbol change.
LINK=$(ninja -C "$BUILD" -t commands qemu-system-arm-unsigned | tail -1)
case $LINK in *" -o qemu-system-arm-unsigned "*) ;; *) echo "unexpected link command" >&2; exit 1 ;; esac
LINK=$(printf '%s' "$LINK" | sed "s| -o qemu-system-arm-unsigned | -dynamiclib -install_name @rpath/$NAME.framework/$NAME -Wl,-alias,_main,_qemu_entry -o $OUT/$NAME |")
(cd "$BUILD" && eval "$LINK")
nm -gU "$OUT/$NAME" | grep -q ' _qemu_entry$'

MIN_IOS=$(otool -l "$OUT/$NAME" | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $2; exit}')
cat > "$OUT/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>$NAME</string>
  <key>CFBundleIdentifier</key><string>me.ancal.msm5xemu.$(echo $NAME | tr A-Z a-z)</string>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>10.2.1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>MinimumOSVersion</key><string>$MIN_IOS</string>
</dict></plist>
PLIST
echo "built $OUT"
