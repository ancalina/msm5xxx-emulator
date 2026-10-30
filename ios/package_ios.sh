#!/bin/sh
# Build MSM5xEmu for devices and package MSM5xEmu.ipa (sideload) and MSM5xEmu.tipa (TrollStore).
# Needs ios/app/Frameworks/iphoneos/{QEMU,QEMUTCI}.framework from build_qemu_framework.sh.
# usage: package_ios.sh OUTPUT_DIR
set -eu
[ "$#" -eq 1 ] || { sed -n 4p "$0" >&2; exit 2; }
APP_DIR=$(cd "$(dirname "$0")/app" && pwd)
for name in QEMU QEMUTCI; do
    [ -d "$APP_DIR/Frameworks/iphoneos/$name.framework" ] || { echo "missing $name.framework" >&2; exit 1; }
done
mkdir -p "$1"; OUT=$(cd "$1" && pwd)
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

xcodebuild -project "$APP_DIR/MSM5xEmu.xcodeproj" -target MSM5xEmu -configuration Release \
    -sdk iphoneos -arch arm64 CODE_SIGNING_ALLOWED=NO SYMROOT="$WORK/build" build >"$WORK/xcodebuild.log" 2>&1 \
    || { tail -20 "$WORK/xcodebuild.log" >&2; exit 1; }
APP="$WORK/build/Release-iphoneos/MSM5xEmu.app"

for kind in ipa tipa; do
    rm -rf "$WORK/Payload"; mkdir "$WORK/Payload"; cp -R "$APP" "$WORK/Payload/"
    A="$WORK/Payload/MSM5xEmu.app"
    for fw in "$A"/Frameworks/*.framework; do codesign --force --sign - "$fw"; done
    codesign --force --sign - --entitlements "$APP_DIR/$kind.entitlements" "$A"
    rm -f "$OUT/MSM5xEmu.$kind"; (cd "$WORK" && zip -qry "$OUT/MSM5xEmu.$kind" Payload)
done
shasum -a 256 "$OUT/MSM5xEmu.ipa" "$OUT/MSM5xEmu.tipa"
