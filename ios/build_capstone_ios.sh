#!/bin/sh
# Build the capstone disassembler for iOS devices: Capstone.framework plus its Python binding.
# usage: build_capstone_ios.sh CAPSTONE_5.0.7_ARCHIVE EMPTY_WORK_DIR
set -eu
[ "$#" -eq 2 ] || { sed -n 3p "$0" >&2; exit 2; }
ARCHIVE=$1
[ ! -e "$2" ] || { echo "work directory exists: $2" >&2; exit 1; }
SHA256=6427a724726d161d1e05fb49fff8cd0064f67836c04ffca3c11d6d859e719caa
[ "$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)" = "$SHA256" ] || { echo "unexpected capstone archive" >&2; exit 1; }
APP_DIR=$(cd "$(dirname "$0")/app" && pwd)
OUT="$APP_DIR/Frameworks/iphoneos"
mkdir -p "$2" "$OUT"; WORK=$(cd "$2" && pwd)
tar -xzf "$ARCHIVE" -C "$WORK"
SRC="$WORK/capstone-5.0.7"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
cmake -S "$SRC" -B "$WORK/build" -G Ninja \
    -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_SYSTEM_PROCESSOR=arm64 -DCMAKE_OSX_SYSROOT="$SDK" -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF -DCAPSTONE_BUILD_MACOS_THIN=ON \
    -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_INSTALL=OFF -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF \
    -DCAPSTONE_ARM_SUPPORT=ON -DCAPSTONE_ARM64_SUPPORT=ON
cmake --build "$WORK/build" --target capstone_shared
LIB=$(find "$WORK/build" -name 'libcapstone*.dylib' -type f | head -n 1)
[ -n "$LIB" ] || { echo "libcapstone was not built" >&2; exit 1; }
F="$OUT/Capstone.framework"
rm -rf "$F" "$OUT/capstone-python"
mkdir -p "$F"
cp "$LIB" "$F/Capstone"
install_name_tool -id @rpath/Capstone.framework/Capstone "$F/Capstone"
xcrun lipo "$F/Capstone" -verify_arch arm64
cat > "$F/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Capstone</string>
<key>CFBundleIdentifier</key><string>org.msm5xxx.emulator.capstone</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>5.0.7</string>
<key>CFBundleVersion</key><string>5.0.7</string>
<key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
<key>MinimumOSVersion</key><string>15.0</string>
</dict></plist>
PLIST
cp -R "$SRC/bindings/python/capstone" "$OUT/capstone-python"
cp "$SRC/LICENSE.TXT" "$SRC/LICENSE_LLVM.TXT" "$OUT/capstone-python/"
echo "$F"
