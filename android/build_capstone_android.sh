#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCHIVE="$ROOT/build/vendor-downloads/capstone-5.0.7.tar.xz"
SOURCE="$ROOT/build/vendor-build/capstone-source"
BUILD="$ROOT/build/vendor-build/capstone-android"
PREFIX="$ROOT/build/vendor-prefix/capstone"
ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
NDK="$ANDROID_SDK/ndk/28.2.13676358"
SHA256=871f18b78e2c77e39aa0a448e135b856c0c71a0398bb1bc779ef59458f83e275
mkdir -p "$(dirname "$ARCHIVE")"
if [ ! -f "$ARCHIVE" ]; then
    curl -fL --retry 3 -o "$ARCHIVE.part" \
        https://github.com/capstone-engine/capstone/releases/download/5.0.7/capstone-5.0.7.tar.xz
    mv "$ARCHIVE.part" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA256" "$ARCHIVE" | sha256sum -c -
test -f "$NDK/build/cmake/android.toolchain.cmake"
mkdir -p "$SOURCE" "$BUILD" "$PREFIX/lib" "$PREFIX/python"
find "$SOURCE" -mindepth 1 -delete
find "$BUILD" -mindepth 1 -delete
find "$PREFIX" -mindepth 1 -delete
mkdir -p "$PREFIX/lib" "$PREFIX/python"
tar -xJf "$ARCHIVE" --strip-components=1 -C "$SOURCE"
cmake -S "$SOURCE" -B "$BUILD" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF \
    -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF
cmake --build "$BUILD" --parallel 4
cp -L "$BUILD/libcapstone.so" "$PREFIX/lib/libcapstone.so"
cp -a "$SOURCE/bindings/python/capstone" "$PREFIX/python/"
cp "$SOURCE/LICENSE.TXT" "$PREFIX/LICENSE.TXT"
cp "$NDK/NOTICE" "$PREFIX/NDK-NOTICE"
echo 'Built Capstone Android runtime.'
