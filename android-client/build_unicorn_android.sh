#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$ROOT/build/vendor-src/unicorn-2.1.4"
BUILD="$ROOT/build/vendor-build/unicorn"
PREFIX="$ROOT/build/vendor-prefix/unicorn"
SDK=${ANDROID_HOME:?ANDROID_HOME must point to the Android SDK}
CMAKE="$SDK/cmake/3.22.1/bin/cmake"
TOOLCHAIN="$SDK/ndk/28.2.13676358/build/cmake/android.toolchain.cmake"

for required in "$SOURCE/CMakeLists.txt" "$CMAKE" "$TOOLCHAIN"; do
    if [ ! -e "$required" ]; then
        echo "Missing pinned Unicorn build input: $(basename -- "$required")" >&2
        exit 1
    fi
done

mkdir -p "$BUILD" "$PREFIX"
find "$BUILD" -mindepth 1 -delete

MAP_FLAGS="-ffile-prefix-map=$SOURCE=. -fmacro-prefix-map=$SOURCE=."
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$BUILD=. -fmacro-prefix-map=$BUILD=."
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$PREFIX=. -fmacro-prefix-map=$PREFIX=."
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$ROOT=. -fmacro-prefix-map=$ROOT=."
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$SDK=. -fmacro-prefix-map=$SDK=."

"$CMAKE" -S "$SOURCE" -B "$BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-24 \
    -DANDROID_STL=none \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_C_FLAGS="$MAP_FLAGS" \
    -DCMAKE_SHARED_LINKER_FLAGS=-Wl,-z,max-page-size=16384 \
    -DBUILD_SHARED_LIBS=ON \
    -DUNICORN_ARCH=arm \
    -DUNICORN_BUILD_TESTS=OFF \
    -DUNICORN_FUZZ=OFF \
    -DUNICORN_LEGACY_STATIC_ARCHIVE=OFF \
    -DUNICORN_LOGGING=OFF \
    -DUNICORN_TRACER=OFF

nice -n 15 ninja -C "$BUILD" -j1 unicorn
"$CMAKE" --install "$BUILD"

LIBRARY="$PREFIX/lib/libunicorn.so"
if readelf -dW "$LIBRARY" | grep -Eq 'RPATH|RUNPATH'; then
    echo "Unicorn contains RPATH/RUNPATH" >&2
    exit 1
fi
if strings -a "$LIBRARY" | grep -Eiq '/home/|codex|evidence|android-client/build'; then
    echo "Unicorn contains a private build path" >&2
    exit 1
fi
if strings -a -el "$LIBRARY" | grep -Eiq '/home/|codex|evidence|android-client/build'; then
    echo "Unicorn contains a UTF-16 private build path" >&2
    exit 1
fi

echo "Built sanitized Unicorn Android runtime."
