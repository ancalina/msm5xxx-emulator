#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCHIVE="$ROOT/build/vendor-downloads/numpy-2.5.1.tar.gz"
SOURCE="$ROOT/build/vendor-build/numpy-source"
CIBW="$ROOT/build/vendor-build/cibuildwheel-4.1.1/bin/python"
PATCHELF="$ROOT/build/vendor-build/cibuildwheel-4.1.1/bin/patchelf"
OUTPUT="$ROOT/build/vendor-wheelhouse/numpy-2.5.1"
PREFIX="$ROOT/build/vendor-prefix/numpy"
CROSS="$ROOT/numpy-android-aarch64.meson.cross"
WHEEL="$OUTPUT/numpy-2.5.1-cp314-cp314-android_24_arm64_v8a.whl"
ANDROID_SDK=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
NDK="$ANDROID_SDK/ndk/27.3.13750724"
CXX_LIBRARY="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so"

for required in "$ARCHIVE" "$CIBW" "$PATCHELF" "$CROSS" \
        "$CXX_LIBRARY" "$NDK/NOTICE"; do
    if [ ! -e "$required" ]; then
        echo "Missing pinned NumPy build input: $(basename -- "$required")" >&2
        exit 1
    fi
done

printf '%s  %s\n' \
    a48a113e6afea91f5608793bafa7ef2ad481fefbda87ec5069f483de61cb9fa3 \
    "$ARCHIVE" | sha256sum -c -
if [ "$("$CIBW" -c \
        'import importlib.metadata as m; print(m.version("cibuildwheel"))')" \
        != 4.1.1 ]; then
    echo "Unexpected cibuildwheel version." >&2
    exit 1
fi

mkdir -p "$SOURCE" "$OUTPUT"
find "$SOURCE" -mindepth 1 -delete
find "$OUTPUT" -mindepth 1 -delete
tar -xzf "$ARCHIVE" --strip-components=1 -C "$SOURCE"
test -f "$SOURCE/pyproject.toml"

SETTINGS="setup-args=--cross-file=$CROSS"
SETTINGS="$SETTINGS setup-args=-Dblas=none setup-args=-Dlapack=none"
SETTINGS="$SETTINGS setup-args=-Dallow-noblas=true"
SETTINGS="$SETTINGS setup-args=-Dcpu-dispatch=none"
SETTINGS="$SETTINGS setup-args=-Ddisable-svml=true"
SETTINGS="$SETTINGS setup-args=-Dc_args=-ffile-prefix-map=$ROOT=."
SETTINGS="$SETTINGS setup-args=-Dcpp_args=-ffile-prefix-map=$ROOT=."
SETTINGS="$SETTINGS compile-args=-j1"

nice -n 15 env \
    LC_ALL=C \
    PYTHONHASHSEED=0 \
    SOURCE_DATE_EPOCH=1783214220 \
    CIBW_BEFORE_BUILD= \
    CIBW_BEFORE_TEST= \
    CIBW_TEST_COMMAND= \
    CIBW_REPAIR_WHEEL_COMMAND= \
    CIBW_CONFIG_SETTINGS="$SETTINGS" \
    "$CIBW" -m cibuildwheel "$SOURCE" \
    --only cp314-android_arm64_v8a --output-dir "$OUTPUT"

python3 -m zipfile -t "$WHEEL"
mkdir -p "$PREFIX/lib"
cp "$CXX_LIBRARY" "$PREFIX/lib/"
cp "$NDK/NOTICE" "$PREFIX/"
echo "Built NumPy Android runtime."
