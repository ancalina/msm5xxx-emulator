#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$ROOT/.." && pwd)
PYTHON_PREFIX="$ROOT/build/vendor-src/python-3.14.4-android/prefix"
UNICORN_SOURCE="$ROOT/build/vendor-src/unicorn-2.1.4/bindings/python/unicorn"
UNICORN_LIBRARY="$ROOT/build/vendor-prefix/unicorn/lib/libunicorn.so"
QEMU_SOURCE="$ROOT/build/vendor-src/qemu-10.2.1"
GLIB_SOURCE="$ROOT/build/vendor-src/glib-2.88.1"
PCRE2_SOURCE="$ROOT/build/vendor-src/pcre2-10.46"
LIBFFI_SOURCE="$ROOT/build/vendor-src/libffi-3.4.4"
ASSETS="$ROOT/build/generated/python-assets/python"
LICENSES="$ROOT/build/generated/python-assets/licenses"
JNI="$ROOT/build/generated/jniLibs/arm64-v8a"

check_sha256() {
    expected=$1
    file=$2
    actual=$(sha256sum "$file")
    actual=${actual%% *}
    if [ "$actual" != "$expected" ]; then
        echo "Unexpected runtime artifact: $(basename -- "$file")" >&2
        exit 1
    fi
}

check_sha256 \
    9b8c1ce18cf7553d67f274893fbfc718edc1ed256305bd8cff5ce3b3d4854b64 \
    "$PYTHON_PREFIX/lib/libpython3.14.so"
check_sha256 \
    96763dcb68f90eea6b27745bb5c252295b347c3cce992a683dded611fd38894c \
    "$UNICORN_LIBRARY"

if [ -d "$ASSETS" ]; then
    find "$ASSETS" -mindepth 1 -delete
fi
if [ -d "$LICENSES" ]; then
    find "$LICENSES" -mindepth 1 -delete
fi
mkdir -p "$ASSETS/lib/python3.14/site-packages"
mkdir -p "$ASSETS/lib/python3.14/site-packages/unicorn"
mkdir -p "$ASSETS/cwd" "$LICENSES" "$JNI"

cp -a "$PYTHON_PREFIX/lib/python3.14/." "$ASSETS/lib/python3.14/"
find "$ASSETS/lib/python3.14" -type f -name '*.pyc' -delete
# This embedded runtime exists only for the detector and transport. Avoid
# shipping optional extension modules and their otherwise unused source deps.
for module in _bz2 _hashlib _lzma _sqlite3 _ssl _zstd; do
    rm -f "$ASSETS/lib/python3.14/lib-dynload/$module".*.so
done

cp "$ROOT/app/src/main/python/msm5xxx_android_runtime.py" \
    "$ASSETS/lib/python3.14/site-packages/"
cp -a "$REPO/src/msm5xxx_emulator" \
    "$ASSETS/lib/python3.14/site-packages/"
cp "$REPO/experiments/qemu-tcg/qemu_transport.py" \
    "$REPO/experiments/qemu-tcg/gdb_remote.py" \
    "$ASSETS/lib/python3.14/site-packages/"
cp -a "$UNICORN_SOURCE/." \
    "$ASSETS/lib/python3.14/site-packages/unicorn/"
find "$ASSETS/lib/python3.14/site-packages" -type f -name '*.pyc' -delete

# Match CPython's Android testbed workaround for assets ending in .gz or '-'.
find "$ASSETS" -type f \( -name '*.gz' -o -name '*-' \) \
    -exec sh -c 'for file do mv -- "$file" "$file-"; done' sh {} +

rm -f "$JNI/libpython3.14.so" "$JNI/libcrypto_python.so" \
    "$JNI/libsqlite3_python.so" "$JNI/libssl_python.so" \
    "$JNI/libunicorn.so"
cp "$PYTHON_PREFIX/lib/libpython3.14.so" "$JNI/"
cp "$UNICORN_LIBRARY" "$JNI/"

for file in \
        "$REPO/LICENSE" \
        "$REPO/THIRD_PARTY_NOTICES.md" \
        "$QEMU_SOURCE/COPYING" \
        "$GLIB_SOURCE/LICENSES/LGPL-2.1-or-later.txt" \
        "$GLIB_SOURCE/subprojects/proxy-libintl-0.5/COPYING" \
        "$PCRE2_SOURCE/LICENCE.md" \
        "$PYTHON_PREFIX/lib/python3.14/LICENSE.txt" \
        "$LIBFFI_SOURCE/LICENSE"; do
    if [ ! -f "$file" ]; then
        echo "missing runtime license: $file" >&2
        exit 1
    fi
done
cp "$REPO/THIRD_PARTY_NOTICES.md" "$LICENSES/"
cp "$REPO/LICENSE" "$LICENSES/GPL-2.0.txt"
cp "$QEMU_SOURCE/COPYING" "$LICENSES/QEMU-GPL-2.0.txt"
cp "$GLIB_SOURCE/LICENSES/LGPL-2.1-or-later.txt" \
    "$LICENSES/GLib-LGPL-2.1-or-later.txt"
cp "$GLIB_SOURCE/subprojects/proxy-libintl-0.5/COPYING" \
    "$LICENSES/proxy-libintl-LGPL-2.0-or-later.txt"
cp "$PCRE2_SOURCE/LICENCE.md" "$LICENSES/PCRE2-LICENSE.txt"
cp "$PYTHON_PREFIX/lib/python3.14/LICENSE.txt" "$LICENSES/CPython-LICENSE.txt"
cp "$LIBFFI_SOURCE/LICENSE" "$LICENSES/libffi-LICENSE.txt"

echo "Prepared pinned Python detector runtime."
