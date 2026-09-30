#!/bin/sh
# Build the Android GLib runtime from pinned source archives (2026-09-30).
# This script does not modify the existing JNI/runtime installation.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$ROOT/.." && pwd)
DEFAULT_ARCHIVES="$ROOT/build/vendor-downloads"
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 EMPTY_WORK_DIR [SOURCE_ARCHIVE_DIR]" >&2
    exit 2
fi
WORK_INPUT=$1
ARCHIVES=${2:-${SOURCE_ARCHIVE_DIR:-$DEFAULT_ARCHIVES}}
if [ -e "$WORK_INPUT" ]; then
    echo "work directory already exists: $WORK_INPUT" >&2
    exit 1
fi

SDK=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
if [ -z "$SDK" ]; then
    echo "set ANDROID_SDK_ROOT or ANDROID_HOME" >&2
    exit 1
fi
NDK_VERSION=28.2.13676358
NDK="$SDK/ndk/$NDK_VERSION"
TOOLBIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CC="$TOOLBIN/aarch64-linux-android28-clang"
CXX="$TOOLBIN/aarch64-linux-android28-clang++"
AR="$TOOLBIN/llvm-ar"
RANLIB="$TOOLBIN/llvm-ranlib"
STRIP="$TOOLBIN/llvm-strip"
READELF="$TOOLBIN/llvm-readelf"
MESON=${MESON:-$(command -v meson || true)}
NINJA=${NINJA:-$(command -v ninja)}
CMAKE=${CMAKE:-$(command -v cmake)}
PKG_CONFIG=${PKG_CONFIG:-$(command -v pkg-config)}
MAKE=${MAKE:-$(command -v make)}

for path in "$CC" "$CXX" "$AR" "$RANLIB" "$STRIP" "$READELF" \
        "$MESON" "$NINJA" "$CMAKE" "$PKG_CONFIG" "$MAKE"; do
    if [ -z "$path" ] || [ ! -x "$path" ]; then
        echo "missing required Android build tool: $path" >&2
        exit 1
    fi
done

check_sha256() {
    expected=$1
    file=$2
    actual=$(sha256sum "$file")
    actual=${actual%% *}
    if [ "$actual" != "$expected" ]; then
        echo "unexpected source input: $file" >&2
        exit 1
    fi
}

GLIB_ARCHIVE="$ARCHIVES/glib-2.88.1.tar.xz"
PCRE_ARCHIVE="$ARCHIVES/pcre2-10.46.tar.bz2"
FFI_ARCHIVE="$ARCHIVES/libffi-3.4.4.tar.gz"
INTL_ARCHIVE="$ARCHIVES/proxy-libintl-0.5.tar.gz"
check_sha256 51ab804c56f6eab3e5045c774d1290ac5e4c923d4f9a3d8e33123bee45c1840e "$GLIB_ARCHIVE"
check_sha256 15fbc5aba6beee0b17aecb04602ae39432393aba1ebd8e39b7cabf7db883299f "$PCRE_ARCHIVE"
check_sha256 d66c56ad259a82cf2a9dfc408b32bf5da52371500b84745f7fb8b645712df676 "$FFI_ARCHIVE"
check_sha256 f7a1cbd7579baaf575c66f9d99fb6295e9b0684a28b095967cfda17857595303 "$INTL_ARCHIVE"

mkdir -p "$WORK_INPUT"
WORK=$(CDPATH= cd -- "$WORK_INPUT" && pwd)
PREFIX="$WORK/prefix"
SRC="$WORK/src"
BUILD="$WORK/build"
mkdir -p "$PREFIX" "$SRC" "$BUILD"

tar -xf "$GLIB_ARCHIVE" -C "$SRC"
tar -xf "$PCRE_ARCHIVE" -C "$SRC"
tar -xf "$FFI_ARCHIVE" -C "$SRC"
tar -xf "$INTL_ARCHIVE" -C "$SRC"
GLIB_SRC="$SRC/glib-2.88.1"
PCRE_SRC="$SRC/pcre2-10.46"
FFI_SRC="$SRC/libffi-3.4.4"
INTL_SRC="$SRC/proxy-libintl-0.5"
test -f "$GLIB_SRC/COPYING" && test -f "$PCRE_SRC/COPYING" \
    && test -f "$FFI_SRC/LICENSE" && test -f "$INTL_SRC/COPYING"

export CC CXX AR RANLIB STRIP
export CFLAGS="-O2 -fPIC -ffile-prefix-map=$WORK=/build -fdebug-prefix-map=$WORK=/build -Wno-error"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-Wl,-z,max-page-size=16384"

# PCRE2 supplies GLib's regex backend as a target-only static dependency.
PCRE_BUILD="$BUILD/pcre2"
"$CMAKE" -S "$PCRE_SRC" -B "$PCRE_BUILD" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=28 \
    -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_AR="$AR" -DCMAKE_RANLIB="$RANLIB" \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
    -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DPCRE2_BUILD_PCRE2_8=ON \
    -DPCRE2_BUILD_PCRE2_16=OFF -DPCRE2_BUILD_PCRE2_32=OFF \
    -DPCRE2_BUILD_TESTS=OFF -DPCRE2_BUILD_PCRE2GREP=OFF \
    -DPCRE2_SUPPORT_JIT=OFF -DPCRE2_SUPPORT_UNICODE=ON \
    -DPCRE2_SUPPORT_LIBZ=OFF -DPCRE2_SUPPORT_LIBBZ2=OFF \
    -DPCRE2_SUPPORT_LIBREADLINE=OFF
DESTDIR="$PREFIX" "$NINJA" -C "$PCRE_BUILD" -j1 install

# libffi is static: GLib/GObject consumes it without adding another runtime DSO.
FFI_BUILD="$BUILD/libffi"
mkdir -p "$FFI_BUILD"
cd "$FFI_BUILD"
"$FFI_SRC/configure" --host=aarch64-linux-android --prefix=/usr/local \
    --libdir=/usr/local/lib --disable-shared --enable-static \
    --disable-exec-static-tramp --disable-docs --disable-multi-os-directory
DESTDIR="$PREFIX" "$MAKE" -j1 install

TARGET_PREFIX="$PREFIX/usr/local"
PC_DIR="$TARGET_PREFIX/lib/pkgconfig"
mkdir -p "$PC_DIR"
export PKG_CONFIG_PATH=
export PKG_CONFIG_LIBDIR="$PC_DIR"
export PKG_CONFIG_SYSROOT_DIR="$PREFIX"

# Cross file locks every Meson compiler and dependency probe to Android NDK.
cat > "$WORK/android-aarch64.ini" <<CROSS
[binaries]
c = '$CC'
cpp = '$CXX'
ar = '$AR'
strip = '$STRIP'
pkg-config = '$PKG_CONFIG'

[host_machine]
system = 'android'
cpu_family = 'aarch64'
cpu = 'armv8-a'
endian = 'little'

[properties]
needs_exe_wrapper = true
sys_root = '$PREFIX'
pkg_config_libdir = ['$PC_DIR']
CROSS

# Make target PCRE2 visible to GLib's Meson dependency lookup.
cat > "$PC_DIR/libpcre2-8.pc" <<'PCRE_PC'
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: libpcre2-8
Description: PCRE2 - Perl compatible regular expressions C library
Version: 10.46
Libs: -L${libdir} -lpcre2-8
Libs.private:
Cflags: -I${includedir}
PCRE_PC

if [ ! -f "$PC_DIR/libffi.pc" ]; then
    echo "libffi install did not provide libffi.pc" >&2
    exit 1
fi

# GLib's declared wrap pin matches this archive; stage its exact contents so
# Meson resolves intl without network access or source modification.
mkdir -p "$GLIB_SRC/subprojects/proxy-libintl-0.5"
cp -a "$INTL_SRC/." "$GLIB_SRC/subprojects/proxy-libintl-0.5/"

GLIB_BUILD="$BUILD/glib"
"$MESON" setup "$GLIB_BUILD" "$GLIB_SRC" \
    --cross-file="$WORK/android-aarch64.ini" --wrap-mode=nodownload \
    --prefix=/usr/local --libdir=lib --buildtype=release \
    -Ddefault_library=shared -Dtests=false -Dinstalled_tests=false \
    -Ddocumentation=false -Dman-pages=disabled \
    -Dintrospection=disabled -Dlibmount=disabled -Dselinux=disabled \
    -Dxattr=false -Dlibelf=disabled -Dnls=enabled \
    -Dsysprof=disabled -Ddtrace=disabled -Dsystemtap=disabled \
    -Dforce_posix_threads=true
DESTDIR="$PREFIX" "$NINJA" -C "$GLIB_BUILD" -j1 install

# Target-side consumer links against the freshly-built GLib and intl outputs.
cat > "$WORK/consumer.c" <<'CONSUMER'
#include <glib.h>
#include <libintl.h>
int main(void) {
    const gchar *text = dgettext("msm5xxx-link-check", "runtime");
    return g_utf8_validate(text, -1, NULL) ? 0 : 1;
}
CONSUMER
"$CC" --sysroot="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot" \
    -fPIE -pie -I"$TARGET_PREFIX/include/glib-2.0" \
    -I"$TARGET_PREFIX/lib/glib-2.0/include" -I"$TARGET_PREFIX/include" \
    "$WORK/consumer.c" -L"$TARGET_PREFIX/lib" \
    -Wl,-rpath-link,"$TARGET_PREFIX/lib" -Wl,-z,max-page-size=16384 \
    -lglib-2.0 -lintl -o "$WORK/glib-intl-link-check"

RUNTIME="$WORK/runtime"
mkdir -p "$RUNTIME"
install -m 0755 "$TARGET_PREFIX/lib/libglib-2.0.so" "$RUNTIME/"
install -m 0755 "$TARGET_PREFIX/lib/libintl.so" "$RUNTIME/"
install -m 0644 "$TARGET_PREFIX/lib/libpcre2-8.a" "$RUNTIME/"
install -m 0644 "$TARGET_PREFIX/lib/libffi.a" "$RUNTIME/"
"$STRIP" --strip-unneeded "$RUNTIME"/*.so

for file in "$RUNTIME"/*.so; do
    "$READELF" -lW "$file" | awk '$1 == "LOAD" { seen=1; if ($NF != "0x4000") exit 1 } END { if (!seen) exit 1 }'
    if "$READELF" -dW "$file" | grep -Eq 'RPATH|RUNPATH'; then
        echo "runtime contains RPATH/RUNPATH: $file" >&2
        exit 1
    fi
    if strings -a "$file" | grep -Eiq '/home/|codex|evidence|android-client/build'; then
        echo "runtime contains a private build path: $file" >&2
        exit 1
    fi
done
"$READELF" -dW "$RUNTIME/libglib-2.0.so" | grep -q 'libintl.so'
"$READELF" -dW "$WORK/glib-intl-link-check" | grep -q 'libglib-2.0.so'
"$READELF" -dW "$WORK/glib-intl-link-check" | grep -q 'libintl.so'

cat > "$WORK/BUILDINFO.txt" <<INFO
Date: 2026-09-30
Target: Android arm64-v8a, API 28, NDK $NDK_VERSION
Sources: GLib 2.88.1, proxy-libintl 0.5, PCRE2 10.46, libffi 3.4.4
SHA256 GLib: 51ab804c56f6eab3e5045c774d1290ac5e4c923d4f9a3d8e33123bee45c1840e
SHA256 proxy-libintl: f7a1cbd7579baaf575c66f9d99fb6295e9b0684a28b095967cfda17857595303
SHA256 PCRE2: 15fbc5aba6beee0b17aecb04602ae39432393aba1ebd8e39b7cabf7db883299f
SHA256 libffi: d66c56ad259a82cf2a9dfc408b32bf5da52371500b84745f7fb8b645712df676
Build: this script; each compiler build uses one job.
Runtime: shared GLib and intl; PCRE2 and libffi are static support dependencies.
Upstream source archives were unmodified.
INFO
sha256sum "$RUNTIME"/* "$WORK/glib-intl-link-check" > "$WORK/SHA256SUMS"
echo "Android GLib runtime built and checked: $WORK"
