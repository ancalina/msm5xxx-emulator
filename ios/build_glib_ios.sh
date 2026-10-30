#!/bin/sh
# Static GLib (+ PCRE2, libffi, proxy-libintl) for iOS device or simulator.
# usage: build_glib_ios.sh iphonesimulator|iphoneos x86_64|arm64 ARCHIVE_DIR EMPTY_WORK_DIR
set -eu
[ "$#" -eq 4 ] || { sed -n 3p "$0" >&2; exit 2; }
PLATFORM=$1 ARCH=$2 ARCHIVES=$3
[ ! -e "$4" ] || { echo "work directory exists: $4" >&2; exit 1; }
MIN_IOS=15.0
MESON=${MESON:-meson}

check_sha256() {
    [ "$(shasum -a 256 "$2" | cut -d' ' -f1)" = "$1" ] || { echo "unexpected input: $2" >&2; exit 1; }
}
check_sha256 51ab804c56f6eab3e5045c774d1290ac5e4c923d4f9a3d8e33123bee45c1840e "$ARCHIVES/glib-2.88.1.tar.xz"
check_sha256 15fbc5aba6beee0b17aecb04602ae39432393aba1ebd8e39b7cabf7db883299f "$ARCHIVES/pcre2-10.46.tar.bz2"
check_sha256 d66c56ad259a82cf2a9dfc408b32bf5da52371500b84745f7fb8b645712df676 "$ARCHIVES/libffi-3.4.4.tar.gz"
check_sha256 f7a1cbd7579baaf575c66f9d99fb6295e9b0684a28b095967cfda17857595303 "$ARCHIVES/proxy-libintl-0.5.tar.gz"

SDK=$(xcrun --sdk "$PLATFORM" --show-sdk-path)
CLANG=$(xcrun --sdk "$PLATFORM" --find clang)
case $PLATFORM in
    iphonesimulator) VERSION_FLAG="-mios-simulator-version-min=$MIN_IOS" SUBSYSTEM=ios-simulator ;;
    iphoneos) VERSION_FLAG="-miphoneos-version-min=$MIN_IOS" SUBSYSTEM=ios ;;
    *) echo "unknown platform $PLATFORM" >&2; exit 2 ;;
esac
case $ARCH in
    x86_64) HOST=x86_64-apple-darwin CPU_FAMILY=x86_64 ;;
    arm64) HOST=aarch64-apple-darwin CPU_FAMILY=aarch64 ;;
    *) echo "unknown arch $ARCH" >&2; exit 2 ;;
esac

mkdir -p "$4"; WORK=$(cd "$4" && pwd)
PREFIX="$WORK/prefix" SRC="$WORK/src" BUILD="$WORK/build"
mkdir -p "$PREFIX" "$SRC" "$BUILD"
for a in glib-2.88.1.tar.xz pcre2-10.46.tar.bz2 libffi-3.4.4.tar.gz proxy-libintl-0.5.tar.gz; do
    tar -xf "$ARCHIVES/$a" -C "$SRC"
done

CC="$CLANG -arch $ARCH -isysroot $SDK $VERSION_FLAG"
export CC CXX="$CC" CFLAGS="-O2 -fPIC -ffile-prefix-map=$WORK=/build" LDFLAGS=""

cmake -S "$SRC/pcre2-10.46" -B "$BUILD/pcre2" -G Ninja \
    -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$SDK" -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=$MIN_IOS -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DPCRE2_BUILD_PCRE2_8=ON \
    -DPCRE2_BUILD_PCRE2_16=OFF -DPCRE2_BUILD_PCRE2_32=OFF -DPCRE2_BUILD_TESTS=OFF \
    -DPCRE2_BUILD_PCRE2GREP=OFF -DPCRE2_SUPPORT_JIT=OFF -DPCRE2_SUPPORT_UNICODE=ON
DESTDIR="$PREFIX" ninja -C "$BUILD/pcre2" -j2 install

# libffi 3.4.4 CFI directives do not assemble with current Apple clang on arm64
mkdir -p "$BUILD/libffi"; (cd "$BUILD/libffi" && gcc_cv_as_cfi_pseudo_op=no "$SRC/libffi-3.4.4/configure" --host=$HOST \
    --prefix=/usr/local --libdir=/usr/local/lib --disable-shared --enable-static \
    --disable-docs --disable-multi-os-directory && DESTDIR="$PREFIX" make -j2 install)

PC_DIR="$PREFIX/usr/local/lib/pkgconfig"; mkdir -p "$PC_DIR"
cat > "$PC_DIR/libpcre2-8.pc" <<'PC'
prefix=/usr/local
libdir=${prefix}/lib
includedir=${prefix}/include
Name: libpcre2-8
Description: PCRE2
Version: 10.46
Libs: -L${libdir} -lpcre2-8
Cflags: -I${includedir} -DPCRE2_STATIC
PC
mkdir -p "$SRC/glib-2.88.1/subprojects/proxy-libintl-0.5"
cp -a "$SRC/proxy-libintl-0.5/." "$SRC/glib-2.88.1/subprojects/proxy-libintl-0.5/"

cat > "$WORK/cross.ini" <<CROSS
[binaries]
c = ['$CLANG', '-arch', '$ARCH', '-isysroot', '$SDK', '$VERSION_FLAG']
objc = ['$CLANG', '-arch', '$ARCH', '-isysroot', '$SDK', '$VERSION_FLAG']
ar = '$(xcrun --sdk "$PLATFORM" --find ar)'
strip = '$(xcrun --sdk "$PLATFORM" --find strip)'
pkg-config = '$(command -v pkg-config)'

[host_machine]
system = 'darwin'
subsystem = '$SUBSYSTEM'
cpu_family = '$CPU_FAMILY'
cpu = '$CPU_FAMILY'
endian = 'little'

[properties]
needs_exe_wrapper = true
sys_root = '$PREFIX'
pkg_config_libdir = ['$PC_DIR']
CROSS

PKG_CONFIG_LIBDIR="$PC_DIR" PKG_CONFIG_SYSROOT_DIR="$PREFIX" PKG_CONFIG_PATH= \
"$MESON" setup "$BUILD/glib" "$SRC/glib-2.88.1" --cross-file="$WORK/cross.ini" \
    --wrap-mode=nodownload --prefix=/usr/local --libdir=lib --buildtype=release \
    -Ddefault_library=static -Dtests=false -Dinstalled_tests=false -Ddocumentation=false \
    -Dman-pages=disabled -Dintrospection=disabled -Dlibmount=disabled -Dselinux=disabled \
    -Dxattr=false -Dlibelf=disabled -Dnls=enabled -Dsysprof=disabled -Ddtrace=disabled \
    -Dsystemtap=disabled
DESTDIR="$PREFIX" ninja -C "$BUILD/glib" -j2 install

T="$PREFIX/usr/local"
cat > "$WORK/consumer.c" <<'C'
#include <glib.h>
#include <libintl.h>
int main(void) { return g_utf8_validate(dgettext("msm5xxx", "runtime"), -1, NULL) ? 0 : 1; }
C
$CC -I"$T/include/glib-2.0" -I"$T/lib/glib-2.0/include" -I"$T/include" "$WORK/consumer.c" \
    -L"$T/lib" -lglib-2.0 -lintl -lpcre2-8 -liconv -framework CoreFoundation -framework Foundation \
    -o "$WORK/glib-link-check"
echo "iOS GLib ($PLATFORM $ARCH) built: $T"
