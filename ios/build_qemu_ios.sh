#!/bin/sh
# qemu-system-arm (msm5xxx-poc) for iOS device or simulator, linked against static GLib.
# usage: build_qemu_ios.sh iphonesimulator|iphoneos x86_64|arm64 tcg|tci QEMU_ARCHIVE DTC_TAR GLIB_PREFIX EMPTY_WORK_DIR
set -eu
[ "$#" -eq 7 ] || { sed -n 3p "$0" >&2; exit 2; }
PLATFORM=$1 ARCH=$2 MODE=$3 ARCHIVE=$4 DTC_TAR=$5 GLIB=$6
[ ! -e "$7" ] || { echo "work directory exists: $7" >&2; exit 1; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/native/qemu/qemu_build_inputs.env"
PATCH="$REPO/native/qemu/qemu-10.2.1-ios-host.patch"
[ "$(shasum -a 256 "$PATCH" | cut -d' ' -f1)" = "$MSM5XXX_IOS_PATCH_SHA256" ] || { echo "unexpected iOS patch" >&2; exit 1; }
MIN_IOS=15.0
SDK=$(xcrun --sdk "$PLATFORM" --show-sdk-path)
CLANG=$(xcrun --sdk "$PLATFORM" --find clang)
case $PLATFORM in
    iphonesimulator) VERSION_FLAG="-mios-simulator-version-min=$MIN_IOS" ;;
    iphoneos) VERSION_FLAG="-miphoneos-version-min=$MIN_IOS" ;;
    *) exit 2 ;;
esac
case $ARCH in x86_64) CPU=x86_64 ;; arm64) CPU=aarch64 ;; *) exit 2 ;; esac
case $MODE in tcg) TCI= ;; tci) TCI=--enable-tcg-interpreter ;; *) exit 2 ;; esac

mkdir -p "$7"; WORK=$(cd "$7" && pwd)
SOURCE="$WORK/qemu" BUILD="$WORK/build" PC_DIR="$WORK/pkgconfig"
"$REPO/native/qemu/stage_qemu_source.sh" "$ARCHIVE" "$SOURCE"
patch -p1 -d "$SOURCE" < "$PATCH"
mkdir "$SOURCE/subprojects/dtc" "$BUILD" "$PC_DIR"
tar -xf "$DTC_TAR" -C "$SOURCE/subprojects/dtc"

LIBS="-lglib-2.0 -lintl -lpcre2-8 -liconv -framework CoreFoundation -framework Foundation"
cat > "$PC_DIR/glib-2.0.pc" <<PC
Name: GLib
Description: static GLib for iOS
Version: 2.88.1
Libs: -L$GLIB/lib $LIBS
Cflags: -I$GLIB/include/glib-2.0 -I$GLIB/lib/glib-2.0/include
PC
# TCI calls helpers through libffi, installed beside GLib
cat > "$PC_DIR/libffi.pc" <<PC
Name: libffi
Description: static libffi for iOS
Version: 3.4.4
Libs: -L$GLIB/lib -lffi
Cflags: -I$GLIB/include
PC
export PKG_CONFIG_PATH="$PC_DIR" PKG_CONFIG_LIBDIR="$PC_DIR"

MAP="-ffile-prefix-map=$WORK=/build -ffile-prefix-map=$GLIB=/glib"
cd "$BUILD"
"$SOURCE/configure" \
    --target-list=arm-softmmu --cpu=$CPU \
    --cc="$CLANG" --cxx="$CLANG" --objcc="$CLANG" --host-cc="$(command -v cc)" \
    --extra-cflags="-arch $ARCH -isysroot $SDK $VERSION_FLAG $MAP" \
    --extra-objcflags="-arch $ARCH -isysroot $SDK $VERSION_FLAG" \
    --extra-ldflags="-arch $ARCH -isysroot $SDK $VERSION_FLAG" \
    --cross-prefix= --without-default-features --enable-system --enable-tcg $TCI \
    --enable-fdt=internal --disable-download --disable-modules --disable-plugins \
    --disable-gio --disable-tools --disable-docs --disable-install-blobs --disable-werror
nice -n 10 ninja -C "$BUILD" -j4 qemu-system-arm
file "$BUILD/qemu-system-arm"
echo "iOS QEMU ($PLATFORM $ARCH $MODE) built: $BUILD/qemu-system-arm"
