#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$ROOT/.." && pwd)
. "$REPO/experiments/qemu-tcg/qemu_build_inputs.env"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 EMPTY_WORK_DIR" >&2
    exit 2
fi
if [ -e "$1" ]; then
    echo "work directory already exists: $1" >&2
    exit 1
fi

SDK=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
if [ -z "$SDK" ]; then
    echo "set ANDROID_SDK_ROOT or ANDROID_HOME" >&2
    exit 1
fi
NDK_VERSION=28.2.13676358
NDK="$SDK/ndk/$NDK_VERSION"
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
ARCHIVE="$ROOT/build/vendor-downloads/qemu-$QEMU_VERSION.tar.xz"
GLIB="$ROOT/build/vendor-install/glib-sanitized2/usr/local"
DTC_SOURCE=${MSM5XXX_DTC_SOURCE:-}
ANDROID_PATCH="$REPO/experiments/qemu-tcg/qemu-10.2.1-android-host.patch"

check_sha256() {
    expected=$1
    file=$2
    actual=$(sha256sum "$file")
    actual=${actual%% *}
    if [ "$actual" != "$expected" ]; then
        echo "unexpected build input: $file" >&2
        exit 1
    fi
}

for file in "$ARCHIVE" "$ANDROID_PATCH" \
        "$GLIB/lib/libglib-2.0.so" "$GLIB/lib/libintl.so" \
        "$TOOLCHAIN/aarch64-linux-android28-clang" \
        "$TOOLCHAIN/aarch64-linux-android28-clang++" \
        "$TOOLCHAIN/llvm-strip" "$TOOLCHAIN/llvm-readelf"; do
    if [ ! -f "$file" ]; then
        echo "missing Android build input: $file" >&2
        exit 1
    fi
done
if [ ! -d "$DTC_SOURCE/.git" ]; then
    echo "set MSM5XXX_DTC_SOURCE to the pinned DTC checkout" >&2
    exit 1
fi

check_sha256 "$MSM5XXX_ANDROID_PATCH_SHA256" "$ANDROID_PATCH"
check_sha256 \
    bf5bf27ec9048f915f7b166eaada1f75ba0eb87e3dc9aef4fc292d5ced183ee3 \
    "$GLIB/lib/libglib-2.0.so"
check_sha256 \
    fe085703f11516d537bae8393260abf6aa3c23459880911d5d8b3e4aa6ab41d2 \
    "$GLIB/lib/libintl.so"
if [ "$(git -C "$DTC_SOURCE" rev-parse HEAD)" != "$QEMU_DTC_REVISION" ]; then
    echo "unexpected DTC source revision" >&2
    exit 1
fi

mkdir -p "$1"
WORK=$(CDPATH= cd -- "$1" && pwd)
SOURCE="$WORK/qemu-$QEMU_VERSION-msm5xxx-android"
BUILD="$WORK/build"
RUNTIME="$WORK/runtime"
PC_DIR="$WORK/pkgconfig"
"$REPO/experiments/qemu-tcg/stage_qemu_source.sh" "$ARCHIVE" "$SOURCE"
patch -p1 -d "$SOURCE" < "$ANDROID_PATCH"
mkdir "$SOURCE/subprojects/dtc" "$BUILD" "$RUNTIME" "$PC_DIR"
git -C "$DTC_SOURCE" archive "$QEMU_DTC_REVISION" \
    | tar -xf - -C "$SOURCE/subprojects/dtc"

printf '%s\n' \
    'prefix=/usr/local' \
    'exec_prefix=${prefix}' \
    'libdir=${exec_prefix}/lib' \
    "includedir=$GLIB/include" \
    '' \
    'Name: GLib' \
    'Description: Core application building blocks' \
    'Version: 2.88.1' \
    'Libs: -lglib-2.0' \
    "Cflags: -I\${includedir}/glib-2.0 -I$GLIB/lib/glib-2.0/include" \
    > "$PC_DIR/glib-2.0.pc"

export PKG_CONFIG=$(command -v pkg-config)
export PKG_CONFIG_PATH="$PC_DIR"
export PKG_CONFIG_LIBDIR="$PC_DIR"
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1

MAP_FLAGS="-fPIC -ffile-prefix-map=$REPO=/work -fmacro-prefix-map=$REPO=/work"
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$SDK=/sdk -fmacro-prefix-map=$SDK=/sdk"
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$GLIB=/usr/local -fmacro-prefix-map=$GLIB=/usr/local"
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$BUILD=/usr/build/qemu -fmacro-prefix-map=$BUILD=/usr/build/qemu"
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$SOURCE=/usr/src/qemu -fmacro-prefix-map=$SOURCE=/usr/src/qemu"

cd "$BUILD"
"$SOURCE/configure" \
    --target-list=arm-softmmu \
    --cpu=aarch64 \
    --cross-prefix="$TOOLCHAIN/llvm-" \
    --cc="$TOOLCHAIN/aarch64-linux-android28-clang" \
    --cxx="$TOOLCHAIN/aarch64-linux-android28-clang++" \
    --host-cc="$(command -v cc)" \
    --python="$(command -v python3)" \
    --ninja="$(command -v ninja)" \
    --without-default-features \
    --enable-system \
    --enable-tcg \
    --enable-pie \
    --enable-fdt=internal \
    --disable-download \
    --disable-modules \
    --disable-plugins \
    --disable-gio \
    --disable-tools \
    --disable-docs \
    --disable-install-blobs \
    --extra-cflags="$MAP_FLAGS" \
    --extra-cxxflags="$MAP_FLAGS" \
    --extra-ldflags="-L$GLIB/lib -Wl,-z,max-page-size=16384" \
    --bindir=/usr/bin
nice -n 15 ninja -C "$BUILD" -j1 qemu-system-arm

install -m 0755 "$BUILD/qemu-system-arm" "$RUNTIME/libqemu-system-arm.so"
install -m 0755 "$GLIB/lib/libglib-2.0.so" "$RUNTIME/libglib-2.0.so"
install -m 0755 "$GLIB/lib/libintl.so" "$RUNTIME/libintl.so"
"$TOOLCHAIN/llvm-strip" --strip-all "$RUNTIME"/*.so

for file in "$RUNTIME"/*.so; do
    "$TOOLCHAIN/llvm-readelf" -lW "$file" \
        | awk '$1 == "LOAD" { seen = 1; if ($NF != "0x4000") exit 1 }
               END { if (!seen) exit 1 }'
    if "$TOOLCHAIN/llvm-readelf" -dW "$file" | grep -Eq 'RPATH|RUNPATH'; then
        echo "runtime contains RPATH/RUNPATH" >&2
        exit 1
    fi
    if strings -a "$file" | grep -Eiq '/home/|codex|evidence|android-client/build'; then
        echo "runtime contains a private build path" >&2
        exit 1
    fi
    if strings -a -e l "$file" | grep -Eiq '/home/|codex|evidence|android-client/build'; then
        echo "runtime contains a private UTF-16 build path" >&2
        exit 1
    fi
done

needed=$("$TOOLCHAIN/llvm-readelf" -dW "$RUNTIME/libqemu-system-arm.so" \
    | awk '/\(NEEDED\)/ { gsub(/\[|\]/, "", $NF); print $NF }' | sort)
expected=$(printf '%s\n' libc.so libglib-2.0.so libm.so libz.so | sort)
if [ "$needed" != "$expected" ]; then
    echo "unexpected QEMU Android dependency closure" >&2
    exit 1
fi

JNI="$ROOT/build/generated/jniLibs/arm64-v8a"
if [ -L "$JNI" ] || { [ -e "$JNI" ] && [ ! -d "$JNI" ]; }; then
    echo "refusing unsafe JNI directory: $JNI" >&2
    exit 1
fi
mkdir -p "$JNI"
for name in libqemu-system-arm.so libglib-2.0.so libintl.so; do
    target="$JNI/$name"
    if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
        echo "refusing unsafe JNI target: $target" >&2
        exit 1
    fi
done
JNI_STAGE=$(mktemp -d "$JNI/.msm5xxx.XXXXXX")
cleanup_jni_stage() {
    rmdir "$JNI_STAGE" 2>/dev/null || :
}
abort_jni_stage() {
    cleanup_jni_stage
    trap - 0 HUP INT TERM
    exit 1
}
trap cleanup_jni_stage 0
trap abort_jni_stage HUP INT TERM
install -m 0755 "$RUNTIME/libqemu-system-arm.so" "$JNI_STAGE/"
install -m 0755 "$RUNTIME/libglib-2.0.so" "$JNI_STAGE/"
install -m 0755 "$RUNTIME/libintl.so" "$JNI_STAGE/"
for name in libqemu-system-arm.so libglib-2.0.so libintl.so; do
    mv -f "$JNI_STAGE/$name" "$JNI/$name"
done
rmdir "$JNI_STAGE"
trap - 0 HUP INT TERM
sha256sum "$JNI/libqemu-system-arm.so" "$JNI/libglib-2.0.so" "$JNI/libintl.so"
