#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$ROOT/qemu_build_inputs.env"

if [ "$#" -ne 2 ]; then
    echo "usage: $0 QEMU_ARCHIVE EMPTY_WORK_DIR" >&2
    exit 2
fi
if [ -e "$2" ]; then
    echo "work directory already exists: $2" >&2
    exit 1
fi

mkdir -p "$2"
WORK=$(CDPATH= cd -- "$2" && pwd)
SOURCE="$WORK/qemu-$QEMU_VERSION-msm5xxx"
BUILD="$WORK/build"
"$ROOT/stage_qemu_source.sh" "$1" "$SOURCE"
mkdir "$BUILD"

DTC_SOURCE=${MSM5XXX_DTC_SOURCE:-}
if [ ! -d "$DTC_SOURCE" ] || [ ! -d "$DTC_SOURCE/.git" ]; then
    echo "set MSM5XXX_DTC_SOURCE to the pinned DTC checkout" >&2
    exit 1
fi
if [ "$(git -C "$DTC_SOURCE" rev-parse HEAD)" != "$QEMU_DTC_REVISION" ]; then
    echo "unexpected DTC source revision" >&2
    exit 1
fi
mkdir "$SOURCE/subprojects/dtc"
git -C "$DTC_SOURCE" archive "$QEMU_DTC_REVISION" \
    | tar -xf - -C "$SOURCE/subprojects/dtc"

MAP_FLAGS="-ffile-prefix-map=$SOURCE=. -fmacro-prefix-map=$SOURCE=."
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$BUILD=. -fmacro-prefix-map=$BUILD=."
MAP_FLAGS="$MAP_FLAGS -ffile-prefix-map=$WORK=. -fmacro-prefix-map=$WORK=."

cd "$BUILD"
"$SOURCE/configure" \
    --target-list=arm-softmmu \
    --without-default-features \
    --enable-fdt=internal \
    --disable-download \
    --disable-docs \
    --disable-tools \
    --disable-guest-agent \
    --disable-werror \
    --disable-debug-info \
    --extra-cflags="$MAP_FLAGS" \
    --enable-strip
nice -n 15 ninja -j1 qemu-system-arm
./qemu-system-arm --version | grep -q "^QEMU emulator version $QEMU_VERSION"
./qemu-system-arm -machine help | grep -q '^msm5xxx-poc '
