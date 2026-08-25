#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$ROOT/qemu_build_inputs.env"

if [ "$#" -ne 2 ]; then
    echo "usage: $0 QEMU_ARCHIVE OUTPUT_DIR" >&2
    exit 2
fi

ARCHIVE=$1
OUTPUT=$2
PATCH="$ROOT/qemu-10.2.1-icount-advance.patch"
CFI02_PATCH="$ROOT/qemu-10.2.1-cfi02-write-while-suspended.patch"
MACHINE="$ROOT/msm5xxx-poc.c"
MA2_CORE="$ROOT/msm5xxx-ma2-audio.c"
MA2_HEADER="$ROOT/msm5xxx-ma2-audio.h"
AUDIO_SYNTH_CORE="$ROOT/msm5xxx-audio-synth.c"
AUDIO_SYNTH_HEADER="$ROOT/msm5xxx-audio-synth.h"
MA5_CORE="$ROOT/msm5xxx-ma5-audio.c"
MA5_HEADER="$ROOT/msm5xxx-ma5-audio.h"
TRANSPORT="$ROOT/qemu_transport.py"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

check_sha256() {
    expected=$1
    file=$2
    actual=$(sha256 "$file")
    if [ "$actual" != "$expected" ]; then
        echo "unexpected SHA-256: $file" >&2
        exit 1
    fi
}

for file in "$ARCHIVE" "$PATCH" "$CFI02_PATCH" "$MACHINE" \
        "$MA2_CORE" "$MA2_HEADER" \
        "$AUDIO_SYNTH_CORE" "$AUDIO_SYNTH_HEADER" \
        "$MA5_CORE" "$MA5_HEADER" "$TRANSPORT"; do
    if [ ! -f "$file" ]; then
        echo "missing build input: $file" >&2
        exit 1
    fi
done
if [ -e "$OUTPUT" ]; then
    echo "output already exists: $OUTPUT" >&2
    exit 1
fi

check_sha256 "$QEMU_ARCHIVE_SHA256" "$ARCHIVE"
check_sha256 "$MSM5XXX_ICOUNT_PATCH_SHA256" "$PATCH"
check_sha256 "$MSM5XXX_CFI02_PATCH_SHA256" "$CFI02_PATCH"
check_sha256 "$MSM5XXX_MACHINE_SHA256" "$MACHINE"
check_sha256 "$MSM5XXX_MA2_CORE_SHA256" "$MA2_CORE"
check_sha256 "$MSM5XXX_MA2_HEADER_SHA256" "$MA2_HEADER"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_CORE_SHA256" "$AUDIO_SYNTH_CORE"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_HEADER_SHA256" "$AUDIO_SYNTH_HEADER"
check_sha256 "$MSM5XXX_MA5_CORE_SHA256" "$MA5_CORE"
check_sha256 "$MSM5XXX_MA5_HEADER_SHA256" "$MA5_HEADER"
check_sha256 "$MSM5XXX_TRANSPORT_SHA256" "$TRANSPORT"

mkdir -p "$OUTPUT"
tar -xJf "$ARCHIVE" --strip-components=1 -C "$OUTPUT"
if [ "$(tr -d '\r\n' < "$OUTPUT/VERSION")" != "$QEMU_VERSION" ]; then
    echo "unexpected QEMU source version" >&2
    exit 1
fi
if [ "$(sed -n 's/^revision = //p' "$OUTPUT/subprojects/dtc.wrap")" != "$QEMU_DTC_REVISION" ]; then
    echo "unexpected QEMU DTC revision" >&2
    exit 1
fi
patch -p1 -d "$OUTPUT" < "$PATCH"
patch -p1 -d "$OUTPUT" < "$CFI02_PATCH"
cp "$MACHINE" "$OUTPUT/hw/arm/msm5xxx-poc.c"
cp "$MA2_CORE" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.c"
cp "$MA2_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.h"
cp "$AUDIO_SYNTH_CORE" "$OUTPUT/hw/arm/msm5xxx-audio-synth.c"
cp "$AUDIO_SYNTH_HEADER" "$OUTPUT/hw/arm/msm5xxx-audio-synth.h"
cp "$MA5_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.c"
cp "$MA5_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.h"
printf "\narm_common_ss.add(files('msm5xxx-poc.c', 'msm5xxx-audio-synth.c', 'msm5xxx-ma2-audio.c', 'msm5xxx-ma5-audio.c'))\n" >> "$OUTPUT/hw/arm/meson.build"

test "$(grep -Fc "arm_common_ss.add(files('msm5xxx-poc.c', 'msm5xxx-audio-synth.c', 'msm5xxx-ma2-audio.c', 'msm5xxx-ma5-audio.c'))" "$OUTPUT/hw/arm/meson.build")" -eq 1
cmp "$MACHINE" "$OUTPUT/hw/arm/msm5xxx-poc.c"
cmp "$MA2_CORE" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.c"
cmp "$MA2_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.h"
cmp "$AUDIO_SYNTH_CORE" "$OUTPUT/hw/arm/msm5xxx-audio-synth.c"
cmp "$AUDIO_SYNTH_HEADER" "$OUTPUT/hw/arm/msm5xxx-audio-synth.h"
cmp "$MA5_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.c"
cmp "$MA5_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.h"
check_sha256 "$MSM5XXX_MACHINE_SHA256" "$OUTPUT/hw/arm/msm5xxx-poc.c"
check_sha256 "$MSM5XXX_MA2_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.c"
check_sha256 "$MSM5XXX_MA2_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.h"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-audio-synth.c"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-audio-synth.h"
check_sha256 "$MSM5XXX_MA5_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.c"
check_sha256 "$MSM5XXX_MA5_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.h"

cat > "$OUTPUT/MSM5XXX_STAGING_INFO" <<EOF
QEMU_VERSION=$QEMU_VERSION
QEMU_ARCHIVE_SHA256=$QEMU_ARCHIVE_SHA256
QEMU_DTC_URL=$QEMU_DTC_URL
QEMU_DTC_REVISION=$QEMU_DTC_REVISION
MSM5XXX_ICOUNT_PATCH_SHA256=$MSM5XXX_ICOUNT_PATCH_SHA256
MSM5XXX_CFI02_PATCH_SHA256=$MSM5XXX_CFI02_PATCH_SHA256
MSM5XXX_ANDROID_PATCH_SHA256=$MSM5XXX_ANDROID_PATCH_SHA256
MSM5XXX_MACHINE_SHA256=$MSM5XXX_MACHINE_SHA256
MSM5XXX_MA2_CORE_SHA256=$MSM5XXX_MA2_CORE_SHA256
MSM5XXX_MA2_HEADER_SHA256=$MSM5XXX_MA2_HEADER_SHA256
MSM5XXX_AUDIO_SYNTH_CORE_SHA256=$MSM5XXX_AUDIO_SYNTH_CORE_SHA256
MSM5XXX_AUDIO_SYNTH_HEADER_SHA256=$MSM5XXX_AUDIO_SYNTH_HEADER_SHA256
MSM5XXX_MA5_CORE_SHA256=$MSM5XXX_MA5_CORE_SHA256
MSM5XXX_MA5_HEADER_SHA256=$MSM5XXX_MA5_HEADER_SHA256
MSM5XXX_TRANSPORT_SHA256=$MSM5XXX_TRANSPORT_SHA256
EOF
