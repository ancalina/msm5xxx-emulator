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
DSOUND_PATCH="$ROOT/qemu-10.2.1-dsound-playback-only.patch"
MACHINE="$ROOT/msm5xxx-poc.c"
AUDIO_REQUEST_CORE="$ROOT/msm5xxx-audio-request.c"
AUDIO_REQUEST_HEADER="$ROOT/msm5xxx-audio-request.h"
MA2_CORE="$ROOT/msm5xxx-ma2-audio.c"
MA2_HEADER="$ROOT/msm5xxx-ma2-audio.h"
AUDIO_SYNTH_CORE="$ROOT/msm5xxx-audio-synth.c"
AUDIO_SYNTH_HEADER="$ROOT/msm5xxx-audio-synth.h"
MA5_CORE="$ROOT/msm5xxx-ma5-audio.c"
MA5_HEADER="$ROOT/msm5xxx-ma5-audio.h"
MA5_GAIN_CORE="$ROOT/msm5xxx-ma5-gain.c"
MA5_GAIN_HEADER="$ROOT/msm5xxx-ma5-gain.h"
MA5_WT_CORE="$ROOT/msm5xxx-ma5-wt-engine.c"
MA5_WT_HEADER="$ROOT/msm5xxx-ma5-wt-engine.h"
MA5_FM_VOICE_CORE="$ROOT/msm5xxx-ma5-fm-voice.c"
MA5_FM_VOICE_HEADER="$ROOT/msm5xxx-ma5-fm-voice.h"
MA5_OPERATOR_CORE="$ROOT/msm5xxx-ma5-operator.c"
MA5_OPERATOR_HEADER="$ROOT/msm5xxx-ma5-operator.h"
MA5_WAVEFORM_CORE="$ROOT/msm5xxx-ma5-waveform.c"
MA5_WAVEFORM_HEADER="$ROOT/msm5xxx-ma5-waveform.h"
MA5_PCM_QUEUE_CORE="$ROOT/msm5xxx-ma5-pcm-queue.c"
MA5_PCM_QUEUE_HEADER="$ROOT/msm5xxx-ma5-pcm-queue.h"
MA5_RATECONV_CORE="$ROOT/msm5xxx-ma5-rateconv.c"
MA5_RATECONV_HEADER="$ROOT/msm5xxx-ma5-rateconv.h"
MA5_PCM_OUTPUT_CORE="$ROOT/msm5xxx-ma5-pcm-output.c"
MA5_PCM_OUTPUT_HEADER="$ROOT/msm5xxx-ma5-pcm-output.h"
SMALL_NAND_CORE="$ROOT/msm5xxx-small-page-nand.c"
SPI_NV_CORE="$ROOT/msm5xxx-spi-nv.c"
SMALL_NAND_HEADER="$ROOT/msm5xxx-small-page-nand.h"
SPI_NV_HEADER="$ROOT/msm5xxx-spi-nv.h"
PROTECTED_NOR_CORE="$ROOT/msm5xxx-protected-nor.c"
PROTECTED_NOR_HEADER="$ROOT/msm5xxx-protected-nor.h"
SEARCH2_CORE="$ROOT/msm5xxx-search2.c"
SEARCH2_HEADER="$ROOT/msm5xxx-search2.h"
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

for file in "$ARCHIVE" "$PATCH" "$CFI02_PATCH" "$DSOUND_PATCH" "$MACHINE" \
        "$AUDIO_REQUEST_CORE" "$AUDIO_REQUEST_HEADER" \
        "$MA2_CORE" "$MA2_HEADER" \
        "$AUDIO_SYNTH_CORE" "$AUDIO_SYNTH_HEADER" \
        "$MA5_CORE" "$MA5_HEADER" "$MA5_GAIN_CORE" "$MA5_GAIN_HEADER" \
        "$MA5_WT_CORE" "$MA5_WT_HEADER" "$MA5_PCM_QUEUE_CORE" \
        "$MA5_FM_VOICE_CORE" "$MA5_FM_VOICE_HEADER" \
        "$MA5_OPERATOR_CORE" "$MA5_OPERATOR_HEADER" \
        "$MA5_WAVEFORM_CORE" "$MA5_WAVEFORM_HEADER" \
        "$MA5_PCM_QUEUE_HEADER" "$MA5_RATECONV_CORE" "$MA5_RATECONV_HEADER" \
        "$MA5_PCM_OUTPUT_CORE" "$MA5_PCM_OUTPUT_HEADER" \
        "$SMALL_NAND_CORE" "$SMALL_NAND_HEADER" \
        "$SPI_NV_CORE" "$SPI_NV_HEADER" \
        "$PROTECTED_NOR_CORE" "$PROTECTED_NOR_HEADER" \
        "$SEARCH2_CORE" "$SEARCH2_HEADER" "$TRANSPORT"; do
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
check_sha256 "$MSM5XXX_DSOUND_PATCH_SHA256" "$DSOUND_PATCH"
check_sha256 "$MSM5XXX_MACHINE_SHA256" "$MACHINE"
check_sha256 "$MSM5XXX_AUDIO_REQUEST_CORE_SHA256" "$AUDIO_REQUEST_CORE"
check_sha256 "$MSM5XXX_MA2_CORE_SHA256" "$MA2_CORE"
check_sha256 "$MSM5XXX_AUDIO_REQUEST_HEADER_SHA256" "$AUDIO_REQUEST_HEADER"
check_sha256 "$MSM5XXX_MA2_HEADER_SHA256" "$MA2_HEADER"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_CORE_SHA256" "$AUDIO_SYNTH_CORE"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_HEADER_SHA256" "$AUDIO_SYNTH_HEADER"
check_sha256 "$MSM5XXX_MA5_CORE_SHA256" "$MA5_CORE"
check_sha256 "$MSM5XXX_MA5_HEADER_SHA256" "$MA5_HEADER"
check_sha256 "$MSM5XXX_MA5_GAIN_CORE_SHA256" "$MA5_GAIN_CORE"
check_sha256 "$MSM5XXX_MA5_GAIN_HEADER_SHA256" "$MA5_GAIN_HEADER"
check_sha256 "$MSM5XXX_MA5_WT_CORE_SHA256" "$MA5_WT_CORE"
check_sha256 "$MSM5XXX_MA5_WT_HEADER_SHA256" "$MA5_WT_HEADER"
check_sha256 "$MSM5XXX_MA5_FM_VOICE_CORE_SHA256" "$MA5_FM_VOICE_CORE"
check_sha256 "$MSM5XXX_MA5_FM_VOICE_HEADER_SHA256" "$MA5_FM_VOICE_HEADER"
check_sha256 "$MSM5XXX_MA5_OPERATOR_CORE_SHA256" "$MA5_OPERATOR_CORE"
check_sha256 "$MSM5XXX_MA5_OPERATOR_HEADER_SHA256" "$MA5_OPERATOR_HEADER"
check_sha256 "$MSM5XXX_MA5_WAVEFORM_CORE_SHA256" "$MA5_WAVEFORM_CORE"
check_sha256 "$MSM5XXX_MA5_WAVEFORM_HEADER_SHA256" "$MA5_WAVEFORM_HEADER"
check_sha256 "$MSM5XXX_MA5_PCM_QUEUE_CORE_SHA256" "$MA5_PCM_QUEUE_CORE"
check_sha256 "$MSM5XXX_MA5_PCM_QUEUE_HEADER_SHA256" "$MA5_PCM_QUEUE_HEADER"
check_sha256 "$MSM5XXX_MA5_RATECONV_CORE_SHA256" "$MA5_RATECONV_CORE"
check_sha256 "$MSM5XXX_MA5_RATECONV_HEADER_SHA256" "$MA5_RATECONV_HEADER"
check_sha256 "$MSM5XXX_MA5_PCM_OUTPUT_CORE_SHA256" "$MA5_PCM_OUTPUT_CORE"
check_sha256 "$MSM5XXX_MA5_PCM_OUTPUT_HEADER_SHA256" "$MA5_PCM_OUTPUT_HEADER"
check_sha256 "$MSM5XXX_SMALL_NAND_CORE_SHA256" "$SMALL_NAND_CORE"
check_sha256 "$MSM5XXX_SPI_NV_CORE_SHA256" "$SPI_NV_CORE"
check_sha256 "$MSM5XXX_SMALL_NAND_HEADER_SHA256" "$SMALL_NAND_HEADER"
check_sha256 "$MSM5XXX_SPI_NV_HEADER_SHA256" "$SPI_NV_HEADER"
check_sha256 "$MSM5XXX_PROTECTED_NOR_CORE_SHA256" "$PROTECTED_NOR_CORE"
check_sha256 "$MSM5XXX_PROTECTED_NOR_HEADER_SHA256" "$PROTECTED_NOR_HEADER"
check_sha256 "$MSM5XXX_SEARCH2_CORE_SHA256" "$SEARCH2_CORE"
check_sha256 "$MSM5XXX_SEARCH2_HEADER_SHA256" "$SEARCH2_HEADER"
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
patch -p1 -d "$OUTPUT" < "$DSOUND_PATCH"
cp "$MACHINE" "$OUTPUT/hw/arm/msm5xxx-poc.c"
cp "$AUDIO_REQUEST_CORE" "$OUTPUT/hw/arm/msm5xxx-audio-request.c"
cp "$MA2_CORE" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.c"
cp "$AUDIO_REQUEST_HEADER" "$OUTPUT/hw/arm/msm5xxx-audio-request.h"
cp "$MA2_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.h"
cp "$AUDIO_SYNTH_CORE" "$OUTPUT/hw/arm/msm5xxx-audio-synth.c"
cp "$AUDIO_SYNTH_HEADER" "$OUTPUT/hw/arm/msm5xxx-audio-synth.h"
cp "$MA5_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.c"
cp "$MA5_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.h"
cp "$MA5_GAIN_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-gain.c"
cp "$MA5_GAIN_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-gain.h"
cp "$MA5_WT_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-wt-engine.c"
cp "$MA5_WT_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-wt-engine.h"
cp "$MA5_FM_VOICE_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-fm-voice.c"
cp "$MA5_FM_VOICE_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-fm-voice.h"
cp "$MA5_OPERATOR_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-operator.c"
cp "$MA5_OPERATOR_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-operator.h"
cp "$MA5_WAVEFORM_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-waveform.c"
cp "$MA5_WAVEFORM_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-waveform.h"
cp "$MA5_PCM_QUEUE_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-queue.c"
cp "$MA5_PCM_QUEUE_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-queue.h"
cp "$MA5_RATECONV_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-rateconv.c"
cp "$MA5_RATECONV_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-rateconv.h"
cp "$MA5_PCM_OUTPUT_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-output.c"
cp "$MA5_PCM_OUTPUT_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-output.h"
cp "$SMALL_NAND_CORE" "$OUTPUT/hw/arm/msm5xxx-small-page-nand.c"
cp "$SPI_NV_CORE" "$OUTPUT/hw/arm/msm5xxx-spi-nv.c"
cp "$SMALL_NAND_HEADER" "$OUTPUT/hw/arm/msm5xxx-small-page-nand.h"
cp "$SPI_NV_HEADER" "$OUTPUT/hw/arm/msm5xxx-spi-nv.h"
cp "$PROTECTED_NOR_CORE" "$OUTPUT/hw/arm/msm5xxx-protected-nor.c"
cp "$PROTECTED_NOR_HEADER" "$OUTPUT/hw/arm/msm5xxx-protected-nor.h"
cp "$SEARCH2_CORE" "$OUTPUT/hw/arm/msm5xxx-search2.c"
cp "$SEARCH2_HEADER" "$OUTPUT/hw/arm/msm5xxx-search2.h"
{
    printf '%s\n' '# Modified by MSM5xxx emulator contributors, 2026-10-02: register the MSM5xxx machine and audio sources.'
    cat "$OUTPUT/hw/arm/meson.build"
} > "$OUTPUT/hw/arm/meson.build.msm5xxx"
mv "$OUTPUT/hw/arm/meson.build.msm5xxx" "$OUTPUT/hw/arm/meson.build"
printf "\narm_common_ss.add(files('msm5xxx-poc.c', 'msm5xxx-audio-request.c', 'msm5xxx-audio-synth.c', 'msm5xxx-ma2-audio.c', 'msm5xxx-ma5-audio.c', 'msm5xxx-ma5-gain.c', 'msm5xxx-ma5-wt-engine.c', 'msm5xxx-ma5-fm-voice.c', 'msm5xxx-ma5-operator.c', 'msm5xxx-ma5-waveform.c', 'msm5xxx-ma5-pcm-queue.c', 'msm5xxx-ma5-rateconv.c', 'msm5xxx-ma5-pcm-output.c', 'msm5xxx-search2.c', 'msm5xxx-small-page-nand.c', 'msm5xxx-spi-nv.c', 'msm5xxx-protected-nor.c'))\n" >> "$OUTPUT/hw/arm/meson.build"

test "$(grep -Fc "arm_common_ss.add(files('msm5xxx-poc.c', 'msm5xxx-audio-request.c', 'msm5xxx-audio-synth.c', 'msm5xxx-ma2-audio.c', 'msm5xxx-ma5-audio.c', 'msm5xxx-ma5-gain.c', 'msm5xxx-ma5-wt-engine.c', 'msm5xxx-ma5-fm-voice.c', 'msm5xxx-ma5-operator.c', 'msm5xxx-ma5-waveform.c', 'msm5xxx-ma5-pcm-queue.c', 'msm5xxx-ma5-rateconv.c', 'msm5xxx-ma5-pcm-output.c', 'msm5xxx-search2.c', 'msm5xxx-small-page-nand.c', 'msm5xxx-spi-nv.c', 'msm5xxx-protected-nor.c'))" "$OUTPUT/hw/arm/meson.build")" -eq 1
cmp "$MACHINE" "$OUTPUT/hw/arm/msm5xxx-poc.c"
cmp "$AUDIO_REQUEST_CORE" "$OUTPUT/hw/arm/msm5xxx-audio-request.c"
cmp "$MA2_CORE" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.c"
cmp "$AUDIO_REQUEST_HEADER" "$OUTPUT/hw/arm/msm5xxx-audio-request.h"
cmp "$MA2_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.h"
cmp "$AUDIO_SYNTH_CORE" "$OUTPUT/hw/arm/msm5xxx-audio-synth.c"
cmp "$AUDIO_SYNTH_HEADER" "$OUTPUT/hw/arm/msm5xxx-audio-synth.h"
cmp "$MA5_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.c"
cmp "$MA5_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.h"
cmp "$MA5_GAIN_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-gain.c"
cmp "$MA5_GAIN_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-gain.h"
cmp "$MA5_WT_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-wt-engine.c"
cmp "$MA5_WT_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-wt-engine.h"
cmp "$MA5_FM_VOICE_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-fm-voice.c"
cmp "$MA5_FM_VOICE_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-fm-voice.h"
cmp "$MA5_OPERATOR_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-operator.c"
cmp "$MA5_OPERATOR_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-operator.h"
cmp "$MA5_WAVEFORM_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-waveform.c"
cmp "$MA5_WAVEFORM_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-waveform.h"
cmp "$MA5_PCM_QUEUE_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-queue.c"
cmp "$MA5_PCM_QUEUE_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-queue.h"
cmp "$MA5_RATECONV_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-rateconv.c"
cmp "$MA5_RATECONV_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-rateconv.h"
cmp "$MA5_PCM_OUTPUT_CORE" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-output.c"
cmp "$MA5_PCM_OUTPUT_HEADER" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-output.h"
cmp "$SMALL_NAND_CORE" "$OUTPUT/hw/arm/msm5xxx-small-page-nand.c"
cmp "$SPI_NV_CORE" "$OUTPUT/hw/arm/msm5xxx-spi-nv.c"
cmp "$SMALL_NAND_HEADER" "$OUTPUT/hw/arm/msm5xxx-small-page-nand.h"
cmp "$SPI_NV_HEADER" "$OUTPUT/hw/arm/msm5xxx-spi-nv.h"
cmp "$PROTECTED_NOR_CORE" "$OUTPUT/hw/arm/msm5xxx-protected-nor.c"
cmp "$PROTECTED_NOR_HEADER" "$OUTPUT/hw/arm/msm5xxx-protected-nor.h"
cmp "$SEARCH2_CORE" "$OUTPUT/hw/arm/msm5xxx-search2.c"
cmp "$SEARCH2_HEADER" "$OUTPUT/hw/arm/msm5xxx-search2.h"
check_sha256 "$MSM5XXX_MACHINE_SHA256" "$OUTPUT/hw/arm/msm5xxx-poc.c"
check_sha256 "$MSM5XXX_AUDIO_REQUEST_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-audio-request.c"
check_sha256 "$MSM5XXX_MA2_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.c"
check_sha256 "$MSM5XXX_AUDIO_REQUEST_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-audio-request.h"
check_sha256 "$MSM5XXX_MA2_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma2-audio.h"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-audio-synth.c"
check_sha256 "$MSM5XXX_AUDIO_SYNTH_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-audio-synth.h"
check_sha256 "$MSM5XXX_MA5_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.c"
check_sha256 "$MSM5XXX_MA5_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-audio.h"
check_sha256 "$MSM5XXX_MA5_GAIN_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-gain.c"
check_sha256 "$MSM5XXX_MA5_GAIN_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-gain.h"
check_sha256 "$MSM5XXX_MA5_WT_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-wt-engine.c"
check_sha256 "$MSM5XXX_MA5_WT_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-wt-engine.h"
check_sha256 "$MSM5XXX_MA5_FM_VOICE_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-fm-voice.c"
check_sha256 "$MSM5XXX_MA5_FM_VOICE_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-fm-voice.h"
check_sha256 "$MSM5XXX_MA5_OPERATOR_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-operator.c"
check_sha256 "$MSM5XXX_MA5_OPERATOR_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-operator.h"
check_sha256 "$MSM5XXX_MA5_WAVEFORM_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-waveform.c"
check_sha256 "$MSM5XXX_MA5_WAVEFORM_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-waveform.h"
check_sha256 "$MSM5XXX_MA5_PCM_QUEUE_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-queue.c"
check_sha256 "$MSM5XXX_MA5_PCM_QUEUE_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-queue.h"
check_sha256 "$MSM5XXX_MA5_RATECONV_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-rateconv.c"
check_sha256 "$MSM5XXX_MA5_RATECONV_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-rateconv.h"
check_sha256 "$MSM5XXX_MA5_PCM_OUTPUT_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-output.c"
check_sha256 "$MSM5XXX_MA5_PCM_OUTPUT_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-ma5-pcm-output.h"
check_sha256 "$MSM5XXX_SMALL_NAND_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-small-page-nand.c"
check_sha256 "$MSM5XXX_SPI_NV_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-spi-nv.c"
check_sha256 "$MSM5XXX_SMALL_NAND_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-small-page-nand.h"
check_sha256 "$MSM5XXX_SPI_NV_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-spi-nv.h"
check_sha256 "$MSM5XXX_PROTECTED_NOR_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-protected-nor.c"
check_sha256 "$MSM5XXX_PROTECTED_NOR_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-protected-nor.h"
check_sha256 "$MSM5XXX_SEARCH2_CORE_SHA256" "$OUTPUT/hw/arm/msm5xxx-search2.c"
check_sha256 "$MSM5XXX_SEARCH2_HEADER_SHA256" "$OUTPUT/hw/arm/msm5xxx-search2.h"

cat > "$OUTPUT/MSM5XXX_STAGING_INFO" <<EOF
QEMU_VERSION=$QEMU_VERSION
QEMU_ARCHIVE_SHA256=$QEMU_ARCHIVE_SHA256
QEMU_DTC_URL=$QEMU_DTC_URL
QEMU_DTC_REVISION=$QEMU_DTC_REVISION
MSM5XXX_ICOUNT_PATCH_SHA256=$MSM5XXX_ICOUNT_PATCH_SHA256
MSM5XXX_CFI02_PATCH_SHA256=$MSM5XXX_CFI02_PATCH_SHA256
MSM5XXX_DSOUND_PATCH_SHA256=$MSM5XXX_DSOUND_PATCH_SHA256
MSM5XXX_ANDROID_PATCH_SHA256=$MSM5XXX_ANDROID_PATCH_SHA256
MSM5XXX_MACHINE_SHA256=$MSM5XXX_MACHINE_SHA256
MSM5XXX_AUDIO_REQUEST_CORE_SHA256=$MSM5XXX_AUDIO_REQUEST_CORE_SHA256
MSM5XXX_MA2_CORE_SHA256=$MSM5XXX_MA2_CORE_SHA256
MSM5XXX_AUDIO_REQUEST_HEADER_SHA256=$MSM5XXX_AUDIO_REQUEST_HEADER_SHA256
MSM5XXX_MA2_HEADER_SHA256=$MSM5XXX_MA2_HEADER_SHA256
MSM5XXX_AUDIO_SYNTH_CORE_SHA256=$MSM5XXX_AUDIO_SYNTH_CORE_SHA256
MSM5XXX_AUDIO_SYNTH_HEADER_SHA256=$MSM5XXX_AUDIO_SYNTH_HEADER_SHA256
MSM5XXX_MA5_CORE_SHA256=$MSM5XXX_MA5_CORE_SHA256
MSM5XXX_MA5_HEADER_SHA256=$MSM5XXX_MA5_HEADER_SHA256
MSM5XXX_MA5_GAIN_CORE_SHA256=$MSM5XXX_MA5_GAIN_CORE_SHA256
MSM5XXX_MA5_GAIN_HEADER_SHA256=$MSM5XXX_MA5_GAIN_HEADER_SHA256
MSM5XXX_MA5_WT_CORE_SHA256=$MSM5XXX_MA5_WT_CORE_SHA256
MSM5XXX_MA5_WT_HEADER_SHA256=$MSM5XXX_MA5_WT_HEADER_SHA256
MSM5XXX_MA5_FM_VOICE_CORE_SHA256=$MSM5XXX_MA5_FM_VOICE_CORE_SHA256
MSM5XXX_MA5_FM_VOICE_HEADER_SHA256=$MSM5XXX_MA5_FM_VOICE_HEADER_SHA256
MSM5XXX_MA5_OPERATOR_CORE_SHA256=$MSM5XXX_MA5_OPERATOR_CORE_SHA256
MSM5XXX_MA5_OPERATOR_HEADER_SHA256=$MSM5XXX_MA5_OPERATOR_HEADER_SHA256
MSM5XXX_MA5_WAVEFORM_CORE_SHA256=$MSM5XXX_MA5_WAVEFORM_CORE_SHA256
MSM5XXX_MA5_WAVEFORM_HEADER_SHA256=$MSM5XXX_MA5_WAVEFORM_HEADER_SHA256
MSM5XXX_MA5_PCM_QUEUE_CORE_SHA256=$MSM5XXX_MA5_PCM_QUEUE_CORE_SHA256
MSM5XXX_MA5_PCM_QUEUE_HEADER_SHA256=$MSM5XXX_MA5_PCM_QUEUE_HEADER_SHA256
MSM5XXX_MA5_RATECONV_CORE_SHA256=$MSM5XXX_MA5_RATECONV_CORE_SHA256
MSM5XXX_MA5_RATECONV_HEADER_SHA256=$MSM5XXX_MA5_RATECONV_HEADER_SHA256
MSM5XXX_MA5_PCM_OUTPUT_CORE_SHA256=$MSM5XXX_MA5_PCM_OUTPUT_CORE_SHA256
MSM5XXX_MA5_PCM_OUTPUT_HEADER_SHA256=$MSM5XXX_MA5_PCM_OUTPUT_HEADER_SHA256
MSM5XXX_SMALL_NAND_CORE_SHA256=$MSM5XXX_SMALL_NAND_CORE_SHA256
MSM5XXX_SPI_NV_CORE_SHA256=$MSM5XXX_SPI_NV_CORE_SHA256
MSM5XXX_SMALL_NAND_HEADER_SHA256=$MSM5XXX_SMALL_NAND_HEADER_SHA256
MSM5XXX_SPI_NV_HEADER_SHA256=$MSM5XXX_SPI_NV_HEADER_SHA256
MSM5XXX_PROTECTED_NOR_CORE_SHA256=$MSM5XXX_PROTECTED_NOR_CORE_SHA256
MSM5XXX_PROTECTED_NOR_HEADER_SHA256=$MSM5XXX_PROTECTED_NOR_HEADER_SHA256
MSM5XXX_SEARCH2_CORE_SHA256=$MSM5XXX_SEARCH2_CORE_SHA256
MSM5XXX_SEARCH2_HEADER_SHA256=$MSM5XXX_SEARCH2_HEADER_SHA256
MSM5XXX_TRANSPORT_SHA256=$MSM5XXX_TRANSPORT_SHA256
EOF
