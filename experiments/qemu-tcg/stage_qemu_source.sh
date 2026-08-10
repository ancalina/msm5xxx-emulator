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
MACHINE="$ROOT/msm5xxx-poc.c"
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

for file in "$ARCHIVE" "$PATCH" "$MACHINE" "$TRANSPORT"; do
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
check_sha256 "$MSM5XXX_MACHINE_SHA256" "$MACHINE"
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
cp "$MACHINE" "$OUTPUT/hw/arm/msm5xxx-poc.c"
printf "\narm_common_ss.add(files('msm5xxx-poc.c'))\n" >> "$OUTPUT/hw/arm/meson.build"

test "$(grep -Fc "arm_common_ss.add(files('msm5xxx-poc.c'))" "$OUTPUT/hw/arm/meson.build")" -eq 1
cmp "$MACHINE" "$OUTPUT/hw/arm/msm5xxx-poc.c"
check_sha256 "$MSM5XXX_MACHINE_SHA256" "$OUTPUT/hw/arm/msm5xxx-poc.c"

cat > "$OUTPUT/MSM5XXX_STAGING_INFO" <<EOF
QEMU_VERSION=$QEMU_VERSION
QEMU_ARCHIVE_SHA256=$QEMU_ARCHIVE_SHA256
QEMU_DTC_URL=$QEMU_DTC_URL
QEMU_DTC_REVISION=$QEMU_DTC_REVISION
MSM5XXX_ICOUNT_PATCH_SHA256=$MSM5XXX_ICOUNT_PATCH_SHA256
MSM5XXX_ANDROID_PATCH_SHA256=$MSM5XXX_ANDROID_PATCH_SHA256
MSM5XXX_MACHINE_SHA256=$MSM5XXX_MACHINE_SHA256
MSM5XXX_TRANSPORT_SHA256=$MSM5XXX_TRANSPORT_SHA256
EOF
