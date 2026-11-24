#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mkdir -p "$1" && cd "$1" && pwd)
export TMPDIR="$work/tmp"
mkdir -p "$TMPDIR"
export TEMP="$(cygpath -m "$TMPDIR")" TMP="$(cygpath -m "$TMPDIR")"
source "$root/native/qemu/qemu_build_inputs.env"
archive="$work/qemu-$QEMU_VERSION.tar.xz"
if [ ! -f "$archive" ]; then
  curl -fL --retry 3 "https://download.qemu.org/qemu-$QEMU_VERSION.tar.xz" -o "$archive"
fi
source_dir="$work/qemu-$QEMU_VERSION-msm5xxx"
if [ ! -d "$source_dir" ]; then
  MSYS=winsymlinks:sys "$root/native/qemu/stage_qemu_source.sh" "$archive" "$source_dir"
  git clone "$QEMU_DTC_URL" "$source_dir/subprojects/dtc"
  git -C "$source_dir/subprojects/dtc" checkout --detach "$QEMU_DTC_REVISION"
fi
test "$(git -C "$source_dir/subprojects/dtc" rev-parse HEAD)" = "$QEMU_DTC_REVISION"
mkdir -p "$work/build"
cd "$work/build"
if [ ! -f build.ninja ]; then
  native_work=$(cygpath -m "$work")
  "$source_dir/configure" --target-list=arm-softmmu --without-default-features \
    --enable-dsound --audio-drv-list=dsound --enable-fdt=internal --disable-download \
    --disable-docs --disable-tools --disable-guest-agent --disable-werror \
    --disable-debug-info --enable-strip \
    --extra-cflags="-ffile-prefix-map=$work=. -ffile-prefix-map=$native_work=."
fi
ninja -j4 qemu-system-arm.exe
mkdir -p "$work/runtime/bin"
cp qemu-system-arm.exe "$work/runtime/bin/"
python "$root/packaging/windows/dll-closure.py" "$work/runtime/bin"
cp "$source_dir/COPYING" "$work/runtime/QEMU_COPYING"
cp "$source_dir/COPYING.LIB" "$work/runtime/QEMU_COPYING.LIB"
while IFS= read -r dll; do
  package=$(pacman -Qqo "/mingw64/bin/$dll")
  pacman -Q "$package" >> "$work/runtime/MSYS2_PACKAGES.txt"
  while IFS= read -r license; do
    [ -f "$license" ] || continue
    relative=${license#/mingw64/share/licenses/}
    mkdir -p "$work/runtime/licenses/msys2/$(dirname "$relative")"
    cp "$license" "$work/runtime/licenses/msys2/$relative"
  done < <(pacman -Ql "$package" | awk '$2 ~ /\/share\/licenses\// {print $2}')
done < "$work/runtime/DLLS.txt"
sort -u "$work/runtime/MSYS2_PACKAGES.txt" -o "$work/runtime/MSYS2_PACKAGES.txt"
"$work/runtime/bin/qemu-system-arm.exe" --version
"$work/runtime/bin/qemu-system-arm.exe" -machine help | grep '^msm5xxx-poc '
echo 'QEMU BUILD OK'
