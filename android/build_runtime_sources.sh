#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
inputs=${ANDROID_INPUTS:-$root/build}
out=${1:?usage: build_runtime_sources.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d "$TMPDIR/android-sources.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/source-companion/sources" "$out"
cd "$inputs/vendor-downloads"
sha256sum -c <<'SUMS'
d923c51303e38e249136fc1bdf3568d56ecb03214efdef48516176d3d7faaef8  Python-3.14.4.tar.xz
51ab804c56f6eab3e5045c774d1290ac5e4c923d4f9a3d8e33123bee45c1840e  glib-2.88.1.tar.xz
d66c56ad259a82cf2a9dfc408b32bf5da52371500b84745f7fb8b645712df676  libffi-3.4.4.tar.gz
a48a113e6afea91f5608793bafa7ef2ad481fefbda87ec5069f483de61cb9fa3  numpy-2.5.1.tar.gz
871f18b78e2c77e39aa0a448e135b856c0c71a0398bb1bc779ef59458f83e275  capstone-5.0.7.tar.xz
15fbc5aba6beee0b17aecb04602ae39432393aba1ebd8e39b7cabf7db883299f  pcre2-10.46.tar.bz2
f7a1cbd7579baaf575c66f9d99fb6295e9b0684a28b095967cfda17857595303  proxy-libintl-0.5.tar.gz
SUMS
for src in Python-3.14.4.tar.xz glib-2.88.1.tar.xz libffi-3.4.4.tar.gz numpy-2.5.1.tar.gz capstone-5.0.7.tar.xz pcre2-10.46.tar.bz2 proxy-libintl-0.5.tar.gz; do
  tar -xf "$src" -C "$work/source-companion/sources"
done
python3 - "$work/source-companion" <<'PY'
from pathlib import Path
import shutil,sys
p=Path(sys.argv[1])
for f in p.rglob('.gitignore'): f.unlink()
for f in p.rglob('*_policy.rst'): f.unlink()
for d in sorted(p.rglob('*'),key=lambda x:len(x.parts),reverse=True):
    if d.is_dir() and (d.name.lower() in ('test','tests','testdata','test cases','__pycache__') or d.name.lower().startswith('testsuite') or d.name.lower().endswith('-tests')):
        shutil.rmtree(d)
for f in p.rglob('*'):
    if f.is_file() and (f.suffix.lower() in ('.bin','.rom','.img','.fd','.pyc','.so','.a','.exe') or f.name.startswith('test_')): f.unlink()
(p/'README.md').write_text('Android runtime sources for the 0.1.0 package. Firmware, test suites, and compiled binaries are omitted. QEMU and project sources are provided separately.\n')
PY
taskset -c 0-3 nice -n 19 tar -C "$work" -cJf "$out/MSM5xxx-QEMU-android-runtime-sources.tar.xz" source-companion
