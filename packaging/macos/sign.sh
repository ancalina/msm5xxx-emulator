#!/bin/bash
set -euo pipefail
python3 - "$1" "${MSM5XXX_SIGN_IDENTITY:--}" "$(dirname "$0")/runtime-entitlements.plist" <<'PY'
from pathlib import Path
import subprocess
import sys
application,identity,entitlements=sys.argv[1:]
root=Path(application)
arguments=['codesign','--force','--sign',identity]
if identity!='-':arguments+=['--options','runtime','--timestamp']
# Inspect magic bytes directly; do not launch a process for each Python resource.
magic={bytes.fromhex(value) for value in ['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca']}
for path in (root/'Contents').rglob('*'):
    if not path.is_file() or path.is_symlink():continue
    with path.open('rb') as stream:header=stream.read(4)
    if header in magic:
        python_binary=path.parent==root/'Contents/Resources/runtime/python/bin' and path.name.startswith('python3')
        # QEMU TCG and Python ctypes callbacks allocate executable memory.
        extra=['--entitlements',entitlements] if path.name=='qemu-system-arm' or python_binary else []
        # Sparkle's sandboxed downloader keeps its network-client entitlement.
        if 'Downloader.xpc' in path.parts:extra+=['--preserve-metadata=entitlements']
        subprocess.run([*arguments,*extra,str(path)],check=True)
# Code precedes its containing bundles; never use --deep to sign a release.
bundles=(p for p in root.rglob('*') if p.is_dir() and not p.is_symlink() and p.suffix in {'.app','.xpc','.framework'})
for path in sorted(bundles,key=lambda p:len(p.parts),reverse=True):
    extra=['--preserve-metadata=entitlements'] if path.name=='Downloader.xpc' else []
    subprocess.run([*arguments,*extra,str(path)],check=True)
subprocess.run([*arguments,str(root)],check=True)
subprocess.run(['codesign','--verify','--deep','--strict','--verbose=2',str(root)],check=True)
PY
