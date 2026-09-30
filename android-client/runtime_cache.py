"""Bind reusable Android runtime outputs to native inputs and frozen assets."""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
GENERATED = ROOT / 'build/generated'


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f'missing/unsafe runtime input: {path.name}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native():
    tree = REPO / 'experiments/qemu-tcg'
    names = ['stage_qemu_source.sh', 'qemu-10.2.1-icount-advance.patch',
             'qemu-10.2.1-cfi02-write-while-suspended.patch',
             'qemu-10.2.1-android-host.patch']
    paths = [tree / name for name in names]
    paths += sorted(tree.glob('msm5xxx-*.c')) + sorted(tree.glob('msm5xxx-*.h'))
    paths += [ROOT / 'build_qemu_android.sh', ROOT / 'build_glib_android.sh']
    inputs = {str(p.relative_to(REPO)): digest(p) for p in paths}
    # Python transport edits do not change native machine code.
    settings = '\n'.join(line for line in (tree / 'qemu_build_inputs.env').read_text().splitlines()
                         if not line.startswith('MSM5XXX_TRANSPORT_SHA256='))
    inputs['native_settings'] = hashlib.sha256(settings.encode()).hexdigest()
    sdk = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME')
    if not sdk:
        raise RuntimeError('set ANDROID_SDK_ROOT or ANDROID_HOME')
    toolchain = Path(sdk) / 'ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin'
    for name in ('aarch64-linux-android28-clang', 'aarch64-linux-android28-clang++',
                 'clang', 'llvm-strip', 'llvm-readelf'):
        # SDK tools can legitimately be symlinks within the installed toolchain.
        inputs['toolchain/' + name] = hashlib.sha256((toolchain / name).read_bytes()).hexdigest()
    jni = GENERATED / 'jniLibs/arm64-v8a'
    outputs = {name: digest(jni / name) for name in
               ('libqemu-system-arm.so', 'libglib-2.0.so', 'libintl.so')}
    return {'inputs': inputs, 'outputs': outputs}


def dependencies():
    assets = GENERATED / 'python-assets'
    site = assets / 'python/lib/python3.14/site-packages'
    project = {'msm5xxx_android_runtime.py', 'qemu_transport.py', 'gdb_remote.py'}
    files = {}
    for p in assets.rglob('*'):
        if p.is_file():
            relative = p.relative_to(site) if p.is_relative_to(site) else None
            if relative and (relative.parts[0] == 'msm5xxx_emulator'
                             or relative.as_posix() in project):
                continue
            if '__pycache__' in p.parts or p.suffix == '.pyc':
                continue
            files[str(p.relative_to(GENERATED))] = digest(p)
    for name in ('libpython3.14.so', 'libunicorn.so', 'libc++_shared.so'):
        p = GENERATED / 'jniLibs/arm64-v8a' / name
        files[str(p.relative_to(GENERATED))] = digest(p)
    if not files:
        raise RuntimeError('prepared dependency assets missing')
    return files


def main(action):
    for kind, snapshot in (('native', native), ('dependencies', dependencies)):
        manifest = GENERATED / f'{kind}-cache.json'
        if action == kind:
            manifest.write_text(json.dumps(snapshot(), sort_keys=True, indent=2))
        elif action == 'verify':
            if not manifest.is_file() or json.loads(manifest.read_text()) != snapshot():
                raise RuntimeError(f'{kind} runtime cache mismatch; rebuild/prepare it first')
    if action not in ('native', 'dependencies', 'verify'):
        raise ValueError('expected native, dependencies or verify')


if __name__ == '__main__':
    main(sys.argv[1])
