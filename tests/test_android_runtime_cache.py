"""Cached APK builds must reject stale native inputs, binaries and dependencies."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


class AndroidRuntimeCacheTests(unittest.TestCase):
    def test_reuse_rejects_native_and_dependency_mutations(self):
        path = Path(__file__).parents[1] / 'android-client/runtime_cache.py'
        spec = importlib.util.spec_from_file_location('android_runtime_cache', path)
        cache = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cache)
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            cache.REPO = repo
            cache.ROOT = repo / 'android-client'
            cache.GENERATED = cache.ROOT / 'build/generated'
            tree = repo / 'experiments/qemu-tcg'
            jni = cache.GENERATED / 'jniLibs/arm64-v8a'
            assets = cache.GENERATED / 'python-assets/python/lib/python3.14'
            tools = repo / 'sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin'
            files = [cache.ROOT / 'build_qemu_android.sh', cache.ROOT / 'build_glib_android.sh',
                     tree / 'stage_qemu_source.sh',
                     tree / 'qemu-10.2.1-icount-advance.patch',
                     tree / 'qemu-10.2.1-cfi02-write-while-suspended.patch',
                     tree / 'qemu-10.2.1-android-host.patch', tree / 'msm5xxx-poc.c',
                     assets / 'os.py']
            files += [jni / name for name in ('libqemu-system-arm.so', 'libglib-2.0.so',
                      'libintl.so', 'libpython3.14.so', 'libunicorn.so', 'libc++_shared.so')]
            files += [tools / name for name in ('aarch64-linux-android28-clang',
                      'aarch64-linux-android28-clang++', 'clang', 'llvm-strip', 'llvm-readelf')]
            for p in files:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'fixture')
            settings = tree / 'qemu_build_inputs.env'
            settings.write_text('QEMU_VERSION=test\nMSM5XXX_TRANSPORT_SHA256=old\n')
            with mock.patch.dict(os.environ, {'ANDROID_SDK_ROOT': str(repo / 'sdk')}):
                cache.main('native')
                cache.main('dependencies')
                cache.main('verify')
                # Common Python edits must not force a native rebuild.
                settings.write_text('QEMU_VERSION=test\nMSM5XXX_TRANSPORT_SHA256=new\n')
                cache.main('verify')
                for p in (cache.ROOT / 'build_glib_android.sh', tree / 'msm5xxx-poc.c',
                          jni / 'libqemu-system-arm.so',
                          assets / 'os.py'):
                    p.write_bytes(b'mutated')
                    with self.assertRaisesRegex(RuntimeError, 'runtime cache mismatch'):
                        cache.main('verify')
                    p.write_bytes(b'fixture')
                cache.main('verify')


if __name__ == '__main__':
    unittest.main()
