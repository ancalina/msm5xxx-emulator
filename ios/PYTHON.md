Embedded CPython preparation (Mac only)
=====================================

`build_python_ios.sh` assembles a relocatable Python.xcframework runtime; it
neither builds nor runs Python on Linux. Full Xcode, an iOS simulator SDK, curl,
and Apple's shell tools are required. Run from the repository root:

```sh
# Set these to your existing pinned source archives (no firmware required).
ARCHIVES=/absolute/path/to/dependency-archives
QEMU_ARCHIVE=/absolute/path/to/qemu-10.2.1.tar.xz
DTC_ARCHIVE=/absolute/path/to/dtc.tar
# Use new work directories. Rebuild old QEMU frameworks: they lack the exit guard.
for target in iphoneos iphonesimulator; do
  case "$target" in iphoneos) arch=arm64 ;; iphonesimulator) arch=x86_64 ;; esac
  nice -n 19 ios/build_glib_ios.sh "$target" "$arch" "$ARCHIVES" "$PWD/work/glib-$target-python"
  for mode in tcg tci; do
    case "$mode" in tcg) name=QEMU ;; tci) name=QEMUTCI ;; esac
    nice -n 19 ios/build_qemu_ios.sh "$target" "$arch" "$mode" "$QEMU_ARCHIVE" "$DTC_ARCHIVE" \
      "$PWD/work/glib-$target-python/prefix/usr/local" "$PWD/work/qemu-$target-$mode-python"
    nice -n 19 ios/build_qemu_framework.sh "$PWD/work/qemu-$target-$mode-python/build" \
      "ios/app/Frameworks/$target" "$name"
  done
done
nice -n 19 ios/build_python_ios.sh "$PWD/work/python-ios-b14"
nice -n 19 xcodebuild -project ios/app/MSM5xEmu.xcodeproj -target MSM5xEmu \
  -configuration Debug -sdk iphonesimulator -arch x86_64 -jobs 2 \
  CODE_SIGNING_ALLOWED=NO SYMROOT="$PWD/work/ios-python-build" build
nice -n 19 xcodebuild -project ios/app/MSM5xEmu.xcodeproj -target MSM5xEmu \
  -configuration Release -sdk iphoneos -arch arm64 -jobs 2 \
  CODE_SIGNING_ALLOWED=NO SYMROOT="$PWD/work/ios-python-build" build
```

The preparation output is `ios/app/Python.xcframework`. It includes arm64 device
and arm64/x86_64 simulator slices. The app still targets iOS 15.0; the script
rejects library or extension deployment requirements above 15.0. The simulator
command requires an Intel simulator runtime and the x86_64 QEMU frameworks.
The device app must be signed before installation; use your usual signing or
`ios/package_ios.sh` packaging flow. No simulator or device is launched by these
commands. Build output is limited to two jobs.

Pinned binary distribution
--------------------------

* URL: <https://github.com/beeware/Python-Apple-support/releases/download/3.14-b14/Python-3.14-iOS-support.b14.tar.gz>
* SHA256: `703ff822529f46edcbcd8b88096b2544f6990f3109ad38b4b4b61bb489a7c1ee`
* Release: <https://github.com/beeware/Python-Apple-support/releases/tag/3.14-b14>
* Digest metadata: <https://api.github.com/repos/beeware/Python-Apple-support/releases/tags/3.14-b14>

This is BeeWare's distribution of **CPython 3.14.10 using the official PEP 730
iOS port**, not a python.org binary release. Python 3.14 does not have an official
python.org iOS XCframework download. The support package bundles CPython and its
native dependencies; the single archive digest pins those binaries together.
No pip packages are fetched, no numpy is bundled. The build script verifies the
archive before extraction. Update the URL and digest together when intentionally
upgrading; do not substitute an unverified local XCframework.

The integration follows [CPython's iOS embedding instructions](https://docs.python.org/3.14/using/ios.html)
and [the distributor's usage guide](https://github.com/beeware/Python-Apple-support/blob/3.14/USAGE.md).
The official port can instead be built from source using
[CPython's Apple build instructions](https://github.com/python/cpython/blob/3.14/Apple/iOS/README.md),
but that is a separate dependency build and is not executed by this script.

Bundle layout and validation
----------------------------

The Xcode build phase calls `ios/build_python_ios.sh --install-bundle`. It copies
`src/msm5xxx_emulator`, `ios/python/*.py` and the shared Android Python runtime
module into `python/lib/python3.14/site-packages/` (using a temporary `app/`
staging directory during installation). The standard library lives in
`python/lib/python3.14/`. CPython's pinned `build/utils.sh` installer moves every
standard-library extension into a signed framework under `Frameworks/`, leaving
PEP 730 `.fwork` references under `lib-dynload`. Copying only the stdlib's `.so`
files into Resources is insufficient on iOS. Signing-disabled builds use ad-hoc
signatures for these extension frameworks; final packaging signs all frameworks.

Verify on Mac/device: imports of `_socket`, `_struct`, `_hashlib`/`hashlib`,
`array`, and the shared detector/decoder; successful detector admission/rejection;
LCD frame updates and key release; QEMU framework architecture; shutdown without
app termination; app restart after closing a session. Python initialization and
extension loading have not been run on Linux. The existing detector/decoder path
has no numpy imports; the Android wrapper's optional dependency probe is bypassed
by the iOS wrapper.

In-process shutdown and limits
-----------------------------

The iOS-only QEMU patch makes normal `qemu_entry` shutdown return a status after
`qemu_cleanup`, including exit notifiers. It redirects QEMU translation units'
`exit`, `_exit` and `_Exit` to `pthread_exit`, and suppresses process `atexit`
registration. UIKit keeps its main run loop; QEMU runs directly on the bridge's
worker. TCG defaults to split W/X mapping on iOS. The exported embedding ABI
marker makes the app reject old unsafe frameworks.

The host quit callback schedules a bottom half on QEMU's main AioContext to
request `SHUTDOWN_CAUSE_HOST_QMP_QUIT`; the Python caller never waits for BQL.
`-no-shutdown` preserves guest shutdown behavior, while host quit still exits the
emulation loop. Native NAND's existing QMP quit uses the same safe cleanup path.
The process-like handle never sends POSIX signals or cancels native threads.
If shutdown times out, resources remain owned and the app must be relaunched.

One QEMU invocation is allowed per app lifetime, including failed initialization.
QEMU globals, remaining worker threads and fatal-path allocations cannot safely be
reinitialized or unloaded. Fatal exits on other native threads may leave QEMU
unusable; this protects QEMU's direct exit calls, not assertions/abort, crashes,
or process termination inside third-party libraries. No global libc interposing
or longjmp across QEMU frames is used. Device validation of clean quit and NAND
persistence is required. Audio playback and virtual networking are disabled in
the initial iOS adapter; the shared transport still provides their existing paths.

After a signed device build, choose firmware, tap Run, check display progress and
supported keys (including release), then Stop. The app must stay open; relaunch
before the next session. Check both TCI without JIT and TCG with JIT, rejected and
accepted detector inputs, extension imports, and writable-state restoration.
