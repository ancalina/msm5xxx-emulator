# iOS build (preparation)

Static GLib and `qemu-system-arm` for the iOS simulator or devices. Run on macOS with Xcode and
`meson` on `PATH`. Source archives are the same pinned inputs as the Android build.

```sh
ios/build_glib_ios.sh iphoneos arm64 /path/to/archives /new/glib-work
ios/build_qemu_ios.sh iphoneos arm64 tcg /path/to/qemu-10.2.1.tar.xz /path/to/dtc.tar \
  /new/glib-work/prefix/usr/local /new/qemu-work
```

`tcg` needs JIT on the device (for example enabled through StikJIT) and runs with
`-accel tcg,split-wx=on`; `tci` is the slower interpreter that works without JIT.
iOS cannot spawn processes, so QEMU is relinked as an embeddable framework exporting
`qemu_entry(argc, argv)`:

```sh
ios/build_qemu_framework.sh /new/qemu-work/build ios/app/Frameworks/iphoneos QEMU   # QEMUTCI for a tci build
```

Packages: `ios/package_ios.sh OUT` builds `MSM5xEmu.ipa` and `MSM5xEmu.tipa` (TrollStore), both with
`get-task-allow` only. `dynamic-codesigning` is banned on A12+ iOS 15 and makes the app fail to launch.
JIT comes from a debugger setting CS_DEBUGGED: Dopamine's "Allow JIT in Apps" (verified on iPhone XS,
iOS 15.6.1), TrollStore "Open with JIT", StikJIT, Jitterbug or AltJIT. The app probes JIT the way QEMU's
split-wx TCG uses it (write, then make executable), picks QEMU (TCG) or QEMUTCI, and re-probes while
running. When installing repeatedly with trollstorehelper, use a new file name each time: it reuses
content cached under a previously used path. It needs `ios/app/Frameworks/iphoneos/QEMU.framework` (tcg) and `QEMUTCI.framework` (tci).

`ios/app/MSM5xEmu.xcodeproj` (bundle id `me.ancal.msm5xemu`, iOS 15.0) embeds
CPython and the shared detector/transport. See [PYTHON.md](PYTHON.md) for the pinned
runtime, exact Mac commands, bundle layout and hardware validation. Firmware is
copied into Application Support; Run applies detector admission before launching
QEMU on a background thread. LCD frames and detector-admitted press/release input
use the same protocol as Android. Desktop and Android still use subprocesses.

Rebuild both QEMU variants with this tree's embedding patch. Older frameworks are
rejected by the app's ABI check. Normal shutdown returns through QEMU cleanup;
QEMU's direct exit calls end their calling thread rather than UIKit's process.
One QEMU invocation is supported per app launch; restart the app after Stop.
