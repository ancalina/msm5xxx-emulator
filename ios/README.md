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

`ios/app/MSM5xEmu.xcodeproj` (bundle id `me.ancal.msm5xemu`) is the SwiftUI shell: firmware import,
LCD placeholder, keypad and engine status. It embeds `ios/app/Frameworks/$PLATFORM_NAME/QEMU.framework`
when present and loads it at launch. Still missing: embedded Python (detector/transport), running
a guest from the app (QEMU currently exits the process on shutdown) and LCD/input wiring.
