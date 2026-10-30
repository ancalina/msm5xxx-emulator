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
ios/build_qemu_framework.sh /new/qemu-work/build ios/app/Frameworks/iphoneos   # or iphonesimulator
```

`ios/app/MSM5xEmu.xcodeproj` (bundle id `me.ancal.msm5xemu`) is the SwiftUI shell: firmware import,
LCD placeholder, keypad and engine status. It embeds `ios/app/Frameworks/$PLATFORM_NAME/QEMU.framework`
when present and loads it at launch. Still missing: embedded Python (detector/transport), running
a guest from the app (QEMU currently exits the process on shutdown) and LCD/input wiring.
