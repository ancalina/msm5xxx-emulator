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
QEMU is relinked as an embeddable framework exporting `qemu_entry(argc, argv)`:
On iOS 26 and later it runs in a fresh bundled extension process per session.
Earlier systems load the framework in the app because their public APIs do not
provide that process-isolation facility.

```sh
ios/build_qemu_framework.sh /new/qemu-work/build ios/app/Frameworks/iphoneos QEMU   # QEMUTCI for a tci build
```

Packages: `ios/package_ios.sh OUT` builds `MSM5xEmu.ipa` and `MSM5xEmu.tipa` (TrollStore).
The IPA requests no custom entitlements and uses TCI without probing JIT; it still needs
the normal signature and provisioning for the intended device. The TIPA requests
`get-task-allow` for optional debugger-assisted JIT. `dynamic-codesigning` is banned on A12+ iOS 15 and makes the app fail to launch.
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
Build the app with Xcode 26 and the iOS 26 SDK. The project embeds the
`QEMUSession` extension and its TCI framework; packaging signs nested frameworks
and the extension before the application. The application's existing iOS 15
minimum has not been raised.

On iOS 26+, Stop, Start, Reboot and firmware changes use fresh QEMU helper
processes while the app stays open. The helper uses TCI independently of the
app's executable-memory permissions. On earlier systems Stop parks the current
machine; Start resets/resumes that same firmware. Arbitrary firmware switching
on those earlier systems still requires reopening the app. If a stopped session
cannot resume or a session ends unexpectedly, reopen the app before starting it again.
The minimum supported version remains iOS 15.

Hardware keyboards use the desktop defaults: arrows, Return (also keypad Enter),
Escape, plus/minus, digits and numeric-pad digits. Manual per-firmware mappings
apply to both touch and physical input. Focus loss and suspension release held
keys. Run the firmware-free input checks on a Mac with:

```sh
swiftc ios/app/MSM5xEmu/HandsetInputState.swift ios/tests/input/main.swift -o /tmp/handset-input-tests
/tmp/handset-input-tests
```

Detailed settings are saved per firmware. While a session is running, choose
**Apply and restart session** to validate and apply changes. On iOS 26 and later
this starts a fresh session. On iOS 15–25, a compatible framebuffer color-format
change can be applied with a reset; changes to machine configuration or device
state take effect after reopening the app. When no session is running, edits
are saved for the next fresh start. Backgrounding still pauses the session.
