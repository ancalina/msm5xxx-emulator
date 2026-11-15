# Android client

The app opens a firmware library with system file and folder pickers, copies imported
files into private storage, and runs the bundled detector before launching QEMU. It displays the
LCD, validates keypad input against the detected profile, and isolates writable
state by firmware SHA-256. Firmware files are never bundled in the app.

With the pinned runtime artifacts present under the ignored `build/` directory,
build and install the arm64-v8a app with Android SDK 35 and Gradle 9.4:

```sh
./build_glib_android.sh /new/glib-build-work
cp -a /new/glib-build-work/prefix build/vendor-install/glib-source-r13
install -m 0755 /new/glib-build-work/runtime/libglib-2.0.so \
  build/vendor-install/glib-source-r13/usr/local/lib/libglib-2.0.so
install -m 0755 /new/glib-build-work/runtime/libintl.so \
  build/vendor-install/glib-source-r13/usr/local/lib/libintl.so
MSM5XXX_DTC_SOURCE=/path/to/pinned/dtc \
  ./build_qemu_android.sh /new/qemu-build-work
./build_numpy_android.sh
./build_capstone_android.sh
./prepare_runtime.sh
nice -n 19 taskset -c 0-3 gradle --offline --max-workers=2 :app:assembleDebug
adb -s R59T103XHAM install -r app/build/outputs/apk/debug/app-debug.apk
```

Launch the app and choose a firmware through the system picker. Use the **⋮**
menu to choose another firmware, change session settings, run, or stop. Tapping
an unmapped keypad button opens its validated manual mapping dialog. Choose
**Edit input mapping** to override or remove mappings for any keypad button.

After upgrading from an earlier runtime layout, run full `prepare_runtime.sh`
once to replace dependency assets and refresh the dependency cache.

For Python-only client/emulator edits, reuse the prepared dependencies and native
runtime rather than rebuilding them:

```sh
./prepare_runtime.sh --source-only
nice -n 19 taskset -c 0-3 gradle --offline --max-workers=2 :app:assembleDebug
```

This synchronizes the complete project package (including deleted modules), the
Android adapter and common transport. It does not validate or rebuild changed
QEMU C sources: native edits still require `build_qemu_android.sh` first. Keep
native source/output hashes with each candidate APK. Kotlin, Java and JNI edits only need
Gradle. A successful build does not substitute for Android device testing.

The fast path verifies recorded native inputs, native ELF outputs, toolchain and
frozen dependency assets before syncing. Fresh native builds and full runtime
preparation create these cache manifests. Missing or mismatched manifests fail
closed; rebuild/prepare the affected runtime instead of blessing an old binary.
Additional display output can be kept in-app or routed to an available Android
Presentation display using the menu. OEM cover screens not exposed by Android
fall back in-app; actual Fold/Flip cover support needs device testing.

For release preparation, run `nice -n 19 taskset -c 0-3 gradle --offline --max-workers=2 :app:assembleRelease`.
The default output is `app/build/outputs/apk/release/app-release-unsigned.apk`.
It must be signed with an approved release key before installation or publication.
No signing credentials are stored in this project. Keep the matching project and
dependency source companions and SHA-256 manifest with the candidate. Generate
the Android runtime companion with `./build_runtime_sources.sh /output/directory`.
Debug APKs
remain test builds and must not be described as signed production releases.

For the developer prerelease, the existing Gradle debug certificate can sign
the Release build with APK v3 signatures using the checked-in build init:

```sh
nice -n 19 taskset -c 0-3 gradle --offline --max-workers=2 -I preview-signing.init.gradle :app:assembleRelease
```

This is a developer preview certificate, not a production signing identity.
The source distribution includes this configuration, but never a private key.
See [source distribution](../docs/SOURCE_DISTRIBUTION.md) for companion archives.

App icons are rendered by Inkscape during every Gradle build from
`branding/chip_icon.py`, including the checkout version, commit and build date.
Install Inkscape and Python 3 on the build host (or set `INKSCAPE` to its binary).
Generated adaptive colour and monochrome layers stay under `app/build/`.
The marking fills 0.96 of the central 72 dp viewport on a 108 dp canvas.
The minimum SDK is 28, so no legacy raster launcher icons are needed; the same
adaptive resources serve round launchers. **Settings → App icon** chooses the
full marking or **Simple (MSM5)**, independently of firmware settings.

## Compose UI

The library, app settings, emulator actions menu and dialogs use Kotlin and
Jetpack Compose Material 3. Android 12+ uses dynamic colour; earlier versions use
the stock light/dark Material schemes. System bars and cutouts use Compose insets.
The emulator has no app bar: its bottom-left more icon opens an anchored Material dropdown menu
with power first and checkmarks for toggles.
The library leaves root back navigation to the system; the emulator confirms
power-off through the Activity back dispatcher. Predictive system animations are
opted in on Android 13+ and require an Android 15+ device for visual verification.

The existing nearest-neighbour LCD renderer and flat, square keypad remain custom
handset content hosted with `AndroidView`. Their input queue, minimum press time,
keyboard mapping, audio and external `Presentation` display paths are retained.
The keypad has seven equal rows and three equal main columns; the wider side
column contains volume, lid and autosizing live counters. On short windows the
LCD fits the available area at its aspect ratio and is aligned to the top.
Hardware settings are grouped into pages; drafts are saved only with Save.
Network time uses Material date and time pickers with calendar, dial and keyboard
input; Clear returns to the device clock.

Pinned UI dependencies: AGP 9.0.1 (built-in Kotlin 2.2.10), Kotlin Compose compiler
plugin 2.2.10, Compose BOM 2025.04.01 (UI 1.8.0, Material 3 1.3.2), and Activity
Compose 1.10.1. All resolve from Google Maven or Maven Central. The first build
requires online resolution; the documented offline commands work after that.
`minSdk` remains 28, and `compileSdk`/`targetSdk` remain 35.

Implementation references: [Material 3](https://developer.android.com/develop/ui/compose/designsystems/material3),
[View interoperability](https://developer.android.com/develop/ui/compose/migrate/interoperability-apis),
[date pickers](https://developer.android.com/develop/ui/compose/components/datepickers),
[time pickers](https://developer.android.com/develop/ui/compose/components/time-pickers),
and [predictive back](https://developer.android.com/develop/ui/compose/system/predictive-back-setup).
