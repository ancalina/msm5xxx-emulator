# Android client

The app opens the system firmware chooser, copies the selected file into private
storage, and runs the bundled detector before launching QEMU. It displays the
LCD, validates keypad input against the detected profile, and isolates writable
state by firmware SHA-256. Firmware files are never bundled in the app.

With the pinned runtime artifacts present under the ignored `build/` directory,
build and install the arm64-v8a app with Android SDK 35 and Gradle 9.4:

```sh
MSM5XXX_DTC_SOURCE=/path/to/pinned/dtc \
  ./build_qemu_android.sh /new/qemu-build-work
./build_unicorn_android.sh
./build_numpy_android.sh
./prepare_runtime.sh
gradle --offline --max-workers=1 :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Launch the app and choose a firmware through the system picker. Use the **⋮**
menu to choose another firmware, change session settings, run, or stop. Tapping
an unmapped keypad button opens its validated manual mapping dialog. Choose
**Edit input mapping** to override or remove mappings for any keypad button.

For Python-only client/emulator edits, reuse the prepared dependencies and native
runtime rather than rebuilding them:

```sh
./prepare_runtime.sh --source-only
gradle --offline --max-workers=1 :app:assembleDebug
```

This synchronizes the complete project package (including deleted modules), the
Android adapter and common transport. It does not validate or rebuild changed
QEMU C sources: native edits still require `build_qemu_android.sh` first. Keep
native source/output hashes with each candidate APK. Java/JNI edits only need
Gradle. A successful build does not substitute for Android device testing.

The fast path verifies recorded native inputs, native ELF outputs, toolchain and
frozen dependency assets before syncing. Fresh native builds and full runtime
preparation create these cache manifests. Missing or mismatched manifests fail
closed; rebuild/prepare the affected runtime instead of blessing an old binary.
Additional display output can be kept in-app or routed to an available Android
Presentation display using the menu. OEM cover screens not exposed by Android
fall back in-app; actual Fold/Flip cover support needs device testing.

For release preparation, run `gradle --offline --max-workers=1 :app:assembleRelease`.
The default output is `app/build/outputs/apk/release/app-release-unsigned.apk`.
It must be signed with an approved release key before installation or publication.
No signing credentials are stored in this project. Keep the matching project and
dependency source companions and SHA-256 manifest with the candidate. Debug APKs
remain test builds and must not be described as signed production releases.
