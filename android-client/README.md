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
./prepare_runtime.sh
gradle --offline --max-workers=1 :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Launch the app and choose a firmware through the system picker. Use the **⋮**
menu to choose another firmware, change session settings, run, or stop. Tapping
an unmapped keypad button opens its validated manual mapping dialog.
