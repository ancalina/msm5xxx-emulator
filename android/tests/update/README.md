Run the dependency-free version checks from the repository root:

```sh
javac -d "$TMPDIR/android-version-test" android/app/src/main/java/org/msm5xxx/emulator/ReleaseVersion.java android/tests/update/ReleaseVersionTest.java
java -cp "$TMPDIR/android-version-test" org.msm5xxx.emulator.ReleaseVersionTest
```

Debug builds accept a GitHub-shaped `files/update-release.json` in private app storage.
Only debug builds accept a local APK URL, and it must identify `files/update.apk` exactly.
Use `adb shell run-as org.msm5xxx.emulator.debug` to place these test files. Release builds always
check GitHub Releases latest over HTTPS. Test metadata must contain one arm64 APK asset
with its exact SHA-256 digest and byte size. The APK must have this app's package ID,
a greater version code, the declared version name, and the installed signing certificate.
Delete the two test files after testing. Never ship test feeds or signing keys.

The complete GUI test runs on a dedicated Android device or emulator with the
isolated debug package. It installs fake 0.1.99, rejects a corrupted APK, accepts
the system update confirmation, checks retained data, changes the preference,
and performs a manual check. It leaves the updated debug app for review.

```sh
python3 android/tests/update/device.py --device DEVICE_SERIAL \
  --artifacts /path/to/debug-test-apks --work "$TMPDIR/android-update-test"
```

The APK directory must contain `MSM5xxx-0.1.99-android-arm64.apk` and
`MSM5xxx-0.2.0-rc-android-arm64.apk`, built with the Gradle version/code properties
and signed with the same debug key. These fixtures are not release assets.
