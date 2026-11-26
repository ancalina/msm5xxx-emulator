# Release installers

`release.py` is the release entry point. Check out the release tag and build each
platform on its native host, or use its all-platform coordinator from Linux with
the existing `win` and `mac` build-host tools. It never publishes a release.
Every output records the tag commit, exact installer size and SHA-256 digest.
The coordinator transfers a Git bundle of the tag to isolated remote checkouts,
verifies transferred artifact checksums, and collects all four platforms plus a
project source archive. The QEMU source companion omits prebuilt firmware, optional
ROM sources, tests and caches; configure it with `--disable-install-blobs`.
Each desktop target also generates a runtime-library source companion with checksums: pinned MSYS2 source packages on Windows, installed Homebrew formula sources and patches on macOS, and exact APT source packages on Linux. The Linux build needs access to its distribution source repositories. Original build inputs stay unchanged. Work directories and private test keys are excluded.

Prerequisites are the native SDKs/toolchains described in each platform README,
project QEMU builds and libraries from the same native inputs, and the pinned
Android dependency runtime prepared by `android/prepare_runtime.sh`. Android's
native/dependency cache validation is mandatory. Rebuild changed native inputs
with `android/build_qemu_android.sh`; do not replace its cache manifest by hand.
No manual app/runtime merge is needed for any installer.

For a local release candidate, commit the source, create `v0.2.0-rc`, check out
that tag, and run this single path with workspace/tool paths in environment variables:

```sh
export TMPDIR="$PWD/tmp"; mkdir -p "$TMPDIR"
python3 packaging/release.py --tag v0.2.0-rc --platform all --dry-run \
  --qemu "$LINUX_QEMU" --qemu-source "$LINUX_QEMU_SOURCE" --runtime "$WINDOWS_QEMU_RUNTIME" \
  --windows-work "$WINDOWS_WORK" --macos-work "$MACOS_WORK" \
  --macos-qemu "$MACOS_QEMU" --macos-qemu-source "$MACOS_QEMU_SOURCE" \
  --gradle "$GRADLE" --build-number 20000 --output "$OUTPUT"
```

Remote workspace paths must be absolute. The coordinator uses `release-source`
and `release-output` inside those workspaces. Windows can use a locally installed
.NET 10 SDK under `tools/dotnet`; otherwise it uses the installed SDK. Its package
cache stays under `tools`. Keep all build caches and temporary directories in the
chosen workspace. Set `CARGO_HOME`, `CARGO_TARGET_DIR`, `GRADLE_USER_HOME`, and
`XDG_CACHE_HOME` there when the host's normal cache directories are not writable.

For independent native-host jobs, use `--platform windows|linux|macos|android`
with the same tag and output directory. Windows takes `--runtime`; Linux takes
`--qemu`; macOS takes `--qemu` and `--qemu-source`; Android takes `--gradle` and a
strictly validated prepared dependency runtime. The Windows desktop workflow now
builds the complete Velopack installer, QEMU, Python, update feed and checksums
from its requested tag instead of publishing an app folder.

`--dry-run` means an ad-hoc, unnotarized Mac. Android candidates still use the
approved release signing identity and normal application ID. Isolated `.debug`
APKs are separate local-feed test fixtures, not release assets. A throwaway Mac EdDSA key is generated under `.work` if no key is
supplied. These candidates are for install tests, not production distribution.
The native Windows and Linux installers are complete. Keep fake-version/local-feed
fixtures separate from production release assets.

For the stable `v0.2.0` release on 2026-11-28, omit `--dry-run` and use build number
`20001`. Finish installation/update tests by 2026-11-27. Configure the Developer ID,
notarytool and persistent Sparkle key environment described in
[macOS signing](macos/README.md) on the Mac build host; the coordinator uses that
host's login environment and keychain. Android release signing uses an approved keystore;
keep its private key and passwords outside the repository and artifact directory.
Set `MSM5XXX_ANDROID_KEYSTORE`, `MSM5XXX_ANDROID_KEY_ALIAS`,
`MSM5XXX_ANDROID_STORE_PASSWORD`, and `MSM5XXX_ANDROID_KEY_PASSWORD`.
Signed APKs must preserve the existing release identity and increase version code.

Windows `--previous DIRECTORY` supplies the previous published Velopack packages
for delta generation. The first installer release has no delta from the retired
ZIP distribution. Delta behavior is tested against a private fake 0.1.99 baseline;
never publish that baseline or its local test feed as a real release.

Publish all generated installer/update assets unchanged on the corresponding
GitHub Release: `releases.win.json` and packages, the AppImage and `.zsync`, and
the Mac archive plus signed `appcast.xml`. The `.deb` and Android notices link to
that release. Preserve checksum/source companions alongside the binaries. On
Android publish exactly one APK asset containing `arm64` in its name. iOS only
notifies and never downloads or installs an update.

The iOS `.ipa` and `.tipa` remain a required separate release step on macOS.
Build the device QEMU and QEMUTCI frameworks using `ios/build_qemu_framework.sh`
as described in `ios/README.md`, then run `ios/package_ios.sh "$OUTPUT/ios"`.
Verify both archives and include their checksums in the GitHub release. Desktop
and Android completion does not complete the iOS release checklist.
