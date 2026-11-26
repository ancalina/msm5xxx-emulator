# macOS installers and updates

Build the native app, our QEMU, relocatable Python and dependency closure into one
app bundle. The DMG contains the app and an Applications link. Drag the app to
Applications; Finder's Move to Trash is the standard uninstall. User data remains
in `~/Library/Application Support/MSM5xxx`; app appearance and Sparkle preferences
use the application's standard user defaults. Delete those only after choosing
to remove your data. Firmware and the optional sound ROM are never included.

The app embeds Sparkle 2.10.1. **Check for Updates…** uses Sparkle's standard UI;
Settings includes its automatic-check preference. Updates and appcasts require
EdDSA signatures. Appcast URL defaults to the `appcast.xml` asset on GitHub Releases
latest; archives use the corresponding versioned release URL. Publish the generated
appcast unchanged: editing signed XML invalidates its signature.

## Build

On an Intel Mac with Xcode command-line tools, Homebrew GLib, Ninja and Python 3.12+
installed, build QEMU from `native/qemu/stage_qemu_source.sh` with the pinned DTC
revision in `qemu_build_inputs.env`, `--target-list=arm-softmmu`,
`--without-default-features`, `--enable-coreaudio`, `--audio-drv-list=coreaudio`,
`--enable-fdt=internal`, and `--disable-download`. Then run:

```sh
export TMPDIR="$PWD/tmp"; mkdir -p "$TMPDIR"
export MSM5XXX_SIGN_IDENTITY='Developer ID Application: YOUR NAME (TEAMID)'
export MSM5XXX_NOTARY_PROFILE='YOUR_NOTARY_PROFILE'
export SPARKLE_KEY_ACCOUNT='YOUR_SPARKLE_ACCOUNT'
export SPARKLE_PUBLIC_KEY="$(path/to/Sparkle/bin/generate_keys --account "$SPARKLE_KEY_ACCOUNT" -p)"
python3 packaging/macos/build.py --version 0.2.0-rc --build-number 20000 \
  --qemu /path/to/build/qemu-system-arm --qemu-source /path/to/staged/qemu \
  --output /path/to/output
```

The script signs code from the inside out, notarizes and staples the app, creates
and notarizes/staples the DMG, and signs the Sparkle update archive/appcast. It fails
if signing/notarization fails. `--adhoc` explicitly builds an unnotarized local test
candidate. Never publish an ad-hoc candidate as a production release.
`SPARKLE_KEY_FILE` can supply an exported key file instead of a keychain account;
keep it outside the source tree and never include it in artifacts. A test build can
set `MSM5XXX_APPCAST_URL` and `--download-prefix` to a loopback feed. Enable local
networking in the test app's Info.plist only when using an HTTP loopback test feed.

## Owner credential setup

1. In Apple Developer → Certificates, create a **Developer ID Application**
   certificate. Import its certificate **and matching private key**
   into the Mac login keychain (open the exported `.p12` in Keychain Access).
   Confirm `security find-identity -v -p codesigning` lists the identity above.
2. Create an app-specific password for your Apple Account. Store notarization
   credentials interactively; the command prompts for the account details and password:

   ```sh
   xcrun notarytool store-credentials YOUR_NOTARY_PROFILE
   xcrun notarytool history --keychain-profile YOUR_NOTARY_PROFILE
   ```

3. Create the persistent Sparkle key once using the pinned Sparkle distribution:

   ```sh
   path/to/Sparkle/bin/generate_keys --account YOUR_SPARKLE_ACCOUNT
   path/to/Sparkle/bin/generate_keys --account YOUR_SPARKLE_ACCOUNT -p
   ```

   Back up the private key securely using `generate_keys --account ACCOUNT -x FILE`.
   This is a separate key from Developer ID. Keep the same public key in later
   versions, or follow Sparkle's key-rotation procedure before changing it.
4. Set the four environment variables in the build example and rerun the release
   build. The local test key must never become the production key.

Official guidance: [Sparkle setup](https://sparkle-project.org/documentation/),
[SwiftUI](https://sparkle-project.org/documentation/programmatic-setup/),
[customization](https://sparkle-project.org/documentation/customization/),
[Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

## Local install/update test

Build fake `0.1.99` / build `19999` and `0.2.0-rc` / build `20000` with the same
throwaway EdDSA key. Set `MSM5XXX_BUILD_CONFIGURATION=debug`,
`MSM5XXX_VERIFY_UPDATES_OUTPUT=/absolute/test/work`, and
`MSM5XXX_APPCAST_URL=http://127.0.0.1:8766/appcast.xml`; pass
`--adhoc --download-prefix http://127.0.0.1:8766/` to the builder. This creates
an isolated `.installertest` bundle ID and keeps backend state in the test work
directory. The verification code and state override are absent from release builds.

```sh
python3 packaging/macos/test-install.py --baseline /path/to/0.1.99.dmg \
  --release-directory /path/to/0.2.0-rc --work /absolute/test/work
```

The driver mounts the real DMG, verifies its Applications link, installs the app,
launches its bundle executable, and checks the update/relaunch and retained data before
removing the app. The debug harness checks the menu wiring and preference, invokes
the menu's actual updater-controller action, clicks Sparkle's real install/restart
buttons, and snapshots only its own AppKit windows. This works without screen
recording access or an unlocked desktop. The driver confirms that the local feed
is serving before launching the app. Its direct test launch uses the command-line
child-process context described in [Apple TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).
No privacy permissions or OS security settings are changed. No firmware is needed or included.

DMGs use hdiutil ULFO (LZFSE compression). The same disk image is signed, submitted
to notarytool and stapled in production. The embedded Python executable is
statically linked; unused libpython, installation tools, documentation data and
headers are omitted after packaged runtime import and Mach-O dependency checks.
