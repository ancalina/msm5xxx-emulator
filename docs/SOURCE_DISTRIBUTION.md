# Binary and corresponding source distribution

The project grants GPL-2.0-or-later rights. This preview selects the GPLv2
option for the combined distribution containing GPLv2-only components.
Each dependency retains its own copyright, license and exceptions. This
does not change a dependency's GPLv2-only grant into an or-later grant.

Publish the following source companions beside their binary artifacts, with
equivalent download access and no additional restrictions on recipients:

| Binary | Corresponding source companions |
| --- | --- |
| Linux x86_64 | `MSM5xxx-QEMU-10.2.1-corresponding-source.tar.xz` |
| Windows x86_64 | Common QEMU/project source above; `MSM5xxx-QEMU-windows-runtime-sources.tar.xz` |
| Intel macOS | Common QEMU/project source above; `MSM5xxx-QEMU-macos-LGPL-sources.tar.xz` |
| Android arm64 APK | Common QEMU/project source above; `MSM5xxx-QEMU-android-runtime-sources.tar.xz` |

Source companions include the preferred editable source, interfaces, patches,
compilation/installation recipes and retained copyright/license texts. The
common source companion includes the exact project source archive and staged
QEMU source; Android additionally includes the host patch, dependency archives
and build configuration. Dependency companions identify their versions and
source input hashes. Binary `BUILDINFO`/payload manifests and `SHA256SUMS`
identify the matching artifacts. Manufacturer firmware is not included.

The desktop native builder is `experiments/qemu-tcg/build_qemu_native.sh`;
Windows configuration and assembly are in `.github/workflows/build-qemu-windows.yml`.
Platform-specific assembly recipes accompany the corresponding source archives.
Android build scripts and the pinned cross-file are in `android-client/`.
Use their recorded source inputs rather than a newer upstream checkout.

The Android developer preview uses this public Gradle configuration:

From the extracted project's `android-client/` directory:

```sh
gradle --offline --max-workers=1 -I preview-signing.init.gradle :app:assembleRelease
```

This selects the local Gradle debug certificate, with v3 APK signatures;
it is a developer preview, not a production signing-key distribution. The
private key is excluded. Building or installing a modified GPLv2 preview
does not require access to the distributor's private signing key.

Source availability and independent byte-identical build reproduction are
different checks. Keep the actual source modifications and required recipes
even when output hashes differ across toolchains. Preserve dated modification
notices in patched third-party files and their original license notices.

This distribution uses GPLv2 section3(a), providing complete corresponding
source. It does not substitute an upstream repository link or a separate
three-year written source offer for the included source companions.
