# MSM5xxx QEMU Emulator 0.2.0

[한국어](README.ko.md)

An experimental QEMU-based emulator for preserving and exploring feature phones
using Qualcomm MSM5000, MSM5100, MSM5105 and MSM5500 chipsets. Compatibility
varies by firmware; a supported chipset does not guarantee a successful boot.

**Use your own firmware dump.** No firmware or saved state is included.

## Features

- Main and secondary displays, where supported by the detected hardware.
- On-screen keypad and side keys, host keyboard input, and editable input mappings.
- Emulated audio, including tone generation and supported Yamaha audio hardware.
- Optional virtual network and configurable network time; this is an emulated
  network, not a connection to a real mobile network.
- Persistent writable device state and a firmware library with per-device settings.
- Native desktop apps for Windows, macOS and Linux with light and dark themes,
  Korean and English, and built-in updates.

## Install and run

Get the package for your platform from [Releases](https://github.com/ancalina/msm5xxx-emulator/releases).
Import or select your own firmware dump in the library, then select it to start.
Desktop packages include everything they need; no Python installation is required.

- **Windows 10 (1809) or later, x86-64:** Run `MSM5xxx-win-Setup.exe`. It installs
  for the current user and adds a Start menu entry. The installer is unsigned: if
  Windows shows "Windows protected your PC", choose **More info → Run anyway**.
  Updates are offered in the app. See [Windows](desktop/windows/README.md).
- **Intel macOS 15 or later:** Open the DMG and drag the app to Applications. The
  app is not notarized: on first launch, right-click it and choose **Open**, or
  allow it in **System Settings → Privacy & Security**. Updates are offered in the
  app. See [macOS](desktop/macos/README.md).
- **Linux x86-64 (glibc 2.43 or later, such as Ubuntu 26.04):** Make the AppImage
  executable and run it, or install the `.deb` with your package manager. If FUSE
  is unavailable, run the AppImage with `APPIMAGE_EXTRACT_AND_RUN=1`. The AppImage
  updates itself from the app. See [Linux](desktop/linux/README.md).
- **Android 9 or later, arm64:** Install the APK, open the app, and import a
  dump using the system file picker. The app checks for updates and installs over
  earlier versions without losing data.
- **iOS 15 or later:** Install a suitably signed and provisioned IPA, or install
  the TIPA using TrollStore. Open the app and import a dump. The IPA uses the
  interpreter; the TIPA can use debugger-assisted JIT when available. See the
  [iOS instructions](ios/README.md).

Writable NOR and EEPROM state is kept separately for each firmware; the original
dump remains read-only. Desktop apps keep the library, settings and state in the
per-user data folder (`%LOCALAPPDATA%\MSM5xxx` on Windows, `Application Support/MSM5xxx`
on macOS, `~/.local/share/msm5xxx` on Linux); uninstalling keeps it. Mobile apps
use app storage.

## Known limits

- Some firmware stops at a logo or produces no frame, and working features vary
  by device. See the [compatibility sheet](docs/COMMUNITY_COMPATIBILITY_SHEET.md).
- On iOS, Stop parks the current machine; Start can reset and resume the same
  firmware. Reopen the app to switch firmware or if a stopped session cannot
  resume. Some settings also require reopening the app.
- Android secondary display output can use an available Presentation display;
  cover screens that Android does not expose fall back to the app.

For build information and licenses, see [QEMU backend](docs/QEMU_TCG_BACKEND.md),
[third-party notices](THIRD_PARTY_NOTICES.md), and
[source distribution](docs/SOURCE_DISTRIBUTION.md). The project is
GPL-2.0-or-later; bundled components retain their own licenses.

## MA5 voice ROM

For MA5 PCM output, set `MSM5XXX_MA5_ROM` to a user-supplied raw 16384-byte
file. File offset 0 maps to chip address 0x0000 and offset 0x3fff to 0x3fff.
Use data for the correct chip revision. The file contains the chip's native
voice records and wave data; it is not a firmware image or an archive. An
invalid or unreadable file stops startup. When the variable is unset, ROM
voices remain unavailable and are counted as skips.

FM records have a two-byte header followed by two or four seven-byte operator
records. WT records are 13 bytes and contain a big-endian sample address and
loop sample indices; PCM16 sample data is little-endian. Sample addresses may
point to the ROM or to guest-uploaded memory. The renderer validates each referenced
record and sample span before playback.

