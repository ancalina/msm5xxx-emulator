# MSM5xxx QEMU Emulator 0.1.0

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

## Install and run

Get the package for your platform from [Releases](https://github.com/ancalina/msm5xxx-emulator/releases).
Import or select your own firmware dump in the library, then select it to start.

- **Windows x86-64:** Extract the complete archive and double-click `run_windows.bat`.
  You can also drag a firmware file onto the launcher. The binary is unsigned.
- **Linux x86-64:** Extract the complete archive and run `./run_linux.sh`.
- **Intel macOS 15 or later:** Extract the complete archive and open
  `run_macos.command`. The bundle is ad-hoc signed and not notarized.
- **Android 9 or later, arm64:** Install the APK, open the app, and import a
  dump using the system file picker.
- **iOS 15 or later:** Install a suitably signed and provisioned IPA, or install
  the TIPA using TrollStore. Open the app and import a dump. The IPA uses the
  interpreter; the TIPA can use debugger-assisted JIT when available. See the
  [iOS instructions](ios/README.md).

Desktop requires Python 3.10 or newer with Tcl/Tk and may need network access
on first launch to install Python packages. Linux may need `python3-tk`; macOS
may need a Tcl/Tk-enabled Python. Keep the desktop launcher, `bin/` and bundled
libraries together.

Writable NOR and EEPROM state is kept separately for each firmware; the original
dump remains read-only. Desktop defaults to `~/.msm5xxx-emulator/qemu-state` and
accepts `--state-dir` to change the state root. Mobile apps use app storage.

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
