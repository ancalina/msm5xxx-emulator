# MSM5xxx QEMU Emulator

[한국어](README.ko.md)

Experimental Qualcomm MSM5000/MSM5100/MSM5500 feature-phone emulator using
QEMU TCG. Firmware is detected from its contents; model names and filenames do
not select hardware behavior.

## Download

Download the archive or Android APK for your OS and `SHA256SUMS` from
[Releases](https://github.com/ancalina/msm5xxx-emulator/releases). Extract the
entire desktop archive. Keep the launcher, `bin/`, and bundled DLLs together.

Firmware and saved state are not included.

## Start

Run the launcher without arguments to open the firmware chooser:

- Windows: double-click `run_windows.bat`.
- Linux: run `./run_linux.sh`.
- Intel macOS: double-click `run_macos.command` or run it in Terminal.
- Android arm64: install the APK and open it.

On Windows, one firmware file can also be dragged onto `run_windows.bat`.
Command-line paths work on every platform:

```sh
./run_linux.sh /path/to/phone.bin
./run_macos.command /path/to/phone.bin
```

```bat
run_windows.bat "C:\path\phone.bin"
```

The firmware file is read-only.

## Persistent state

Writable NOR and EEPROM data persist across restarts in a firmware SHA-256
scoped directory. Use `--state-dir` to choose a different state root:

```sh
./run_linux.sh /path/to/phone.bin --state-dir /path/to/qemu-state
```

The desktop default is `~/.msm5xxx-emulator/qemu-state`. Android uses
app-private storage. The original firmware file remains read-only.

## Requirements

- Desktop: Python 3.10 or newer with Tcl/Tk.
- Desktop: Linux x86-64, Windows x86-64, or Intel macOS 15.0 or newer.
- Android: Android 9 or newer on arm64-v8a.
- Desktop network access on first start if Python packages must be installed.

Linux may need `python3-tk`. On macOS, install a Tcl/Tk-enabled Python such as
`brew install python-tk@3.14`. The Windows binary is unsigned. The macOS bundle
is ad-hoc signed and not notarized.

## Current compatibility

| Firmware | Current QEMU result |
|---|---|
| SCH-X350 | Persistent warm boot reaches the verified idle consumer; END input reaches the input task |
| KTFT-X3500 | Stable standby frame; handset-idle path remains incomplete |
| SCH-X250 / X250RUS | Splash and boot animation; idle remains incomplete |
| SD810 | Reaches the 120×160 boot splash; idle remains incomplete |

This is a developer preview. Unsupported firmware may stop before idle, but
detectors fail closed instead of selecting behavior by model name.

## Troubleshooting

- Missing Tk: install Tcl/Tk support for the selected Python.
- Dependency installation failed: check Python `pip` and network access.
- Missing QEMU or DLL: extract the complete archive again.
- Nonzero exit: run the launcher from a terminal and keep the full error text.

## Development and license

Build details and backend boundaries are in
[docs/QEMU_TCG_BACKEND.md](docs/QEMU_TCG_BACKEND.md).

The project is `GPL-2.0-or-later`. QEMU and bundled-library source archives and
notices accompany binary releases. Do not redistribute manufacturer firmware.
