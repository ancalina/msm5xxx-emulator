# MSM5xxx Emulator: experimental QEMU TCG build

[한국어](README.ko.md)

This branch moves Qualcomm MSM5000/MSM5100/MSM5500 firmware execution to
QEMU TCG. It is an experimental build checkpoint; the compatibility table
below is the release boundary.

The Unicorn implementation remains in the tree as a behavioral oracle. Root
launchers now start the QEMU backend and use the matching binary under `bin/`.

## Current status

`handset idle` requires the firmware's identified idle consumer plus supporting
task and frame evidence. A visible frame or live QEMU process is not a pass.

| Firmware | Verified on QEMU | Remaining gap |
|---|---|---|
| SCH-X350 | Cold storage initialization; same-state warm boot reaches UISIdle `0xC125C -> 0xC1308`; 20M further guest instructions retain REX/LCD progress; physical END `0x51` press/release reaches the input task | UI power-off effect, reset parity, release packaging |
| KTFT-X3500 | Detector-admitted DC0 battery profile reaches a stable 128x160 standby frame without guest state injection | Current module remains module0B; module1/idle consumer is not closed |
| SD810 | Detector-admitted 8 MiB upper x8 NOR at `0x02800000` is mapped, readable, and persistent | Periodic IRQ producer, cadence, and acknowledge path are unresolved; no completed frame |
| SCH-X250 | Anycall splash and animation | Idle entry not reached |
| SCH-X250RUS | Anycall splash and animation | Early-device RX status/data/frame/CRC contract is unresolved; firmware enters fatal loop `0x1608` |

No row is a release pass yet. The fixed five-firmware alpha gate is not met.

END event `0x51` is not rejected merely because it is absent from the matrix
event table. It is enabled only when one unique physical sideband producer and
its consumer path are detected; absent, duplicated, ambiguous, or colliding
producers still fail closed.

## Backend boundary

- QEMU executes ARMv4T firmware with deterministic instruction-counted time.
- Native C handles device/MMIO hot paths, IRQs, LCD, storage, matrix input, and
  the currently admitted protocol classes.
- Python detects firmware structures, supplies accepted machine properties,
  decodes completed LCD writes, and owns the experimental GUI.
- Detection uses firmware signatures, call shapes, consumers, and runtime
  readback—not model names or firmware filenames.
- Incomplete detectors retain native fallback or emit a reject reason. Unknown
  hardware values are not invented to advance boot.

See [the QEMU backend notes](docs/QEMU_TCG_BACKEND.md) for exact device,
determinism, reset, and release boundaries.

## Build

The verified target is QEMU `v10.2.1`, `arm-softmmu`, plus Python 3.10+ and Tk.
Clone this branch, copy the machine source into a QEMU source tree, and add it to
`hw/arm/meson.build`:

```sh
git clone --branch engine/qemu-tcg-alpha-20260809 \
  https://github.com/ancalina/msm5xxx-emulator.git
cp msm5xxx-emulator/experiments/qemu-tcg/msm5xxx-poc.c \
  /path/to/qemu/hw/arm/
```

```meson
arm_common_ss.add(files('msm5xxx-poc.c'))
```

Configure and build QEMU with the command in
[docs/QEMU_TCG_BACKEND.md](docs/QEMU_TCG_BACKEND.md#build-and-run).

## Run

Binary archives use this layout:

```text
MSM5xxx-QEMU-<platform>/
  bin/qemu-system-arm[.exe]
  run_linux.sh | run_windows.bat | run_macos.command
```

Linux:

```sh
./run_linux.sh FIRMWARE --state-dir /path/to/qemu-state
```

Windows x86-64:

```bat
run_windows.bat "C:\path\phone.bin" --state-dir "C:\path\qemu-state"
```

Intel macOS:

```sh
./run_macos.command FIRMWARE --state-dir /path/to/qemu-state
```

Firmware input remains read-only. NOR and EEPROM changes are written under the
separate state directory. Reuse that directory when a firmware needs one cold
storage initialization before a persistent warm boot. Omitting `--state-dir`
creates disposable state.

Python 3.10+, Tk, and the packages in `requirements.txt` are required. The
launchers create a local virtual environment and install missing Python
packages on first use. For a source checkout or external binary, set
`MSM5XXX_QEMU=/path/to/qemu-system-arm`.

## Verify

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The published checkpoint passed 380 tests with 10 corpus-dependent skips and a
native `qemu-system-arm` build.

## Distribution and license

This repository contains no manufacturer firmware, user state, evidence,
diagnostic logs, screenshots, or IDA databases. Do not add them to a source or
binary archive.

The project is licensed under `GPL-2.0-or-later`. A distributed QEMU binary
must also include the corresponding source and notices required by its
licenses. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Current binary targets are Linux x86-64, Windows x86-64, and Intel macOS.
Android is not advertised: QEMU's required host libraries and the Python/Tk
frontend do not yet have a verified Android package path.
