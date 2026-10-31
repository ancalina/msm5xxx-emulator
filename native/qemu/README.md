# QEMU TCG probe machine

This directory contains the experimental QEMU `v10.2.1` backend used by the
root launchers. It includes no firmware.

Stage and build the pinned QEMU source on Linux or macOS:

```sh
./native/qemu/build_qemu_native.sh \
  /path/to/qemu-10.2.1.tar.xz /new/build/work
```

Set `MSM5XXX_DTC_SOURCE` to a checkout at the revision recorded in
`qemu_build_inputs.env`.

The same checked staging script is used by the Windows build. It verifies the
upstream archive, icount patch, machine source, and transport source
(`src/msm5xxx_emulator/qemu/transport.py`) before
changing the QEMU tree.

Run:

```sh
PYTHONPATH=src python3 -m msm5xxx_emulator.qemu.live_display [FIRMWARE] \
  --qemu /path/to/qemu-system-arm --state-dir /path/to/qemu-state
```

The live display reuses the existing firmware detector and display decoder.
Omitting `FIRMWARE` opens the same chooser as the desktop GUI.
It passes only detector-accepted machine properties, starts QEMU without GDB
register/memory seeding, and transports LCD writes plus accepted physical input
edges over a loopback TCP chardev. A second loopback chardev releases the paused
QEMU startup through GDB. Per-MMIO Python callbacks are not used.

QEMU owns persistent NOR/EEPROM state. The desktop
default is `~/.msm5xxx-emulator/qemu-state`; `--state-dir` overrides that root.
Applying boot settings restarts QEMU. Different firmware images use separate
SHA-256 subdirectories. Existing root-level state stays with the first
firmware opened after upgrading.

Current representative firmware status and release gates are documented in
[../../docs/QEMU_TCG_BACKEND.md](../../docs/QEMU_TCG_BACKEND.md). A visible frame or live process is not by itself a
handset-idle pass.

For native boot-input diagnostics, the disabled-by-default machine property
`experimental-boot-contact=GPIO:PC:MASK:WIDTH` accepts hexadecimal fields. GPIO
must be `0300066c` or `0300072c`; byte loads support masks `2` and `4`, and
halfword loads support masks `8` and `1f`. The configured Thumb guest load receives the
released bits while other reads and all writes retain the MSM backing value.
The entire four-byte register must have no other device owner. Every matching
load receives the release, including after reset; `boot-contact-state` counters
accumulate across resets. Automatic binding is limited to complete reset/key/LCD
source classes, reparsed against the immutable loaded image with RAM and GPIO
ownership checks. Other uses remain manual diagnostics.

The source-qualified `dmd5100-program-760=ENTRY:DESCRIPTOR:PAYLOAD:PAIR_COUNT`
variant uses the paired DMD word-memory controller with readback registers at
`03000768` and `0300076c`. The original `dmd5100-program` property keeps its
`030007e8`/`030007ec` register bank and four-field syntax. Both variants capture
actual uploaded words, preserve backing writes, and require the typed transfer
sequence, source PCs, descriptor/payload registers, and readback counters.
Automatic selection of the new bank also requires the matching reset-linked
boot-contact source class. Live guest validation is required for each family.
