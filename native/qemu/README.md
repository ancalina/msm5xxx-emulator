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
halfword loads support mask `1f`. The configured Thumb guest load receives the
released bits while other reads and all writes retain the MSM backing value.
The entire four-byte register must have no other device owner. Every matching
load receives the release, including after reset; `boot-contact-state` counters
accumulate across resets. This experiment has no automatic detector activation
and requires separate live-guest validation for each proposed source profile.
