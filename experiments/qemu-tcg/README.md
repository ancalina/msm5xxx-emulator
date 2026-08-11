# QEMU TCG probe machine

This directory contains the experimental QEMU `v10.2.1` backend used by the
root launchers. It includes no firmware.

Stage and build the pinned QEMU source on Linux or macOS:

```sh
./experiments/qemu-tcg/build_qemu_native.sh \
  /path/to/qemu-10.2.1.tar.xz /new/build/work
```

Set `MSM5XXX_DTC_SOURCE` to a checkout at the revision recorded in
`qemu_build_inputs.env`.

The same checked staging script is used by the Windows build. It verifies the
upstream archive, icount patch, machine source, and transport source before
changing the QEMU tree.

Run:

```sh
PYTHONPATH=src python3 experiments/qemu-tcg/live-display.py [FIRMWARE] \
  --qemu /path/to/qemu-system-arm --state-dir /path/to/qemu-state
```

`live-display.py` reuses the existing firmware detector and display decoder.
Omitting `FIRMWARE` opens the same chooser as the Unicorn GUI.
It passes only detector-accepted machine properties, starts QEMU without GDB
register/memory seeding, and transports LCD writes plus accepted physical input
edges over a loopback TCP chardev. A second loopback chardev releases the paused
QEMU startup through GDB. Per-MMIO Python callbacks are not used.

Persistent QEMU NOR/EEPROM files are separate from Unicorn state. The desktop
default is `~/.msm5xxx-emulator/qemu-state`; `--state-dir` overrides that root.
Applying boot settings restarts QEMU. Different firmware images use separate
SHA-256 subdirectories. Existing root-level state stays with the first
firmware opened after upgrading.

Current representative firmware status and release gates are documented in
[../../docs/QEMU_TCG_BACKEND.md](../../docs/QEMU_TCG_BACKEND.md). A visible frame or live process is not by itself a
handset-idle pass.
