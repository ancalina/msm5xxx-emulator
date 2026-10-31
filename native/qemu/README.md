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

The optional `sharp-primary-nv=BASE:SIZE:SECTOR:ID0:ID1` machine property maps an
exclusive writable x16 CFI01 partition inside the primary ROM envelope. It is
experimental and disabled by default. The caller must preserve all supplied
bytes in the drive seed and exclude that range from raw loader writes.

Its `sharp-pcr` flash capability records matching halfword `60/04` transactions
and reads back address-latched partition bits through identifier word 6. The
flash property `sharp-pcr-reset` chooses a compatible bottom (`0x100`, default)
or top (`0x400`) reset value; this choice does not identify the original part.
The `sharp-locks` capability tracks lock and lock-down bits per block, including
identifier readback and protection for single-word program, buffered program,
and erase. Blocks reset to locked. The machine mode enables this capability;
`sharp-nv-wp-high=on` explicitly selects a compatible WP# high pin level (the
default is low). This fixed virtual pin does not establish original GPIO wiring.
Partition timing and read-while-write execution remain unimplemented.

`intel-adjacent-nv16=BASE:SIZE:SECTOR:ID0:ID1` selects a single x16 CFI01 device
between the primary ROM end and RAM, with the same exclusive-owner checks as
`intel-adjacent-nv`. Its status lane is `0x80`; the older adjacent mode retains
two x8 lanes (`0x8080`). The new mode enables confirmed erase: `20` arms an
operation and a valid `D0` in the same sector is required to modify the array.
All supplied primary bytes remain immutable. These properties do not infer
physical geometry or reconstruct missing NV records.
