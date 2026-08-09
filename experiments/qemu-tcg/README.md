# QEMU TCG probe machine

This directory contains the explicit, experimental QEMU `v10.2.1` backend.
It includes no firmware and is not selected by the stable launchers.

Build the machine by copying `msm5xxx-poc.c` to QEMU `hw/arm/`, adding:

```meson
arm_common_ss.add(files('msm5xxx-poc.c'))
```

to `hw/arm/meson.build`, then following the configure command in
`docs/QEMU_TCG_BACKEND.md`.

Run:

```sh
PYTHONPATH=src python3 experiments/qemu-tcg/live-display.py FIRMWARE \
  --qemu /path/to/qemu-system-arm --state-dir /path/to/qemu-state
```

`live-display.py` reuses the existing firmware detector and display decoder.
It passes only detector-accepted machine properties, starts QEMU without GDB
register/memory seeding, and transports LCD writes plus accepted physical input
edges over one batched socket. Per-MMIO Python callbacks are not used.

Persistent QEMU NOR/EEPROM files are separate from Unicorn state. Omitting
`--state-dir` makes an isolated temporary copy and discards it on exit. The
settings button is disabled; restart the command to apply settings. Keep the
same state directory when a cold storage initialization requires a warm boot.

Current representative firmware status and release gates are documented in
`docs/QEMU_TCG_BACKEND.md`. A visible frame or live process is not by itself a
handset-idle pass.
