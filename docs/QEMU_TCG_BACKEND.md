# Experimental QEMU TCG backend

Status: `engine/qemu-tcg` experiment. Unicorn remains the stable/default
backend. QEMU is not yet an alpha release and is never selected implicitly.

## Boundary

The backend uses QEMU system emulation with native C MMIO/device hot paths.
Python performs firmware detection, constructs fail-closed machine properties,
decodes completed LCD writes, and owns the GUI. GDB and QMP are control and
checkpoint interfaces; they are not per-access device buses.

The prototype currently provides:

- ARMv4T execution with explicit reset CPSR and detected RAM/SP geometry;
- deterministic instruction-counted virtual time;
- native IRQ, SBI/DC0, LCD, ready-poll, matrix, MA2 aperture, REX timer,
  Fujitsu x16 NOR, and GPIO 24LC256 boundaries;
- persistent raw NOR/EEPROM images separated from Unicorn state;
- a batched full-duplex LCD/input transport;
- native fallback or rejection when a detector cannot close a protocol class.

No detector uses a firmware filename or model-name branch. Device properties
come from firmware signatures, call shapes, consumers, and runtime readback.

## Current representative gate

`handset idle` means entry into the firmware's statically identified idle
consumer with supporting frame/task evidence. Process liveness, a visible
frame, or a running scheduler does not count.

| Firmware | Current final-source result |
|---|---|
| SCH-X350 | cold storage initialization, then one same-state warm QEMU process reaches UISIdle entry `0xC125C`, body `0xC1308`, and 20M further guest instructions; input/reset gate pending |
| SCH-X250 | Anycall splash/animation; idle entry not reached in 30 s |
| SCH-X250RUS | Anycall splash/animation, then fatal loop at `0x1608`; idle entry not reached |
| SD810 | detected upper x8 NOR is mapped, readable, and persistent; no completed frame and the timer/IRQ producer remains unresolved |
| KTFT-X3500 | stable standby frame plus exact app-idle module init/callback; full release gate pending |

No row is yet a release pass. X350 cold initializes the raw storage; restarting
with the same `--state-dir` reaches the entry and body in one process without
guest register or memory writes. The strict idle-consumer boundary is closed,
and REX/LCD activity continues for 20M further instructions, but input, reset,
and cross-firmware gates remain. SD810 keeps native
fallback because the periodic IRQ producer is not evidence-closed. The project
alpha gate remains five real handset-idle passes among the fixed set.

Input support is also evidence-scoped. A physical event must have one unique
matrix or sideband producer. END event `0x51` is no longer rejected merely
because it is absent from the matrix table; absent, ambiguous, or colliding
physical producers still fail closed. X250 has carried END press/release into
its input task, but the downstream UI/power effect is not yet proven.

## Determinism and reset

The interactive runner uses:

```text
-icount shift=6,align=on,sleep=on
```

Guest virtual time remains instruction-counted. LCD batching uses the virtual
clock. A QMP system reset clears device state, counters, pending IRQ/timers,
matrix/ready state, and bit-banged I2C transaction state while retaining RAM
and persistent flash/EEPROM contents. A native reset smoke verifies those
boundaries.

The 24LC256 device implements 64-byte page wrapping. Write-cycle busy/NACK
timing is intentionally still unmodeled until a firmware-visible timing class
is proven.

## Build and run

The local verified target is QEMU `v10.2.1`, `arm-softmmu`. Copy
`experiments/qemu-tcg/msm5xxx-poc.c` into QEMU `hw/arm/`, add it to
`hw/arm/meson.build`, then configure and build:

```sh
../qemu/configure --target-list=arm-softmmu \
  --disable-docs --disable-tools --disable-guest-agent \
  --disable-gtk --disable-sdl --disable-vnc --disable-curses \
  --disable-slirp --disable-plugins --disable-werror --disable-debug-info \
  --audio-drv-list= --enable-fdt=internal
ninja -j2 qemu-system-arm
```

Run the explicit experimental GUI:

```sh
PYTHONPATH=src python3 experiments/qemu-tcg/live-display.py FIRMWARE \
  --qemu /path/to/qemu-system-arm --state-dir /path/to/qemu-state
```

The QEMU settings button is disabled because this runner cannot safely restart
the native process in place. Restart the command after changing settings.
Keep the same state directory across restarts; firmware-owned cold storage
initialization can be required before a persistent warm boot reaches idle.

## Release gates

1. Close the current X250RUS early-device fatal protocol without invented RX.
2. Prove real handset-idle paths, including persistent warm storage.
3. Verify reset, storage parity/quiescence, input effect, and reject telemetry.
4. Run the full source tests and native build on the exact staged tree.
5. Package one-command Linux and Windows launchers without firmware or evidence.
