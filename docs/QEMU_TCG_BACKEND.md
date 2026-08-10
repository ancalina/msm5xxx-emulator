# Experimental QEMU TCG backend

Status: developer preview. Unicorn remains the behavioral oracle; root
launchers use QEMU.

## Boundary

The backend uses QEMU system emulation with native C MMIO/device hot paths.
Python performs firmware detection, constructs fail-closed machine properties,
decodes completed LCD writes, and owns the GUI. GDB and QMP are control and
checkpoint interfaces; they are not per-access device buses.
Loopback LCD/GDB control sockets assume a trusted local user session.

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
| SCH-X350 | cold storage initialization, then one same-state warm QEMU process reaches UISIdle entry `0xC125C`, body `0xC1308`, and 20M further guest instructions; physical END reaches the input task, while UI power/reset effects remain pending |
| SCH-X250 | Anycall splash/animation; idle entry not reached in 30 s |
| SCH-X250RUS | Anycall splash/animation, then fatal loop at `0x1608`; idle entry not reached |
| SD810 | detector-accepted DMD completion reaches one 120×160 boot splash frame; the idle timer/IRQ route remains unresolved |
| KTFT-X3500 | detector-admitted DC0 battery profile reaches a stable standby frame, but current module remains module0B and the module1/idle consumer is not closed |

No row is yet a release pass. X350 cold initializes the raw storage; restarting
with the same `--state-dir` reaches the entry and body in one process without
guest register or memory writes. The strict idle-consumer boundary is closed,
and REX/LCD activity continues for 20M further instructions. Physical END
press/release reaches the input task, but its UI power effect, reset, and
cross-firmware gates remain. SD810 keeps native
fallback because the periodic IRQ producer is not evidence-closed. The project
alpha gate remains five real handset-idle passes among the fixed set.

Input support is also evidence-scoped. A physical event must have one unique
matrix or sideband producer. END event `0x51` is no longer rejected merely
because it is absent from the matrix table; absent, ambiguous, or colliding
physical producers still fail closed. X350 has carried END press/release into
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

The local verified target is QEMU `v10.2.1`, `arm-softmmu`. Linux and macOS use
the checked source staging and native build wrapper:

```sh
./experiments/qemu-tcg/build_qemu_native.sh \
  /path/to/qemu-10.2.1.tar.xz /new/build/work
```

Set `MSM5XXX_DTC_SOURCE` to a checkout at the revision recorded in
`experiments/qemu-tcg/qemu_build_inputs.env`.

The Windows workflow calls the same staging script before its MinGW build.

Run a matching binary archive:

```sh
./run_linux.sh                         # firmware chooser
./run_linux.sh FIRMWARE --state-dir /path/to/qemu-state
./run_macos.command                    # Intel macOS 15+ chooser
```

Windows uses `run_windows.bat`; double-click for the chooser or drag one
firmware file onto it. Source builds can set `MSM5XXX_QEMU` to an external
`qemu-system-arm` path.

The Android arm64 client and its pinned QEMU build command are in the
[public Android source tree](https://github.com/ancalina/msm5xxx-emulator/tree/engine/qemu-tcg-alpha-20260809/android-client).

Applying boot settings restarts the native QEMU process. Keep the same state
directory across restarts; firmware-owned cold storage initialization can be
required before a persistent warm boot reaches idle. Writable state is kept in
a separate firmware-identity subdirectory. Existing root-level state remains
assigned to the first firmware opened after upgrading.

## Release gates

1. Close the current X250RUS early-device fatal protocol without invented RX.
2. Prove real handset-idle paths, including persistent warm storage.
3. Verify reset, storage parity/quiescence, input effect, and reject telemetry.
4. Run the full source tests and native build on the exact staged tree.
5. Verify Linux, Windows, and Intel macOS 15+ archives without firmware or evidence.
