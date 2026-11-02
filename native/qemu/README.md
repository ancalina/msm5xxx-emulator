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

`experimental-gpio660-lcd=PC[:PC...]` is a disabled passive GPIO observer. It
accepts up to 64 unique even source PCs in primary NOR. Only Thumb guest
halfword writes at those PCs to03000660 enter the existing LCD trace stream.
All access widths, other writers and reads retain the actual backing bytes.
The whole four-byte register must have exclusive MSM backing at its correct offset;
no input, status, clock, GPIO or pixel value is synthesized. `gpio660-lcd-state`
reports captures. Source graph/loaded-image admission and serial decoding are
separate requirements before automatic use.

`dmd5100-program-760-layout=ENTRY:DESCRIPTOR:PAYLOAD:PAIR_COUNT:LAYOUT`
extends the opt-in paired readback controller with four fixed source layouts.
Layout 0 retains the original late reset release; layout 1 observes release at
+56 before verification and the six-byte shifted readback block. Layout 2 also
uses the alternate program-address and close register roles; layout 3 retains
late release with the alternate address register. Values are hexadecimal.
No layout preloads DSP words or skips guest comparisons. All captured halfwords,
barriers, widths, source PCs and register contexts remain required. This property
has no automatic source admission yet.

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

Automatic EFS selection requires a source-qualified Sharp driver, descriptor,
and relocated table, rechecked against the loaded image. The selected range is
seeded from the capture and excluded from raw loader writes. The observed x16
driver configures PCR separately from block locks; it unlocks before erase and
relocks after programming. The selected board mirrors status into both x16
byte lanes for its two observed polling conventions; the opt-in
`sharp-nv-status-mirror` property leaves the existing default unchanged.
This admission does not establish physical WP# wiring
or the original part's reset orientation.

`intel-adjacent-nv16=BASE:SIZE:SECTOR:ID0:ID1` selects a single x16 CFI01 device
between the primary ROM end and RAM, with the same exclusive-owner checks as
`intel-adjacent-nv`. Its status lane is `0x80`; the older adjacent mode retains
two x8 lanes (`0x8080`). The new mode enables confirmed erase: `20` arms an
operation and a valid `D0` in the same sector is required to modify the array.
All supplied primary bytes remain immutable. These properties do not infer
physical geometry or reconstruct missing NV records.

The copied middle-aperture x16 NAND class uses data/address/command ports at
`0x01800000`/`0x01900000`/`0x01a00000`, with 16 MiB of main data, 512-byte pages
and 32-page erase blocks. Automatic binding requires a reset-linked copy table,
closed producer instruction contracts, matching loaded source, and a compatible
NOR/RAM map. It does not use a model name or whole-image hash allowlist.

This class also requires `raw-nand-ready=ADDRESS:MASK`: the source-owned GPIO
input is either `03000728:1` or `03000720:10`. It follows NAND status bit 6;
other GPIO bits and backing writes are retained. The final memory map must leave
the entire halfword on the passive MSM RAM underlay. Operations in this existing
main-area bridge complete synchronously. Original NAND contents, spare/OOB
storage and physical timing are not supplied; an erased virtual main area can
legitimately lead firmware to a missing-data error screen.
