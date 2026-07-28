# MSM5xxx Emulator

[한국어](README.ko.md)

Unicorn-based Qualcomm MSM5000/MSM5100/MSM5500 feature-phone firmware emulator.
Experimental project. 
This tree contains no firmware, user state, logs, screenshots, or audio asset.
No project build step is required: extract the GitHub source archive and use the
platform launcher below.

## Run

Python 3.10+ and Tk are required.

```sh
sh ./run_linux.sh /path/to/firmware.bin
```

```bat
run_windows.bat C:\path\to\firmware.bin
```

First launcher run may create `.venv` and install `unicorn` and `Pillow`.
Firmware original is read-only. Persistent NOR/EEPROM/NAND state defaults to
`~/.msm5xxx-emulator/`; set `MSM5XXX_STATE_DIR` and `MSM5XXX_LOG_DIR` to move it.
On a recognized legacy GEFS seed mismatch, existing persistent MSM5000
secondary-NOR state is reused in place; its data and path are preserved.
Diagnostic JSON uses additive `schema: 1`; `runtime.sources` contains path-free
SHA-256 identities for CLI, GUI, boot probe, and runtime logger modules.

Raw binaries, strict Intel HEX (`.hex`), and HXB (`.hxb`) can be selected
directly. HXB is decoded in memory only when it contains exactly one top-level
HEX member matching the archive stem. No embedded loader is run and no file is
extracted; invalid checksum, EOF, address, overlap, or size is rejected.

When firmware closes the relocatable catalog, address materializer, translator,
native AMD writer, and caller grammar, an independent 8 MiB NOR is mapped at
`0x02800000..0x02FFFFFF`. Its state is persisted separately and that range is
not decoded as LCD traffic. Every incomplete or ambiguous match keeps native
fallback behavior and records its rejection reason. This storage admission is
not by itself a handset-idle claim.

Automatic keypad input is enabled only when firmware structure closes an exact
direct 6x4 matrix with a Samsung ring32 or LG ring256 queue sink. An LG
descriptor 6x5 path is also enabled when its legacy 5 ms timer, detector-closed
two- or three-bank controller route, IRQ wrapper, handler slots, and queue drain
all close. Three-bank pending/status access is limited to its validated IRQ
handler. Detection uses no model- or filename-specific rules. LG classes map
numeric keys, `*`, and `#` to evidenced matrix positions; remaining single-key
controls use deterministic experimental unique-cell mapping. Samsung ring32
maps `MENU`, `UP/DOWN/LEFT/RIGHT`, Cancel, and Call, but never infers remaining
labels from firmware table order. Centre OK is provisionally mapped to `0x53`
only when the same image contains the exact KEYEMUL `O=0x53` grammar and one
unique matrix cell. It is logged as `automatic-experimental`; End and volume
remain unmapped. Unknown transports, ambiguous cells, and multi-key input
remain disabled.

Right-click any button to override its event byte. Clicking a control with no
usable automatic cell opens the same editor. A value such as `0x53` is accepted
only when it occurs exactly once in the detected firmware matrix table;
`0x00`, `0xFF`, and matrix no-key values are rejected. The emulator drives that
physical row and column through normal scanner/debounce—it never injects the
byte into a firmware queue. Mappings are stored per firmware SHA-256; an empty
value removes the mapping.

Every accepted or rejected edge logs requested source, mapping source
(`automatic-evidenced`, `automatic-experimental`, or `manual`), rule, and
reason. Accepted edges also record detector family/fingerprint, firmware
event, row/column, fallback rank, and scanner/queue/task counters. Manual
mapping edits log their accepted/rejected decision and sanitized requested
value. These fields distinguish a wrong experimental label from a transport
failure.

For descriptor input, telemetry distinguishes the scanner-to-enqueue call edge
from the actual raw-ring store, dequeue return, and task receipt. Fresh numeric
press/release runs on SV130 and SD810 After reached all four stages without a
fault. This proves firmware task delivery, not a visible UI response, handset
idle, or `OK` semantics.

### Updates

The GUI checks GitHub `main` in the background. When it sees a commit not yet
seen by this install, it asks before downloading it. Accepting downloads a
verified copy into `~/.msm5xxx-emulator/updates/`, replaces only manifest-owned
runtime files in the extracted folder, and restarts the GUI. Firmware and files
outside the manifest remain untouched; replacing modified distributed source
requires explicit confirmation. Declining suppresses that commit only; a later
commit prompts again. Failed/offline checks are silent and do not affect emulation.

### Attach a separate NAND dump

A NAND dump is data, not boot firmware. Run its matching NOR dump and attach NAND
separately. For a RIFF-style raw dump with 16 MiB main data plus 16 spare bytes per
512-byte page:

```sh
python msm5xxx.py phone-nor.bin --nand-image phone-nand.bin \
  --nand-data-size 0x1000000 --nand-page-size 512 --nand-spare-size 16 \
  --nand-pages-per-block 32 --nand-bus-width 2
```

That interleaved main+spare layout is `0x1080000` bytes
(`32768 × (512 + 16)`). The input dump stays read-only; persistent NAND changes
are stored separately. Do not guess different geometry—submit its log and size.

## Help Improve the Emulator

### Community Firmware Status

Track firmware model, chipset, display, input, boot, and runtime status in the
[community compatibility sheet](docs/COMMUNITY_COMPATIBILITY_SHEET.md).
Its document contains the single canonical sheet URL for future changes.

### Submit a Test Log

1. Run the emulator with your firmware.
2. Compress the generated `logs/` directory as `logs.zip` and submit it through
   [the test log form](https://forms.gle/8ThEtrJgZceiAE3HA).
3. State the GUI button, expected action, and action the firmware actually took.

...or find Ancalina somewhere and send the archive directly.

CLI JSON records a completed direct primary-NOR `0x90`, `+0/+2`, `0xFF` ID
probe without changing mapped NOR data. Captured words are dump bytes, not
claimed physical IDs.

Terminal diagnostics retain the latest 16 unmapped accesses with PC, address,
size, value, and outcome. This records device evidence; it does not infer a
device response or map unknown hardware.

## Package

```sh
python3 -m pip install .
msm5xxx-emulator /path/to/firmware.bin --detect-only
msm5xxx-boot-probe /path/to/firmware.bin
```

Existing source-checkout commands remain supported: `python msm5xxx.py`,
`python boot_probe.py`, `python gui.py`, `run_linux.sh`, and `run_windows.bat`.

## Development

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile _compat.py msm5xxx.py gui.py boot_probe.py
python3 -m py_compile $(find src -name '*.py' -print)
```

Most tests use synthetic byte sequences. Corpus-dependent regressions skip
unless a private local `firmwares/` directory exists. Do not add manufacturer
firmware, user state, diagnostic bundles, screenshots, SoundFonts, or local paths.

## License

Copyright © 2026 Ancalina. Licensed under `GPL-2.0-or-later`.

Unicorn is GPLv2-only. Any emulator distribution that includes or combines
with Unicorn must use this project's GPLv2 option; do not combine it with
GPLv3-only or AGPL code. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
