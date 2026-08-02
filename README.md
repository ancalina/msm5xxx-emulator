# MSM5xxx Emulator

[한국어](README.ko.md)

Experimental Qualcomm MSM5000/MSM5100/MSM5500 feature-phone firmware emulator
built on Unicorn.

The project focuses on preservation and reproducible research of undocumented,
obsolete mobile hardware. It contains no manufacturer firmware, user state,
logs, or screenshots. The only bundled audio asset is the audited
GPL-2.0-only TimGM6mb SoundFont.

No build step is required. Clone or extract the source tree and run the platform
launcher.

## Run

Requirements:

- Python 3.10+
- Tk
- Git, or a downloaded source archive

Linux:

```sh
git clone https://github.com/ancalina/msm5xxx-emulator.git
cd msm5xxx-emulator
sh ./run_linux.sh /path/to/firmware.bin
```

Windows:

```bat
git clone https://github.com/ancalina/msm5xxx-emulator.git
cd msm5xxx-emulator
run_windows.bat C:\path\to\firmware.bin
```

The first run may create `.venv` and install `unicorn`, `Pillow`, and `NumPy`.

The single-witness C80 timer/IRQ profile remains opt-in:

```text
--experimental-c80-controller
```

## Project status

The emulator is under active development and does not yet provide complete
handset emulation.

Current work includes:

- ARM firmware execution
- firmware-derived memory and device detection
- display and keypad emulation
- persistent NOR, EEPROM, and NAND state
- REX, timer, IRQ, and storage research
- experimental Yamaha MA-2 and MA-5 handling
- reproducible diagnostics and compatibility tracking

Detection does not depend on handset model names or firmware filenames.
Incomplete or ambiguous matches remain disabled or use native fallback
behavior.

## Firmware and state

Firmware input remains read-only. Persistent state defaults to:

```text
~/.msm5xxx-emulator/
```

Override state and log locations with:

```text
MSM5XXX_STATE_DIR
MSM5XXX_LOG_DIR
```

Supported input formats:

- raw binary
- strict Intel HEX (`.hex`)
- HXB (`.hxb`)

HXB files are decoded in memory only when they contain one valid matching HEX
member. Embedded loaders are never executed.

Diagnostic reports use an additive JSON schema and path-free SHA-256 source
identities.

## Storage

The emulator can provide persistent NOR, secondary NOR, EEPROM, and NAND state
when the required firmware structures are detected.

A NAND dump must be attached separately from its matching NOR firmware:

```sh
python msm5xxx.py phone-nor.bin --nand-image phone-nand.bin \
  --nand-data-size 0x1000000 --nand-page-size 512 --nand-spare-size 16 \
  --nand-pages-per-block 32 --nand-bus-width 2
```

The original dump remains read-only. Persistent changes are stored separately.
Do not guess unknown NAND geometry; provide the exact dump size and a diagnostic
log when requesting support.

## Keypad input

Automatic keypad input is enabled only when a supported firmware matrix and
queue path are detected.

Detection uses firmware structure rather than manufacturer, model, KEYEMUL, or
filename maps. Unknown transports, ambiguous cells, and unsupported multi-key
paths remain disabled.

Right-click a GUI button to set a per-firmware manual event-byte mapping. The
emulator drives the detected physical row and column through the firmware's
normal scanner path instead of injecting events directly into a queue.

## Experimental audio

Firmware continues to execute its own audio driver.

Current status:

- MA-2: approximate MMF/PCM rendering
- MA-5: write telemetry only
- MA-3: disabled

MA-2 FIFO snapshots and valid MMF buffers can be rendered with the bundled
TimGM6mb SoundFont. Output is approximate and does not reproduce exact Yamaha
hardware.

Playback uses `ffplay`, then Windows `winsound`. Hosts with neither remain
render-only. Audio failure does not stop guest emulation.

## Updates

The GUI can check GitHub `main` for updates.

Updates require confirmation, replace only verified manifest-owned runtime
files, and do not modify firmware or unrelated files. Offline or failed checks
do not affect emulation.

## Help improve the emulator

### Compatibility status

Track model, chipset, display, input, boot, and runtime results in the
[community compatibility sheet](docs/COMMUNITY_COMPATIBILITY_SHEET.md).

### Submit a test log

1. Run the emulator.
2. Compress the generated `logs/` directory as `logs.zip`.
3. Submit it through the
   [test log form](https://forms.gle/8ThEtrJgZceiAE3HA).
4. Include the expected action and actual result.

You may also contact Ancalina directly.

## Package

Source checkout is the primary distribution method. Local package installation
is also supported:

```sh
python3 -m pip install .
msm5xxx-emulator /path/to/firmware.bin --detect-only
msm5xxx-boot-probe /path/to/firmware.bin
```

Existing source commands remain supported:

```text
python msm5xxx.py
python boot_probe.py
python gui.py
run_linux.sh
run_windows.bat
```

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m py_compile _compat.py msm5xxx.py gui.py boot_probe.py
python3 -m py_compile $(find src -name '*.py' -print)
```

Most tests use synthetic byte sequences. Corpus-dependent tests require a
private local `firmwares/` directory.

Do not add manufacturer firmware, user state, diagnostic bundles, screenshots,
unreviewed SoundFonts, or local paths to the repository.

## License

Copyright © 2026 Ancalina.

Licensed under `GPL-2.0-or-later`.

Unicorn is `GPL-2.0-only`. Distributions that include or combine with Unicorn
must use this project's GPLv2 option and must not include GPLv3-only or AGPL
code.

See [`LICENSE`](LICENSE) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
