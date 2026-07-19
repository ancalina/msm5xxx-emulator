# MSM5xxx Emulator

Unicorn-based Qualcomm MSM5000/MSM5100/MSM5500 feature-phone firmware emulator.
Experimental project. 
This tree contains no firmware, user state, logs, screenshots, or audio asset.

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
Diagnostic JSON uses additive `schema: 1`; `runtime.sources` contains path-free
SHA-256 identities for CLI, GUI, boot probe, and runtime logger modules.

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

### Submit a Test Log

1. Run the emulator with your firmware.
2. Compress the generated `logs/` directory as `logs.zip` and submit it through
   [the test log form](https://forms.gle/8ThEtrJgZceiAE3HA).

CLI JSON records a completed direct primary-NOR `0x90`, `+0/+2`, `0xFF` ID
probe without changing mapped NOR data. Captured words are dump bytes, not
claimed physical IDs.

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

`README_ALPHA.md` records current alpha runtime scope.
