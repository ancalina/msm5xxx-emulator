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
