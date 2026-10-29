# Contributing

- Never commit firmware dumps, state sidecars, logs, screenshots, IDA databases,
  unreviewed SoundFonts, credentials, or absolute local paths. Bundled
  TimGM6mb is the sole audited SoundFont exception.
- Add a synthetic regression test for behavior changes.
- Preserve deterministic guest CPU, memory, device, timer, and storage behavior.
- Describe firmware evidence by hash, offset, and minimal trace; do not attach
  proprietary bytes.
- Contributions must be compatible with `GPL-2.0-or-later`. Do not submit
  GPLv3-only or AGPL code: distribution with Unicorn must use GPLv2.

## Layout

| Path | Contents |
| --- | --- |
| `src/msm5xxx_emulator/` | Python package: detectors, devices, GUI, `qemu/` transport and live display |
| `native/qemu/` | QEMU machine sources, upstream patches, pinned build inputs and scripts |
| `android/` | Android client and its runtime build scripts |
| `tests/` | Unit and native regression tests |
| `docs/` | Backend and source distribution notes |

Run the tests from the repository root:

```sh
PYTHONPATH=src:tests python3 -m unittest discover -s tests
```
