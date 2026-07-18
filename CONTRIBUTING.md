# Contributing

- Never commit firmware dumps, state sidecars, logs, screenshots, IDA databases,
  SoundFonts, credentials, or absolute local paths.
- Add a synthetic regression test for behavior changes.
- Preserve deterministic guest CPU, memory, device, timer, and storage behavior.
- Describe firmware evidence by hash, offset, and minimal trace; do not attach
  proprietary bytes.
- Contributions must be compatible with `GPL-2.0-or-later`. Do not submit
  GPLv3-only or AGPL code: distribution with Unicorn must use GPLv2.
