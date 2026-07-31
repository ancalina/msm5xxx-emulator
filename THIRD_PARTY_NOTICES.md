# Third-party notices

- Unicorn Engine (`unicorn==2.1.4`) is GPLv2. It supplies the native CPU
  engine used by this emulator. A combined distribution must use this
  project's GPLv2 option.
- Pillow (`Pillow>=10,<13`) uses the MIT-CMU License.
- NumPy (`numpy>=1.26,<3`) uses the BSD 3-Clause License.
- `src/msm5xxx_emulator/gm.sf2` is TimGM6mb, copyright 2004 Tim
  Brechbill and 2010 David Bolton, distributed under GPL-2.0-only. The
  unmodified file comes from Debian source package `timgm6mb-soundfont`
  1.3-5:
  <https://sources.debian.org/src/timgm6mb-soundfont/1.3-5/>
  SHA-256:
  `c5378b62028c920cb11e4803327983fee2f2cdff5dc89c708e39da417e51c854`.

Dependencies are installed by the launcher or package manager; their source
and license notices are not replaced by this file. The complete GPLv2 text
covering this distribution and TimGM6mb is in `LICENSE`.
