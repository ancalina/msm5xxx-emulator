# Changelog

## 0.1.0

Changes since the previous public release, `qemu-tcg-preview-20261030-r17.1`.
Compatibility and individual features continue to depend on the firmware.

### Compatibility

- Expanded MSM5000, MSM5100 and MSM5105 boot and hardware support, including
  legacy processor behavior and additional external devices. MSM5500 remains supported.
- Improved detection of firmware hardware, storage, keypad, display and lid
  behavior. Model identity no longer depends on the file name.
- Removed the legacy Unicorn execution mode; QEMU is the execution backend.
  The earlier Unicorn-based history remains on the `unicorn-legacy` branch.
- Improved virtual radio behavior and added host-clock and custom network-time options.

### Display

- Added or improved packed color, monochrome, page-mode and shifted display
  decoding, including additional secondary display paths.
- Improved display replay performance and Android frame delivery.

### Input

- Added keypad, navigation, side-key and lid mappings for more detected layouts,
  including six- and seven-row matrices. Improved Android tap timing.
- Added physical keyboard input on iOS and editable per-firmware mappings.
- Key mappings you enter are kept as entered, even for keys detection did not find.

### Audio

- Added MA3 and MSM5000 tone-generator emulation and improved MA2 and MA5 behavior.
- Added MA2 and native MA5 playback on iOS and audio recovery after foregrounding.
- The previous r17.1 release restored MA2 audio; this release builds on that fix.

### Storage

- Improved NOR bank mapping, erase and protection behavior, NAND detection and
  EEPROM handling. Writable state is kept separately for each firmware.

### Platforms and UI

- Added an iOS app with embedded QEMU and Python. Reopening the app is required
  for firmware changes and some restart situations.
- Added firmware libraries, grouped entries, settings, session actions and
  localized interfaces across desktop and mobile. Added screen-reader labels on mobile.
- Aligned desktop and Android session, library and capture features and improved
  secondary display controls on mobile.

### Compatibility numbers

Of 635 surveyed MSM5xxx firmware images, 145 improved over r17.1 and none
regressed; 250 now draw a screen. See [compatibility](docs/COMMUNITY_COMPATIBILITY_SHEET.md).
