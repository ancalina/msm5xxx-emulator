# Android Compose migration verification

Device: Samsung Galaxy XCover5, Android 12 (API 31), serial R59T103XHAM.
The app retains minSdk 28 and compile/target SDK 35. Every device command selected
this serial explicitly; stay-awake was enabled during verification.

The library, settings, hardware pages, menus and dialogs use stock Compose
Material 3 components, dynamic colour and system light/dark mode. The emulator
has no app bar. Its bottom-left flat key uses the Material horizontal more icon
and anchors a power-first DropdownMenu; network time opens a second DropdownMenu
and toggles show checkmarks. The LCD, flat handset keypad, overlay and
Presentation renderer use View interoperability to retain rendering and input
timing. The three main keypad columns are equal; the wider side column and
counters never determine the window width. On short windows the LCD fits its
available area at its real frame aspect ratio. Python, JSON and native runtime
interfaces are unchanged.

## Build and host checks

- Debug and preview-signed release builds and Android lint pass with pinned
  dependencies from Google Maven/Maven Central. Gradle ran at nice 19, on CPUs
  0–3, with two workers within the 16 GiB memory scope.
- The existing preview-signing init works; APK v3 signature verification passes.
  This uses the developer certificate, not a production release identity.
- All five existing host checks pass: key minimum duration, library ownership
  and removal, grouping and network-time bounds, menu session state, and
  selection labels.

## Device checks

- Imported the supplied firmware through Android's system document picker and
  verified the private copies against SHA-256:
  x350 `7a6a4df853b51a4b44e86c3334330c12facad2954eef5a94031724ff1ff44073`;
  a640 `1497ee6140e2d0ec4a9526cfb7d3a40cbfb79c5efdae12b7517ecaee2ca9a272`.
  Importing x350 reused the identical existing library entry.
- SCH-X350 reached its monochrome firmware home screen with changing execution,
  LCD and frame counters. Touch, injected keyboard events and long-press input
  received backend acknowledgements. Saved and inspected a 128×128 capture PNG
  using Android's Create Document flow.
- SPH-A640 completed detection and native startup after several minutes each,
  then displayed its colour Sprint splash at 128×160 with live execution/LCD
  counters. It remained on that splash during observation; automatic key
  assignments were unavailable. No A640 home screen or key acknowledgements are
  claimed. The runtime was not changed to address this firmware limitation.
- Inspected screenshots of the open anchored actions menu, checked network-time
  submenu, library, firmware info, removal confirmation, emulator and keypad,
  settings, and English/Korean UI in system light/dark themes.
- A system light/dark change while A640 ran preserved the QEMU process and
  advancing counters. Canceling the running-session Back confirmation did too.
- Invalid key mapping was rejected inline. A valid byte persisted and reloaded;
  clearing it removed the override. Exited mapping mode with Done.
- Verified lid close/open and secondary overlay show/hide, move and resize.
  Routed the secondary clock to an Android simulated display through Presentation;
  removing the display restored the in-app fallback. Restored the original display
  configuration and in-app destination.
- Added and removed a test SAF folder, preserving the original folder and source
  firmware SHA-256. Inspected firmware info and canceled removal without deleting
  the supplied A640 entry.
- Switched both Full/Simple launcher aliases and restored Simple.
- Hardware settings retain all fields in section pages with draft values. Samsung
  Korean IME composition, deletion and back navigation worked in the model field;
  Cancel left no saved hardware-settings file.
- Inspected settings and icon choices at 200% text size. Network time retains
  stock calendar, clock dial and keyboard entry, defaults to text input at large
  font sizes, and scrolls its content when needed. Saving round-tripped the
  selected local date/time; Back and Cancel preserved the saved value.

## Coverage limits

Android 15+ predictive-back animations, API 28 execution, a physical external
display and keyboard, a complete TalkBack/audio walkthrough and exhaustive
hardware-profile combinations were not exercised on this Android 12 phone.
The simulated-display and injected-key checks cover their app routing paths.
A640's splash and missing automatic key assignments remain as described above.

Firmware, captures, screenshots, logs and temporary verification tools stay
outside the source checkout. Generated build/runtime artifacts are ignored.
