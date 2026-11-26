# MSM5xxx Desktop for Linux

A native GNOME-style firmware library and phone emulator, written in Rust with GTK 4
and libadwaita. Also runs on KDE Wayland. Each phone window owns an independent Python
backend and QEMU session; opening the same firmware again focuses its existing window.

## Install and update

Release packages contain the native GTK app, QEMU and its library closure, an embedded Python runtime with Capstone/Pillow, GTK 4 and libadwaita. Firmware and the optional sound-chip ROM remain user-supplied. The x86-64 packages require glibc 2.43 or newer (Ubuntu 26.04 or newer); graphics drivers, system fonts and locales come from the OS.

Install the `.deb` with your normal package manager. It registers an application-menu entry and icon; `apt remove msm5xxx-emulator` removes the program and its menu entry while retaining per-user data. A new-version notice links to GitHub Releases; install the new `.deb` with the package manager.

Make the AppImage executable and open it. Its first launch registers a per-user application-menu entry and icon. **Settings → Updates** provides **Check for Updates** and the startup-check switch. A persistent stock banner offers **Review** when a newer version is available. **Install and Restart** verifies the release asset's SHA-256 and byte count, keeps the previous image as `<image>.old`, replaces the AppImage atomically and stops running phones before restarting. The image must be owned by the current user in a writable directory. Update information and `.zsync` metadata also support standard AppImage update tools; the in-app updater downloads the full image.

To uninstall an AppImage, delete the AppImage, its `.old` backup, and its per-user `~/.local/share/applications/io.github.ancalina.MSM5xxx.desktop` and `~/.local/share/icons/hicolor/256x256/apps/io.github.ancalina.MSM5xxx.png`. User data is retained. Data lives in `$XDG_DATA_HOME/msm5xxx` (default `~/.local/share/msm5xxx`), with appearance preferences in `$XDG_CONFIG_HOME/msm5xxx-emulator`; `MSM5XXX_STATE_DIR` overrides both for tests. No package removal deletes these folders.

Build packages after building the native QEMU runtime:

```sh
python3 packaging/linux/build.py 0.2.0-rc /path/to/qemu-system-arm /path/to/artifacts
```

Set `TMPDIR`, `CARGO_HOME` and `CARGO_TARGET_DIR` to workspace directories. The build pins the AppImage tooling by SHA-256, bundles GTK resources and runtime license notices, and creates an AppImage, `.zsync`, and `.deb`. For local update tests, `MSM5XXX_UPDATE_FEED` names a local JSON file with GitHub release fields and a matching SHA-256/size; local `file:` and loopback download URLs are accepted only with this explicit override. Source-archive replacement is retired.

References: [GNOME banners](https://developer.gnome.org/hig/patterns/feedback/banners.html), [GNOME dialogs](https://developer.gnome.org/hig/patterns/feedback/dialogs.html), and [AppImage update information](https://docs.appimage.org/packaging-guide/optional/updates.html).

## Build

Requirements: Rust/Cargo **1.93+**, GTK **4.22.4+**, libadwaita **1.9.1+**, their development
packages with X11 backend support (`gtk4-x11`), `pkg-config`, `gettext` (`msgfmt`), and GLib development tools
(`glib-compile-resources`), X11 development libraries (`libX11`), and Python 3 for the SVG icon generator. The toolkit crate versions are locked; API feature levels
are `v4_22` and `v1_9`, without APIs from newer toolkit releases.

From the repository root:

```sh
cargo build --locked --release --manifest-path desktop/linux/Cargo.toml -j 1
```

`Cargo.lock` is included. A single build job avoids concurrent toolkit compiler processes. The backend
needs Python 3 and the repository's Python dependencies (`capstone`, `Pillow`, etc.).
No Python GUI packages are used by this app.

## Run from a checkout

```sh
export MSM5XXX_BUNDLE="$PWD"
export MSM5XXX_QEMU=/absolute/path/to/qemu-system-arm
unset GTK_THEME
cargo run --locked --release --manifest-path desktop/linux/Cargo.toml
# Optional: open one or more firmware images directly
cargo run --locked --release --manifest-path desktop/linux/Cargo.toml -- /path/to/firmware.bin
```

For the supplied development environment, from the repository root:

```sh
MSM5XXX_BUNDLE="$PWD" \
MSM5XXX_QEMU=/path/to/qemu-system-arm \
MSM5XXX_STATE_DIR="$TMPDIR/linux-state" \
env -u GTK_THEME taskset -c 6-7 nice -n 19 \
  cargo run --locked --release --manifest-path desktop/linux/Cargo.toml -- ../samples/x350.bin
```

Use a directory under `$TMPDIR` for `CARGO_HOME` and `CARGO_TARGET_DIR` if the default
Cargo directories are read-only. Keep at most one guest running during sample verification.
The application itself supports several different firmware sessions concurrently.

The backend command is `<python> -m msm5xxx_emulator.backend --qemu <qemu>` with
`PYTHONPATH=$MSM5XXX_BUNDLE/src`. Python is selected from `MSM5XXX_PYTHON`, then the bundle's
`python/bin/python3`, `python/python3`, or `python/bin/python`, then system `python3`.
The bundle defaults to the parent of the executable's `bin/` directory. QEMU defaults
to `MSM5XXX_QEMU`, then `<bundle>/bin/qemu-system-arm`.
`MSM5XXX_STATE_DIR` is passed through unchanged; without it the backend uses its normal
settings location. Firmware is never copied or modified by the UI.

## Install in an existing emulator bundle

```sh
# Set bundle to a distribution containing src/ and the QEMU executable in bin/.
bundle=/absolute/path/to/bundle
install -Dm755 desktop/linux/target/release/msm5xxx-desktop "$bundle/bin/msm5xxx-desktop"
install -d "$bundle/share/locale/ko/LC_MESSAGES"
msgfmt desktop/linux/po/ko.po -o "$bundle/share/locale/ko/LC_MESSAGES/msm5xxx.mo"
install -Dm644 desktop/linux/data/io.github.ancalina.MSM5xxx.desktop \
  "$bundle/share/applications/io.github.ancalina.MSM5xxx.desktop"
install -Dm644 desktop/linux/target/release/msm5xxx-icons/io.github.ancalina.MSM5xxx.svg \
  "$bundle/share/icons/hicolor/scalable/apps/io.github.ancalina.MSM5xxx.svg"
install -Dm644 desktop/linux/target/release/msm5xxx-icons/io.github.ancalina.MSM5xxx-symbolic.svg \
  "$bundle/share/icons/hicolor/symbolic/apps/io.github.ancalina.MSM5xxx-symbolic.svg"
cp -a desktop/linux/target/release/msm5xxx-icons/hicolor/. "$bundle/share/icons/hicolor/"
```

If using `CARGO_TARGET_DIR`, substitute that directory for `desktop/linux/target`.
Add the bundle's `bin` to `PATH`, and expose its `share` directory via `XDG_DATA_DIRS`,
or install the desktop entry and icon into your desktop's standard application directories.
The icon is also embedded in the executable. Installation never changes file associations.
The build runs the current shared chip-icon generator with only platform and output
arguments. The generator reads the repository version from `pyproject.toml`, Git HEAD,
and the current date itself, using the `LNX X64`/`LNX A64` platform marking. Set
`SOURCE_DATE_EPOCH` for a reproducible date. Build from a checkout that includes the
repository metadata and `pyproject.toml`. The local glyph source needs no system font package.
The generated SVGs and hicolor PNGs (16–512 pixels) are in the build profile's
`msm5xxx-icons/` directory. The GTK SVG image loader is required to build/render them.
Settings → **App Icon** switches every open window/taskbar icon between **Full** and
**Simple (MSM5)** immediately; the installed launcher icon stays Full. The choice persists
in `linux-appearance` under `MSM5XXX_STATE_DIR`, or the user's configuration directory.
The native Wayland toplevel-icon protocol is used when supported by the compositor.
Title bars omit the app icon in every window and dialog, including on desktops whose
GTK decoration layout requests it. The remaining system button order follows the desktop
and updates when its layout changes; taskbar and window-switcher icons remain available.
The bundled Hershey vector glyph source and generated SVG metadata retain its original
acknowledgements and redistribution terms; no system font package is needed to build icons.
GNU gettext uses `share/locale` in a bundle and the build output's locale directory during
development. English source strings and a Korean PO catalog are included. Language is
selected through backend settings (automatic/Korean/English). Install the system
`ko_KR.UTF-8` locale for Korean toolkit translations; reopen the app after changing
it for toolkit-owned system dialogs; app windows and Settings labels update live without restarting firmware.

## Controls and behavior

- Import a firmware file or add a folder; scans run in the background. Removing an entry
  or folder changes the library, leaving original files on disk.
- Power, reboot, capture to PNG, firmware information, virtual network, network time,
  key mapping and settings are available from each phone window.
- The emulator uses an `AdwHeaderBar`: a flat native power button at the start
  (`system-shutdown-symbolic`, “Power on” / “Power off” tooltip and accessible name)
  and one primary `GtkMenuButton` at the end (`open-menu-symbolic`, “Main Menu”).
  F10 opens the [GTK primary menu](https://docs.gtk.org/gtk4/property.MenuButton.primary.html). Every other emulator command is in that menu, including
  the Network Time submenu. Header buttons use the stock Adwaita style in every power state.
- The title bar shows the model name only. Info contains chipset, actual LCD dimensions,
  network status, power and secondary-display details. There is no subtitle or extra status row.
- The LCD refits to actual frame dimensions. Its opening width fits the keypad buttons
  plus their own margins and the header minimum, with the native LCD width as a
  lower bound, without rounding the width up to an integer LCD scale.
  The model title may ellipsize and never supplies its natural width to this calculation.
  Keypad columns 1–3 have exactly equal widths; column 0 fits its longest button label.
  The keypad-only CSS keeps square, flat buttons; Done uses the spare column-0, row-8 cell.
  All keypad buttons have equal heights. Live counters shrink their monospace font
  to a 7-point floor instead of widening any column or window; the full value remains
  available in a tooltip if it exceeds that floor.
  **Close lid** / **Open lid** remain complete. The opening size is enforced as the
  minimum for all resize paths, and is recomputed without a sticky previous width.
  Resizing preserves aspect ratio and nearest-neighbour pixels; additional height stays
  above the bottom-aligned keypad.
- Keyboard bindings come from `ui.layout`. Tab moves between native controls; Space
  activates a focused keypad key. With focus on the LCD or keypad, mapped keys control
  the phone. Ctrl/Alt/Super/Meta shortcuts, menus, text entries and dialogs keep their
  normal behavior. Switching windows releases held keys. Quick taps remain down for at
  least the backend's hold interval, measured after its acceptance reply.
- Right-click a key, or enable **Edit Key Layout**, then activate it to enter a decimal
  or hexadecimal event byte. Empty clears a mapping. Unavailable keys can be edited in
  edit mode. **Done** exits editing. `session.keys` refreshes availability after a change.
- A qualified secondary LCD opens once automatically per boot at its measured minimum:
  a 1× LCD content area plus native window chrome, widened if needed for header controls.
  Its window remains resizable. GTK letterboxes
  the pixels at their original aspect ratio. Closing hides it; the menu reopens it.
- On native X11 sessions, dragging the secondary display within 16 logical pixels of
  either main-window side snaps the visible edges flush and aligns the LCD tops. Moving
  or resizing the main window keeps the secondary alongside it; minimize/restore follows.
  Drag the secondary more than the snap distance away to detach. The attached side and
  state persist per firmware in `linux-displays/` under the isolated state directory
  (or app configuration directory). X11 positioning accounts for native frame/shadow extents.
  Wayland sessions have no docking controls, side pane or positioning controller; the
  secondary display remains a separate resizable window, with no transient parent on Wayland.
  Its native window title displays only the model name, without a subtitle or app icon.
  Power, dimensions and display notes remain available in the LCD tooltip and Info.
  Native close-only utility controls follow the desktop's button placement.
  Power off hides it.
- General settings save when changed; apply a time entry with its Apply button. Hardware
  settings are grouped on the Hardware page; **Apply and Restart** validates all fields,
  disables editing while applying, preserves edits on failure, then restarts after success.
  Hardware settings remain available after a QEMU launch failure.
- Closing a phone sends `session.stop`, closes stdin and waits off the UI thread. The
  backend process group is terminated ten seconds after the close request if it has
  not exited, including when an earlier request is still waiting for a reply.

Keyboard shortcuts: Ctrl+O import; Ctrl+R/F5 refresh; Ctrl+, settings; Ctrl+S capture;
Ctrl+W close current window; Ctrl+Q close all windows and sessions.

The LCD is firmware-rendered pixel content and has no semantic text tree. Its surrounding
controls have native keyboard focus and AT-SPI names, roles and states. System font,
contrast, color scheme and button arrangement are respected. The only application CSS is
scoped to keypad buttons for the owner's square/flat-key exception.

## Development verification

```sh
cargo build --locked --manifest-path desktop/linux/Cargo.toml -j 1
cargo test --locked --manifest-path desktop/linux/Cargo.toml -j 1
cargo fmt --manifest-path desktop/linux/Cargo.toml -- --check
cargo clippy --locked --manifest-path desktop/linux/Cargo.toml --all-targets -- -D warnings
PYTHONPATH="$PWD/src" python3 -m unittest discover -s tests -p test_backend_server.py -v
```

Debug builds only accept `MSM5XXX_VERIFY_DIR=/absolute/path/under/tmp` and
`MSM5XXX_TRACE=/absolute/path/under/tmp/protocol.log`. The former enables a local JSON
request/response harness in `src/verify.rs`;
`MSM5XXX_VERIFY_NON_UNIQUE=1` starts a separate debug application on the desktop bus,
so its native accessibility tree and keyboard input can be tested while an owner app
remains open. This flag is excluded from release builds. The harness drives real GTK actions and widgets,
resizes windows, inspects session state, and captures windows through
`GtkWidgetPaintable` and the window's `GskRenderer`. Write `request.json` atomically and
read `response.json` before the next request. Example requests:

```json
{"command":"inspect"}
{"command":"open","path":"/absolute/path/to/firmware.bin"}
{"command":"snapshot","target":"library","path":"/absolute/path/under/tmp/library.png"}
{"command":"snapshot","target":"x350","path":"/absolute/path/under/tmp/phone.png"}
{"command":"layout","target":"x350"}
{"command":"keypad-margins","target":"x350","value":32}
{"command":"main-menu","target":"x350","open":true}
{"command":"snapshot","target":"x350","menu":true,"path":"/absolute/path/under/tmp/phone-menu.png"}
{"command":"resize","target":"x350","width":200,"height":300}
{"command":"counter","target":"x350","key":"run","value":"123,456,789,012"}
{"command":"action","target":"x350","name":"win.settings"}
{"command":"form","target":"x350"}
{"command":"page","target":"x350","value":"hardware"}
{"command":"theme","dark":true}
{"command":"quit"}
```

With `menu: true`, a snapshot also renders the actual mapped GTK popover at its native
position, accounting for client-side window shadows. The debug-only `icon-theme`
request can select Adwaita for a stock-symbolic comparison without changing desktop settings.

The debug-only `counter` request injects a display value through the production font-fitting
widget; stop the guest first so normal polling does not replace it.

Targets are `library`, a firmware filename stem, `secondary` for the visible secondary LCD,
or `secondary:x350` to choose a particular phone. The backend regression tests include
a deliberate ten-second shutdown timeout.
Wait for transitions and guest boot to finish before capturing. Trace logs omit RGB data.
Both diagnostic features are excluded from release builds. Keep captures, runtime data,
protocol traces and build output outside Git. See the workspace's `STATUS-linux.md` for
actual verification results and evidence paths.
