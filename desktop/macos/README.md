# MSM5xxx Emulator for macOS

Native SwiftUI desktop application for macOS 15 or later. No third-party Swift dependencies. Requires Xcode 26 or newer for Icon Composer asset compilation (Swift package uses Swift 5.10 or newer), Python 3 with the repository's backend dependencies, and the macOS MSM5xxx QEMU executable. The application, bundle, product and executable are named **MSM5xxx Emulator**.

Build from a clean checkout on a Mac:

```sh
cd desktop/macos
swift build --jobs 2
swift build -c release --jobs 2
./build-app.sh release
```

The last command creates an ad-hoc signed `.build/application/MSM5xxx Emulator.app`, including the `MSM5xxx Emulator` executable, localization resources, 16–1024 pixel `.icns` icons, and a layered Icon Composer document compiled for macOS 26. Quote the app path because it contains a space. Set `MSM5XXX_APP_OUTPUT` to an absolute `.app` path to package another configuration separately. No firmware or QEMU binaries are included.

SwiftUI owns the library `Window`, URL-valued emulator and secondary `WindowGroup` scenes, Settings scene, toolbars, menus and window sizing. Shared emulator commands use `FocusedValue`. Emulator content declares its minimum with `.frame(minWidth:minHeight:)` and `.windowResizability(.contentMinSize)`. Keypad controls are SwiftUI `Button`s with a `ButtonStyle` that tracks `configuration.isPressed`; guest keyboard input uses `.onKeyPress`. The LCD pixel canvas and a small secondary-click-only key event accessor are `NSViewRepresentable` bridges; the accessor passes primary clicks and keyboard focus through to SwiftUI and opens mapping directly on secondary click, including for disabled keys. AppKit also provides Dock icon switching, secondary-window aspect ratio and child-window docking, and a small scene-owned window accessor for refitting after actual LCD geometry arrives and maintaining the main window’s screen-to-keypad sizing while it is resized. SwiftUI 15 has no API for that dynamic refit/height-for-width behavior. The app uses the system appearance, standard menus and controls, SwiftUI file importer/exporter panels, and native accessibility. The LCD remains a pixel image; VoiceOver can navigate its named display and the surrounding keypad, metrics, menus and forms.

Development run on the owner's Mac, with copies under the dedicated working directory:

```sh
cd ~/desktop-ui-macos
mkdir -p tmp/state
export MSM5XXX_BUNDLE="$PWD"
export TMPDIR="$PWD/tmp"
export MSM5XXX_PYTHON="$HOME/desktop-ui-macos/python/bin/python3"
export MSM5XXX_QEMU="$HOME/desktop-ui-macos/bin/qemu-system-arm"
export MSM5XXX_STATE_DIR="$PWD/tmp/state"
cd desktop/macos
./run.sh debug
```

Apple Quick Look renders the SVG grain filter for the classic icons; Icon Composer layers are compiled by `actool`. The icon build uses the project's unchanged `Branding/chip_icon.py` generator and the bundled Hershey stroke data (license in `Branding/NOTICE`), with the version from `pyproject.toml`, UTC build date (`SOURCE_DATE_EPOCH` supported), and checkout commit. `MSM5XXX_APP_VERSION` and `MSM5XXX_APP_COMMIT` override metadata. For a source-only transfer, first run `python3 desktop/macos/Tools/build_branding.py --metadata-only --out desktop/macos/.build-metadata.json` in the checkout and transfer that ignored file too.

The run script packages `.build/application/MSM5xxx Emulator.app` and launches it through Launch Services, passing explicit environment overrides. Use `./run.sh release` for the optimized app. The script translates `--verify SAMPLES OUTPUT`, `--verify-feedback SAMPLES OUTPUT`, `--verify-native-drag` and `--inspect OUTPUT` into debug-only environment settings. This preserves the regular SwiftUI scene launch event while keeping the documented verification commands unchanged. Unknown arguments are passed to the app. Launching through Finder also presents the library; directly executing a SwiftUI binary does not reliably send the open-application event. For distribution place the app under `<bundle>/bin/` beside `qemu-system-arm`, with the backend under `<bundle>/src/` and optionally Python at `<bundle>/python/bin/python3`. `MSM5XXX_BUNDLE`, `MSM5XXX_PYTHON` and `MSM5XXX_QEMU` override those locations. Otherwise Python falls back to `python3` on PATH. `MSM5XXX_STATE_DIR` overrides the backend's normal saved-state directory.

Import firmware with Command-O or the toolbar's plus button. Double-click an entry, press Return on a selected row, or use its Boot button. One window is reused for each firmware path. Each emulator owns its backend process and stops it before closing. Several firmware windows can exist independently; routine verification runs one guest at a time.

Click the LCD to focus guest keyboard input. Arrows, Return, Escape, digits, plus and minus follow `ui.layout.keyboard`. Command, Control and Option shortcuts pass through to macOS. Tab moves into the native keypad. Pointer presses stay held while pressed; quick pointer, keyboard and accessibility presses last at least `key_hold_ms`. Leaving the window releases all held keys. Use Edit key layout, secondary-click or Control-click a key to edit its firmware event byte. Done appears in the spare bottom-left keypad cell while editing and leaves edit mode.

The opening window measures keypad labels and both lid labels, then chooses the smallest whole LCD scale that accommodates them. Buttons have a 56-point natural minimum width; columns 1–3 have identical widths; column 0 fits its longest button label. Live metric values shrink to fit down to 8 points and never widen the column or window. All keypad buttons share a 32-point height. It refits when real frame geometry arrives and prevents shrinking below that opening size through pointer, keyboard and programmatic resizing. SwiftUI declares the content minimum with `.frame(minWidth:minHeight:)` and the scene’s `.windowResizability(.contentMinSize)`. The small geometry bridge maintains the same minimum after native frame/content-size requests and keeps LCD height coupled to width. The title bar shows only the model; chipset, real LCD dimensions and network status appear in Info. Widening preserves LCD proportions; extra height goes to the LCD area.

The secondary display opens at 3× and resizes at its native aspect ratio down to 1×. Its window accessor uses the standard content area below the title bar so AppKit’s content aspect ratio describes the LCD. Drag it within 16 points of either emulator edge to attach, aligned with the main content top. Native child windows follow parent movement and minimization; drag it away to detach. The attached side is remembered for each firmware. General settings offers Full / Simple (MSM5) and switches the Dock icon immediately. These frontend preferences live in `desktop-macos.json` beside the isolated backend state.

The toolbar contains exactly two primary-action items: Power and the ellipsis menu. The menu bar’s Emulator menu shares the same actions and uses Shift-Command-P for power, Command-R for reboot, Shift-Command-S for capture, and Command-I for Info. Command-comma and Settings open the native Settings scene. From an emulator it offers General and Hardware tabs for that device; from the library it offers General options. Apply and Restart validates hardware fields before restarting. App-wide machine options take effect on restart; changing network time refreshes running sessions. Language changes apply to open windows; hardware forms update when reopened.

Debug verification, using a fresh directory so saved settings are isolated:

```sh
cd ~/desktop-ui-macos
export MSM5XXX_BUNDLE="$PWD"
export TMPDIR="$PWD/tmp"
export MSM5XXX_PYTHON="$HOME/desktop-ui-macos/python/bin/python3"
export MSM5XXX_QEMU="$HOME/desktop-ui-macos/bin/qemu-system-arm"
export MSM5XXX_STATE_DIR="$PWD/tmp/verification-state"
mkdir -p "$MSM5XXX_STATE_DIR" tmp/verification
# Run the native input/snapshot driver outside the app.
swift desktop/macos/Tools/native-verification.swift "$PWD/tmp/verification" >tmp/native-verification.log 2>&1 &
cd desktop/macos
./run.sh debug --verify "$MSM5XXX_BUNDLE/samples" "$MSM5XXX_BUNDLE/tmp/verification"
```

Run interactive verification with the Mac desktop unlocked. The external driver posts real keyboard/pointer events only while the requested app instance under `MSM5XXX_BUNDLE` is active, accepts the PNG export panel, and captures owned windows. The terminal running this development tool needs macOS event-posting and Accessibility access for the native event and AX-action checks. The application itself needs no event-posting permission for normal keyboard/pointer input. Verification waits while the screen is locked, since macOS prevents native dialog and accessibility interaction in that state.

Use `--verify-feedback SAMPLES OUTPUT` for firmware geometry, window behavior and snapshot checks without the full suite's interactive lock-screen gate. It records accessibility data but leaves interactive acceptance to `--verify`. The debug-only program uses real firmware and backend processes, writes `checks.txt`, `result.txt`, and window PNGs, and exits. It exercises library operations, both firmware images, display geometry, settings validation, key mapping, input handlers, lid and secondary display, restart, errors, languages, themes and shutdown. Snapshots use AppKit's view caching API so no screen-recording entitlement is needed. This program is excluded from release builds. A debug-only `--inspect OUTPUT` mode accepts numbered JSON requests in `OUTPUT/request.json`, replies in `response.json`, and supports native dialog, field composition, key, settings, snapshot and shutdown inspection. Both inspection hooks and window snapshots are excluded from release builds. Validation details and platform limits are recorded in STATUS-macos.md in the workspace.

Linux-to-Mac transfer and build commands (run from the workspace, using only the supported transport):

```sh
mac run 'mkdir -p ~/desktop-ui-macos/desktop ~/desktop-ui-macos/samples ~/desktop-ui-macos/tmp'
mac push repo-macos/src desktop-ui-macos/
mac push repo-macos/desktop/macos desktop-ui-macos/desktop/
mac push samples/x350.bin desktop-ui-macos/samples/
mac push samples/a640.bin desktop-ui-macos/samples/
mac run 'cd ~/desktop-ui-macos/desktop/macos && swift build --jobs 2'
mac pull desktop-ui-macos/tmp/verification tmp/macos-verification
```
