# MSM5xxx Windows desktop

Native C# / WinUI 3 frontend for the MSM5xxx QEMU feature-phone emulator. The app uses stock Windows controls, the WinUI TitleBar with system caption buttons, Mica and the system theme, native file pickers, and English/Korean Windows resources. Each firmware window owns its own backend process. Firmware is user-supplied; the installer includes the complete emulator runtime.

## Requirements

- Windows x64, Windows 10 version 1809 (build 17763) or later; Windows 11 recommended. OS servicing depends on the Windows edition.
- To build: .NET 10 SDK, Python 3 and Git on PATH, and a Windows 10/11 SDK. NuGet restores pinned Windows App SDK 2.6.5 and Windows SDK build tools. The Visual Studio IDE is optional. The GitHub `windows-2022` image supplies the SDK and native redistributable files.
- To run: a matching Windows QEMU runtime bundle containing `bin/qemu-system-arm.exe`, `src/msm5xxx_emulator/`, and Python with the backend's dependencies (Capstone and Pillow). The installer build assembles this runtime bundle.

The published frontend is unpackaged and self-contained for both .NET and Windows App SDK. It needs no MSIX registration or separate .NET/Windows App Runtime installation. Publish the entire directory; copying only the executable will not work. The workflow also copies Visual Studio's redistributable x64 C++ runtime DLLs beside the executable.

## Build and test

Run these PowerShell commands at the repository root:

```powershell
dotnet restore desktop/windows/Emulator.Core.Tests/Emulator.Core.Tests.csproj
dotnet test desktop/windows/Emulator.Core.Tests/Emulator.Core.Tests.csproj -c Release --no-restore
dotnet restore desktop/windows/Emulator.App/Emulator.App.csproj -r win-x64 -p:Platform=x64
dotnet build desktop/windows/Emulator.App/Emulator.App.csproj -c Release -r win-x64 -p:Platform=x64 --no-restore
dotnet publish desktop/windows/Emulator.App/Emulator.App.csproj -c Release -r win-x64 -p:Platform=x64 --self-contained true --no-build --no-restore -o desktop/windows/artifacts/bin
```

For deployment from a local build, also copy the x64 `Microsoft.VC143.CRT` DLLs from your Visual Studio `VC/Redist/MSVC/<version>/x64/` directory to the publish directory, for a development-only publish. Observe Microsoft's redistribution license. The unpackaged publish remains available for development; release distribution uses Velopack.

On GitHub, select **Actions → Build Windows installers → Run workflow** and enter the release tag. Download `MSM5xxx-windows-installers`; it contains Setup, packages, the update feed, checksums and test results. The workflow builds QEMU and assembles the complete native/Python runtime automatically.

## Install and update

Run `MSM5xxx-win-Setup.exe`. Velopack installs per user to `%LOCALAPPDATA%\MSM5xxx.Desktop`, separate from `%LOCALAPPDATA%\MSM5xxx` user data, registers an uninstall entry and creates a Start menu shortcut. The first app launch offers **Create a desktop shortcut** (off) and **Check for updates on start** (on) in a stock WinUI dialog. Firmware and the optional sound-chip ROM are never included.

**Settings → Updates** provides the automatic-check toggle and **Check now**. Updates come from GitHub Releases, including delta packages when a previous full package is available. A stock InfoBar announces a verified, downloaded update. **Restart now** stops emulator sessions before applying it; closing and reopening the app also applies it. Library, settings and saved state live in `%LOCALAPPDATA%\MSM5xxx`, outside the installed version directory. Windows Settings → Apps uninstalls the app and asks whether to delete this data; the default answer preserves it.

[Velopack Setup 1.2.161](https://docs.velopack.io/reference/cli/content/setup-windows) supports `--silent` (`-s`), `--verbose` (`-v`), `--log FILE` (`-l`), `--installto DIR` (`-t`), and `--help` (`-h`). Arguments after `--` are passed to the launched app. Shortcut and automatic-update choices are in the app. An unanswered uninstall data prompt preserves data when Velopack's 30-second hook deadline expires.

Build the runtime in a MINGW64 shell, then package in PowerShell with .NET 10 and Python 3.12 on PATH:

```sh
bash packaging/windows/build-qemu.sh /absolute/path/to/runtime-work
```

```powershell
$env:BUILD_COMMIT = git rev-parse HEAD
./packaging/windows/build.ps1 -Version 0.2.0-rc -RuntimeDirectory runtime-work/runtime -OutputDirectory artifacts/windows
```

The pack directory contains the self-contained WinUI app at its root, `bin/qemu-system-arm.exe` and its DLL closure, `python/python.exe` with Capstone/Pillow, and `src/msm5xxx_emulator`. The app-local Microsoft VC runtime is extracted from Microsoft's redistributable Desktop VCLibs package. The pinned `vpk` tool is restored from `.config/dotnet-tools.json`. Keep the previous full package in the output directory when packing the next version to generate a delta.

For local update testing, set `MSM5XXX_UPDATE_FEED` to a directory containing Velopack's `releases.win.json` and packages before launching the installed app. Use an isolated `MSM5XXX_STATE_DIR`; install 0.1.99 first, then put the 0.2.0-rc packages in that feed. Production uses the public GitHub Releases source.

For development, use the publish output against an existing bundle:

```powershell
$env:MSM5XXX_BUNDLE = 'C:\Emulators\MSM5xxx-QEMU-windows-x64'
$env:MSM5XXX_STATE_DIR = Join-Path $env:TEMP 'msm5xxx-desktop-test'
& '.\desktop\windows\artifacts\bin\MSM5xxx.Desktop.exe'
```

Optional overrides: `MSM5XXX_PYTHON` is an interpreter executable path (without extra arguments); `MSM5XXX_QEMU` is the QEMU executable path. Python resolution uses that override, then `<bundle>/python/python.exe`, then `py -3`, then `python`. The bundle is found by looking for `bin/` and `src/` above the application directory unless `MSM5XXX_BUNDLE` is set. All backend communication is UTF-8 JSON over redirected pipes; no shell is involved.

## Use

Import a firmware file with **Import file** or **Ctrl+O**, or add a scan folder through the menu. **Ctrl+R** refreshes. Activate an available library row with Enter or a click to boot it. Opening it again focuses its existing window. Removing an entry or scan folder preserves the firmware files. Info shows model, chipset, bytes, source path and last boot time.

The emulator's power button starts/stops its session. Its menu provides reboot, PNG capture, additional display, info, virtual network, network time, key mapping and settings. The additional display appears automatically when the backend first qualifies it; closing it hides it and the menu can reopen it. It opens beside the main window inside that display's work area: right if possible, then left, then overlapping inside the work area. A remembered attachment is honored where it still fits, and moves to a safe side if needed. It opens at 3× LCD scale and can be resized with its LCD aspect ratio preserved; the LCD minimum is 1×. Drag it within 16 physical pixels of either main-window side to attach, and drag away to detach. Attached windows follow moves and minimize/restore, top-aligned with the main content; the side is remembered per firmware in `display-docking.json`. Closing an emulator stops that session; closing the library closes all its sessions. Stdin is then closed; after ten seconds an uncooperative backend is terminated. A Windows job owns the backend, venv interpreter and later children, so inherited pipes and emulator processes cannot outlive the client.

Arrow keys, Enter, Escape, number keys (including the number pad), and plus/minus follow `ui.layout.keyboard`. Ctrl, Alt and Windows shortcuts remain available. Tab moves among controls, and Space/UI Automation can activate a focused key. Pointer and keyboard holds are combined and remain down for at least the backend's requested hold time. Deactivating a window or opening an in-app dialog releases keys. **Edit key layout** enables mapping even for absent keys; select a key, enter a decimal/hexadecimal event byte, or leave it blank to clear its override. Right-click also opens mapping. The visible **Done** button in spare column 0, row 8 exits edit mode; it never covers a phone key.

The opening size comes from actual frame dimensions and the fresh natural keypad width, including its margins. The model title does not widen the window and may ellipsize. The smallest whole-number LCD scale that fits the keypad is used, capped to the window display's available work area after native borders. If needed, only the LCD scale is reduced, fractionally below 1× when necessary; the keypad retains its natural width and height. The resulting opening size becomes the user minimum. The keypad is fixed at the bottom without a ScrollViewer. The emulator title bar contains only the model name, Power, actions menu and system buttons. Chipset, LCD dimensions and localized network status are shown in Info. Keypad column minima are reset and measured on each fit, so earlier stretched widths cannot accumulate. Column 0 takes the natural width of its button labels; columns 1–3 share their largest natural minimum and divide the remaining width equally in physical pixels. Any indivisible one- or two-pixel remainder goes to column 0, so resizing cannot leave one digit column a pixel narrower. All keypad buttons occupy 32 px rows with square corners and no border/elevation treatment, as required by the phone-content exception. Live monospace counters stay inside column 0 at 11 DIP, shrinking proportionally to an 8 DIP floor; values that exceed even that floor ellipsize, with the full value available in the tooltip and accessible name. A separate cell supplies the fitting width, so short text returns to 11 DIP. Counter updates never widen columns or refit the window. Live language changes remeasure the button minima. Widening increases the screen and client height at the LCD aspect ratio; extra user-added height stays in the display area. A small Win32 `WM_SIZING` hook constrains interactive width drags because WinUI has no height-for-width window property; Snap, maximize and monitor DPI changes retain system-selected bounds. Rendering maps LCD pixels to physical display pixels with nearest-neighbour sampling and aspect-preserving black bars. Metrics remain under the lid button. Their names and descriptions come from the backend.

Settings opens a separate non-modal window. Four app-wide on/off options use ToggleSwitch; app-wide fields save immediately, with inline errors retaining invalid input. Machine-option changes in an emulator restart that session. Network time saves on Enter or focus loss. Language is Auto/Korean/English and refreshes all open windows, including settings and the secondary display, without restarting the session. In an emulator, expandable hardware groups expose choices/text fields from `session.settings`; their **Apply** button validates through the backend and restarts the session. Hardware drafts survive a live language change. Closing the owning window also closes its settings window.

## Portable validation on Linux

Only `Emulator.Core` and its tests are portable. With .NET 10 installed:

```bash
dotnet test desktop/windows/Emulator.Core.Tests/Emulator.Core.Tests.csproj -c Release
```

To include the real-backend integration test, point the following variables at your existing Linux bundle/runtime and a firmware image. Use a fresh state directory. In this workspace the required invocation is:

```bash
MSM5XXX_BUNDLE="$PWD" \
MSM5XXX_PYTHON=/usr/bin/python3 \
MSM5XXX_QEMU=/path/to/qemu-system-arm \
MSM5XXX_STATE_DIR="$TMPDIR/windows-real-session" \
MSM5XXX_TEST_FIRMWARE=/path/to/firmware.bin \
taskset -c 6-7 nice -n 19 dotnet test desktop/windows/Emulator.Core.Tests/Emulator.Core.Tests.csproj -c Release
```

Tests require Python 3 for the standard-library process fixture and cover protocol serialization, cancellation, backend errors, bad replies, process arguments, minimum key holds, equal keypad columns, counter font fitting and recovery, multiple input sources, shortcut exclusion, number-pad mapping, frame conversion, LCD sizing and network-time validation. The optional integration test boots one guest, reads real frames/state/settings, sends keys and stops.

## Title bars and icons

The launcher, emulator and secondary display use the stock WinUI `TitleBar` in root row 0, with extended content, a tall system caption area and `MicaBackdrop`. The launcher puts Import/More options in RightHeader; the emulator puts Power immediately before More options in RightHeader. Both use the stock `SubtleButtonStyle`, 48×48 DIP caption-height hit targets and 16 DIP system-font glyphs, with no resting fill or accent color. The command group is explicitly excluded from dragging. More options uses E712 and opens one stock MenuFlyout containing reboot, capture, secondary display, Info, virtual network, the network-time submenu, key-layout editing and Settings. Power uses E7E8. Title-bar controls and flyout items retain native Enter/Space/arrow handling instead of being interpreted as phone input. Power has localized “Power on” / “Power off” accessible names and tooltips. The library, emulator and secondary title bars omit app icons; generated Full/Simple icons remain on the taskbar and window switcher, including after changing the icon setting. There is no toolbar below the bar. Dynamic commands trigger `RecomputeDragRegions()`. At compact widths the model title ellipsizes while the command and caption buttons retain their full hit targets. The emulator has no subtitle, including during startup and after stopping. Chipset, dimensions and network status are available in Info. `TitleBarLayout` uses parts of the pinned SDK template to bound title text and remove optional spacing at compact widths. Recheck that helper when upgrading WinUI.

The opening LCD size excludes the decoder's sequence-zero profile buffer and waits for real published pixels. Client sizing accounts for the extended caption area and the top border pixel. Opening geometry and position are capped to `DisplayArea.WorkArea` while keeping a whole LCD scale, so the entire keypad stays above the taskbar. The full model name remains visible for the sample devices; metadata is in Info. Windows keeps control of Snap/maximize bounds. The opening content size is also the content minimum and OverlappedPresenter minimum. A Win32 subclass clamps all WM_SIZING edges, WM_GETMINMAXINFO and WM_WINDOWPOSCHANGING; post-change correction also covers resize calls with SWP_NOSENDCHANGING. Both width and height are enforced for drag, keyboard and programmatic resizing. The frame inset comes from the native border metric rather than a potentially stale XAML height during a resize. The opening scale and minimum size are recalculated when the window moves to a display with a different work area or DPI. Their maximum height also follows the largest permitted width at the LCD aspect ratio, preventing Windows from shortening a width-driven resize.

`Branding/chip_icon.py` is the shared generator from the repository's branding source, with its font path made portable and checkout-root discovery adapted to this directory. The build runs it with `--platform "WIN X64"`; by default it reads version from `pyproject.toml`, commit from Git HEAD and date from today (`SOURCE_DATE_EPOCH` is supported). The PowerShell/GDI converter writes 16/20/24/32/40/48/64/128/256-pixel ICO entries, using small.svg at 48 pixels and below. The executable's embedded icon stays Full; **App icon → Full / Simple (MSM5)** changes taskbar and window-switcher icons for all open app windows immediately, keeps title bars icon-free, and persists in `desktop-settings.json` under the selected state directory.

Source archives without Git can supply `-p:BuildCommit=<SHA>`. Optional `BuildVersion` and `BuildDate` properties override the generator defaults. The bundled Hershey Sans stroke data includes its acknowledgements/license in `HersheySans1.svg`; that file is included in the published Branding folder with both ICOs. No font or image converter is downloaded during builds.

## Native validation

Validated on Windows 11 IoT Enterprise LTSC build 26100 with workspace-local .NET SDK 10.0.404, the real Python backend and Windows QEMU. The unpackaged app loads .NET and WinUI from its publish directory. Native XAML/PRI compilation, build and self-contained x64 publish pass. All 75 tests pass on Windows with no skips, including real X350 frames and the ten-second timeout/venv-child cleanup regression. All 74 portable tests pass on Linux; its optional firmware test is skipped when no image is configured. The minimum-hold test uses the performance counter and requires the complete configured interval.

The current visible Windows test desktop is 1024×768 at 100%, with a 1024×720 work area. Current review evidence is in `tmp/windows-validation/review1-*`: Korean X350 opens with a 256×256 LCD (2×), 256×632 content and 272×641 outer rectangle. Its natural keypad columns are 60 / 56 / 56 / 56 px, with 32 px buttons. English X350 exercises the work-area fallback: the natural keypad remains 277 px wide while only the LCD drops from 3× to 2×, yielding a 293×641 outer rectangle. Korean A640 opens at 272×705 outer pixels with a 256×320 LCD (2×). A 200×300 outer-size request preserves each opening minimum. The fixed keypad, visible row-8 Done, non-modal settings, ToggleSwitch roles, immediate save/restart/restore, invalid-time retention, hardware validation and live-language draft retention are checked natively. Current settings/keypad captures include both Korean and English in light and dark themes; the dark validation build uses a temporary source-export override and a separate publish folder. Earlier feature evidence on the 1920×1080 desktop remains in that directory; earlier 3× opening measurements included the title width, which the owner has since excluded.

The Windows checks cover native import/save pickers, folder scanning/progress, metadata/thumbnails, unavailable entries and removal without deleting files; X350 (128×128) and A640 (128×160); duplicate-window focus; actual pointer/keyboard holds, repeat suppression, combined sources and focus-loss releases; minimum holds and 30/10 Hz polling; mapping validation/save/clear/edit mode; PNG output; power/reboot and closing; settings errors and valid Apply/restart; live language changes; secondary display/lid power; Snap/maximize/restore; secondary aspect resizing, drag docking/follow/detach and side persistence; generated icon switching; and Korean IME composition in a hardware text field. UI Automation trees check control names and live metric values. The firmware LCD is exposed as a named image, not as accessible firmware text.

Evidence is kept outside Git in workspace `tmp/windows-validation/` and `tmp/windows-tests/`: pulled Windows captures, automation trees, protocol timing summaries, TRX results and native build logs. Dark-theme checks use a temporary RequestedTheme override in the Windows validation source export, preserving the shared machine's OS theme; shipped source follows the system. Owned dialogs explicitly use the window's actual theme, including dark dialogs; settings uses a normal system-themed window. Validation used one 1920×1080 display at 100% scale and one emulator guest at a time, at BelowNormal priority. Simultaneous guests and physical mixed-DPI monitors were not exercised. No backend changes were needed.

Implementation references: [stock SubtleButtonStyle](https://github.com/microsoft/microsoft-ui-xaml/blob/main/controls/dev/CommonStyles/Button_themeresources.xaml), [DWM frame attributes](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute), [WinUI TitleBar](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/title-bar), [title-bar customization](https://learn.microsoft.com/en-us/windows/apps/develop/title-bar), [self-contained deployment](https://learn.microsoft.com/windows/apps/package-and-deploy/self-contained-deploy/deploy-self-contained-apps), [owned ContentDialog](https://learn.microsoft.com/windows/apps/develop/ui/controls/dialogs-and-flyouts/dialogs), and [WinRT picker HWND ownership](https://learn.microsoft.com/windows/apps/develop/files/using-file-folder-pickers#use-winrt-pickers-with-hwnd-interop).

The shared icon generator includes dev `f3e648e`: the small MSM5 marking is centered horizontally on the drawn strokes and vertically on the package, and uses the smaller 0.68× package width. Only the bundled font path and checkout-root discovery differ from the shared script.

Platform guidance in `design-standards/` is binding. The only product-specific presentation exceptions are the phone LCD/keypad content (including square flat keys), specified opening/minimum/edge-to-edge LCD geometry, and model-only emulator title. The surrounding UI uses stock WinUI controls, styles, native caption buttons, pickers and dialogs. Earlier native English/Korean command verification includes opening More options with Enter and inspecting the complete MenuFlyout command set; those captures remain as `standards-final-{en,ko}-opening.png` and `standards-final-{en,ko}-menu-open.png` under workspace `tmp/windows-validation/`.

## Installer validation

In an interactive Windows desktop, build 0.1.99 first and keep its Setup separately, then pack 0.2.0-rc into the same feed directory. Run:

```powershell
./packaging/windows/test-install.ps1 -BaselineSetup baseline/MSM5xxx-win-Setup.exe -Feed releases -WorkDirectory installer-test
```

The work directory must not exist. The test uses an isolated state directory and installs under that directory. It checks first-run defaults and saved choices, shortcuts and uninstall registration, Settings controls, a delta-only local-feed update, restarted version and retained data, uninstall with No, and a fresh install/uninstall with Yes. Screenshots, automation snapshots and `result.txt` are written there. The fake 0.1.99 feed is test evidence and must not be published as a production release.

The self-contained publish references the supported `Microsoft.WindowsAppSDK.WinUI`
component package rather than the all-components Windows App SDK package. WinUI
retains its Base, Foundation and Interactive Experiences dependencies; AI/ML,
Search and Widgets are not runtime requirements. The app-local Desktop VCLibs
selection retains the C/C++ runtime and omits the unused MFC libraries.
