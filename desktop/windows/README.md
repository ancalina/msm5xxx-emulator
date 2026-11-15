# MSM5xxx Windows desktop

Native C# / WinUI 3 frontend for the MSM5xxx QEMU feature-phone emulator. The app uses stock Windows controls, the WinUI TitleBar with system caption buttons, Mica and the system theme, native file pickers, and English/Korean Windows resources. Each firmware window owns its own backend process. Firmware and the emulator runtime are supplied separately.

## Requirements

- Windows x64, Windows 10 version 1809 (build 17763) or later; Windows 11 recommended. OS servicing depends on the Windows edition.
- To build: .NET 10 SDK, Python 3 and Git on PATH, and a Windows 10/11 SDK. NuGet restores pinned Windows App SDK 2.6.5 and Windows SDK build tools. The Visual Studio IDE is optional. The GitHub `windows-2022` image supplies the SDK and native redistributable files.
- To run: a matching Windows QEMU runtime bundle containing `bin/qemu-system-arm.exe`, `src/msm5xxx_emulator/`, and Python with the backend's dependencies (Capstone and Pillow). The existing QEMU Windows build workflow produces this runtime bundle.

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

For deployment from a local build, also copy the x64 `Microsoft.VC143.CRT` DLLs from your Visual Studio `VC/Redist/MSVC/<version>/x64/` directory to the publish directory, as the workflow does. Observe Microsoft's redistribution license. No installer or signing certificate is needed to run the unpackaged app.

On GitHub, select **Actions → Build Windows desktop → Run workflow**, choosing the branch containing this app. Download `MSM5xxx-Desktop-windows-x64`. The workflow restores, tests, builds and publishes; `windows-desktop-build-results` contains TRX results and the MSBuild binary log. The real-firmware integration test is explicitly skipped when no test firmware is configured; no firmware is uploaded or downloaded by CI.

## Run

Extract the desktop artifact into the matching runtime bundle, merging its `bin/` directory. Keep all the published files together:

```text
MSM5xxx-QEMU-windows-x64/
  bin/
    MSM5xxx.Desktop.exe
    MSM5xxx.Desktop.dll
    resources.pri
    ...all other desktop publish files...
    qemu-system-arm.exe
    ...QEMU runtime DLLs...
  python/
    python.exe
    ...Python runtime and dependencies...
  src/
    msm5xxx_emulator/
```

```powershell
& 'C:\Emulators\MSM5xxx-QEMU-windows-x64\bin\MSM5xxx.Desktop.exe'
```

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

Arrow keys, Enter, Escape, number keys (including the number pad), and plus/minus follow `ui.layout.keyboard`. Ctrl, Alt and Windows shortcuts remain available. Tab moves among controls, and Space/UI Automation can activate a focused key. Pointer and keyboard holds are combined and remain down for at least the backend's requested hold time. Deactivating a window or opening an in-app dialog releases keys. **Edit key layout** enables mapping even for absent keys; select a key, enter a decimal/hexadecimal event byte, or leave it blank to clear its override. Right-click also opens mapping. **Done** in the actions menu exits edit mode.

The opening size comes from actual frame dimensions and the fresh natural size of compact keypad buttons and the title bar's fixed controls plus model name. It uses the smallest whole-number LCD scale that fits both, capped to the window display's available work area after native borders. If that natural size will not fit, the largest whole-number LCD scale that fits is used instead, and becomes the user minimum. The emulator title bar contains only the model name, Power, actions menu and system buttons. Chipset, LCD dimensions and localized network status are shown in Info. Keypad column minima are reset and measured on each fit, so earlier stretched widths cannot accumulate. Column 0 takes the natural width of its button labels; columns 1–3 share their largest natural minimum and divide the remaining width equally in physical pixels. Any indivisible one- or two-pixel remainder goes to column 0, so resizing cannot leave one digit column a pixel narrower. All keypad buttons occupy 32 px rows with square corners and no border/elevation treatment, as required by the phone-content exception. Live monospace counters stay inside column 0 at 11 DIP, shrinking proportionally to an 8 DIP floor; values that exceed even that floor ellipsize, with the full value available in the tooltip and accessible name. A separate cell supplies the fitting width, so short text returns to 11 DIP. Counter updates never widen columns or refit the window. Live language changes remeasure the button minima. Widening increases the screen and client height at the LCD aspect ratio; extra user-added height stays in the display area. A small Win32 `WM_SIZING` hook constrains interactive width drags because WinUI has no height-for-width window property; Snap, maximize and monitor DPI changes retain system-selected bounds. Rendering maps LCD pixels to physical display pixels with nearest-neighbour sampling and aspect-preserving black bars. Metrics remain under the lid button. Their names and descriptions come from the backend.

Settings has the app-wide fields and, in an emulator, expandable hardware groups with choices/text fields from `session.settings`. Apply validates through the backend and restarts the session. Invalid values remain in the dialog with an inline error. App-wide machine settings take effect on the next boot; menu network changes restart a running session and preserve a stopped session, and network time changes apply live. Language is Auto/Korean/English. Saving a language change refreshes all open windows, including the secondary display, without restarting a running session.

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

The launcher, emulator and secondary display use the stock WinUI `TitleBar` in root row 0, with extended content, a tall system caption area and `MicaBackdrop`. The launcher puts Import/More options in RightHeader; the emulator puts Power immediately before More options in RightHeader. Both use the stock `SubtleButtonStyle`, 48×48 DIP caption-height hit targets and 16 DIP system-font glyphs, with no resting fill or accent color. The command group is explicitly excluded from dragging. More options uses E712 and opens one stock MenuFlyout containing reboot, capture, secondary display, Info, virtual network, the network-time submenu, key-layout editing and Settings. Power uses E7E8. Title-bar controls and flyout items retain native Enter/Space/arrow handling instead of being interpreted as phone input. Power has localized “Power on” / “Power off” accessible names and tooltips. The library, emulator and secondary title bars omit app icons; generated Full/Simple icons remain on the taskbar and window switcher, including after changing the icon setting. There is no toolbar below the bar. Dynamic commands trigger `RecomputeDragRegions()`. The emulator measures fixed title-bar columns and the model name only, then applies the work-area scale cap. The emulator has no subtitle, including during startup and after stopping. Chipset, dimensions and network status are available in Info; Done editing is also in the actions menu. `TitleBarLayout` uses named parts of the pinned SDK template to bound its auto-sized text columns. Recheck that helper when upgrading WinUI.

The opening LCD size excludes the decoder's sequence-zero profile buffer and waits for real published pixels. Client sizing accounts for the extended caption area and the top border pixel. Opening geometry and position are capped to `DisplayArea.WorkArea` while keeping a whole LCD scale, so the entire keypad stays above the taskbar. The full model name remains visible for the sample devices; metadata is in Info. Windows keeps control of Snap/maximize bounds. The opening content size is also the content minimum and OverlappedPresenter minimum. A Win32 subclass clamps all WM_SIZING edges, WM_GETMINMAXINFO and WM_WINDOWPOSCHANGING; post-change correction also covers resize calls with SWP_NOSENDCHANGING. Both width and height are enforced for drag, keyboard and programmatic resizing. The frame inset comes from the native border metric rather than a potentially stale XAML height during a resize. The opening scale and minimum size are recalculated when the window moves to a display with a different work area or DPI. Their maximum height also follows the largest permitted width at the LCD aspect ratio, preventing Windows from shortening a width-driven resize.

`Branding/chip_icon.py` is the shared generator from the repository's branding source, with its font path made portable and checkout-root discovery adapted to this directory. The build runs it with `--platform "WIN X64"`; by default it reads version from `pyproject.toml`, commit from Git HEAD and date from today (`SOURCE_DATE_EPOCH` is supported). The PowerShell/GDI converter writes 16/20/24/32/40/48/64/128/256-pixel ICO entries, using small.svg at 48 pixels and below. The executable's embedded icon stays Full; **App icon → Full / Simple (MSM5)** changes taskbar and window-switcher icons for all open app windows immediately, keeps title bars icon-free, and persists in `desktop-settings.json` under the selected state directory.

Source archives without Git can supply `-p:BuildCommit=<SHA>`. Optional `BuildVersion` and `BuildDate` properties override the generator defaults. The bundled Hershey Sans stroke data includes its acknowledgements/license in `HersheySans1.svg`; that file is included in the published Branding folder with both ICOs. No font or image converter is downloaded during builds.

## Native validation

Validated on Windows 11 IoT Enterprise LTSC build 26100 with workspace-local .NET SDK 10.0.404, the real Python backend and Windows QEMU. The unpackaged app loads .NET and WinUI from its publish directory. Native XAML/PRI compilation, build and self-contained x64 publish pass. All 75 tests pass on Windows with no skips, including real X350 frames and the ten-second timeout/venv-child cleanup regression. All 74 portable tests pass on Linux; its optional firmware test is skipped when no image is configured. The minimum-hold test uses the performance counter and requires the complete configured interval.

The visible Windows test desktop is 1920×1080 at 100%, with a 1920×1032 work area. X350 and A640 both open at 384 px client width (3×). Fixed title-bar columns plus model text measure 349 px for both samples. English keypad columns measure 59 / 99 / 99 / 99 px at that opening size; each button is 32 px high. Korean columns measure 62 / 98 / 98 / 98 px, and widening to 560 px client width gives 64 / 156 / 156 / 156 px. The real published Run counter was measured at 9.6866 DIP for an eleven-character value, alongside short counters at 11 DIP. No subtitle is displayed. The opening rectangle, every bottom keypad button, and the secondary rectangle are checked against that real work area. Requests for 200×300 outer pixels leave X350 at 400×769 and A640 at 400×865, equal to opening size, through SetWindowPos, MoveWindow, actual border dragging, keyboard sizing and WM_SIZING tests. Checks include safe left/right/overlapping placement, localized virtual-network status in Info, and the system Power glyph (U+E7E8, Segoe Fluent Icons on Windows 11; Segoe MDL2 Assets on Windows 10).

The Windows checks cover native import/save pickers, folder scanning/progress, metadata/thumbnails, unavailable entries and removal without deleting files; X350 (128×128) and A640 (128×160); duplicate-window focus; actual pointer/keyboard holds, repeat suppression, combined sources and focus-loss releases; minimum holds and 30/10 Hz polling; mapping validation/save/clear/edit mode; PNG output; power/reboot and closing; settings errors and valid Apply/restart; live language changes; secondary display/lid power; Snap/maximize/restore; secondary aspect resizing, drag docking/follow/detach and side persistence; generated icon switching; and Korean IME composition in a hardware text field. UI Automation trees check control names and live metric values. The firmware LCD is exposed as a named image, not as accessible firmware text.

Evidence is kept outside Git in workspace `tmp/windows-validation/` and `tmp/windows-tests/`: pulled Windows captures, automation trees, protocol timing summaries, TRX results and native build logs. Dark-theme checks use a temporary RequestedTheme override in the Windows validation source export, preserving the shared machine's OS theme; shipped source follows the system. Owned dialogs explicitly use the window's actual theme, including dark settings. Validation used one 1920×1080 display at 100% scale and one emulator guest at a time, at BelowNormal priority. Simultaneous guests and physical mixed-DPI monitors were not exercised. No backend changes were needed.

Implementation references: [stock SubtleButtonStyle](https://github.com/microsoft/microsoft-ui-xaml/blob/main/controls/dev/CommonStyles/Button_themeresources.xaml), [DWM frame attributes](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute), [WinUI TitleBar](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/title-bar), [title-bar customization](https://learn.microsoft.com/en-us/windows/apps/develop/title-bar), [self-contained deployment](https://learn.microsoft.com/windows/apps/package-and-deploy/self-contained-deploy/deploy-self-contained-apps), [owned ContentDialog](https://learn.microsoft.com/windows/apps/develop/ui/controls/dialogs-and-flyouts/dialogs), and [WinRT picker HWND ownership](https://learn.microsoft.com/windows/apps/develop/files/using-file-folder-pickers#use-winrt-pickers-with-hwnd-interop).

The shared icon generator includes dev `f3e648e`: the small MSM5 marking is centered horizontally on the drawn strokes and vertically on the package, and uses the smaller 0.68× package width. Only the bundled font path and checkout-root discovery differ from the shared script.

Platform guidance in `design-standards/` is binding. The only product-specific presentation exceptions are the phone LCD/keypad content (including square flat keys), specified opening/minimum/edge-to-edge LCD geometry, and model-only emulator title. The surrounding UI uses stock WinUI controls, styles, native caption buttons, pickers and dialogs. Native English/Korean verification at the 384 px X350 opening width includes opening More options with Enter and inspecting the complete MenuFlyout command set; current captures are `standards-final-{en,ko}-opening.png` and `standards-final-{en,ko}-menu-open.png` under workspace `tmp/windows-validation/`.
