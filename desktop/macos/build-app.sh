#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
configuration=${1:-release}
: "${SPARKLE_PUBLIC_KEY:?Set SPARKLE_PUBLIC_KEY; packaging/release.py --dry-run generates a local test key}"
case "$configuration" in debug|release) ;; *) echo 'Usage: ./build-app.sh [debug|release]' >&2; exit 2 ;; esac
./Tools/build-icons.sh
swift build -c "$configuration" --jobs 2
binary_dir=$(swift build -c "$configuration" --show-bin-path)
application="${MSM5XXX_APP_OUTPUT:-$PWD/.build/application/MSM5xxx Emulator.app}"
mkdir -p "$application/Contents/MacOS" "$application/Contents/Resources"
cp "$binary_dir/MSM5xxx Emulator" "$application/Contents/MacOS/MSM5xxx Emulator"
mkdir -p "$application/Contents/Frameworks"
framework=$(find .build/artifacts -path "*/macos-arm64_x86_64/Sparkle.framework" -type d -print -quit)
test -n "$framework"
ditto "$framework" "$application/Contents/Frameworks/Sparkle.framework"
install_name_tool -add_rpath "@executable_path/../Frameworks" "$application/Contents/MacOS/MSM5xxx Emulator"
cp -R "$binary_dir/MSM5xxx Emulator_MSM5xxxEmulator.bundle" "$application/Contents/Resources/"
cp Branding/NOTICE "$application/Contents/Resources/Icon-LICENSE.txt"
cp .build/artifacts/sparkle/Sparkle/LICENSE "$application/Contents/Resources/Sparkle-LICENSE"
cp .build/Branding/full.icns "$application/Contents/Resources/AppIcon.icns"
cp .build/Branding/small.icns "$application/Contents/Resources/AppIconSimple.icns"
cp -R .build/Branding/AppIcon.icon "$application/Contents/Resources/"
if [ -f .build/Branding/compiled/Assets.car ]; then cp .build/Branding/compiled/Assets.car "$application/Contents/Resources/"; fi
cat > "$application/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>MSM5xxx Emulator</string>
<key>CFBundleIdentifier</key><string>io.github.ancalina.MSM5xxx.desktop</string>
<key>CFBundleName</key><string>MSM5xxx Emulator</string>
<key>CFBundleDisplayName</key><string>MSM5xxx Emulator</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundleIconName</key><string>AppIcon</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleLocalizations</key><array><string>en</string><string>ko</string></array>
</dict></plist>
PLIST
icon_python=${MSM5XXX_PYTHON:-python3}
"$icon_python" - "$application/Contents/Info.plist" .build/Branding/metadata.json .build/Branding/icon-info.plist <<'PYCODE'
import json, os, plistlib, re, sys
path, metadata, generated = sys.argv[1:]
with open(path, 'rb') as stream: info = plistlib.load(stream)
with open(metadata) as stream: build = json.load(stream)
with open(generated, 'rb') as stream: info.update(plistlib.load(stream))
info['CFBundleShortVersionString'] = re.match(r'\d+\.\d+\.\d+', build['version']).group(0)
info['CFBundleVersion'] = os.environ.get('MSM5XXX_BUILD_NUMBER', '20000')
info['SUFeedURL'] = os.environ.get('MSM5XXX_APPCAST_URL', 'https://github.com/ancalina/msm5xxx-emulator/releases/latest/download/appcast.xml')
info['SUPublicEDKey'] = os.environ['SPARKLE_PUBLIC_KEY']
if re.match(r'^http://(?:localhost|127\.0\.0\.1):[0-9]+/', info['SUFeedURL']):
    info['NSAppTransportSecurity'] = {'NSAllowsLocalNetworking': True}
if os.environ.get('MSM5XXX_VERIFY_UPDATES_OUTPUT'):
    if os.environ.get('MSM5XXX_BUILD_CONFIGURATION') != 'debug':
        raise SystemExit('Update verification requires a debug build')
    info['CFBundleIdentifier'] += '.installertest'
    info['MSM5xxxUpdateTestDirectory'] = os.environ['MSM5XXX_VERIFY_UPDATES_OUTPUT']
    info['MSM5xxxUpdateTestStateDirectory'] = os.path.join(os.environ['MSM5XXX_VERIFY_UPDATES_OUTPUT'], 'data')
info['SUEnableAutomaticChecks'] = True
info['SUAutomaticallyUpdate'] = False
info['SUVerifyUpdateBeforeExtraction'] = True
info['SURequireSignedFeed'] = True
info['MSM5xxxBuildVersion'] = build['version']
info['MSM5xxxBuildCommit'] = build['commit']
info['MSM5xxxBuildDate'] = build['date']
with open(path, 'wb') as stream: plistlib.dump(info, stream)
PYCODE
"../../packaging/macos/sign.sh" "$application"
printf '%s\n' "$application"
