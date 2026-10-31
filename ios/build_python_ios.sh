#!/bin/bash
# macOS only. Prepare the pinned CPython iOS runtime, or install it during Xcode build.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
APP_DIR="$SCRIPT_DIR/app"
PYTHON_URL=https://github.com/beeware/Python-Apple-support/releases/download/3.14-b14/Python-3.14-iOS-support.b14.tar.gz
PYTHON_SHA256=703ff822529f46edcbcd8b88096b2544f6990f3109ad38b4b4b61bb489a7c1ee
fail() { echo "$*" >&2; exit 1; }
[[ $(uname -s) == Darwin ]] || fail 'Run this script on macOS with full Xcode installed.'

if [[ ${1:-} == --install-bundle ]]; then
    [[ $# == 1 ]] || fail 'usage: build_python_ios.sh --install-bundle'
    : "${CODESIGNING_FOLDER_PATH:?Xcode build environment required}"
    : "${PROJECT_DIR:?Xcode build environment required}"
    : "${ARCHS:?Xcode build environment required}"
    [[ "$ARCHS" != *' '* ]] || fail 'Build one architecture at a time (ARCHS=arm64 or ARCHS=x86_64).'
    [[ -d "$APP_DIR/Python.xcframework" ]] || fail 'First run ios/build_python_ios.sh WORK_DIR.'
    mkdir -p "$CODESIGNING_FOLDER_PATH/app"
    rsync -a --delete --exclude __pycache__ --exclude '*.pyc' \
        "$REPO_DIR/src/msm5xxx_emulator/" "$CODESIGNING_FOLDER_PATH/app/msm5xxx_emulator/"
    # The bridge runtime is shared as ordinary Python source, with no numpy wheel.
    for module in "$SCRIPT_DIR"/python/*.py; do
        [[ -f "$module" ]] && cp "$module" "$CODESIGNING_FOLDER_PATH/app/"
    done
    cp "$REPO_DIR/android/app/src/main/python/msm5xxx_android_runtime.py" "$CODESIGNING_FOLDER_PATH/app/"
    # CPython's PEP 730 installer converts extension .so files into frameworks
    # and places .fwork references in lib-dynload. Merely copying lib is invalid.
    UTIL="$APP_DIR/Python.xcframework/build/utils.sh"
    [[ -f "$UTIL" ]] || fail "Missing pinned runtime installer: $UTIL"
    export EXPANDED_CODE_SIGN_IDENTITY="${EXPANDED_CODE_SIGN_IDENTITY:--}"
    [[ -n "$EXPANDED_CODE_SIGN_IDENTITY" ]] || export EXPANDED_CODE_SIGN_IDENTITY=-
    export EXPANDED_CODE_SIGN_IDENTITY_NAME="${EXPANDED_CODE_SIGN_IDENTITY_NAME:-ad-hoc}"
    export PLATFORM_FAMILY_NAME=iOS
    # The upstream script expects Xcode environment variables that may be unset
    # when signing is disabled, so don't apply nounset to its functions.
    set +u
    source "$UTIL"
    install_stdlib Python.xcframework
    while IFS= read -r -d '' extension; do
        install_dylib Python.xcframework python/lib/python3.14/lib-dynload/ "$extension"
    done < <(find "$CODESIGNING_FOLDER_PATH/python/lib/python3.14/lib-dynload" -name '*.so' -print0)
    mkdir -p "$CODESIGNING_FOLDER_PATH/python/lib/python3.14/site-packages"
    rsync -a "$CODESIGNING_FOLDER_PATH/app/" "$CODESIGNING_FOLDER_PATH/python/lib/python3.14/site-packages/"
    rm -rf "$CODESIGNING_FOLDER_PATH/app"
    exit 0
fi

[[ $# == 1 ]] || fail 'usage: ios/build_python_ios.sh NEW_WORK_DIR'
[[ ! -e "$APP_DIR/Python.xcframework" ]] || fail 'Python.xcframework already exists; move it aside to replace it.'
[[ ! -e "$1" ]] || fail 'Use a new work directory.'
xcrun --sdk iphoneos --show-sdk-path >/dev/null
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null
mkdir -p "$1"
WORK_DIR=$(cd "$1" && pwd)
ARCHIVE="$WORK_DIR/Python-3.14-iOS-support.b14.tar.gz"
curl --fail --location --retry 5 "$PYTHON_URL" -o "$ARCHIVE"
printf '%s  %s\n' "$PYTHON_SHA256" "$ARCHIVE" | shasum -a 256 -c -
mkdir "$WORK_DIR/unpacked"
tar -xzf "$ARCHIVE" -C "$WORK_DIR/unpacked"
# Distribution layouts may include a support/<version>/iOS parent folder.
FRAMEWORK=$(find "$WORK_DIR/unpacked" -type d -name Python.xcframework -prune)
[[ -n "$FRAMEWORK" && "$FRAMEWORK" != *$'\n'* ]] || fail 'Expected exactly one Python.xcframework.'
[[ -f "$FRAMEWORK/build/utils.sh" ]] || fail 'Expected CPython extension-framework installer.'
for slice in ios-arm64 ios-arm64_x86_64-simulator; do
    [[ -f "$FRAMEWORK/$slice/Python.framework/Python" ]] || fail "Missing $slice"
done
xcrun lipo "$FRAMEWORK/ios-arm64/Python.framework/Python" -verify_arch arm64
xcrun lipo "$FRAMEWORK/ios-arm64_x86_64-simulator/Python.framework/Python" -verify_arch x86_64
# Enforce compatibility with the app's deployment target, rather than assuming
# a distribution build target. Check every Mach-O module as well as libPython.
while IFS= read -r -d '' binary; do
    minimums=$(xcrun vtool -show-build "$binary" | awk '$1 == "minos" {print $2}')
    [[ -n "$minimums" ]] || fail "No deployment metadata: $binary"
    while IFS= read -r minimum; do
        awk -v minimum="$minimum" 'BEGIN {split(minimum,v,"."); exit !(v[1] < 15 || (v[1] == 15 && v[2] == 0))}' \
            || fail "Runtime requires iOS $minimum (app supports 15.0): $binary"
    done <<< "$minimums"
done < <(find "$FRAMEWORK" -type f \( -name Python -o -name '*.so' \) -print0)
cp -R "$FRAMEWORK" "$APP_DIR/Python.xcframework"
echo 'Prepared ios/app/Python.xcframework (CPython 3.14.10). Build the app with Xcode.'
