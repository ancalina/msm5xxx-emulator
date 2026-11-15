#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
configuration=${1:-debug}
if [ "$#" -gt 0 ]; then shift; fi
./build-app.sh "$configuration"
application="${MSM5XXX_APP_OUTPUT:-$PWD/.build/application/MSM5xxx Emulator.app}"
bundle_root=${MSM5XXX_BUNDLE:-$(cd ../.. && pwd)}
launch_environment=(--env "MSM5XXX_BUNDLE=$bundle_root")
for variable in MSM5XXX_PYTHON MSM5XXX_QEMU MSM5XXX_STATE_DIR TMPDIR; do
    if [ -n "${!variable:-}" ]; then launch_environment+=(--env "$variable=${!variable}"); fi
done
passthrough=()
while (($#)); do
    case "$1" in
        --verify|--verify-feedback)
            mode=full
            if [ "$1" = "--verify-feedback" ]; then mode=feedback; fi
            if (($# < 3)); then
                printf 'Usage: %s debug %s SAMPLES OUTPUT\n' "$0" "$1" >&2
                exit 2
            fi
            launch_environment+=(--env "MSM5XXX_VERIFY_MODE=$mode")
            launch_environment+=(--env "MSM5XXX_VERIFY_SAMPLES=$2")
            launch_environment+=(--env "MSM5XXX_VERIFY_OUTPUT=$3")
            shift 3
            ;;
        --verify-native-drag)
            launch_environment+=(--env "MSM5XXX_VERIFY_NATIVE_DRAG=1")
            shift
            ;;
        --inspect)
            if (($# < 2)); then
                printf 'Usage: %s debug --inspect OUTPUT\n' "$0" >&2
                exit 2
            fi
            launch_environment+=(--env "MSM5XXX_INSPECT_OUTPUT=$2")
            shift 2
            ;;
        *)
            passthrough+=("$1")
            shift
            ;;
    esac
done
# Launch Services sends the open-application event that presents SwiftUI scenes.
launch=(open -n -W "${launch_environment[@]}" "$application")
if ((${#passthrough[@]})); then launch+=(--args "${passthrough[@]}"); fi
"${launch[@]}"
