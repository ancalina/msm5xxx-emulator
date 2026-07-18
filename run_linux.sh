#!/bin/sh
set -u

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
venv_dir="$script_dir/.venv"
venv_python="$venv_dir/bin/python"

die() {
    printf '%s\n' "$1" >&2
    exit "$2"
}

is_supported_python() {
    "$1" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'
}

if [ -x "$venv_python" ] && is_supported_python "$venv_python"; then
    python="$venv_python"
else
    python=
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && is_supported_python "$candidate"; then
            python="$candidate"
            break
        fi
    done
    [ -n "$python" ] || die "Python 3.10 or newer is required. Install Python, then run this launcher again." 127

    if [ -d "$venv_dir" ]; then
        printf '%s\n' "Repairing local .venv..."
        "$python" -m venv --upgrade "$venv_dir" || die "Could not repair local .venv." "$?"
        python="$venv_python"
    fi
fi

is_supported_python "$python" ||
    die "Python 3.10 or newer is required. Install a newer Python, then run this launcher again." 1

if ! "$python" -c 'import tkinter' >/dev/null 2>&1; then
    die "Tk is missing. Install your distribution's Tk package (for Debian/Ubuntu: python3-tk), then run this launcher again." 1
fi

if ! "$python" -c 'import unicorn, PIL' >/dev/null 2>&1; then
    if [ ! -x "$venv_python" ]; then
        printf '%s\n' "Creating local .venv..."
        "$python" -m venv "$venv_dir" || die "Could not create local .venv." "$?"
        python="$venv_python"
    fi
    [ -f "$script_dir/requirements.txt" ] || die "Missing requirements.txt beside launcher." 1
    printf '%s\n' "Installing Python dependencies. First setup may require network access..."
    "$python" -m pip install -r "$script_dir/requirements.txt" ||
        die "Dependency installation failed. Check network access and Python pip, then run this launcher again." "$?"
fi

"$python" -c 'import unicorn, PIL' >/dev/null 2>&1 ||
    die "Python dependencies are still unavailable after installation." 1

exec "$python" "$script_dir/gui.py" "$@"
