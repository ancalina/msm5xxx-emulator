#!/bin/sh
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
exec "$script_dir/run_linux.sh" "$@"
