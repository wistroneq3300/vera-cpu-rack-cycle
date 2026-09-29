#!/usr/bin/env bash
# Request a graceful stop of one campaign owned by the current user.
set -eu
if [[ $# -ne 1 ]]; then
    echo 'Usage: ./stop_cycle.sh <run_id>' >&2
    exit 2
fi
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/neutrin_cycle.py" --stop "$1"
