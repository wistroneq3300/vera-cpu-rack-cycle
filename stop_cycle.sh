#!/usr/bin/env bash
# Stop one campaign owned by the current user.
#
# The only PID this script will ever signal is the one recorded in the run's
# owner.json, and only after verify_owner re-derives the process start token and
# confirms it still matches. Endpoint lock files are shown for troubleshooting
# but are never used as a kill target: their contents outlive the process that
# wrote them, so a stale PID there can point at an unrelated program.
#
# Stopping means SIGTERM, nothing more. The campaign handles TERM by finishing
# the POST it is in and stopping at the loop boundary; escalating to SIGKILL is
# deliberately not automated.
#
# Usage:
#   ./stop_cycle.sh                 Pick a running campaign from a menu, then stop it
#   ./stop_cycle.sh <run_id>        Stop that Run ID
#   ./stop_cycle.sh --status        List running campaigns and held endpoint locks
set -eu

show_usage() {
    echo 'Usage: ./stop_cycle.sh [<run_id>|--status]' >&2
    exit 2
}

STATUS=0
RUN_ID=''
for arg in "$@"; do
    case "$arg" in
        --status) STATUS=1 ;;
        -h|--help) show_usage ;;
        -*) echo "Unknown option: $arg" >&2; show_usage ;;
        *) [ -n "$RUN_ID" ] && show_usage; RUN_ID="$arg" ;;
    esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNTIME_DIR="${VERA_RUNTIME_DIR:-/tmp/vera-cycle-runtime}"

# Running campaigns, one "run_id<TAB>header<TAB>nodes<TAB>started" per line.
list_running() {
    python3 - "$SCRIPT_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
try:
    from vera_cycle.engine import cycle_runtime
    runs = cycle_runtime.list_running()
except Exception as exc:  # keep the wrapper usable even if the module moved
    print(f'(could not read registrations: {exc})', file=sys.stderr)
    raise SystemExit(0)
for run in runs:
    nodes = ', '.join(run.get('nodes', [])) or 'Not recorded'
    header = f"{run.get('cycle_mode', '?')}/{run.get('channel', '?')}"
    print(f"{run['run_id']}\t{header}\t{nodes}\t{run.get('utc', '?')}")
PY
}

# Endpoint locks held by a live process, for troubleshooting only (never killed).
report_holders() {
    python3 - "$RUNTIME_DIR" <<'PY'
import glob, json, os, sys
root = sys.argv[1]
uid = os.getuid()
seen = {}
for path in sorted(glob.glob(os.path.join(root, 'endpoint-*.lock'))):
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        continue
    if not isinstance(data, dict):
        continue
    pid = data.get('pid')
    if not isinstance(pid, int) or pid <= 0:
        continue
    try:
        if os.stat(f'/proc/{pid}').st_uid != uid:
            continue
        with open(f'/proc/{pid}/cmdline', 'rb') as fh:
            cmd = fh.read().split(b'\0')
    except OSError:
        continue
    if not any(b'neutrino_cycle.py' in part for part in cmd):
        continue
    info = seen.setdefault(pid, {'run_id': str(data.get('run_id', '?')), 'nodes': set()})
    info['nodes'].add(str(data.get('node', '?')))
if not seen:
    print('No endpoint locks held by a live cycle process.')
    raise SystemExit(0)
print('Endpoint locks currently held by a live cycle process (informational only):')
for pid in sorted(seen):
    info = seen[pid]
    print(f"  pid {pid} | run {info['run_id']} | nodes: {','.join(sorted(info['nodes']))}")
PY
}

# Prove the recorded PID is still this campaign, then send exactly one SIGTERM.
stop_run() {
    local run_id="$1" pid
    pid=$(python3 - "$SCRIPT_DIR" "$run_id" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from vera_cycle.engine import cycle_runtime
try:
    owner = cycle_runtime.verify_owner(sys.argv[2])
    # Record the stop request too, so a campaign polling it exits even if it is
    # between loop boundaries when the signal arrives.
    cycle_runtime.request_stop(sys.argv[2])
except Exception as exc:
    print(f'REFUSED: {exc}', file=sys.stderr)
    raise SystemExit(1)
print(owner['pid'])
PY
) || return 1
    echo "Stopping run $run_id (pid $pid)."
    echo 'The campaign finishes the POST it is in, then stops at the loop boundary.'
    kill -TERM "$pid"
}

if [ "$STATUS" = 1 ]; then
    echo 'Running campaigns:'
    listing=$(list_running)
    if [ -z "$listing" ]; then
        echo '  (none)'
    else
        printf '%s\n' "$listing" | awk -F'\t' '{printf "  %s  [%s]  nodes: %s  started: %s\n", $1, $2, $3, $4}'
    fi
    echo
    report_holders
    exit 0
fi

if [ -n "$RUN_ID" ]; then
    stop_run "$RUN_ID"
    exit $?
fi

listing=$(list_running)
if [ -z "$listing" ]; then
    echo 'No campaign is running.'
    exit 1
fi

count=$(printf '%s\n' "$listing" | wc -l | tr -d ' ')
if [ "$count" -eq 1 ]; then
    chosen=$(printf '%s\n' "$listing" | cut -f1)
    header=$(printf '%s\n' "$listing" | cut -f2)
    nodes=$(printf '%s\n' "$listing" | cut -f3)
    echo "One campaign is running: $header"
    echo "  nodes: $nodes"
    echo "  run:   $chosen"
    printf 'Stop it? [y/N]: '
    read -r reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo 'Left running.'; exit 0 ;;
    esac
else
    echo 'Running campaigns:'
    i=0
    while IFS="$(printf '\t')" read -r rid header nodes started; do
        i=$((i + 1))
        echo "  [$i] $header"
        echo "      nodes: $nodes   started: $started"
        echo "      run:   $rid"
    done <<EOF
$listing
EOF
    printf 'Stop which one? [1-%s, q to quit]: ' "$count"
    read -r reply
    case "$reply" in
        q|Q|'') echo 'Left running.'; exit 0 ;;
        *[!0-9]*) echo 'Not a number.' >&2; exit 2 ;;
    esac
    if [ "$reply" -lt 1 ] || [ "$reply" -gt "$count" ]; then
        echo 'Out of range.' >&2
        exit 2
    fi
    chosen=$(printf '%s\n' "$listing" | sed -n "${reply}p" | cut -f1)
fi

stop_run "$chosen"
