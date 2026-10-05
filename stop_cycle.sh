#!/usr/bin/env bash
# Request a graceful stop of one campaign owned by the current user.
#
# A campaign registers itself (run-<run_id>/owner.json) only AFTER it has
# acquired endpoint locks, so a process that hangs in that window holds the
# endpoints but is invisible to the graceful stop menu. This wrapper closes
# that gap: in addition to the graceful request it inspects the endpoint lock
# files and can force-terminate a stuck holder.
#
# Usage:
#   ./stop_cycle.sh                 Interactive graceful stop menu
#   ./stop_cycle.sh <run_id>        Graceful stop of one Run ID
#   ./stop_cycle.sh --status        Report registered campaigns and lock holders
#   ./stop_cycle.sh --force [id]    Skip the menu; terminate stuck lock holders
set -eu

show_usage() {
    echo 'Usage: ./stop_cycle.sh [--force|--status] [run_id]' >&2
    exit 2
}

FORCE=0
STATUS=0
RUN_ID=''
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --status) STATUS=1 ;;
        -h|--help) show_usage ;;
        -*) echo "Unknown option: $arg" >&2; show_usage ;;
        *) [ -n "$RUN_ID" ] && show_usage; RUN_ID="$arg" ;;
    esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNTIME_DIR="${VERA_RUNTIME_DIR:-/tmp/vera-cycle-runtime}"

# Registered campaigns, in the same shape the interactive menu uses. Read-only.
list_registered() {
    python3 - "$SCRIPT_DIR" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
try:
    import cycle_runtime
    runs = cycle_runtime.list_running()
except Exception as exc:  # keep the wrapper usable even if the module moved
    print(f'  (could not read registrations: {exc})')
    raise SystemExit(0)
if not runs:
    print('  (none registered)')
for run in runs:
    nodes = ', '.join(run.get('nodes', [])) or 'Not recorded'
    print(f"  {run['run_id']}  [{run.get('project','?')}/{run.get('cycle_mode','?')}/{run.get('channel','?')}]"
          f"  nodes: {nodes}  started: {run.get('utc','?')}")
PY
}

# Pids that currently hold endpoint locks for the current user. Liveness is
# proven from /proc, and the cmdline must still reference neutrino_cycle.py so
# a recycled PID can never be mistaken for a live campaign.
# Output: TAB-separated "pid run_id user nodes endpoint_count".
lock_holders() {
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
    info = seen.setdefault(pid, {'run_id': data.get('run_id', '?'),
                                 'user': data.get('user', '?'),
                                 'nodes': set(), 'count': 0})
    info['nodes'].add(str(data.get('node', '?')))
    info['count'] += 1
for pid in sorted(seen):
    info = seen[pid]
    print(f"{pid}\t{info['run_id']}\t{info['user']}\t{','.join(sorted(info['nodes']))}\t{info['count']}")
PY
}

report_holders() {
    local holders
    holders=$(lock_holders)
    [ -z "$holders" ] && return 0
    echo 'Endpoint locks currently held by a live cycle process:'
    printf '%s\n' "$holders" | while IFS="$(printf '\t')" read -r pid run user nodes count; do
        echo "  pid $pid | run $run | user $user | nodes: $nodes | endpoints: $count"
    done
}

terminate_holders() {
    local holders pids pid remaining left
    holders=$(lock_holders)
    [ -z "$holders" ] && return 0
    pids=$(printf '%s\n' "$holders" | cut -f1 | sort -u)
    echo "Terminating stuck cycle process(es): $(echo $pids | tr '\n' ' ')"
    for pid in $pids; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    # Give the handler a chance to unwind before escalating.
    for _ in $(seq 1 10); do
        sleep 1
        remaining=''
        for pid in $pids; do
            kill -0 "$pid" 2>/dev/null && remaining="$remaining $pid"
        done
        [ -z "$remaining" ] && break
    done
    for pid in $pids; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "  pid $pid ignored SIGTERM; sending SIGKILL"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    sleep 1
    left=$(lock_holders)
    if [ -z "$left" ]; then
        echo 'All endpoint locks released.'
    else
        echo 'WARNING: some endpoint locks are still held:' >&2
        printf '%s\n' "$left" >&2
        return 1
    fi
}

if [ "$STATUS" = 1 ]; then
    echo 'Registered campaigns:'
    list_registered
    echo
    if [ -z "$(lock_holders)" ]; then
        echo 'No endpoint locks held by a live cycle process.'
    else
        report_holders
    fi
    exit 0
fi

if [ "$FORCE" = 1 ]; then
    # A named Run ID first gets the graceful request, then the fallback sweep.
    if [ -n "$RUN_ID" ]; then
        python3 "$SCRIPT_DIR/neutrino_cycle.py" --stop "$RUN_ID" || true
    fi
    terminate_holders
    exit 0
fi

# Default: behave exactly as before (graceful, interactive or by Run ID).
python3 "$SCRIPT_DIR/neutrino_cycle.py" --stop "$@"

# The graceful path cannot see a holder that never registered. Surface any that
# remain and, on a terminal, offer to force-kill them.
if [ -n "$(lock_holders)" ]; then
    echo
    report_holders
    if [ -t 0 ]; then
        printf 'Force-terminate these stuck process(es)? [y/N]: '
        read -r reply
        case "$reply" in
            y|Y|yes|YES) terminate_holders ;;
            *) echo 'Left running. Re-run with --force to terminate them.' ;;
        esac
    else
        echo 'Re-run with --force to terminate them.'
    fi
fi
