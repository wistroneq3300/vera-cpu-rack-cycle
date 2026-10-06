#!/usr/bin/env python3
"""Outside-host Vera campaign runner. Run without arguments for the wizard."""
from __future__ import annotations

import argparse
import getpass
import math
import os
import re
import signal
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path

from cycle_core import (
    LOG_TIMEZONE,
    ROLES,
    atomic_write,
    digest,
    inventory_blocks,
    issue,
    load_inventory,
    now,
    parse_policy,
    select_targets,
)
from cycle_engine import NodeSession
from cycle_report import duration, elapsed, rebuild, status, write_reports
from cycle_runtime import EndpointLocks, RunRegistry, list_running, request_stop
from cycle_transport import Transport
from cycle_storage import writer_identity

BASE = Path(__file__).resolve().parent


def project_config_path(project):
    """Return the project-owned hardware configuration script."""
    return BASE / f'{project}_config.sh'

# Colour the words that decide whether a run needs a human look: FAIL and NEW
# stand out on the terminal, while the log file keeps the plain text so it
# stays greppable. Disabled when the output is not a terminal or when NO_COLOR
# is set.
COLOURS = {'FAIL': '\033[1;31m', 'NEW': '\033[1;33m', 'KNOWN': '\033[90m',
           'WARN': '\033[1;33m', 'OK': '\033[1;32m', 'PASS': '\033[1;32m', 'DONE': '\033[1;32m',
           'COMPLETE': '\033[1;32m', 'INCOMPLETE': '\033[1;33m', 'STOPPED': '\033[1;31m',
           'BLOCKED': '\033[1;35m', 'PENDING': '\033[90m'}
BLUE = '\033[1;34m'
CYAN = '\033[1;36m'
MAGENTA = '\033[1;35m'
RESET = '\033[0m'
COLOUR_ON = sys.stdout.isatty() and not os.environ.get('NO_COLOR')

class Console:
    def __init__(self):
        self.lines = []
        self.node_names = []
        self.path = None
        self.lock = threading.Lock()

    def __call__(self, message):
        with self.lock:
            line = f"{now()} {message}"
            print(self.paint(line), flush=True)
            self.lines.append(line)
            if self.path:
                with self.path.open('a', encoding='utf-8') as stream:
                    stream.write(line + '\n')

    def paint(self, line):
        if not COLOUR_ON:
            return line
        # A result line is "<timestamp> <system> | <phase> | <status>". Colour
        # the system slug (blue) and the phase slug (magenta) so the eye can
        # answer "which system, which loop" without reading the sentence. Both
        # are anchored between the pipes, so ordinary prose is never recoloured.
        line = re.sub(r'(?<= )(\S+) \| (PRE|POST|LOOP \d+)( \|)',
                      lambda m: f'{m.group(1) if self.node_names else BLUE + m.group(1) + RESET} | {MAGENTA}{m.group(2)}{RESET}{m.group(3)}',
                      line, count=1)
        # Standalone loop markers, e.g. "Loop 1: waiting for 2 target(s)".
        line = re.sub(r'Loop (\d+)\b', lambda m: f'{MAGENTA}Loop {m.group(1)}{RESET}', line)
        # Highlight the selected values, not every timestamp or heading.
        line = re.sub(r'(Selected targets: )([^\n]+)', lambda m: m[1] + BLUE + m[2] + RESET, line)
        line = re.sub(r'(Mode: )([^;]+)', lambda m: m[1] + MAGENTA + m[2] + RESET, line)
        line = re.sub(r'((?:loops|hours|Duration|Campaign elapsed): )([^;\n]+)', lambda m: m[1] + CYAN + m[2] + RESET, line)
        line = line.replace('COLLECTION FAILED', MAGENTA + 'COLLECTION FAILED' + RESET)
        for name in self.node_names:
            line = re.sub(rf'(?<![\w;]){re.escape(name)}(?![\w])', lambda m: BLUE + m[0] + RESET, line)
        # The run ID identifies the whole run, so it gets its own colour to be
        # scannable in a long transcript. Matched on the generated shape
        # (<project>_<cycle>_<channel>_<YYYYmmdd>_<HHMMSS>_<hex>) rather than on the label, so
        # ids quoted in other messages colourise too.
        line = re.sub(r'\b[A-Za-z0-9-]+_(?:reboot|power_cycle|aux_cycle)_(?:inband|outband)_\d{8}_\d{6}_[0-9a-f]{6}\b',
                      lambda m: f'{BLUE}{m.group(0)}{RESET}', line)
        for word, colour in COLOURS.items():
            line = re.sub(rf'\b{word}\b', f'{colour}{word}{RESET}', line)
        return line

    def attach(self, path):
        self.path = path
        atomic_write(path, '\n'.join(self.lines) + '\n')

def show_result(console, node, record):
    console(f"{node['key']} | {record['phase']} | {'BLOCKED' if node['blocked'] else record['status']}")
    if record.get('duration_seconds') is not None:
        console('  Duration: ' + duration(record['duration_seconds']))
    if record['phase'] == 'PRE':
        console('  Identity: ' + ' | '.join(f"{role.upper()} SSH {'OK' if role in record['identities'] else 'NOT VERIFIED'}" for role in ('bmc', 'os')))
    if record.get('check_summary'):
        visible = {'hardware', 'CPU', 'CPU_ONLINE', 'DIMM', 'MEMORY_VISIBLE', 'NVMe', 'NIC', 'BF4',
                   'sensor', 'pci', 'dmesg', 'sel', 'eventlog', 'redfish_sel', 'power'}
        console('  Checks: ' + ' | '.join(f'{name} {state}' for name, state in record['check_summary'].items() if name in visible))
    # BMC log services: one summary line each, never one line per event. Entries
    # are severity-tagged in the HTML; console stays compact to avoid flooding.
    for stem, label in (('eventlog', 'EventLog'), ('redfish_sel', 'Redfish SEL')):
        meta = record.get(f'{stem}_meta')
        if not meta:
            continue
        if meta.get('status') != 'COLLECTED':
            console(f'  {label}: COLLECTION FAILED')
            continue
        counts = meta.get('counts', {})
        delta = meta.get('delta')
        # One summary line per service. The per-entry detail is intentionally
        # omitted here (the full log lives in the HTML report and evidence
        # files); this keeps the transcript from being flooded by a long-lived
        # critical event that persists across many loops.
        #   Critical/Warning/OK  -> totals in the *current accumulated* snapshot
        #   new                  -> records added between this loop's before-cycle
        #                           and POST snapshots
        #   total                -> Critical + Warning + OK in that snapshot
        total = counts.get('Critical', 0) + counts.get('Warning', 0) + counts.get('OK', 0)
        new_count = delta.get('new_count', 0) if delta and delta.get('status') == 'COMPARED' else 0
        line = (f"  {label}: {meta.get('verdict')} · Critical:{counts.get('Critical', 0)}"
                f" Warning:{counts.get('Warning', 0)} OK:{counts.get('OK', 0)}"
                f" · new:{new_count} · total:{total}")
        console(line)
    dmesg_delta = record.get('dmesg_delta') or {}
    if any(value for value in dmesg_delta.values()):
        console('  New dmesg observations: ' + ', '.join(f'{key}={value}' for key, value in dmesg_delta.items()))
    if any(record.get('dmesg_native_error_counts', {}).values()):
        console('  Native errors reported in captured messages (not lifetime counters): ' + ', '.join(f'{key}={value}' for key, value in record['dmesg_native_error_counts'].items()))
    groups = {}
    for item in record['issues']:
        key = (item['severity'], item['code'], item['component'], item['detail'])
        groups[key] = groups.get(key, 0) + 1
    if record['phase'] != 'PRE':
        known_count = sum(1 for item in record['issues'] if item.get('classification') == 'KNOWN')
        if known_count:
            console(f"  Previously observed in PRE: {known_count} finding(s); see PRE and HTML for details")
    for (severity, _code, component, detail), count in groups.items():
        # Redfish EventLog/SEL entries are summarised by the one-line totals
        # above; printing each entry floods the transcript when a long-lived
        # event persists across loops. Their full detail stays in the HTML
        # report and the EventLog/SEL evidence files.
        if component in {'eventlog', 'redfish_sel'}:
            continue
        if record['phase'] != 'PRE' and all(item.get('classification') == 'KNOWN' for item in record['issues']
                                            if (item['severity'], item['code'], item['component'], item['detail']) == (severity, _code, component, detail)):
            continue
        text = ' '.join(detail.split())[:300]
        console(f"  {severity} {component}: {text}" + (f" (repeated {count} times)" if count > 1 else ''))
    for reason in node['blocked']:
        console(f"  BLOCKED: {reason}")

def parallel(function, sessions, console, label, display_result=True):
    """Bounded wait with concise progress; never dump remote command output."""
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(sessions)))) as pool:
        futures = {pool.submit(function, s): s for s in sessions}
        pending = set(futures)
        while pending:
            done, pending = wait(pending, timeout=30, return_when=FIRST_COMPLETED)
            if not done:
                # Show where each still-running node is, so a long silence is
                # always attributable to a phase rather than looking hung.
                where = ', '.join(
                    f"{futures[f].target.key}: {futures[f].node.get('stage') or 'starting'}"
                    for f in sorted(pending, key=lambda f: futures[f].target.key)
                )
                console(f"{label}: still running — {where}")
            for future in done:
                session = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    session.node.update(active=False, stop_reason=f"{label}: {type(exc).__name__}: {exc}")
                    record = session.node['loops'][-1] if session.node['loops'] else session.node.get('start', session.node['pre'])
                    session.add(record, 'EXECUTION_ERROR', label, str(exc))
                    if label == 'PRE':
                        session.node['blocked'].append(str(exc))
                    session.finish(record)
                record = session.node['loops'][-1] if session.node['loops'] else session.node.get('start', session.node['pre'])
                if display_result:
                    show_result(console, session.node, record)
                elif label == 'Start log clearing':
                    console(f"{session.node['key']} | log clearing | {record['status']}")

def campaign(options, targets, credentials, confirm=input, transport_factory=Transport, runtime_root=None):
    console = Console()
    console.node_names = [t.key for t in targets]
    run_id = f"{options.project}_{options.cycle_mode}_{options.channel}_{datetime.now(LOG_TIMEZONE).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    output = options.output.resolve() / run_id
    locks = EndpointLocks(runtime_root)
    stop = threading.Event()
    prior_handlers = {}
    registry = None
    data = None
    finalized = False
    sessions = []
    # Both keyboard interrupt and TERM are graceful: finish current POST.
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            prior_handlers[sig] = signal.signal(sig, lambda *_: stop.set())
    try:
        script = options.config_script.read_bytes().replace(b'\r\n', b'\n')
        policy_text = options.issue_policy.read_text(encoding='utf-8')
        rules = parse_policy(policy_text)
        console(f"Run ID: {run_id}")
        console("Time zone: UTC+8 (local time in Run ID and +08:00 in console/evidence timestamps)")
        console(f"Planned output: {output}")
        console(f"Project config: {options.config_script.resolve()}")
        console("Selected targets: " + ', '.join(t.key for t in targets))
        console(f"Mode: {options.cycle_mode}; channel: {options.channel}; loops: {options.loops or 'unlimited'}; hours: {options.hours or 'unlimited'}")
        if options.cycle_mode == 'reboot' and options.channel == 'outband':
            console("Outband reboot uses BMC power reset.")
        if options.cycle_mode == 'aux_cycle':
            console("Auxiliary AC cycle uses the BMC standby controller for either selected channel.")
        blocked = inventory_blocks(targets)
        for target in targets:
            if target.key not in blocked:
                try:
                    locks.acquire(target, run_id)
                except Exception as exc:
                    blocked[target.key] = [f"Cannot acquire endpoint lock: {exc}"]
        options.output.mkdir(parents=True, exist_ok=True)
        # Staging on the output filesystem permits an atomic approval promotion.
        with tempfile.TemporaryDirectory(prefix='.vera-pre-', dir=options.output) as staging:
            root = Path(staging)
            transport = transport_factory(credentials, root / '.ssh')
            sessions = [NodeSession(t, transport, root, run_id, script, digest(script), options, rules) for t in targets]
            for session in sessions:
                if session.target.key in blocked:
                    session.node['blocked'] = blocked[session.target.key]
                    session.node['active'] = False
                    for reason in session.node['blocked']:
                        session.node['pre']['issues'].append(issue('TARGET_BLOCKED', 'inventory', reason))
                    session.finish(session.node['pre'])
                    show_result(console, session.node, session.node['pre'])
            runnable = [s for s in sessions if not s.node['blocked']]
            if not runnable:
                console("BLOCKED: no runnable targets. Campaign not started; PRE evidence discarded.")
                return 2
            console("PRE started. Missing standard tools will be installed with apt when available; mst is not installed by this program.")
            local = transport.local_dependencies()
            atomic_write(root / 'pre_orchestrator_dependencies.txt', f"Exit: {local.code}\n{local.output}")
            parallel(lambda s: s.precheck(), runnable, console, 'PRE')
            if local.code:
                for session in runnable:
                    session.add(session.node['pre'], 'ORCHESTRATOR_DEPENDENCY', 'ipmitool', 'Local ipmitool installation failed; see pre_orchestrator_dependencies.txt', evidence='pre_orchestrator_dependencies.txt')
                    session.finish(session.node['pre'])
                console("FAIL: orchestrator ipmitool dependency installation failed.")
            runnable = [s for s in sessions if not s.node['blocked']]
            excluded = [s for s in sessions if s.node['blocked']]
            if excluded:
                console("Excluded targets: " + ', '.join(s.target.key for s in excluded))
            if not runnable:
                console("BLOCKED: no usable PRE baselines. Campaign not started; PRE evidence discarded.")
                return 2
            if stop.is_set() or not options.cycle:
                console("PRE finished. No cycle requested; temporary PRE evidence discarded.")
                return 0
            answer = confirm(f"Start {run_id} on {len(runnable)} runnable target(s), accepting the listed findings and exclusions? [y/N]: ")
            console("Operator decision: " + ('START' if answer.strip().lower() in {'y', 'yes'} else 'CANCEL'))
            if answer.strip().lower() not in {'y', 'yes'} or stop.is_set():
                console("Cancelled. PRE evidence discarded; no campaign directory retained.")
                return 0
            root.rename(output)
            for session in sessions:
                session.root = output
            transport.known_hosts = output / '.ssh'
            console.attach(output / 'console.log')
            registry = RunRegistry(run_id, runtime_root)
            registry.register(output, project=options.project, cycle_mode=options.cycle_mode,
                              channel=options.channel, nodes=[s.target.key for s in runnable])
            atomic_write(output / f'{options.project}_config.snapshot.sh', script.decode('utf-8'))
            atomic_write(output / 'issue_policy.snapshot.md', policy_text)
            data = dict(run_id=run_id, project=options.project, started=now(), finished=None,
                        writer_owner=writer_identity(),
                        tool_version=(BASE / 'VERSION').read_text().strip(),
                        state='RUNNING', stop_reason='', cycle_mode=options.cycle_mode, channel=options.channel,
                        limits=dict(loops=options.loops, hours=options.hours), script_sha256=digest(script),
                        nodes=[s.node for s in sessions])
            write_reports(output, data)
            console(f"Campaign started. Output: {output}")
            console(f"Stop after the current POST: ./stop_cycle.sh {run_id}")
            parallel(lambda s: s.start(), runnable, console, 'Start log clearing', display_result=False)
            write_reports(output, data)
            start = time.monotonic()
            number = 0
            while True:
                active = [s for s in runnable if s.node['active']]
                if stop.is_set() or registry.requested():
                    data.update(state='INCOMPLETE', stop_reason='Operator requested stop after the current POST')
                    break
                if (options.loops and number >= options.loops) or (options.hours and time.monotonic()-start >= options.hours*3600):
                    if number == 0:
                        data.update(state='INCOMPLETE', stop_reason='No cycles exercised')
                    elif any(not s.node['active'] for s in runnable):
                        data.update(state='INCOMPLETE', stop_reason='Run limit reached; one or more targets became unavailable')
                    else:
                        data.update(state='COMPLETE', stop_reason='Requested run limit reached')
                    break
                if not active:
                    data.update(state='INCOMPLETE', stop_reason='All approved targets became unavailable')
                    break
                number += 1
                console(f"Loop {number}: starting {len(active)} target(s) concurrently")
                for session in active:
                    session.progress = (lambda msg, n=number: console(f"Loop {n}: {msg}"))
                parallel(lambda s, n=number: s.one_loop(n), active, console, f'Loop {number}')
                for session in active:
                    session.progress = None
                write_reports(output, data)
            data['finished'] = now()
            write_reports(output, data)
            registry.finish(data['state'])
            finalized = True
            result = status(data)
            console("=" * 60)
            console(f"FINISHED: {result['completion']} | Health: {result['health']} | Completed node-loops: {result['completed_node_loops']}")
            console("Campaign elapsed: " + duration(elapsed(data["started"], data["finished"])))
            console(f"Report: {output / 'CYCLE_REVIEW_REPORT.html'}")
            console("=" * 60)
            return 0 if result['completion'] == 'COMPLETE' and result['health'] != 'FAIL' else 1
    finally:
        if data and not finalized:
            data.update(state='INCOMPLETE', finished=now(), stop_reason='Orchestrator interrupted by an unexpected error; retained all available evidence')
            try:
                write_reports(output, data)
                if registry:
                    registry.finish('INCOMPLETE')
            except Exception as exc:
                console(f"Final report could not be written: {exc}. Recover with --report {output}")
        for session in sessions:
            session.cleanup_remote()
        locks.close()
        for sig, handler in prior_handlers.items():
            signal.signal(sig, handler)

def stop_menu(root=None, input_func=None):
    read = input_func or input
    while True:
        runs = list_running(root)
        print('\nStop Cycle - Your running campaigns')
        if not runs:
            print('No running campaigns found for this OS user on this controller.')
            return 0
        for number, run in enumerate(runs, 1):
            nodes = run.get('nodes', [])
            preview = ', '.join(nodes[:8]) or 'Not recorded'
            if len(nodes) > 8:
                preview += f' ... ({len(nodes)} nodes total)'
            print(f"\n  {number}. {run.get('project', 'Unknown')} | {run.get('cycle_mode', 'Unknown')} | {run.get('channel', 'Unknown')}")
            print(f"     Nodes: {preview}")
            print(f"     Run ID: {run['run_id']}")
            print(f"     Started: {run.get('utc', 'Not recorded')}")
            if run['stop_requested']:
                print('     STOP REQUESTED - waiting for the current round and POST to finish')
        print('\n  0. Exit')
        try:
            reply = read('Select campaign number [0]: ').strip()
            if reply in {'', '0'}:
                return 0
            if not reply.isascii() or not reply.isdecimal() or not 1 <= int(reply) <= len(runs):
                print('INVALID: enter a listed number.')
                continue
            run = runs[int(reply) - 1]
            print(f"\nSelected: {run['run_id']}")
            print('Nodes: ' + (', '.join(run.get('nodes', [])) or 'Not recorded'))
            print(f"Output: {run['output']}")
            print('Stop the entire selected campaign after this round and POST finish.')
            print('  1. Request stop\n  0. Back')
            while True:
                answer = read('Select [0]: ').strip()
                if answer in {'', '0', '1'}:
                    break
                print('INVALID: enter 1 or 0.')
            if answer != '1':
                continue
            try:
                info = request_stop(run['run_id'], root)
            except (OSError, ValueError) as exc:
                print(f'Cannot request stop: {exc}')
                continue
            print(f"Stop requested for {run['run_id']}. This is a request, not completion.")
            print(f"The current round and POST will finish. Output: {info['output']}")
            return 0
        except (EOFError, KeyboardInterrupt):
            print('\nCancelled. No stop request sent.')
            return 0


def choose(title, options, default):
    """Numbered menu. Accepts the number, or the option text (case-insensitive).

    Re-prompts on anything else so a typo never aborts the wizard. An empty
    reply takes the default. `options` is a list of (key, label) pairs.
    """
    print(f"\n{title}:")
    for index, (_, label) in enumerate(options, 1):
        mark = ' (default)' if index == default else ''
        print(f"  {index}. {label}{mark}")
    keys = {key for key, _ in options}
    while True:
        reply = input(f"Select [{default}]: ").strip().lower()
        if not reply:
            return options[default - 1][0]
        if reply.isdigit() and 1 <= int(reply) <= len(options):
            return options[int(reply) - 1][0]
        if reply in keys:
            return reply
        valid = ', '.join(str(i) for i in range(1, len(options) + 1))
        print(f"  INVALID: '{reply}' — enter {valid}, or the option name")


def choose_limit(kind):
    """Loop or hour limit; re-prompts on non-numeric input. No default value."""
    unit = 'loops' if kind == 'loops' else 'hours'
    while True:
        reply = input(f"How many {unit}? ").strip()
        if not reply:
            print(f"  Enter a number of {unit}")
            continue
        try:
            value = int(reply) if kind == 'loops' else float(reply)
        except ValueError:
            print(f"  INVALID: '{reply}' is not a number")
            continue
        if not math.isfinite(value) or value <= 0:
            print(f"  Must be a positive number of {unit}")
            continue
        return value


def wizard(options):
    """Interactive campaign setup, mirroring the rackctl prompt style."""
    print('=' * 50)
    print('  Vera Cycle Wizard (interactive)')
    print('=' * 50)
    options.project = choose('Project', [('neutrino', 'neutrino'), ('naboo', 'naboo')], 1)
    options.inventory = options.inventory or BASE / f'cycle_inventory_{options.project}.csv'
    targets = load_inventory(options.inventory)
    names = sorted({t.node for t in targets})
    print(f"\nNodes in inventory: {', '.join(names)}")
    while True:
        reply = input("Which nodes? (all / comma-sep, e.g. n1,n2) [all]: ").strip()
        if not reply or reply.lower() == 'all':
            options.node = None
            break
        parts = [p for p in reply.replace(',', ' ').split() if p]
        bad = [p for p in parts if p not in names]
        if bad:
            print(f"  INVALID: {', '.join(bad)} — valid: {', '.join(names)}")
            continue
        options.node = parts
        break
    options.cycle_mode = choose('Cycle mode', [
        ('power_cycle', 'power_cycle'), ('reboot', 'reboot'), ('aux_cycle', 'aux_cycle')], 1)
    options.channel = choose('Channel', [('inband', 'inband'), ('outband', 'outband')], 1)
    options.loops, options.hours = 0, 0.0
    if choose('Duration type', [('loops', 'Loops (number of cycles)'), ('hours', 'Hours (time limit)')], 1) == 'loops':
        options.loops = choose_limit('loops')
    else:
        options.hours = choose_limit('hours')
    options.cycle = True
    return targets


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', action='version', version=(BASE / 'VERSION').read_text().strip())
    p.add_argument('--project', choices=('1', '2', 'neutrino', 'naboo'))
    p.add_argument('--node', action='append', help='all, unique node name, or tray/node; may repeat')
    p.add_argument('--inventory', type=Path)
    p.add_argument('--loops', type=int, default=0)
    p.add_argument('--hours', type=float, default=0)
    p.add_argument('--cycle-mode', choices=('reboot', 'power_cycle', 'aux_cycle'), default='power_cycle')
    p.add_argument('--channel', choices=('inband', 'outband'), default='inband')
    p.add_argument('--boot-timeout', type=float, default=900)
    p.add_argument('--poll-interval', type=float, default=10)
    p.add_argument('--memory-min-ratio', type=float, default=0.90, help='Minimum OS MemTotal / installed SMBIOS capacity (0 < ratio <= 1)')
    p.add_argument('--config-script', type=Path,
                   help='Override the selected project config script')
    p.add_argument('--issue-policy', type=Path, default=BASE / 'issue_policy.md')
    p.add_argument('--output', type=Path, default=BASE / 'campaigns')
    p.add_argument('--cycle', action='store_true', help='Run cycles after PRE and explicit confirmation; wizard enables this')
    p.add_argument('--keep-going', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--stop', metavar='RUN_ID', nargs='?', const='', help='Open numbered stop menu, or stop the specified Run ID')
    p.add_argument('--report', type=Path, metavar='CAMPAIGN_DIR', help='Rebuild a stopped campaign report from its journal; do not use during a live run')
    return p

def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    p = parser()
    options = p.parse_args(arguments)
    try:
        if options.stop is not None:
            if not options.stop:
                return stop_menu()
            info = request_stop(options.stop)
            print(f"Stop requested for {options.stop}. Current POST will finish. Output: {info['output']}")
            return 0
        if options.report:
            info = rebuild(options.report)
            print(f"Report rebuilt: {options.report / 'CYCLE_REVIEW_REPORT.html'} ({info['state']})")
            return 0
        interactive = not arguments
        if interactive:
            targets = wizard(options)
        else:
            options.project = {'1': 'neutrino', '2': 'naboo'}.get(options.project, options.project)
            if options.project not in {'neutrino', 'naboo'}:
                raise ValueError('Invalid project')
            options.inventory = options.inventory or BASE / f'cycle_inventory_{options.project}.csv'
            targets = load_inventory(options.inventory)
        if options.config_script is None:
            options.config_script = project_config_path(options.project)
        if not options.config_script.is_file():
            raise ValueError(f'Project config script not found: {options.config_script}')
        targets = select_targets(targets, options.node or ['all'])
        if options.cycle_mode not in {'reboot', 'power_cycle', 'aux_cycle'} or options.channel not in {'inband', 'outband'}:
            raise ValueError('Invalid mode or channel')
        if options.loops < 0 or not math.isfinite(options.hours) or options.hours < 0 or not (options.loops or options.hours):
            raise ValueError('Provide a positive --loops or --hours limit; negative/non-finite limits are invalid')
        if not math.isfinite(options.boot_timeout) or options.boot_timeout < 1 or not math.isfinite(options.poll_interval) or options.poll_interval <= 0:
            raise ValueError('Boot timeout must be >= 1 second and polling interval must be positive')
        if not math.isfinite(options.memory_min_ratio) or not 0 < options.memory_min_ratio <= 1:
            raise ValueError('Memory minimum ratio must be finite and in (0, 1]')
        if options.keep_going:
            print('Note: --keep-going is now always enabled for hardware/firmware findings.')
        blocks = inventory_blocks(targets)
        if len(blocks) == len(targets):
            for key, reasons in blocks.items():
                print(f"BLOCKED {key}: {'; '.join(reasons)}")
            print('Campaign not started. Fill the real hostnames and resolve inventory conflicts.')
            return 2
        roles = {role for t in targets if t.key not in blocks for role, _, _ in t.endpoints()}
        credentials = {}
        for role in ROLES:
            if role in roles:
                credentials[role] = os.environ.get(f'{options.project.upper()}_{role.upper()}_PASSWORD', os.environ.get(role.upper() + '_PASSWORD'))
                if credentials[role] is None:
                    credentials[role] = input(f'{role} password [VISIBLE] (blank for SSH key; BMC IPMI needs a password): ')
        return campaign(options, targets, credentials)
    except (ValueError, OSError, RuntimeError, EOFError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
