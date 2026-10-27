#!/usr/bin/env python3
"""Outside-host Vera campaign runner. Run without arguments for the wizard."""
from __future__ import annotations

import argparse
import getpass
import json
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

try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX fallback
    termios = None
    tty = None

from vera_cycle import paths
from vera_cycle.core.cycle_core import (
    LOG_TIMEZONE,
    ROLES,
    atomic_write,
    digest,
    display_component,
    inventory_blocks,
    issue,
    load_inventory,
    now,
    parse_policy,
    select_targets,
)
from vera_cycle.core.cycle_transport import Transport
from vera_cycle.core.cycle_storage import owner_alive, writer_identity
from vera_cycle.engine.cycle_engine import AuxCycleGate, NodeSession
from vera_cycle.engine.cycle_runtime import EndpointLocks, RunRegistry, list_running, request_stop
from vera_cycle.reporting.cycle_report import (
    ReportDegraded, campaign_tmp, create_delivery_zip, duration, elapsed, rebuild,
    run_status, status, write_checkpoint, write_reports,
)

# Repository root, kept for callers that derive sibling paths from it.
BASE = paths.REPO_ROOT


def discover_interrupted_campaigns(output_root=None):
    """Find local RUNNING journals whose writer is no longer alive.

    This is read-only. A foreign-controller owner cannot be proved dead here and
    is therefore not offered as rebuildable; the source controller must handle
    it. Missing output bundles are likewise left untouched.
    """
    output_root = Path(output_root or paths.CAMPAIGNS_DIR)
    found = []
    try:
        journals = sorted(campaign_tmp().glob('*/campaign.json'))
    except OSError:
        return found
    for path in journals:
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get('state') != 'RUNNING':
            continue
        owner = data.get('writer_owner') or {}
        try:
            if owner and owner_alive(owner):
                continue
        except (OSError, RuntimeError, ValueError, KeyError):
            # Unknown is not dead. Never invite an unsafe cross-controller
            # rebuild based on a guess.
            continue
        run_id = str(data.get('run_id') or path.parent.name)
        output = output_root / run_id
        if not output.is_dir():
            continue
        found.append(dict(run_id=run_id, output=output, journal=path, campaign=data))
    return found


def startup_recovery_prompt(output_root=None, input_func=input, output_func=print):
    """Offer rebuild/view/skip for dead RUNNING campaigns; never auto-resume."""
    results = []
    for item in discover_interrupted_campaigns(output_root):
        data = item['campaign']
        while True:
            output_func(
                f"Interrupted campaign detected: {item['run_id']} "
                f"({sum(len(n.get('loops', [])) for n in data.get('nodes', []))} retained loop record(s))."
            )
            answer = input_func('Recovery: [r]ebuild HTML, [v]iew details, [s]kip [s]: ').strip().lower()
            if answer in {'v', 'view'}:
                output_func(
                    f"Run ID: {item['run_id']}\nOutput: {item['output']}\n"
                    f"Journal: {item['journal']}\nState: {data.get('state')}\n"
                    "No cycle will be resumed or replayed."
                )
                continue
            if answer in {'r', 'rebuild'}:
                try:
                    rebuilt = rebuild(item['output'], journal=item['journal'])
                except Exception as exc:
                    output_func(f"Recovery rebuild failed: {exc}. Data was retained; startup may continue.")
                    results.append(dict(run_id=item['run_id'], action='FAILED', detail=str(exc)))
                else:
                    output_func(
                        f"Recovered report: {item['output'] / 'CYCLE_REVIEW_REPORT.html'} "
                        f"({rebuilt['state']}). No power action was executed."
                    )
                    results.append(dict(run_id=item['run_id'], action='REBUILT'))
                break
            if answer in {'', 's', 'skip'}:
                output_func('Skipped. Existing Journal, JSON, logs and evidence were not changed.')
                results.append(dict(run_id=item['run_id'], action='SKIPPED'))
                break
            output_func('Enter r, v or s.')
    return results


def project_config_path(project):
    """Return the project-owned hardware configuration script."""
    return paths.project_config_path(project)

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
        if meta.get('present') is False:
            console(f'  {label}: PASS / N/A · service not present')
            continue
        if meta.get('status') != 'COLLECTED':
            console(f'  {label}: UNAVAILABLE')
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
        label = display_component(dict(code=_code, component=component))
        console(f"  {severity} {label}: {text}" + (f" (repeated {count} times)" if count > 1 else ''))
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

def safe_write_reports(output, data, console):
    """Generate the report without ever letting its failure change the run.

    Report generation is an output step; a rendering bug, a full disk or a
    missing asset must not abort the cycles or rewrite the execution verdict.
    The journal and the rendered documents are written independently, so one
    failing leaves the other in place; ``run_status`` names which one failed
    and the run records DEGRADED rather than pretending the output is complete.
    """
    try:
        write_reports(output, data)
        return True
    except ReportDegraded as exc:
        data['persistence'] = exc.persistence
        data['report'] = exc.report
        console(f"Output degraded: {exc}. Execution continues; rebuild later with --report {output}")
        return False
    except Exception as exc:
        data['report'] = dict(state='FAILED', detail=f'{type(exc).__name__}: {exc}')
        console(f"Report generation failed: {exc}. Execution continues; rebuild later with --report {output}")
        return False


def safe_checkpoint(output, data, console):
    """Save live recovery state; never render or retry the terminal HTML."""
    try:
        write_checkpoint(output, data)
        return True
    except Exception as exc:
        console(f"Journal checkpoint failed: {exc}. Execution continues; data may be incomplete.")
        return False

def campaign(options, targets, credentials, confirm=input, transport_factory=Transport, runtime_root=None):
    console = Console()
    console.node_names = [t.key for t in targets]
    # The run folder is named after the trays under test, so an operator opening
    # the campaigns directory sees which hardware a run covered without reading
    # the journal. One entry per tray, in selection order: a whole tray shows
    # once rather than repeating for each of its nodes.
    trays = list(dict.fromkeys(t.tray for t in targets)) or [options.project]
    run_id = f"{'-'.join(trays)}_{options.cycle_mode}_{options.channel}_{datetime.now(LOG_TIMEZONE).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    output = options.output.resolve() / run_id
    locks = EndpointLocks(runtime_root)
    stop = threading.Event()
    prior_handlers = {}
    registry = None
    data = None
    verdict_fixed = False
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
        # Operators read the console while standing at a rack; a bare node name
        # does not tell them which machine to walk to. Print the endpoint map up
        # front so the OS and BMC addresses of every target are visible before
        # any action is issued.
        for target in targets:
            console(f"  Target {target.key}: os={target.os_ip or '-'} ({target.os_hostname or '-'})"
                    f"  bmc={target.bmc_ip or '-'} ({target.bmc_hostname or '-'})")
        console(f"Mode: {options.cycle_mode}; channel: {options.channel}; loops: {options.loops or 'unlimited'}; hours: {options.hours or 'unlimited'}")
        if options.cycle_mode == 'reboot' and options.channel == 'outband':
            console("Outband reboot uses BMC power reset.")
        if options.cycle_mode == 'aux_cycle':
            console("Auxiliary AC cycle uses the BMC standby controller for either selected channel.")
            if options.aux_interval > 0 and len(targets) > 1:
                console(f"Aux cycles are staggered: one command every {options.aux_interval:g}s "
                        f"(~{(len(targets) - 1) * options.aux_interval:g}s for {len(targets)} targets).")
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
            # One gate per campaign: aux cycles are spaced across nodes because a
            # simultaneous AC cycle on several nodes of a tray takes the others
            # down. Other cycle modes are unaffected.
            aux_gate = AuxCycleGate(options.aux_interval) if options.cycle_mode == 'aux_cycle' else None
            sessions = [NodeSession(t, transport, root, run_id, script, digest(script), options, rules,
                                    aux_gate=aux_gate, stop_requested=stop.is_set) for t in targets]
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
            inventory_source = getattr(options, 'inventory', paths.inventory_path(options.project))
            atomic_write(output / f'{options.project}_inventory.snapshot.csv',
                         inventory_source.read_text(encoding='utf-8'))
            atomic_write(output / 'issue_policy.snapshot.md', policy_text)
            data = dict(run_id=run_id, project=options.project, started=now(), finished=None,
                        writer_owner=writer_identity(),
                        tool_version=paths.VERSION_FILE.read_text().strip(),
                        state='RUNNING', stop_reason='', cycle_mode=options.cycle_mode, channel=options.channel,
                        limits=dict(loops=options.loops, hours=options.hours), script_sha256=digest(script),
                        nodes=[s.node for s in sessions],
                        persistence=dict(state='OK', detail='', history=[]),
                        report=dict(state='NOT_GENERATED', detail='', history=[]))
            safe_checkpoint(output, data, console)
            console(f"Campaign started. Output: {output}")
            console(f"Stop after the current POST: ./stop_cycle.sh {run_id}")
            parallel(lambda s: s.start(), runnable, console, 'Start log clearing', display_result=False)
            safe_checkpoint(output, data, console)
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
                safe_checkpoint(output, data, console)
            data['finished'] = now()
            verdict_fixed = True
            # The execution verdict is persisted on its own first: a later HTML
            # failure must never rewrite COMPLETE to INCOMPLETE. The full report
            # is then attempted without letting a rendering error change the run.
            safe_checkpoint(output, data, console)
            safe_write_reports(output, data, console)
            verdict = run_status(data)
            console(f"Output: persistence {verdict['persistence']['state']}; report {verdict['report']['state']}")
            registry.finish(data['state'])
            result = status(data)
            console("=" * 60)
            console(f"FINISHED: {result['completion']} | Health: {result['health']} | Completed node-loops: {result['completed_node_loops']}")
            console("Campaign elapsed: " + duration(elapsed(data["started"], data["finished"])))
            console(f"Report: {output / 'CYCLE_REVIEW_REPORT.html'}")
            console("=" * 60)
            return 0 if result['completion'] == 'COMPLETE' and result['health'] != 'FAIL' else 1
    finally:
        if data and not verdict_fixed:
            # Only an abnormal unwind (an exception before any terminal verdict)
            # marks the campaign INCOMPLETE. A report-generation failure happens
            # after the verdict is fixed, so it never reaches here.
            data.update(state='INCOMPLETE', finished=now(), stop_reason='Orchestrator interrupted by an unexpected error; retained all available evidence')
            # A catchable abnormal unwind is still a safe terminal point: retain
            # the final Journal first, then make the single terminal HTML
            # attempt. SIGKILL/power loss cannot reach this block and is rebuilt
            # explicitly by the operator on the original controller.
            safe_checkpoint(output, data, console)
            safe_write_reports(output, data, console)
            try:
                if registry:
                    registry.finish('INCOMPLETE')
            except Exception as exc:
                console(f"Stop request could not be recorded: {exc}")
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


def _read_key(stream):
    """Translate one raw keypress into a token.

    Returns 'up', 'down', 'space', 'enter', 'quit' or the literal character.
    Reads byte-by-byte so it works inside cbreak mode; arrow keys arrive as the
    three-byte escape sequence ESC [ A/B and are collapsed into one token.
    """
    char = stream.read(1)
    if not char:
        return 'enter'
    if char == '\x03':  # Ctrl-C
        raise KeyboardInterrupt
    if char in ('\r', '\n'):
        return 'enter'
    if char == ' ':
        return 'space'
    if char in ('k',):
        return 'up'
    if char in ('j',):
        return 'down'
    if char == '\x1b':
        seq = stream.read(1)
        if seq == '[':
            final = stream.read(1)
            return {'A': 'up', 'B': 'down'}.get(final, 'other')
        return 'other'
    return char


def _make_key_reader(stream=None):
    """Return a callable that yields tokens from a raw (cbreak) terminal.

    The terminal is put into cbreak mode and restored via ``close()``, which the
    caller must invoke in a ``finally`` block so Ctrl-C never leaves the shell
    with echo disabled.
    """
    stream = stream or sys.stdin
    fd = stream.fileno()
    original = termios.tcgetattr(fd)
    tty.setcbreak(fd)

    def read():
        return _read_key(stream)

    closed = False

    def close():
        nonlocal closed
        if closed:
            return
        closed = True
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, original)
        except Exception:
            pass

    read.close = close
    return read


def _checklist(title, items, preselected, read_key, out=sys.stdout, multi=True,
               require=False):
    """Arrow-key selection list. Space selects, Enter confirms.

    ``items`` may be plain labels or ``(label, value)`` pairs. A pair shows
    ``label`` in the list while returning ``value``, so an operator-facing label
    can carry the endpoint addresses without inventing a new selection format.

    `multi=True` toggles items independently (trays, nodes). `multi=False`
    enforces a single choice: selecting one clears the previous one, so the
    cursor can move freely without losing the current pick.

    `read_key()` yields tokens ('up'/'down'/'space'/'enter'/'quit'); all state
    lives here, so the interaction is testable by injecting a scripted reader.
    Returns the list of chosen item labels (empty is allowed).
    """
    entries = [item if isinstance(item, tuple) else (item, item) for item in items]
    labels = [label for label, _ in entries]
    values = [value for _, value in entries]
    chosen = [bool(preselected.get(value, False)) for value in values]
    cursor = 0
    rendered = 0
    warning = ''

    def selected():
        return [value for value, flag in zip(values, chosen) if flag]

    def draw():
        nonlocal rendered, warning
        hint = _dim("  \u2191/\u2193 move  \u00b7  SPACE select  \u00b7  ENTER confirm")
        lines = [_bold(title), hint]
        for index, label in enumerate(labels):
            box = _green('[v]') if chosen[index] else '[ ]'
            pointer = _cyan('\u276f') if index == cursor else ' '
            text = label if index == cursor else _dim(label)
            lines.append(f"  {pointer} {box} {text}")
        picked = selected()
        summary = ', '.join(picked) if picked else _dim('(nothing selected yet)')
        lines.append(f"  {_yellow('\u2192')} {_bold(summary)}")
        if warning:
            lines.append(f"  {_yellow('\u26a0 ' + warning)}")
        out.write('\r' + '\x1b[K' + '\n'.join(lines) + '\n')
        rendered = len(lines)
        out.flush()

    def clear():
        if rendered:
            out.write('\x1b[F' * rendered + '\x1b[J')
            out.flush()

    draw()
    while True:
        token = read_key()
        if token == 'up':
            cursor = (cursor - 1) % len(labels)
        elif token == 'down':
            cursor = (cursor + 1) % len(labels)
        elif token == 'space':
            if multi:
                chosen[cursor] = not chosen[cursor]
            else:
                # Single choice: selecting one clears the rest.
                picked = not chosen[cursor]
                chosen = [False] * len(labels)
                chosen[cursor] = picked
        elif token == 'enter':
            if require and not selected():
                warning = 'Select at least one item, then press ENTER'
                clear()
                draw()
                continue
            clear()
            return selected()
        elif token == 'quit':
            clear()
            raise KeyboardInterrupt
        else:
            continue
        warning = ''
        clear()
        draw()


def _menu(title, options, read_key, out=sys.stdout, default=None):
    """Single-choice TUI menu over (key, label) pairs; returns the chosen key.

    With ``default=None`` nothing is preselected, so the user must make a
    deliberate choice; otherwise the item at ``default`` starts checked.
    """
    labels = [label for _, label in options]
    preselected = {labels[default]: True} if default is not None and 0 <= default < len(labels) else {}
    picked = _checklist(title, labels, preselected, read_key, out, multi=False,
                        require=default is None)
    if not picked:
        return options[default][0] if default is not None else None
    chosen_label = picked[0]
    for key, label in options:
        if label == chosen_label:
            return key
    return options[default][0] if default is not None else None


def _supports_color():
    """ANSI is used only on a real terminal (never pollutes piped output)."""
    return sys.stdout.isatty() and os.environ.get('NO_COLOR') is None


def _c(text, code):
    return f'\x1b[{code}m{text}\x1b[0m' if _supports_color() else str(text)


def _bold(text):
    return _c(text, '1')


def _dim(text):
    return _c(text, '2')


def _green(text):
    return _c(text, '32')


def _cyan(text):
    return _c(text, '36')


def _yellow(text):
    return _c(text, '33')


def _console_symbol(symbol, fallback):
    """Avoid crashing a Windows legacy-codepage console on cosmetic glyphs."""
    encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
    try:
        symbol.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return fallback
    return symbol


def _echo(message):
    print(f"  {_green(_console_symbol('\u2714', '[OK]'))} {message}")


def _echo_kv(label, value):
    """'✔ Label: value' with the chosen value highlighted so it stands out."""
    print(f"  {_green(_console_symbol('\u2714', '[OK]'))} {label}: {_cyan(_bold(value))}")


def cycle_command(mode, channel):
    """The real action command for (cycle_mode, channel), mirroring cycle_engine.

    Returns ``(role, command)`` where role is the transport ('os'/'oob'/'bmc').

    The ``command`` is shown the way the runner actually issues it:
      * role 'os'  -> the literal argv sent over SSH (e.g. 'ipmitool power cycle')
      * role 'oob' -> the IPMI sub-command; transport.oob() wraps it as
        ``ipmitool -I lanplus ... -E <command>``, so 'power reset' runs as
        ``ipmitool ... power reset`` (the ipmitool prefix is added by the
        transport, not carried in the string).
      * role 'bmc' -> the helper path run over SSH on the BMC.
    """
    if mode == 'aux_cycle':
        return 'bmc', '/usr/bin/stbypowerctrl.sh aux_cycle'
    if mode == 'reboot' and channel == 'outband':
        return 'oob', 'power reset'
    if mode == 'reboot':
        return 'os', 'reboot'
    if channel == 'inband':
        return 'os', 'ipmitool power cycle'
    return 'bmc', '/usr/bin/powerctrl.sh power_cycle'


def display_command(role, command):
    """Full command line as it truly reaches the target, for the preview."""
    if role == 'oob':
        # transport.oob() prepends the ipmitool argv; show that, so the operator
        # recognises this as IPMI rather than a bare 'power reset'.
        return f'ipmitool -I lanplus ... -H <bmc_ip> -E {command}'
    return command


def build_command(options):
    """Real per-target command lines the runner will send, one per node."""
    role, command = cycle_command(options.cycle_mode, options.channel)
    shown = display_command(role, command)
    targets = options.node or ['<all nodes>']
    lines = []
    for node in targets:
        lines.append(f'[{role}] {node}: {shown}')
    if getattr(options, 'loops', 0):
        limit = f'{options.loops} loops'
    elif getattr(options, 'hours', 0):
        limit = f'{options.hours} hours'
    else:
        limit = 'continuous'
    return lines, limit


def show_command(options):
    """Print the assembled per-target commands with a little colour."""
    lines, limit = build_command(options)
    print(f"  {_bold('Will run')} {_dim('(cycle action per target)')}")
    for line in lines:
        print(f"    {_cyan(line)}")
    print(f"  {_bold('Repeat')} {_yellow(limit)}")
    if getattr(options, 'cycle_mode', '') == 'aux_cycle':
        interval = getattr(options, 'aux_interval', 20.0)
        if interval > 0 and len(getattr(options, 'node', None) or []) > 1:
            print(f"  {_bold('Stagger')} {_cyan(f'one node every {interval:g}s')} "
                  f"{_dim('(AC cycle must not hit several nodes at once)')}")
        else:
            print(f"  {_bold('Stagger')} {_dim('off')}")


def _group_by_tray(targets):
    """Ordered tray -> [node] map, preserving inventory (CSV) order."""
    trays = []
    nodes = {}
    for target in targets:
        if target.tray not in nodes:
            nodes[target.tray] = []
            trays.append(target.tray)
        nodes[target.tray].append(target.node)
    return trays, nodes


def _tray_label(tray, tray_targets):
    """'Neutrino0  os 10.36.72.2 .4 .10 .8' -- every OS address, spelled out.

    Abbreviating the range as '3-9' hid the addresses an operator actually
    needs, and the n2 row breaks the numeric order, so a compressed span was
    misleading. Listing them in full is short enough for a 4-node tray.
    """
    os_ips = [t.os_ip for t in tray_targets if t.os_ip]
    if not os_ips:
        return tray
    return f'{tray}  os ' + ' '.join(os_ips)


def _node_label(target):
    """'n0  os 10.36.72.2  bmc 10.36.72.3' -- the machine, not just its name."""
    return f'{target.node}  os {target.os_ip or "-"}'


def _tui_select_targets(targets, read_key, out=sys.stdout):
    """Full-screen selection: pick trays, then per-tray nodes.

    Returns a list of '<tray>/<node>' selections. Feeds select_targets(), which
    already accepts tray/node, so the core stays untouched.
    """
    trays, nodes = _group_by_tray(targets)
    members = {}
    for target in targets:
        members.setdefault(target.tray, []).append(target)
    if len(trays) == 1:
        # Single tray: skip the tray step, only ask which nodes.
        chosen_trays = trays
        _echo(f'Only one tray present ({trays[0]}); selecting its nodes.')
    else:
        # The label carries the BMC range so an operator can find the tray;
        # the returned value stays the bare tray name.
        entries = [(_tray_label(t, members[t]), t) for t in trays]
        chosen_trays = _checklist('Select trays', entries, {}, read_key, out,
                                  require=True)
        _echo(f'Trays: {", ".join(chosen_trays)}')
    selected = []
    for tray in chosen_trays:
        # require=True: Enter with nothing picked re-prompts, so a node must be
        # chosen explicitly instead of defaulting to every node.
        entries = []
        for target in members[tray]:
            entries.append((_node_label(target), target.node))
        picked = _checklist(f'Select nodes in {tray}', entries, {}, read_key, out,
                            require=True)
        _echo(f'{tray}: {", ".join(picked)}')
        selected.extend(f'{tray}/{node}' for node in picked)
    return selected


def _plain_node_prompt(names):
    """Legacy text prompt, kept as the non-interactive (non-TTY) fallback."""
    while True:
        reply = input("Which nodes? (all / comma-sep, e.g. n1,n2) [all]: ").strip()
        if not reply or reply.lower() == 'all':
            return None
        parts = [p for p in reply.replace(',', ' ').split() if p]
        bad = [p for p in parts if p not in names]
        if bad:
            print(f"  INVALID: {', '.join(bad)} — valid: {', '.join(names)}")
            continue
        return parts


def _menu_wizard(options):
    """Interactive (TTY) wizard using the shared TUI reader for every choice."""
    reader = _make_key_reader()
    try:
        options.project = _menu('Project', [('neutrino', 'neutrino'), ('naboo', 'naboo')],
                                reader, default=None)
        _echo_kv('Project', options.project)
        options.inventory = options.inventory or paths.inventory_path(options.project)
        targets = load_inventory(options.inventory)
        options.node = _tui_select_targets(targets, reader)
        _echo_kv('Targets', ', '.join(options.node))
        options.cycle_mode = _menu('Cycle mode', [
            ('power_cycle', 'power_cycle'), ('reboot', 'reboot'), ('aux_cycle', 'aux_cycle')], reader)
        _echo_kv('Cycle mode', options.cycle_mode)
        if options.cycle_mode == 'aux_cycle':
            options.aux_interval = _menu('Aux cycle stagger', [
                ('20', '20 seconds between nodes (recommended)'),
                ('30', '30 seconds between nodes'),
                ('10', '10 seconds between nodes'),
                ('0', 'off - all nodes at once (may drop nodes on this platform)')], reader, default=0)
            options.aux_interval = float(options.aux_interval)
            _echo_kv('Aux stagger', 'off' if not options.aux_interval else f'{options.aux_interval:g} s')
        options.channel = _menu('Channel', [('inband', 'inband'), ('outband', 'outband')], reader)
        _echo_kv('Channel', options.channel)
        duration = _menu('Duration type', [
            ('loops', 'Loops (number of cycles)'), ('hours', 'Hours (time limit)')], reader)
        # Leave cbreak before prompting: choose_limit() needs line-buffered stdin.
        reader.close()
        options.loops, options.hours = 0, 0.0
        if duration == 'loops':
            options.loops = choose_limit('loops')
            _echo_kv('Duration', f'{options.loops} loops')
        else:
            options.hours = choose_limit('hours')
            _echo_kv('Duration', f'{options.hours} hours')
        show_command(options)
    finally:
        reader.close()
    options.cycle = True
    return targets


def wizard(options):
    """Interactive campaign setup, mirroring the rackctl prompt style."""
    print('=' * 50)
    print('  Vera Cycle Wizard (interactive)')
    print('=' * 50)
    if sys.stdin.isatty() and termios is not None:
        return _menu_wizard(options)
    options.project = choose('Project', [('neutrino', 'neutrino'), ('naboo', 'naboo')], 1)
    options.inventory = options.inventory or paths.inventory_path(options.project)
    targets = load_inventory(options.inventory)
    names = sorted({t.node for t in targets})
    print(f"\nNodes in inventory: {', '.join(names)}")
    options.node = _plain_node_prompt(names)
    options.cycle_mode = choose('Cycle mode', [
        ('power_cycle', 'power_cycle'), ('reboot', 'reboot'), ('aux_cycle', 'aux_cycle')], 1)
    if options.cycle_mode == 'aux_cycle':
        options.aux_interval = choose('Aux cycle stagger', [
            ('20', '20 seconds between nodes (recommended)'),
            ('30', '30 seconds between nodes'),
            ('10', '10 seconds between nodes'),
            ('0', 'off - all nodes at once (may drop nodes on this platform)')], 1)
        options.aux_interval = float(options.aux_interval)
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
    p.add_argument('--version', action='version', version=paths.VERSION_FILE.read_text().strip())
    p.add_argument('--project', choices=('1', '2', 'neutrino', 'naboo'))
    p.add_argument('--node', action='append', help='all, unique node name, or tray/node; may repeat')
    p.add_argument('--inventory', type=Path)
    p.add_argument('--loops', type=int, default=0)
    p.add_argument('--hours', type=float, default=0)
    p.add_argument('--cycle-mode', choices=('reboot', 'power_cycle', 'aux_cycle'), default='power_cycle')
    p.add_argument('--channel', choices=('inband', 'outband'), default='inband')
    p.add_argument('--boot-timeout', type=float, default=900)
    p.add_argument('--aux-interval', type=float, default=20.0,
                   help='Seconds between consecutive aux_cycle commands across nodes (0 disables staggering; ignored by other cycle modes)')
    p.add_argument('--poll-interval', type=float, default=10)
    p.add_argument('--memory-min-ratio', type=float, default=0.90, help='Minimum OS MemTotal / installed SMBIOS capacity (0 < ratio <= 1)')
    p.add_argument('--config-script', type=Path,
                   help='Override the selected project config script')
    p.add_argument('--issue-policy', type=Path, default=paths.ISSUE_POLICY)
    p.add_argument('--output', type=Path, default=paths.CAMPAIGNS_DIR)
    p.add_argument('--cycle', action='store_true', help='Run cycles after PRE and explicit confirmation; wizard enables this')
    p.add_argument('--keep-going', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--stop', metavar='RUN_ID', nargs='?', const='', help='Open numbered stop menu, or stop the specified Run ID')
    p.add_argument('--report', type=Path, metavar='CAMPAIGN_DIR', help='Rebuild a stopped campaign report from its journal; do not use during a live run')
    p.add_argument('--journal', type=Path, metavar='CAMPAIGN_JSON',
                   help='Journal to rebuild from; defaults to the campaign journal for CAMPAIGN_DIR')
    p.add_argument('--export-zip', type=Path, metavar='CAMPAIGN_DIR',
                   help='Create a delivery ZIP without the external/legacy campaign journal')
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
            info = rebuild(options.report, journal=options.journal)
            print(f"Report rebuilt: {options.report / 'CYCLE_REVIEW_REPORT.html'} ({info['state']})")
            return 0
        if options.export_zip:
            archive = create_delivery_zip(options.export_zip)
            print(f"Delivery ZIP: {archive}")
            return 0
        interactive = not arguments
        if interactive:
            startup_recovery_prompt()
            targets = wizard(options)
        else:
            options.project = {'1': 'neutrino', '2': 'naboo'}.get(options.project, options.project)
            if options.project not in {'neutrino', 'naboo'}:
                raise ValueError('Invalid project')
            options.inventory = options.inventory or paths.inventory_path(options.project)
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
        if not math.isfinite(options.aux_interval) or not 0 <= options.aux_interval <= 3600:
            raise ValueError('Aux cycle interval must be finite and between 0 and 3600 seconds')
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
