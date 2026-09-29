#!/usr/bin/env python3
"""Outside-host Vera campaign runner. Run without arguments for the wizard."""
from __future__ import annotations
import argparse
import getpass
import json
import math
import os
import signal
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from cycle_core import (ROLES, atomic_write, digest, health, inventory_blocks, issue,
                        load_inventory, now, parse_policy, select_targets, classify)
from cycle_engine import NodeSession, new_record
from cycle_report import rebuild, status, write_reports
from cycle_runtime import EndpointLocks, RunRegistry, request_stop
from cycle_transport import Transport

BASE = Path(__file__).resolve().parent

class Console:
    def __init__(self):
        self.lines = []
        self.path = None
        self.lock = threading.Lock()

    def __call__(self, message):
        with self.lock:
            line = f"{now()} {message}"
            print(line, flush=True)
            self.lines.append(line)
            if self.path:
                with self.path.open('a', encoding='utf-8') as stream:
                    stream.write(line + '\n')

    def attach(self, path):
        self.path = path
        atomic_write(path, '\n'.join(self.lines) + '\n')

def show_result(console, node, record):
    console(f"{node['key']} | {record['phase']} | {'BLOCKED' if node['blocked'] else record['status']}")
    if record['phase'] == 'PRE':
        console('  Identity: ' + ' | '.join(f"{role.upper()} SSH {'OK' if role in record['identities'] else 'NOT VERIFIED'}" for role in ('bmc', 'os')))
    groups = {}
    for item in record['issues']:
        key = (item['severity'], item['code'], item['component'], item['detail'], item.get('classification', 'NEW'))
        groups[key] = groups.get(key, 0) + 1
    for (severity, code, component, detail, classification), count in groups.items():
        text = ' '.join(detail.split())[:300]
        console(f"  {severity} [{classification}] {component}: {text}" + (f" (repeated {count} times)" if count > 1 else ''))
    for reason in node['blocked']:
        console(f"  BLOCKED: {reason}")

def parallel(function, sessions, console, label):
    """Bounded wait with concise progress; never dump remote command output."""
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(sessions)))) as pool:
        futures = {pool.submit(function, s): s for s in sessions}
        from concurrent.futures import wait, FIRST_COMPLETED
        pending = set(futures)
        while pending:
            done, pending = wait(pending, timeout=30, return_when=FIRST_COMPLETED)
            if not done:
                console(f"{label}: waiting for {len(pending)} target(s)")
            for future in done:
                session = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    session.node.update(active=False, stop_reason=f"{label}: {type(exc).__name__}: {exc}")
                    record = session.node['loops'][-1] if session.node['loops'] else session.node['pre']
                    session.add(record, 'EXECUTION_ERROR', label, str(exc))
                    if label == 'PRE':
                        session.node['blocked'].append(str(exc))
                    session.finish(record)
                record = session.node['loops'][-1] if session.node['loops'] else session.node['pre']
                show_result(console, session.node, record)

def campaign(options, targets, credentials, confirm=input, transport_factory=Transport, runtime_root=None):
    console = Console()
    run_id = f"{options.project}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    output = options.output.resolve() / run_id
    locks = EndpointLocks(runtime_root)
    stop = threading.Event()
    prior_handlers = {}
    registry = None
    data = None
    finalized = False
    # Both keyboard interrupt and TERM are graceful: finish current POST.
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            prior_handlers[sig] = signal.signal(sig, lambda *_: stop.set())
    try:
        script = options.config_script.read_bytes().replace(b'\r\n', b'\n')
        policy_text = options.issue_policy.read_text(encoding='utf-8')
        rules = parse_policy(policy_text)
        console(f"Run ID: {run_id}")
        console(f"Planned output: {output}")
        console("Selected targets: " + ', '.join(t.key for t in targets))
        console(f"Mode: {options.cycle_mode}; channel: {options.channel}; loops: {options.loops or 'unlimited'}; hours: {options.hours or 'unlimited'}")
        if options.cycle_mode == 'reboot' and options.channel == 'outband':
            console("Outband reboot uses ACPI power soft, waits for confirmed Off, then sends power on once.")
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
            registry.register(output)
            atomic_write(output / 'vera_rack.snapshot.sh', script.decode('utf-8'))
            atomic_write(output / 'issue_policy.snapshot.md', policy_text)
            data = dict(run_id=run_id, project=options.project, started=now(), finished=None,
                        state='RUNNING', stop_reason='', cycle_mode=options.cycle_mode, channel=options.channel,
                        limits=dict(loops=options.loops, hours=options.hours), script_sha256=digest(script),
                        nodes=[s.node for s in sessions])
            write_reports(output, data)
            console(f"Campaign started. Output: {output}")
            console(f"Stop after the current POST: ./stop_cycle.sh {run_id}")
            start = time.monotonic()
            parallel(lambda s: s.start(), runnable, console, 'Start log clearing')
            write_reports(output, data)
            number = 0
            while True:
                active = [s for s in runnable if s.node['active']]
                if stop.is_set() or registry.requested():
                    data.update(state='INCOMPLETE', stop_reason='Operator requested stop after the current POST')
                    break
                if (options.loops and number >= options.loops) or (options.hours and time.monotonic()-start >= options.hours*3600):
                    if any(not s.node['active'] for s in runnable):
                        data.update(state='INCOMPLETE', stop_reason='Run limit reached; one or more targets became unavailable')
                    else:
                        data.update(state='COMPLETE', stop_reason='Requested run limit reached')
                    break
                if not active:
                    data.update(state='INCOMPLETE', stop_reason='All approved targets became unavailable')
                    break
                number += 1
                console(f"Loop {number}: starting {len(active)} target(s) concurrently")
                parallel(lambda s: s.one_loop(number), active, console, f'Loop {number}')
                write_reports(output, data)
            data['finished'] = now()
            write_reports(output, data)
            registry.finish(data['state'])
            finalized = True
            result = status(data)
            console(f"Execution: {result['completion']} | Health: {result['health']} | Completed node-loops: {result['completed_node_loops']}")
            console(f"Report: {output / 'CYCLE_REVIEW_REPORT.html'}")
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
        locks.close()
        for sig, handler in prior_handlers.items():
            signal.signal(sig, handler)

def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', choices=('1', '2', 'neutrino', 'naboo'))
    p.add_argument('--node', action='append', help='all, unique node name, or tray/node; may repeat')
    p.add_argument('--inventory', type=Path)
    p.add_argument('--loops', type=int, default=0)
    p.add_argument('--hours', type=float, default=0)
    p.add_argument('--cycle-mode', choices=('reboot', 'power_cycle', 'aux_cycle'), default='power_cycle')
    p.add_argument('--channel', choices=('inband', 'outband'), default='inband')
    p.add_argument('--boot-timeout', type=float, default=900)
    p.add_argument('--poll-interval', type=float, default=10)
    p.add_argument('--config-script', type=Path, default=BASE / 'vera_rack.sh')
    p.add_argument('--issue-policy', type=Path, default=BASE / 'issue_policy.md')
    p.add_argument('--output', type=Path, default=BASE / 'campaigns')
    p.add_argument('--cycle', action='store_true', help='Run cycles after PRE and explicit confirmation; wizard enables this')
    p.add_argument('--keep-going', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--stop', metavar='RUN_ID', help='Owner-only request to finish current POST and stop')
    p.add_argument('--report', type=Path, metavar='CAMPAIGN_DIR', help='Rebuild a stopped campaign report from its journal; do not use during a live run')
    return p

def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    p = parser()
    options = p.parse_args(arguments)
    try:
        if options.stop:
            info = request_stop(options.stop)
            print(f"Stop requested for {options.stop}. Current POST will finish. Output: {info['output']}")
            return 0
        if options.report:
            info = rebuild(options.report)
            print(f"Report rebuilt: {options.report / 'CYCLE_REVIEW_REPORT.html'} ({info['state']})")
            return 0
        interactive = not arguments
        if not options.project:
            options.project = input('Project [1=neutrino, 2=naboo]: ').strip()
        options.project = {'1': 'neutrino', '2': 'naboo'}.get(options.project, options.project)
        if options.project not in {'neutrino', 'naboo'}:
            raise ValueError('Invalid project')
        options.inventory = options.inventory or BASE / f'cycle_inventory_{options.project}.csv'
        targets = load_inventory(options.inventory)
        if not options.node:
            print('Available targets: ' + ', '.join(f'{t.tray}/{t.node}' for t in targets))
            options.node = input('Select targets separated by commas, or all: ').strip().split(',')
            options.node = [s.strip() for s in options.node]
        targets = select_targets(targets, options.node)
        if interactive:
            options.cycle_mode = input('Cycle mode [reboot / power_cycle / aux_cycle]: ').strip()
            options.channel = input('Channel [inband / outband]: ').strip()
            options.loops = int(input('Loop limit [0 = no loop limit]: ').strip())
            options.hours = float(input('Hour limit [0 = no time limit]: ').strip())
            options.cycle = True
        if options.cycle_mode not in {'reboot', 'power_cycle', 'aux_cycle'} or options.channel not in {'inband', 'outband'}:
            raise ValueError('Invalid mode or channel')
        if options.loops < 0 or not math.isfinite(options.hours) or options.hours < 0 or not (options.loops or options.hours):
            raise ValueError('Provide a positive --loops or --hours limit; negative/non-finite limits are invalid')
        if not math.isfinite(options.boot_timeout) or options.boot_timeout < 1 or not math.isfinite(options.poll_interval) or options.poll_interval <= 0:
            raise ValueError('Boot timeout must be >= 1 second and polling interval must be positive')
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
                    credentials[role] = getpass.getpass(f'{role} password (blank for SSH key; BMC IPMI needs a password): ')
        return campaign(options, targets, credentials)
    except (ValueError, OSError, RuntimeError, EOFError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
