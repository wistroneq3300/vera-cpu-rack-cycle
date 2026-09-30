"""Conservative recovery: a missing sidecar never deletes journal history."""
import copy
import json
from datetime import datetime

from cycle_core import classify_against_pre, health, issue, issue_baseline, now


def _clean(record):
    return {k: v for k, v in record.items() if k not in {'missing_evidence', 'recovery_versions'}}


def _unique(values):
    found = {}
    for value in values:
        comparable = {k: v for k, v in value.items() if k not in {'classification', 'known_reason'}} if isinstance(value, dict) else value
        found.setdefault(json.dumps(comparable, sort_keys=True), value)
    return list(found.values())


def _validate(record, phase, number=None):
    if not isinstance(record, dict) or record.get('phase') != phase:
        raise ValueError('Record phase does not match its identity')
    if number is not None and (type(record.get('loop')) is not int or record['loop'] != number):
        raise ValueError('Record loop does not match directory identity')
    for name, kind in {'issues': list, 'evidence': list, 'commands': dict, 'identities': dict,
                       'action': list, 'recovery': dict}.items():
        if not isinstance(record.get(name), kind):
            raise ValueError('Invalid record field: ' + name)
    for finding in record['issues']:
        if not isinstance(finding, dict) or not all(k in finding for k in ('code', 'component', 'detail', 'severity')):
            raise ValueError('Malformed finding')
        if finding['severity'] not in {'WARN', 'FAIL'}:
            raise ValueError('Invalid finding severity')
    if not all(isinstance(e, str) for e in record['evidence']):
        raise ValueError('Invalid evidence paths')
    if type(record.get('revision', 0)) is not int or record.get('revision', 0) < 0:
        raise ValueError('Invalid record revision')
    for name in ('post_complete', 'boot_confirmed', 'valid_cycle', 'hardware_execution_complete', 'script_verified'):
        if name in record and type(record[name]) is not bool:
            raise ValueError('Invalid completion flag: ' + name)
    if record.get('valid_cycle') and not (record.get('post_complete') and record.get('boot_confirmed')):
        raise ValueError('Valid cycle lacks completed POST or confirmed boot')
    for name in ('started', 'finished'):
        if record.get(name):
            datetime.fromisoformat(record[name])
    return record


def _read(path, phase, number, notes):
    try:
        return _validate(json.loads(path.read_text(encoding='utf-8')), phase, number)
    except (OSError, ValueError, TypeError) as exc:
        reason = 'missing' if isinstance(exc, FileNotFoundError) else 'invalid'
        notes.add(f'{phase}: {reason} independent record ({path.name}); journal retained when available')
        return None


def _order(record):
    # Revision is written by the engine. Older bundles have no revision, so
    # prefer a completed record, then its recorded time, never file mtime.
    return (bool(record.get('finished')), record.get('revision', 0), record.get('finished') or record.get('started', ''))


def _merge(journal, disk, label, notes):
    if journal is None:
        return copy.deepcopy(disk)
    if disk is None:
        return copy.deepcopy(journal)
    versions = journal.get('recovery_versions') or [_clean(journal)]
    versions = _unique([*versions, _clean(disk)])
    if len(versions) == 1:
        return copy.deepcopy(journal)
    complete = [r for r in versions if r.get('finished')]
    chosen = max(complete or versions, key=_order)
    # A partial prefix followed by a complete superset is ordinary crash
    # recovery. Contradictory terminal records or a newer partial are conflicts.
    normal_progress = (len(complete) == 1 and all(
        _order(r) <= _order(chosen)
        and all(i in _unique(chosen['issues']) for i in _unique(r['issues']))
        and set(r['evidence']).issubset(chosen['evidence'])
        and (not r.get('revision') or r['revision'] <= chosen.get('revision', 0))
        and (r.get('finished') or (r.get('started', '') <= chosen.get('started', '')))
        for r in versions))
    if not normal_progress:
        notes.add(f'{label}: conflicting record versions retained; terminal evidence cannot be silently replaced')
    result = copy.deepcopy(chosen)
    result['issues'] = _unique([i for r in versions for i in r['issues']])
    result['evidence'] = _unique([e for r in versions for e in r['evidence']])
    result['action'] = _unique([a for r in versions for a in r['action']])
    if result.get('finished'):
        result['status'] = health(result['issues'])
    result['recovery_versions'] = copy.deepcopy(versions)
    return result


def recover_records(root, campaign):
    campaign = copy.deepcopy(campaign)
    damaged = False
    for node in campaign['nodes']:
        key = node['key']
        if not isinstance(key, str) or '/' in key or '\\' in key or key in {'.', '..'}:
            raise ValueError('Invalid node identity in journal')
        folder = root / key
        notes = set(node.get('recovery_notes', []))
        _validate(node['pre'], 'PRE')  # Never replace corrupt primary data silently.
        merged_pre = _merge(node['pre'], _read(folder/'pre_report.json', 'PRE', None, notes), 'PRE', notes)
        if merged_pre.get('recovery_versions'):
            node['recovery_pre_versions'] = merged_pre['recovery_versions']
            # Do not redefine the reviewed baseline. Alternate PRE findings
            # remain visible separately and still affect campaign health.
            node['recovery_issues'] = _unique([*node.get('recovery_issues', []),
                                             *[i for i in merged_pre['issues'] if i not in node['pre']['issues']]])
        if node.get('start') or (folder/'start/report.json').exists():
            if node.get('start'):
                _validate(node['start'], 'START')
            node['start'] = _merge(node.get('start'), _read(folder/'start/report.json', 'START', None, notes), 'START', notes)
        loops = {}
        for record in node['loops']:
            number = record.get('loop')
            if type(number) is not int or number <= 0:
                raise ValueError('Invalid loop identity in campaign journal')
            _validate(record, f'LOOP {number}', number)
            if number in loops:
                notes.add(f'LOOP {number}: duplicate journal identity')
                loops[number] = _merge(loops[number], record, f'LOOP {number}', notes)
            else:
                loops[number] = record
        paths = {n: folder/f'loop{n:04d}'/'report.json' for n in loops}
        for path in folder.glob('loop*/report.json'):
            suffix = path.parent.name[4:]
            if not suffix.isdecimal() or int(suffix) <= 0 or path.parent.name != f'loop{int(suffix):04d}':
                notes.add('Invalid independent loop directory: ' + path.parent.name)
                continue
            paths[int(suffix)] = path
        for number, path in sorted(paths.items()):
            disk = _read(path, f'LOOP {number}', number, notes)
            record = _merge(loops.get(number), disk, f'LOOP {number}', notes)
            if record is not None:
                loops[number] = record
        node['loops'] = [loops[n] for n in sorted(loops)]
        calculated = dict(completed=sum(bool(r.get('post_complete')) for r in node['loops']),
                          attempts=sum(bool(r.get('action')) for r in node['loops']),
                          boot_confirmed=sum(bool(r.get('boot_confirmed')) for r in node['loops']),
                          valid_cycles=sum(bool(r.get('valid_cycle')) for r in node['loops']))
        for name, count in calculated.items():
            if node.get(name, 0) > count:
                notes.add(f'Journal {name}={node[name]} exceeds recoverable record count={count}')
                node.setdefault('recovery_original_counters', {})[name] = node[name]
        node.update(calculated)
        if campaign['state'] == 'COMPLETE' and not node.get('blocked'):
            if not node['loops'] or any(not r.get('post_complete') for r in node['loops']):
                notes.add('COMPLETE journal has zero exercised loops or unfinished POST')
        if notes:
            damaged = True
            node['recovery_notes'] = sorted(notes)
            # Recovery findings must not modify immutable PRE or real START.
            node['recovery_issues'] = [i for i in node.get('recovery_issues', []) if i['code'] != 'REPORT_RECOVERY_INTEGRITY']
            node['recovery_issues'].append(issue('REPORT_RECOVERY_INTEGRITY', 'report', '\n'.join(sorted(notes))))
        baseline = issue_baseline(node['pre']['issues'])
        for record in node['loops']:
            classify_against_pre(record['issues'], baseline)
    if campaign['state'] == 'RUNNING' or damaged:
        campaign.update(state='INCOMPLETE', finished=campaign.get('finished') or now(),
                        stop_reason='Recovered journal; original run unfinished or evidence integrity needs review')
    return campaign
