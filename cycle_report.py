"""All report formats derive from the same records and evaluator."""
from __future__ import annotations

from datetime import datetime
import html
import json
import re
from pathlib import Path
from urllib.parse import quote

from cycle_core import aggregate_issues, atomic_write, health, now, write_json

ASSETS = Path(__file__).parent

def esc(value):
    return html.escape(str(value), quote=True)

def badge(value):
    return f'<span class="badge {esc(str(value).lower().replace(" ", "-"))}">{esc(value)}</span>'

def evidence_link(path):
    # Only links to the campaign bundle. No absolute paths, schemes or traversal.
    p = Path(path)
    if not path or p.is_absolute() or ".." in p.parts or ":" in path or "\\" in path:
        return "Evidence unavailable"
    return f'<a href="{quote(path, safe="/")}" target="_blank" rel="noopener">{esc(path)}</a>'

def status(campaign):
    items = aggregate_issues(campaign)
    return {"health": health(items), "completion": campaign["state"],
            "unique_issues": len(items), "known": sum(i["classification"] == "KNOWN" for i in items),
            "new": sum(i["classification"] == "NEW" for i in items),
            "completed_node_loops": sum(n["completed"] for n in campaign["nodes"]),
            "issues": items}

def facts(pairs):
    return '<dl class="facts">' + ''.join(f'<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>' for k, v in pairs) + '</dl>'

def record_html(record, node_index):
    phase_id = f"node-{node_index}-" + ("pre" if record["phase"] == "PRE" else f"loop-{record['loop']}")
    issues = ''.join(f'<li>{badge(i["severity"])} <strong>{esc(i["component"])}</strong> — {esc(i["detail"])} {badge("PRE-EXISTING" if record["phase"] == "PRE" else i.get("classification", "NEW"))}' + (f'<pre class="snippet">{esc(i["snippet"])}</pre>' if i.get("snippet") else '') + '</li>' for i in record["issues"])
    evidence = ''.join('<li>' + (badge('MISSING') + ' ' + esc(p) if p in record.get('missing_evidence', []) else evidence_link(p)) + '</li>' for p in dict.fromkeys(record["evidence"]))
    action = ''
    if record['phase'] != 'PRE':
        rows = ''.join(f'<tr><td><code>{esc(a["command"])}</code></td><td>{esc(a["role"])}</td><td>{badge(a["state"])}</td><td>{esc(a["code"])}</td></tr>' for a in record['action'])
        action = '<h3>Cycle action and recovery</h3><div class="tablewrap"><table><thead><tr><th scope="col">Command</th><th scope="col">Channel endpoint</th><th scope="col">Result</th><th scope="col">Exit code</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
        recovery = record['recovery']
        action += facts([('OS boot changed', 'Yes' if recovery.get('boot_changed') else 'Not confirmed'), ('Recovery attempts', recovery.get('attempts', 'Not recorded')), ('Before boot ID', recovery.get('old_boot_id', 'Not recorded')), ('After boot ID', recovery.get('new_boot_id', 'Not recorded'))])
    identity = '<h3>Verified identities</h3><div class="tablewrap"><table><thead><tr><th scope="col">Endpoint</th><th scope="col">Hostname</th><th scope="col">Boot ID</th></tr></thead><tbody>' + ''.join(f'<tr><td>{esc(role.upper())}</td><td>{esc(values["hostname"])}</td><td><code>{esc(values.get("boot_id", "Not recorded"))}</code></td></tr>' for role, values in record['identities'].items()) + '</tbody></table></div>'
    collection = ''.join(f'<li><strong>{esc(name)}</strong> {badge("COLLECTION FAILED")}<pre class="snippet">{esc(cmd.get("output_excerpt") or "No output captured; check the command evidence.")}</pre></li>' for name, cmd in record.get('commands', {}).items() if not cmd.get('valid', True) and name != 'hardware' and not name.startswith('cycle_'))
    collection = '<details><summary>Collection failures</summary><ul>' + collection + '</ul></details>' if collection else ''
    sel = ''
    if record['phase'] != 'PRE':
        events = record.get('sel_events')
        if events is None:
            sel = '<p>BMC SEL delta: ' + badge(record.get('sel_status', 'MISSING')) + '</p>'
        elif not events:
            sel = '<details class="sel-events empty-sel"><summary>BMC SEL: EMPTY — 0 events</summary><div class="detail-body"><p>The before-cycle and POST snapshots were read successfully. The BMC returned no SEL records.</p></div></details>'
        else:
            content = ''.join(f'<li><code>{esc(e)}</code></li>' for e in events)
            sel = f'<details class="sel-events"><summary>New BMC SEL events: {len(events)}</summary><div class="detail-body"><p>Review event correctness manually. Compared with the snapshot immediately before this loop.</p><ul>{content}</ul></div></details>'
    return f'''<details id="{phase_id}"><summary><strong>{esc(record['phase'])}</strong> {badge(record['status'])}<span class="phase-count">{len(record['issues'])} findings · {esc(duration(record.get('duration_seconds')))} · {esc(record.get('finished') or 'Not finished')}</span></summary><div class="detail-body">
      <ul class="record-issues">{issues}</ul>{'<p>No issues recorded.</p>' if not issues else ''}{collection}{sel}<details><summary>Cycle action and verified identities</summary>{action}{identity}</details>
      <p class="muted">{esc(record.get('sel_review', ''))}</p><details><summary>Original evidence files</summary><ul class="evidence-list">{evidence}</ul></details></div></details>'''

def duration(seconds):
    if seconds is None:
        return "Not recorded"
    seconds = max(0, int(seconds))
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def elapsed(start, end):
    if not start or not end:
        return None
    try:
        return max(0, (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except (ValueError, TypeError):
        return None


def node_order(node):
    name = node['target'].get('node', node['key']).lower()
    return tuple((0, int(part)) if part.isdigit() else (1, part)
                 for part in re.split(r'(\d+)', name)), node['key']


def issue_cards(items, indices):
    rows = []
    opened = False
    for item in sorted(items, key=lambda x: (x['severity'] != 'FAIL', x['node'], x['code'])):
        occurrences = []
        phases = list(dict.fromkeys(e['phase'] for e in item['occurrences']))
        for event in item['occurrences']:
            i = indices[item['node']]
            loop = re.search(r'(\d+)\s*$', event['phase'])
            phase_id = f"node-{i}-" + (f"loop-{loop.group(1)}" if event['phase'] != 'PRE' and loop else 'pre')
            source = f'<pre class="snippet">{esc(event["snippet"])}</pre>' if event.get('snippet') else ''
            occurrences.append(f'<tr><td><a href="#{phase_id}" data-panel="node-{i}">{esc(event["phase"])}</a></td><td>{esc(event["detail"])}{source}</td><td>{evidence_link(event["evidence"])}</td></tr>')
        loops = [int(m.group(1)) for p in phases if (m := re.search(r'LOOP (\d+)', p))]
        scope = (('PRE; ' if 'PRE' in phases else '') + (f"Loops {min(loops)}–{max(loops)}" if loops else '')) or 'PRE'
        open_attr = ' open' if not opened and item['severity'] == 'FAIL' else ''
        opened = opened or bool(open_attr)
        rows.append(f'''<details class="issue-row" data-severity="{esc(item['severity'])}" data-classification="{esc(item['classification'])}"{open_attr}><summary>{badge(item['severity'])}<span class="issue-title">{esc(item['node'])} / {esc(item['component'])}</span> {badge(item['classification'])}<span class="issue-meta">{esc(item['code'])} · {len(item['occurrences'])} occurrence(s) · {scope}</span></summary><div class="detail-body"><p>{esc(item['detail'])}</p><details><summary>All occurrences ({len(item['occurrences'])})</summary><div class="tablewrap"><table><thead><tr><th>Phase</th><th>Finding and source</th><th>Evidence</th></tr></thead><tbody>{''.join(occurrences)}</tbody></table></div></details></div></details>''')
    return ''.join(rows) or '<p>No issues recorded.</p>'


def render_html(campaign, console_log=''):
    result = status(campaign)
    nodes, items = campaign['nodes'], result['issues']
    indices = {n['key']: i for i, n in enumerate(nodes)}
    tabs = [('overview', 'Overview'), ('nodes', f'Nodes ({len(nodes)})'), ('issues', f'Issues ({len(items)})')]
    tab_html = ''.join(f'<button id="tab-{key}" role="tab" aria-controls="{key}" aria-selected="{str(i == 0).lower()}" tabindex="{0 if i == 0 else -1}">{esc(label)}</button>' for i, (key, label) in enumerate(tabs))
    rows, choices, panels = [], [], []
    for node in sorted(nodes, key=node_order):
        i = indices[node['key']]
        node_items = [item for item in items if item['node'] == node['key']]
        health_value = health(node_items)
        state = 'BLOCKED' if node['blocked'] else 'STOPPED' if node['stop_reason'] else campaign['state']
        note = '; '.join(node['blocked']) or node['stop_reason'] or '; '.join(dict.fromkeys(item['component'] + ': ' + item['code'] for item in node_items)) or 'No findings'
        rows.append(f'<tr><td class="target"><a href="#node-{i}" data-panel="node-{i}">{esc(node["key"])}</a><small>{esc(node["target"]["os_ip"])}</small></td><td>{badge(health_value)}</td><td>{badge(state)}</td><td>{node["completed"]}</td><td>{esc(note)}</td></tr>')
        choices.append(f'<a class="node-choice" href="#node-{i}" data-panel="node-{i}" data-health="{health_value}">{esc(node["key"])} {badge(health_value)}<small>{node["completed"]} loops</small></a>')
        records = record_html(node['pre'], i) + ''.join(record_html(r, i) for r in node['loops'])
        last = node['loops'][-1] if node['loops'] else node['pre']
        times = [r['duration_seconds'] for r in node['loops'] if r.get('post_complete') and r.get('duration_seconds') is not None]
        notice = f'<p class="notice">{esc("; ".join(node["blocked"]) or node["stop_reason"])}</p>' if node['blocked'] or node['stop_reason'] else ''
        panels.append(f'''<article class="node-panel" id="node-{i}" aria-labelledby="heading-node-{i}"><h2 id="heading-node-{i}">{esc(node['key'])} {badge(health_value)}</h2>{notice}{facts([('BMC', node['target']['bmc_ip']), ('OS', node['target']['os_ip']), ('Node elapsed (PRE to last POST)', duration(elapsed(node['pre']['started'], last.get('finished')))), ('Average completed loop', duration(sum(times) / len(times) if times else None))])}<h3>PRE and cycle history</h3><p class="muted">POST uses the original PRE baseline. PRE-EXISTING findings become KNOWN when repeated.</p>{records}</article>''')
    outcome = f'''<div class="sheet"><div class="outcome"><div><h2>Campaign outcome</h2><p>{esc(campaign.get('stop_reason') or 'Campaign is in progress.')}</p></div><div class="outcome-badges"><div><span class="label">Execution</span>{badge(result['completion'])}</div><div><span class="label">Health</span>{badge(result['health'])}</div></div></div>{facts([('Cycle / channel', f"{campaign['cycle_mode']} / {campaign['channel']}"), ('Requested limits', f"{campaign['limits']['loops'] or 'No'} loop limit / {campaign['limits']['hours'] or 'No'} hour limit"), ('Campaign elapsed', duration(elapsed(campaign['started'], campaign.get('finished') or now()))), ('Completed node-loops', result['completed_node_loops']), ('Selected / approved nodes', f"{len(nodes)} / {sum(not n['blocked'] for n in nodes)}"), ('PRE-existing issue groups', result['known']), ('New issue groups during cycling', result['new'])])}</div>'''
    overview = f'''<section role="tabpanel" id="overview" aria-labelledby="tab-overview">{outcome}<div class="sheet"><h2>Target results</h2><p class="muted">All selected nodes. Filters in other views do not change this overview.</p><div class="tablewrap"><table id="target-results"><thead><tr><th>Target / OS address</th><th>Health</th><th>Execution</th><th>Completed loops</th><th>Findings</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div><div class="sheet"><h2>Problems to review</h2><p>FAIL first, then WARN. Repeated findings are grouped within each node; KNOWN still affects health.</p>{issue_cards(items, indices)}</div></section>'''
    node_panel = f'''<section role="tabpanel" id="nodes" aria-labelledby="tab-nodes"><div class="sheet node-browser"><aside><h2>Find a node</h2><label for="node-search">Node name</label><input id="node-search" type="search" placeholder="Search nodes"><label for="node-health">Health</label><select id="node-health"><option value="">All nodes</option><option>FAIL</option><option>WARN</option><option>PASS</option></select><p id="node-count" aria-live="polite">{len(nodes)} nodes</p><nav class="node-list" aria-label="Select a node">{''.join(choices)}</nav></aside><div class="node-content">{''.join(panels)}</div></div></section>'''
    issues_panel = f'''<section role="tabpanel" id="issues" aria-labelledby="tab-issues"><div class="sheet"><h2>Issue review</h2><div class="filterbar"><label>Search node, component or finding<input id="issue-search" type="search" placeholder="Search issues"></label><label>Severity<select id="severity-filter"><option value="">All severities</option><option>FAIL</option><option>WARN</option></select></label><label>Classification<select id="class-filter"><option value="">Known and new</option><option>KNOWN</option><option>NEW</option></select></label></div><p id="issue-count" aria-live="polite">{len(items)} matching issues</p>{issue_cards(items, indices)}<p id="no-matches" hidden>No matching issues. Clear the filters to show all findings.</p></div></section>'''
    console_panel = f'''<details class="console-panel"><summary>Console log <span class="muted">{len(console_log.splitlines()) if console_log else 0} lines</span></summary><div class="console-tools"><label for="console-search">Search console log<input id="console-search" type="search" placeholder="Search console output"></label><button id="download-console" type="button">Download console.log</button></div><pre id="console-log">{esc(console_log) if console_log else 'Console log is not available for this report.'}</pre></details>'''
    overview = overview.replace('</section>', console_panel + '</section>', 1)
    css = (ASSETS / 'report.css').read_text(encoding='utf-8')
    js = (ASSETS / 'report.js').read_text(encoding='utf-8')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>{esc(campaign['run_id'])} | Cycle review</title><style>{css}</style></head><body>
    <a class="skip" href="#main">Skip to report</a>{'<div class="sample">SYNTHETIC DEMONSTRATION — no hardware was operated</div>' if campaign.get('synthetic') else ''}
    <div class="brandbar"><div class="brand">Wistron <small>System validation</small></div><span>Engineering / Cycle review</span></div><header><button id="print-report" class="print-button">Print report</button><h1>Cycle review</h1><div class="runline"><code>{esc(campaign['run_id'])}</code><span class="muted">Started {esc(campaign['started'])}</span></div><nav class="tabs" role="tablist" aria-label="Campaign views">{tab_html}</nav></header>
    <main id="main">{overview}{node_panel}{issues_panel}</main><footer><p>Generated {esc(now())}. Offline report. Keep this HTML with its evidence folders to use log links.</p><p>Hardware script SHA-256: <code>{esc(campaign['script_sha256'])}</code></p></footer><script>{js}</script></body></html>'''

def write_reports(root, campaign):
    root = Path(root)
    for node in campaign['nodes']:
        for record in [node['pre'], *node['loops']]:
            record['missing_evidence'] = [p for p in record['evidence'] if not (root / p).is_file()]
    result = status(campaign)
    # The journal is independent of HTML generation and is written first.
    write_json(root / "campaign.json", campaign)
    write_json(root / "cycle_summary.json", {**campaign, "summary": result})
    lines = [f"Run ID: {campaign['run_id']}", f"Execution: {result['completion']}", f"Health: {result['health']}",
             f"Requested limits: {campaign['limits']}", f"Completed node-loops: {result['completed_node_loops']}",
             f"Stop reason: {campaign.get('stop_reason', '')}", f"Unique issues: {len(result['issues'])}", f"Campaign elapsed: {duration(elapsed(campaign['started'], campaign.get('finished')))}"]
    for node in campaign['nodes']:
        node_lines = [f"Target: {node['key']}", f"Completed loops: {node['completed']}",
                      f"Blocked: {'; '.join(node['blocked']) or 'No'}", f"Stop reason: {node['stop_reason']}"]
        for record in [node['pre'], *node['loops']]:
            node_lines.append(f"{record['phase']}: {record['status']} ({len(record['issues'])} findings)")
        atomic_write(root / node['key'] / "node_summary.txt", '\n'.join(node_lines) + '\n')
        lines += node_lines
    atomic_write(root / "cycle_summary.txt", '\n'.join(lines) + '\n')
    atomic_write(root / "CYCLE_REVIEW_REPORT.md", '# Cycle review\n\n' + '\n\n'.join(lines) + '\n\nSee CYCLE_REVIEW_REPORT.html for expandable evidence and issue recurrence.\n')
    for classification in ('KNOWN', 'NEW'):
        markdown = [f"# {classification.title()} issues", "", "Classification does not change severity.", ""]
        for item in result['issues']:
            if item['classification'] != classification:
                continue
            markdown += [f"## {item['node']} / {item['code']} / {item['component']}", '',
                         f"Severity: {item['severity']}", '', item.get('known_reason', ''), '']
            for event in item['occurrences']:
                markdown.append(f"- {event['phase']}: {event['detail']} ({event['evidence'] or 'No evidence file'})")
            markdown.append('')
        atomic_write(root / (classification.lower() + '_issues.md'), '\n'.join(markdown) + '\n')
    console_path = root / "console.log"
    try:
        console_log = console_path.read_text(encoding='utf-8') if console_path.is_file() else ''
    except OSError:
        console_log = ''
    atomic_write(root / "CYCLE_REVIEW_REPORT.html", render_html(campaign, console_log))

def rebuild(root):
    root = Path(root)
    campaign = json.loads((root / 'campaign.json').read_text(encoding='utf-8'))
    for node in campaign['nodes']:
        pre_path = root / node['key'] / 'pre_report.json'
        if pre_path.exists():
            node['pre'] = json.loads(pre_path.read_text(encoding='utf-8'))
        node['loops'] = [json.loads(p.read_text(encoding='utf-8')) for p in sorted((root / node['key']).glob('loop*/report.json'))]
        node['completed'] = sum(r.get('post_complete', False) for r in node['loops'])
    if campaign['state'] == 'RUNNING':
        campaign.update(state='INCOMPLETE', finished=now(), stop_reason='Recovered journal; original process did not finalize this campaign')
    write_reports(root, campaign)
    return campaign
