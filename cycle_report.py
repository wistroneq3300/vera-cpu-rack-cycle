"""All report formats derive from the same records and evaluator."""
from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from cycle_core import aggregate_issues, atomic_write, health, now, write_json

ASSETS = Path(__file__).parent

def esc(value):
    return html.escape(str(value), quote=True)

def badge(value):
    return f'<span class="badge {esc(str(value).lower())}">{esc(value)}</span>'

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
    issues = ''.join(f'<li>{badge(i["severity"])} <strong>{esc(i["component"])}</strong> — {esc(i["detail"])} {badge(i.get("classification", "NEW"))}</li>' for i in record["issues"])
    evidence = ''.join(f'<li>{evidence_link(p)}</li>' for p in dict.fromkeys(record["evidence"]))
    action = ''
    if record['phase'] != 'PRE':
        rows = ''.join(f'<tr><td><code>{esc(a["command"])}</code></td><td>{esc(a["role"])}</td><td>{badge(a["state"])}</td><td>{esc(a["code"])}</td></tr>' for a in record['action'])
        action = '<h3>Cycle action and recovery</h3><div class="tablewrap"><table><thead><tr><th scope="col">Command</th><th scope="col">Channel endpoint</th><th scope="col">Result</th><th scope="col">Exit code</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
        recovery = record['recovery']
        action += facts([('OS boot changed', 'Yes' if recovery.get('boot_changed') else 'Not confirmed'), ('Recovery attempts', recovery.get('attempts', 'Not recorded')), ('Before boot ID', recovery.get('old_boot_id', 'Not recorded')), ('After boot ID', recovery.get('new_boot_id', 'Not recorded'))])
    identity = '<h3>Verified identities</h3><div class="tablewrap"><table><thead><tr><th scope="col">Endpoint</th><th scope="col">Hostname</th><th scope="col">Boot ID</th></tr></thead><tbody>' + ''.join(f'<tr><td>{esc(role.upper())}</td><td>{esc(values["hostname"])}</td><td><code>{esc(values.get("boot_id", "Not recorded"))}</code></td></tr>' for role, values in record['identities'].items()) + '</tbody></table></div>'
    return f'''<details id="{phase_id}"><summary><strong>{esc(record['phase'])}</strong> {badge(record['status'])}<span class="phase-count">{len(record['issues'])} findings · {esc(record.get('finished') or 'Not finished')}</span></summary><div class="detail-body">
      <ul class="record-issues">{issues}</ul>{'<p>No issues recorded.</p>' if not issues else ''}{action}{identity}
      <p class="muted">{esc(record.get('sel_review', ''))}</p><h3>Original evidence</h3><ul class="evidence-list">{evidence}</ul></div></details>'''

def render_html(campaign):
    result = status(campaign)
    nodes, items = campaign["nodes"], result["issues"]
    tabs = [('overview', 'Overview')] + [(f'node-{i}', n['key']) for i, n in enumerate(nodes)] + [('issues', f'Issues ({len(items)})')]
    tab_html = ''.join(f'<button id="tab-{key}" role="tab" aria-controls="{key}" aria-selected="{str(i == 0).lower()}" tabindex="{0 if i == 0 else -1}">{esc(label)}</button>' for i, (key, label) in enumerate(tabs))
    rows = []
    for i, node in enumerate(nodes):
        health_value = health([item for r in [node['pre'], *node['loops']] for item in r['issues']])
        state = 'BLOCKED' if node['blocked'] else 'STOPPED' if node['stop_reason'] else campaign['state']
        rows.append(f'<tr><td class="target"><a href="#node-{i}" data-panel="node-{i}">{esc(node["key"])}</a><small>{esc(node["target"]["os_ip"])}</small></td><td>{badge(health_value)}</td><td>{badge(state)}</td><td>{node["completed"]}</td><td>{esc("; ".join(node["blocked"]) or node["stop_reason"] or "See node detail")}</td></tr>')
    outcome = f'''<div class="sheet"><div class="outcome"><div><h2>Campaign outcome</h2><p class="muted">{esc(campaign.get('stop_reason') or 'Campaign is in progress.')}</p></div><div class="outcome-badges"><div><span class="label">Execution</span>{badge(result['completion'])}</div><div><span class="label">Health</span>{badge(result['health'])}</div></div></div>
      {facts([('Requested limits', f"{campaign['limits']['loops'] or 'No'} loop limit / {campaign['limits']['hours'] or 'No'} hour limit"), ('Completed node-loops', result['completed_node_loops']), ('Selected / approved nodes', f"{len(nodes)} / {sum(not n['blocked'] for n in nodes)}"), ('Known / new issues', f"{result['known']} / {result['new']}"), ('Mode / channel', f"{campaign['cycle_mode']} / {campaign['channel']}"), ('Finished', campaign.get('finished') or 'In progress')])}</div>'''
    overview = f'''<section role="tabpanel" id="overview" aria-labelledby="tab-overview">{outcome}<div class="sheet"><h2>Target results</h2><div class="tablewrap"><table><thead><tr><th scope="col">Target / OS address</th><th scope="col">Health</th><th scope="col">Execution</th><th scope="col">Completed loops</th><th scope="col">Notes</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div><div class="sheet"><h2>Review priorities</h2><p>{len(items)} unique issues. Repeated findings are grouped by node, code and component. Known issues still contribute to FAIL.</p><p><a href="#issues" data-panel="issues">Review all issues and occurrences</a></p><p class="muted">BMC event correctness requires manual review. Each node includes cumulative SEL and per-loop deltas. Firmware versions are recorded as evidence.</p></div></section>'''
    panels = []
    for i, node in enumerate(nodes):
        notice = f'<p class="notice">{esc("; ".join(node["blocked"]) or node["stop_reason"])}</p>' if node['blocked'] or node['stop_reason'] else ''
        records = record_html(node['pre'], i) + ''.join(record_html(r, i) for r in node['loops'])
        panels.append(f'''<section role="tabpanel" id="node-{i}" aria-labelledby="tab-node-{i}"><div class="sheet"><h2>{esc(node['key'])}</h2><p class="muted">Every POST compares with this campaign's original PRE.</p>{notice}{facts([('BMC', node['target']['bmc_ip']), ('OS', node['target']['os_ip']), ('Expected OS hostname', node['target']['os_hostname']), ('Completed loops', node['completed'])])}</div><div class="sheet"><h2>PRE and cycle history</h2>{records}</div></section>''')
    issue_rows = []
    indices = {n['key']: i for i, n in enumerate(nodes)}
    for item in sorted(items, key=lambda x: (x['severity'] != 'FAIL', x['classification'] != 'NEW', x['node'], x['code'])):
        occurrences = []
        for event in item['occurrences']:
            i = indices[item['node']]
            phase_id = f"node-{i}-" + ('pre' if event['phase'] == 'PRE' else 'loop-' + event['phase'].split()[-1])
            occurrences.append(f'<tr><td><a href="#{phase_id}" data-panel="node-{i}">{esc(event["phase"])}</a></td><td>{esc(event["detail"])}</td><td>{evidence_link(event["evidence"])}</td></tr>')
        issue_rows.append(f'''<details class="issue-row" data-severity="{esc(item['severity'])}" data-classification="{esc(item['classification'])}"><summary>{badge(item['severity'])}<span class="issue-title">{esc(item['node'])} / {esc(item['component'])}</span> {badge(item['classification'])}<span class="issue-meta">{esc(item['code'])} · {len(item['occurrences'])} finding(s)</span></summary><div class="detail-body"><p>{esc(item['detail'])}</p><p class="muted">{esc(item.get('known_reason',''))}</p><div class="tablewrap"><table><thead><tr><th scope="col">Phase</th><th scope="col">Finding</th><th scope="col">Evidence</th></tr></thead><tbody>{''.join(occurrences)}</tbody></table></div></div></details>''')
    issues_panel = f'''<section role="tabpanel" id="issues" aria-labelledby="tab-issues"><div class="sheet"><h2>Issue review</h2><div class="filterbar"><label>Search node, component or finding<input id="issue-search" type="search" placeholder="Search issues"></label><label>Severity<select id="severity-filter"><option value="">All severities</option><option>FAIL</option><option>WARN</option></select></label><label>Classification<select id="class-filter"><option value="">Known and new</option><option>KNOWN</option><option>NEW</option></select></label></div><p id="issue-count" aria-live="polite" class="muted">{len(items)} matching issues</p>{''.join(issue_rows)}<p id="no-matches" class="empty" {'hidden' if items else ''}>No matching issues. Clear the filters to show all findings.</p></div></section>'''
    css = (ASSETS / 'report.css').read_text(encoding='utf-8')
    js = (ASSETS / 'report.js').read_text(encoding='utf-8')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>{esc(campaign['run_id'])} | Cycle review</title><style>{css}</style></head><body>
    <a class="skip" href="#main">Skip to report</a>{'<div class="sample">SYNTHETIC DEMONSTRATION — no hardware was operated</div>' if campaign.get('synthetic') else ''}
    <div class="brandbar"><div class="brand">Wistron <small>Vera CPU Rack</small></div><span>Engineering validation / Cycle review</span></div><header><button id="print-report" class="print-button">Print report</button><h1>Cycle review</h1><div class="runline"><code>{esc(campaign['run_id'])}</code><span class="muted">Started {esc(campaign['started'])}</span></div><nav class="tabs" role="tablist" aria-label="Campaign views">{tab_html}</nav></header>
    <main id="main">{overview}{''.join(panels)}{issues_panel}</main><footer><p>Generated {esc(now())}. Offline report. Keep this HTML with its evidence folders to use log links.</p><p>Hardware script SHA-256: <code>{esc(campaign['script_sha256'])}</code></p></footer><script>{js}</script></body></html>'''

def write_reports(root, campaign):
    root = Path(root)
    result = status(campaign)
    # The journal is independent of HTML generation and is written first.
    write_json(root / "campaign.json", campaign)
    write_json(root / "cycle_summary.json", {**campaign, "summary": result})
    lines = [f"Run ID: {campaign['run_id']}", f"Execution: {result['completion']}", f"Health: {result['health']}",
             f"Requested limits: {campaign['limits']}", f"Completed node-loops: {result['completed_node_loops']}",
             f"Stop reason: {campaign.get('stop_reason', '')}", f"Unique issues: {len(result['issues'])}"]
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
    atomic_write(root / "CYCLE_REVIEW_REPORT.html", render_html(campaign))

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
