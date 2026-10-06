"""All report formats derive from the same records and evaluator."""
from __future__ import annotations

from datetime import datetime
import copy
import html
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from cycle_core import aggregate_issues, atomic_write, health, now, write_json
from cycle_storage import report_writer_lock, reject_live_rebuild

ASSETS = Path(__file__).parent


def _wistron_logo():
    """Return the official two-colour Wistron wordmark for the self-contained report."""
    try:
        svg = (ASSETS / 'wistron-logo.svg').read_text(encoding='utf-8')
    except OSError:
        return '<span class="brand-fallback">Wistron</span>'
    # The XML declaration/doctype are valid as a file but not inside an HTML body.
    svg = re.sub(r'<\?xml[^>]*\?>|<!DOCTYPE[^>]*>', '', svg, flags=re.I)
    return f'<span class="brand-mark" role="img" aria-label="Wistron">{svg}</span>'

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
            "worsened": sum(i["classification"] == "WORSENED" for i in items),
            "attempted_node_loops": sum(n.get("attempts", len(n["loops"])) for n in campaign["nodes"]),
            "valid_node_cycles": sum(n.get("valid_cycles", 0) for n in campaign["nodes"]),
            "boot_confirmed_node_loops": sum(n.get("boot_confirmed", 0) for n in campaign["nodes"]),
            "completed_node_loops": sum(n["completed"] for n in campaign["nodes"]),
            "issues": items}

def facts(pairs):
    return '<dl class="facts">' + ''.join(f'<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>' for k, v in pairs) + '</dl>'

def _record_evidence(record, path):
    if not path:
        return '<span class="muted">Not retained</span>'
    if path in record.get('missing_evidence', []):
        return badge('MISSING') + ' ' + esc(path)
    return evidence_link(path)


def _issue_counts(record):
    severity = Counter(i.get('severity', 'UNKNOWN') for i in record.get('issues', []))
    classification = Counter(i.get('classification', 'NEW') for i in record.get('issues', [])
                             if record.get('phase') != 'PRE')
    return severity, classification


def _finding_summary(record):
    severity, classification = _issue_counts(record)
    parts = [f'{severity.get("FAIL", 0)} FAIL', f'{severity.get("WARN", 0)} WARN']
    if record.get('phase') == 'PRE':
        parts.append(f'{len(record.get("issues", []))} PRE baseline finding(s)')
    else:
        parts.append(' / '.join(f'{classification.get(k, 0)} {k}' for k in ('KNOWN', 'NEW', 'WORSENED')))
    return ' · '.join(parts)


def _finding_html(record):
    if not record.get('issues'):
        return '<p class="empty">No issues recorded.</p>'
    rows = []
    for item in record['issues']:
        classification = 'PRE-EXISTING' if record.get('phase') == 'PRE' else item.get('classification', 'NEW')
        snippet = ''
        if item.get('snippet'):
            raw = f'<pre class="snippet">{esc(item["snippet"])}</pre>'
            if classification == 'KNOWN' and item.get('severity') != 'FAIL':
                snippet = f'<details class="known-raw"><summary>Raw snippet</summary>{raw}</details>'
            else:
                snippet = raw
        rows.append(f'<li>{badge(item.get("severity", "UNKNOWN"))} <strong>{esc(item.get("component", "unknown"))}</strong> — {esc(item.get("detail", ""))} {badge(classification)}{snippet}</li>')
    return '<ul class="record-issues">' + ''.join(rows) + '</ul>'


def _status_from_items(items, kind):
    statuses = [str(item.get('status', 'UNKNOWN')).upper() for item in items]
    if any(value in {'FAIL', 'BLOCKED'} for value in statuses):
        return 'FAIL'
    if any(value in {'UNKNOWN', 'UNAVAILABLE'} for value in statuses):
        return 'UNKNOWN'
    if any(value == 'WARN' for value in statuses):
        return 'WARN'
    if not statuses:
        return 'NOT RECORDED'
    if kind == 'evidence':
        return 'COLLECTED'
    if all(value in {'N/A', 'UNSUPPORTED'} for value in statuses):
        return 'N/A'
    return 'PASS'


_LABELS = {
    'CPU': 'CPU topology', 'CPU_ONLINE': 'CPU Online', 'DIMM': 'DIMM count',
    'MEMORY_VISIBLE': 'Memory visible to OS', 'NVMe': 'NVMe validation',
    'NIC': 'NIC validation', 'NIC_DEGRADED': 'NIC degraded (device type mismatch)',
    'NIC_MISSING': 'NIC removed (present at PRE, absent after loop)',
    'NIC_SLOT': 'NIC slot inventory',
    'BF4': 'BF4 validation', 'BF4_IDENTITIES': 'BF4 identities',
    'PCI': 'PCI inventory', 'PCIe': 'PCIe validation', 'PCIeFAB': 'PCIeFAB bridge inventory', 'sensor': 'Sensors',
    'dmesg': 'dmesg observations', 'sel': 'SEL collection', 'sel_before': 'Before-cycle SEL collection',
    'start_sel_clear': 'START SEL clear', 'start_dmesg_clear': 'START dmesg clear', 'failure_sel': 'Failure-path SEL collection',
    'hardware': 'Hardware script execution',
    'pci': 'PCI raw inventory', 'pci_tree': 'PCI topology raw', 'pci_verbose': 'PCI verbose raw',
    'pci_config': 'PCI config-space raw', 'disks': 'Block devices raw', 'nvme': 'NVMe command output',
    'usb': 'USB command output', 'memory': 'Memory command output', 'network': 'Network command output',
    'firmware': 'Firmware command output', 'system': 'System command output',
    'identity': 'Endpoint identity', 'root_uid': 'Root privilege', 'dependencies': 'OS dependencies',
    'package_install': 'Dependency installation', 'dependencies_after_install': 'Dependency recheck',
    'mst_available': 'MST availability', 'script_safety': 'Script safety', 'script_sha256': 'SHA verification',
    'cycle_command': 'Cycle command', 'power': 'Chassis power', 'host_power': 'Host power state',
    'bmc_firmware': 'BMC firmware', 'recovery': 'Boot recovery',
}


def _check_label(key):
    base = key.split('/', 1)[0]
    return _LABELS.get(key, _LABELS.get(base, key))


def _hardware_detail(record, key):
    detail = record.get('hardware_check_details', {}).get(key, {})
    values = detail.get('values', {})
    if not values:
        return ''
    display = []
    preferred = ('actual', 'minimum', 'exact', 'logical', 'online', 'sockets', 'row_errors', 'missing_socket', 'state')
    seen = set()
    for name in preferred:
        if name in values:
            display.append(f'{name}={values[name]}')
            seen.add(name)
    for name, value in values.items():
        if name not in seen:
            display.append(f'{name}={value}')
    text = ' · '.join(display)
    # Surface per-slot NIC findings that the issue records captured but the
    # count-only check values do not. A slot whose MST DEVICE_TYPE is not Vera
    # (e.g. NA) is a degraded card, not a removed one, and must be labelled
    # separately so the report never claims lspci-visible hardware vanished.
    if key in {'NIC', 'NIC_DEGRADED', 'NIC_MISSING'}:
        summary = _nic_slot_summary(record)
        if summary:
            text += f' · {summary}'
    return text


def _nic_slot_summary(record):
    """Summarise the NIC slots called out by the issue records.

    The slot BDF is the upstream root port (a PCI bridge), not the card, so the
    summary names the downstream NIC and its MST device to avoid reading as a
    missing first-level bridge. Returns e.g.
    'degraded slot 0002:00:00.0 (root port -> downstream Vera NIC, MST device
    mt12184_pciconf0, DEVICE_TYPE=NA)' and, separately, 'missing slot <bdf>' for
    genuinely absent cards. Empty string when no issue carries slot information.
    """
    import re as _re
    degraded, missing = [], []
    for item in record.get('issues', []):
        if item.get('component') != 'NIC':
            continue
        if item.get('code') not in {'DEVICE_MISSING', 'NIC_DEGRADED', 'NIC_MISSING'}:
            continue
        blob = ' '.join(str(item.get(field, '')) for field in ('snippet', 'detail'))
        dev = _re.search(r'MST device (\S+?)[\)\s]', blob)
        dtype = _re.search(r"DEVICE_TYPE='?([A-Za-z0-9_-]+)'?", blob)
        for bdf in _re.findall(r'degraded slot ([0-9a-fA-F:.]+)', blob):
            annot = 'root port -> downstream Vera NIC'
            if dev:
                annot += f', MST device {dev.group(1)}'
            if dtype:
                annot += f', DEVICE_TYPE={dtype.group(1)}'
            entry = f'{bdf} ({annot})'
            if entry not in degraded:
                degraded.append(entry)
        for bdf in _re.findall(r'missing slot ([0-9a-fA-F:.]+)', blob):
            if bdf not in missing:
                missing.append(bdf)
    parts = []
    if degraded:
        parts.append('degraded slot ' + '; '.join(degraded))
    if missing:
        parts.append('missing slot ' + ', '.join(missing))
    return ' · '.join(parts)


def _missing_nic_slots(record):
    """Backwards-compatible accessor: return the comma-separated list of NIC
    PCI slot BDFs that were absent in this loop, parsed from the issue
    snippet. Empty string if no issue carries slot information."""
    return ''


def _pci_devices(record):
    devices = record.get('pci_devices') or {}
    if not devices:
        devices = record.get('pci') or {}
    rows = []
    for bdf, value in sorted(devices.items()):
        item = dict(value)
        item['bdf'] = bdf
        raw = str(item.get('raw', '')).lower()
        if (str(item.get('class_id', '')).startswith('06') or
                'bridge' in str(item.get('class_name', '')).lower() or ' bridge ' in raw):
            continue
        rows.append(item)
    return rows


def _phase_kind(record):
    """Normalize phase names for rendering without changing their stored text."""
    phase = str(record.get('phase', '')).strip()
    upper = phase.upper()
    if upper == 'PRE':
        return 'PRE'
    if upper == 'START':
        return 'START'
    if re.fullmatch(r'LOOP(?:\s+\d+)?', phase, re.I) or record.get('loop') is not None:
        return 'LOOP'
    return upper or 'UNKNOWN'


def _loop_number(record):
    value = record.get('loop')
    if value is not None:
        return str(value)
    match = re.fullmatch(r'LOOP\s+(\d+)', str(record.get('phase', '')).strip(), re.I)
    return match.group(1) if match else ''


def _is_pci_device_check(key):
    return bool(re.match(r'^(?:PCIE_LINK|PCIE_DOWNGRADE)/[^/]+$', str(key), re.I))


def _pci_hardware_results(record):
    """Return saved hardware-script PCIe results keyed by full BDF.

    ``hardware_checks`` is authoritative for the script result, while
    ``check_summary`` is accepted for recovered/legacy records that only kept
    the flattened summary.  The original keys and raw details remain available
    to the renderer so a capture disagreement is visible.
    """
    results = {}
    hardware_checks = record.get('hardware_checks') or {}
    details = record.get('hardware_check_details') or {}
    for source_name, mapping in (('hardware_checks', hardware_checks),
                                 ('check_summary', record.get('check_summary') or {})):
        for key, state in mapping.items():
            match = re.match(r'^(PCIE_LINK|PCIE_DOWNGRADE)/(.+)$', str(key), re.I)
            if not match:
                continue
            if source_name == 'check_summary' and key in hardware_checks:
                continue
            bdf = match.group(2)
            normalized = str(state or 'UNKNOWN').upper()
            entry = results.setdefault(bdf, {'states': [], 'keys': [], 'details': []})
            entry['states'].append(normalized)
            entry['keys'].append(str(key))
            detail = details.get(key) or {}
            raw = detail.get('raw') if isinstance(detail, dict) else ''
            if raw:
                entry['details'].append(str(raw))
    return results


def _pci_effective_result(item, hardware):
    parser_result = str(item.get('link_result') or 'UNKNOWN').upper()
    entry = hardware.get(item.get('bdf'))
    if not entry:
        return parser_result, item.get('link_reason') or 'No link applicability reason was recorded', ''
    states = entry['states']
    # Keep a failure from either saved source visible.  Otherwise the formal
    # hardware check wins over a parser-only unknown/N/A classification.
    if 'FAIL' in states or parser_result == 'FAIL':
        effective = 'FAIL'
    elif 'WARN' in states or parser_result == 'WARN':
        effective = 'WARN'
    else:
        effective = states[0] if states else parser_result
    source_summary = '; '.join(f'{key}={state}' for key, state in zip(entry['keys'], states))
    if parser_result != effective or len(set(states + [parser_result])) > 1:
        note = f'Parsed lspci={parser_result}; hardware script={source_summary}; captures differ and are both retained.'
    else:
        note = f'Hardware script={source_summary}'
    reason = item.get('link_reason') or 'No link applicability reason was recorded'
    return effective, f'{reason}; {note}', note


def _pci_summary(record):
    devices = _pci_devices(record)
    hardware = _pci_hardware_results(record)
    by_bdf = {item.get('bdf'): item for item in devices}
    # A saved per-BDF hardware result without a retained lspci row is still a
    # measured endpoint result, and must not disappear from the group summary.
    for bdf in sorted(set(hardware) - set(by_bdf)):
        item = dict(bdf=bdf, device_name=bdf, class_name='PCIe endpoint',
                    link_result='UNKNOWN', link_reason='Hardware script result has no matching saved PCI inventory row')
        devices.append(item)
        by_bdf[bdf] = item
    for item in devices:
        effective, reason, source_note = _pci_effective_result(item, hardware)
        item['_effective_link_result'] = effective
        item['_effective_link_reason'] = reason
        item['_source_note'] = source_note
    counts = Counter(str(item.get('_effective_link_result', 'UNKNOWN')).upper() for item in devices)
    evaluated = sum(counts.get(name, 0) for name in ('PASS', 'FAIL', 'WARN'))
    command = record.get('commands', {}).get('pci', {})
    if counts.get('FAIL') or (not devices and command and not command.get('valid', False)):
        status = 'FAIL'
    elif counts.get('WARN'):
        status = 'WARN'
    elif counts.get('UNKNOWN'):
        status = 'UNKNOWN'
    elif evaluated == 0 and (counts.get('N/A') or counts.get('UNSUPPORTED')):
        status = 'N/A'
    elif evaluated:
        status = 'PASS'
    else:
        status = 'UNKNOWN'
    return devices, counts, evaluated, status


def _pci_class(item):
    class_name = str(item.get('class_name') or '').strip()
    class_id = str(item.get('class_id') or '').lower()
    if class_id.startswith('0108') or 'non-volatile memory' in class_name.lower():
        return 'NVMe controller'
    if class_id.startswith('0c03') or 'usb' in class_name.lower():
        return 'USB controller'
    if class_id.startswith('0300') or 'vga' in class_name.lower() or 'display' in class_name.lower():
        return 'VGA / display controller'
    if class_id.startswith('0200') or 'ethernet' in class_name.lower() or 'network' in class_name.lower():
        return 'NIC / network controller'
    return class_name or 'Unknown PCI function'


def _pci_link_evidence(record):
    commands = record.get('commands', {})
    # ``hardware.txt`` carries the full ``lspci`` text; ``pci_verbose.txt`` is
    # narrowed to end devices and ``pci`` is the one-line inventory. Prefer the
    # complete capture, then fall back to whichever narrower file exists.
    paths = [commands.get(name, {}).get('evidence', '') for name in ('hardware', 'pci_verbose', 'pci')]
    return [path for path in paths if path]


def _render_pci_group(record, baseline=None):
    devices, counts, evaluated, result = _pci_summary(record)
    command = record.get('commands', {}).get('pci', {})
    baseline_devices = {item.get('bdf'): item for item in _pci_devices(baseline or {})}
    na_count = counts.get('N/A', 0) + counts.get('UNSUPPORTED', 0)
    summary = (f'{len(devices)} device item(s) · evaluated={evaluated} · '
               f'N/A={na_count} · UNKNOWN={counts.get("UNKNOWN", 0)}; '
               'counts are PCI functions, not physical cards')
    if not devices:
        if command and not command.get('valid', False):
            body = '<p>PCI inventory collection failed; no endpoint list is asserted. Check the command evidence and collection failure.</p>'
        elif command:
            body = '<p>No end-device rows were retained. This is not a PASS result.</p>'
        else:
            body = '<p>PCI end-device data was not collected in this phase.</p>'
        return f'<details class="pci-device-group"><summary><strong>PCI / PCIe End Devices</strong> {badge(result)}<span class="summary-meta">{esc(summary)}</span></summary><div class="detail-body"><h3>PCIe Endpoint Link Validation</h3>{body}</div></details>'
    rows = []
    for item in devices:
        bdf = item.get('bdf', '')
        pre = baseline_devices.get(bdf, {})
        current = item.get('link_current') or 'Not reported'
        capability = item.get('link_capability') or 'Not reported'
        pre_link = pre.get('link_current') or ('Not recorded' if pre else 'No PRE row')
        expected = 'Not configured'
        status_value = str(item.get('_effective_link_result') or item.get('link_result') or 'UNKNOWN').upper()
        reason = item.get('_effective_link_reason') or item.get('link_reason') or 'No link applicability reason was recorded'
        evidence = ' · '.join(_record_evidence(record, path) for path in _pci_link_evidence(record))
        raw_name = item.get('raw_name') or item.get('raw') or ''
        raw_name_html = f'<small class="raw-key">Raw name: {esc(raw_name)}</small>' if raw_name and raw_name != item.get('device_name') else ''
        rows.append(f'''<tr><td><strong>{esc(item.get('device_name') or raw_name or bdf)}</strong><small>{esc(_pci_class(item))}</small>{raw_name_html}<small class="raw-key">Vendor/Device ID: {esc(item.get('id', 'UNKNOWN'))}</small></td><td><code>{esc(bdf)}</code></td><td>{esc(item.get('pcie_type') or 'Not reported')}</td><td><strong>Current:</strong> {esc(current)}<br><strong>Capability:</strong> {esc(capability)}<br><strong>PRE:</strong> {esc(pre_link)}<br><strong>Expected:</strong> {esc(expected)}</td><td>{badge(status_value)}<br><span class="muted">{esc(reason)}</span></td><td>{evidence or '<span class="muted">Not retained</span>'}</td></tr>''')
    bridge_note = ''
    if 'PCIeFAB' in record.get('hardware_checks', {}) or 'PCIeFAB' in record.get('check_summary', {}):
        bridge_note = '<p class="muted">PCIeFAB is shown separately as bridge inventory/count evidence. It is not an assertion that every bridge link was validated, and bridges are excluded from this end-device count.</p>'
    return f'''<details class="pci-device-group"><summary><strong>PCI / PCIe End Devices</strong> {badge(result)}<span class="summary-meta">{esc(summary)}</span></summary><div class="detail-body"><h3>PCIe Endpoint Link Validation</h3><p class="muted">Device rows come from this node and run's saved lspci records. Link expectations are not inferred from LnkCap; no project target is configured here.</p><div class="tablewrap"><table><thead><tr><th>Device / class</th><th>Full BDF</th><th>PCIe type / applicability</th><th>Link data</th><th>Result / reason</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>{bridge_note}</div></details>'''


def _summary_groups(record):
    groups = {'hardware': [], 'evidence': [], 'execution': [], 'other': []}
    hardware_keys = set(record.get('hardware_checks', {}))
    collection_keys = {'pci', 'pci_tree', 'pci_verbose', 'pci_config', 'disks', 'nvme', 'usb', 'memory', 'network', 'firmware', 'system', 'sel', 'sel_before', 'failure_sel'}
    execution_keys = {'root_uid', 'dependencies', 'package_install', 'dependencies_after_install', 'mst_available', 'script_safety', 'script_sha256', 'hardware', 'cycle_command', 'power', 'host_power', 'bmc_firmware'}
    for key, value in record.get('check_summary', {}).items():
        if _is_pci_device_check(key):
            # Per-BDF rows are rendered in the PCI / PCIe End Devices group.
            # Keep the JSON key intact, but do not show the same finding twice
            # in the general Hardware validation table.
            continue
        if key in hardware_keys or key.split('/', 1)[0] in {'CPU', 'CPU_ONLINE', 'DIMM', 'MEMORY_VISIBLE', 'NVMe', 'NIC', 'BF4', 'BF4_IDENTITIES', 'PCIe', 'PCIeFAB', 'PCIE_LINK', 'PCIE_DOWNGRADE', 'sensor', 'dmesg'}:
            group = 'hardware'
        elif key in collection_keys:
            group = 'evidence'
        elif key in execution_keys or key.startswith('start_') or key.endswith('_identity') or key == 'recovery':
            group = 'execution'
        else:
            group = 'other'
        command = record.get('commands', {}).get(key, {})
        detail = _hardware_detail(record, key)
        evidence = command.get('evidence', '')
        if not evidence:
            # These sub-checks have no command of their own but do have a
            # retained artefact: hardware-script checks live in the phase's
            # hardware.txt, dmesg observations in the phase's dmesg capture.
            if key == 'dmesg':
                evidence = (record.get('commands', {}).get('dmesg_clear', {}).get('evidence')
                            or record.get('commands', {}).get('pre_dmesg_clear', {}).get('evidence', ''))
            elif key in record.get('hardware_checks', {}):
                evidence = record.get('commands', {}).get('hardware', {}).get('evidence', '')
        if key == 'hardware' and any('BF4' in str(item.get('code', '')).upper() and item.get('severity') == 'FAIL'
                                    for item in record.get('issues', [])):
            detail = 'Cause: BF4 missing; see BF4 validation for the measured source counts'
        groups[group].append(dict(key=key, label=_check_label(key), status=value,
                                  detail=detail,
                                  evidence=evidence, raw_key=key))
    pci_command = record.get('commands', {}).get('pci', {})
    pci = record.get('pci') or {}
    if pci_command or pci:
        groups['hardware'].append(dict(key='PCI inventory', label='PCI functions',
                                       status='PASS' if pci else 'FAIL',
                                       detail=f'{len(pci)} PCI function(s); bridges are inventory only, not end-device link validation',
                                       evidence=pci_command.get('evidence', ''), raw_key='pci'))
    devices, counts, evaluated, pci_status = _pci_summary(record)
    if devices or pci_command:
        groups['hardware'].append(dict(key='PCIe End Devices', label='PCIe End Devices', status=pci_status,
                                       detail=f'{len(devices)} device item(s) · evaluated={evaluated} · N/A={counts.get("N/A", 0) + counts.get("UNSUPPORTED", 0)} · UNKNOWN={counts.get("UNKNOWN", 0)}',
                                       evidence=record.get('commands', {}).get('pci_verbose', {}).get('evidence', ''), raw_key='PCIe End Devices'))
    return groups


def _render_summary_groups(record):
    labels = {'hardware': 'Hardware validation', 'evidence': 'Evidence collection', 'execution': 'Execution / safety', 'other': 'Other / technical details'}
    html_groups = []
    groups = _summary_groups(record)
    for key in ('hardware', 'evidence', 'execution', 'other'):
        items = groups[key]
        if not items:
            continue
        status = _status_from_items(items, key)
        rows = ''.join(f'<tr><td><strong>{esc(item["label"])}</strong><small class="raw-key">{esc(item["raw_key"])}</small></td><td>{badge(item["status"])}</td><td>{esc(item["detail"] or "—")}</td><td>{_record_evidence(record, item["evidence"])}</td></tr>' for item in items)
        html_groups.append(f'<details class="summary-group"{" open" if key in {"hardware", "execution"} else ""}><summary><span>{labels[key]}</span> {badge(status)}<span class="summary-meta">{len(items)} item(s)</span></summary><div class="tablewrap"><table><thead><tr><th>Check</th><th>Result</th><th>Measured detail</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></div></details>')
    return '<div class="summary-groups">' + ''.join(html_groups) + '</div>'


def _render_action(record):
    phase = _phase_kind(record)
    if phase == 'START':
        rows = []
        for name, command in record.get('commands', {}).items():
            if name.startswith('start_'):
                rows.append(f'<tr><td><code>{esc(name)}</code></td><td>{badge("SUCCEEDED" if command.get("valid") else "FAILED")}</td><td>{esc(command.get("state", "UNKNOWN"))}</td><td>{_record_evidence(record, command.get("evidence", ""))}</td></tr>')
        note = 'START only re-verifies identity; log clearing (dmesg / IPMI SEL / Redfish) already ran in PRE.'
        if not rows:
            return f'<h3>START preparation</h3><p class="muted">{esc(note)} No temporary clearing is performed here.</p>'
        return f'<h3>START preparation</h3><p class="muted">{esc(note)}</p><div class="tablewrap"><table><thead><tr><th>Command</th><th>Result</th><th>Transport</th><th>Evidence</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'
    if phase != 'LOOP':
        return ''
    rows = ''.join(f'<tr><td><code>{esc(a.get("command", ""))}</code></td><td>{esc(a.get("role", ""))}</td><td>{badge(a.get("state", "UNKNOWN"))}</td><td>{esc(a.get("code", ""))}</td></tr>' for a in record.get('action', []))
    recovery = record.get('recovery') or {}
    action = '<h3>Cycle action and recovery</h3><div class="tablewrap"><table><thead><tr><th>Command</th><th>Channel endpoint</th><th>Result</th><th>Exit code</th></tr></thead><tbody>' + (rows or '<tr><td colspan="4">No cycle action was dispatched.</td></tr>') + '</tbody></table></div>'
    action += facts([('OS boot changed', 'Yes' if recovery.get('boot_changed') else 'No / not confirmed'), ('Recovery attempts', recovery.get('attempts', 'Not recorded')), ('Before boot ID', recovery.get('old_boot_id', 'Not recorded')), ('After boot ID', recovery.get('new_boot_id', 'Not recorded'))])
    return action


def _render_redfish(record):
    """Render the Redfish EventLog/SEL collection panel (one block per service).

    Severity is colour-tagged in the entry list; the verdict (worst severity)
    is shown as a badge. An absent service means a merged vendor layout, not a
    failure, and is labelled as such.
    """
    blocks = []
    for stem, label in (('eventlog', 'Redfish EventLog'), ('redfish_sel', 'Redfish SEL')):
        meta = record.get(f'{stem}_meta')
        if not meta:
            continue
        if meta.get('present') is False:
            blocks.append(f'<div class="sel-panel"><h3>{label}</h3><p>Not present on this BMC: '
                          f'{esc(meta.get("reason", "merged into EventLog"))}</p></div>')
            continue
        if meta.get('present') is None:
            # Discovery failed: we do not know whether this service exists.
            blocks.append(f'<div class="sel-panel"><h3>{label}</h3><p>Service status {badge("UNAVAILABLE")} · '
                          f'Discovery failed, cannot confirm presence · {esc(meta.get("reason", ""))}</p></div>')
            continue
        if meta.get('status') != 'COLLECTED':
            ev = _record_evidence(record, meta.get('evidence'))
            blocks.append(f'<div class="sel-panel"><h3>{label}</h3><p>Collection: {badge("COLLECTION FAILED")} · '
                          f'{esc(meta.get("reason", ""))} · Evidence: {ev}</p></div>')
            continue
        verdict = meta.get('verdict', 'PASS')
        counts = meta.get('counts', {})
        summary = (f'Collection: {badge("PASS")} · Verdict: {badge(verdict)} · '
                   f'Critical: {esc(counts.get("Critical", 0))} · Warning: {esc(counts.get("Warning", 0))} · '
                   f'OK: {esc(counts.get("OK", 0))}')
        entries = meta.get('entries') or []
        rows = ''
        for entry in entries:
            sev = (entry.get('severity') or '').strip()
            cls = 'badge' + (' fail' if sev.lower() == 'critical' else ' warn' if sev.lower() == 'warning' else '')
            rows += (f'<tr><td>{esc(entry.get("id", ""))}</td><td><span class="{cls}">{esc(sev or "--")}</span></td>'
                     f'<td>{esc(entry.get("created", ""))}</td><td>{esc(entry.get("message", ""))}</td></tr>')
        table = ('<div class="tablewrap"><table><thead><tr><th>ID</th><th>Severity</th><th>Created</th>'
                 '<th>Message</th></tr></thead><tbody>' + (rows or '<tr><td colspan="4">No entries.</td></tr>') +
                 '</tbody></table></div>')
        delta = meta.get('delta')
        delta_line = ''
        if delta:
            if delta.get('status') == 'COMPARED':
                delta_line = f'<p><strong>New this loop: {esc(delta.get("new_count", 0))}</strong></p>'
                new_rows = ''.join(f'<li><code>{esc(e.get("id",""))} | {esc(e.get("severity",""))} | {esc(e.get("message",""))}</code></li>'
                                   for e in (delta.get('new_entries') or []))
                if new_rows:
                    delta_line += f'<details><summary>New entries ({len(delta.get("new_entries") or [])})</summary><ul>{new_rows}</ul></details>'
            else:
                delta_line = f'<p>Delta: UNAVAILABLE · {esc(delta.get("reason", ""))}</p>'
        ev = _record_evidence(record, meta.get('evidence'))
        blocks.append(f'<div class="sel-panel"><h3>{label}</h3><p>{summary} · Evidence: {ev}</p>'
                      f'{delta_line}{table}<p class="muted">Collection success is not a hardware verdict; '
                      f'only Critical/Warning severities are flagged, benign entries are listed for review.</p></div>')
    return ''.join(blocks)

def _render_sel(record):
    phase = _phase_kind(record)
    if phase == 'PRE':
        meta = record.get('sel_collection')
        if meta:
            count = meta.get('event_count') if meta.get('valid') else '--'
            snapshot = _record_evidence(record, meta.get('evidence'))
            return f'<div class="sel-panel"><h3>PRE SEL collection</h3><p>Collection: {badge(meta.get("status", "UNKNOWN"))} · Snapshot events: {esc(count)} · Delta: N/A — PRE baseline phase</p><p>Evidence: {snapshot}</p><p class="muted">Collection success does not certify that every SEL event is healthy; event review remains separate.</p></div>'
        command = record.get('commands', {}).get('sel', {})
        if record.get('sel_evidence_schema'):
            if command:
                collection = 'COLLECTED' if command.get('valid') else 'FAILED'
                reason = 'Command was recorded but retention metadata is unavailable'
            else:
                collection, reason = 'NOT RUN', 'PRE SEL collection was not reached'
            evidence = _record_evidence(record, command.get('evidence', ''))
            return f'<div class="sel-panel"><h3>PRE SEL collection</h3><p>Collection: {badge(collection)} · Snapshot events: -- · Delta: N/A — PRE baseline phase</p><p>Reason: {esc(reason)} · Evidence: {evidence}</p><p class="muted">This new-format record does not claim a snapshot that was not retained.</p></div>'
        evidence = _record_evidence(record, command.get('evidence', ''))
        return f'<div class="sel-panel"><h3>PRE SEL collection</h3><p>Collection: {badge("PASS" if command.get("valid") else "UNKNOWN")} · Snapshot events: -- · Delta: N/A — NOT RETAINED — legacy run</p><p>Evidence: {evidence}</p><p class="muted">Event count and raw retention metadata were not recorded by this legacy run; no baseline claim is made.</p></div>'
    if phase == 'START':
        # Clearing moved to PRE; START has no SEL command of its own.
        return ('<div class="sel-panel"><h3>START SEL preparation</h3>'
                '<p>SEL is not cleared here: log clearing (dmesg / IPMI SEL / Redfish) now runs in PRE, '
                'before the baseline. See the PRE section for the clear result.</p></div>')
    before = record.get('sel_before_meta')
    after = record.get('sel_post_meta')
    delta = record.get('sel_delta_meta')
    if not before or not after or not delta:
        if record.get('sel_evidence_schema') or any(record.get(name) is not None for name in ('sel_before_meta', 'sel_post_meta', 'sel_delta_meta')):
            commands = record.get('commands', {})
            before_command = commands.get('sel_before', {})
            failure_command = commands.get('failure_sel', {})
            before_status = before.get('status', 'UNKNOWN') if before else ('COLLECTED' if before_command.get('valid') else 'NOT RUN')
            before_count = before.get('event_count', '--') if before else '--'
            before_evidence = _record_evidence(record, before.get('evidence', '') if before else before_command.get('evidence', ''))
            failure_row = ''
            if after:
                after_status = after.get('status', 'UNKNOWN')
                after_count = after.get('event_count', '--')
                after_evidence = _record_evidence(record, after.get('evidence', ''))
                after_reason = ''
            elif failure_command:
                after_status = 'NOT RUN'
                after_count = '--'
                after_evidence = '<span class="muted">POST was not completed</span>'
                after_reason = 'POST SEL collection was not completed.'
                failure_status = 'COLLECTED' if failure_command.get('valid') else 'FAILED'
                failure_row = f'<tr><td>Failure-path SEL collection</td><td>{badge(failure_status)}</td><td>--</td><td>{_record_evidence(record, failure_command.get("evidence", ""))}</td></tr>'
            else:
                after_status = 'NOT RUN'
                after_count = '--'
                after_evidence = '<span class="muted">POST was not completed</span>'
                after_reason = 'POST SEL collection was not reached.'
            delta_reason = (delta or {}).get('reason') or 'Before-cycle and POST snapshots were not both available'
            # Any missing stage makes the comparison incomplete, even if a
            # malformed journal happens to carry a stale COMPARED label.
            delta_status = 'UNAVAILABLE'
            delta_evidence = _record_evidence(record, (delta or {}).get('evidence', ''))
            return f'<div class="sel-panel"><h3>LOOP SEL comparison</h3><div class="tablewrap"><table><thead><tr><th>Stage</th><th>Status</th><th>Event count</th><th>Evidence</th></tr></thead><tbody><tr><td>Before-cycle SEL collection</td><td>{badge(before_status)}</td><td>{esc(before_count if before_count is not None else "--")}</td><td>{before_evidence}</td></tr><tr><td>POST SEL collection</td><td>{badge(after_status)}</td><td>{esc(after_count if after_count is not None else "--")}</td><td>{after_evidence}</td></tr>{failure_row}<tr><td>Delta comparison</td><td>{badge(delta_status)}</td><td>--</td><td>{delta_evidence}</td></tr></tbody></table></div><p><strong>Delta: UNAVAILABLE</strong> · Event review: {esc(delta_reason)}</p>{f'<p class="muted">{esc(after_reason)}</p>' if after_reason else ''}</div>'
        return '<div class="sel-panel"><h3>LOOP SEL comparison</h3><p>Delta: UNAVAILABLE · Event count: -- · Event review: NOT RETAINED — legacy run</p><p class="muted">The schema does not retain both the action-before and POST raw snapshots; this is not evidence that collection failed.</p></div>'
    before_status = before.get('status', 'UNKNOWN')
    after_status = after.get('status', 'UNKNOWN')
    if delta.get('valid') and delta.get('new_event_count') == 0:
        result = 'Delta: 0 new events'
        review = 'Event review: No new records to review; cumulative SEL may still exist.'
    elif delta.get('valid'):
        result = f'Delta: {delta.get("new_event_count", 0)} new events'
        review = 'Event review: REVIEW REQUIRED'
    else:
        result = 'Delta: UNAVAILABLE · Event count: --'
        review = f'Event review: {delta.get("reason", "Comparison could not be completed")}'
    events = record.get('sel_events') or []
    content = ''.join(f'<li><code>{esc(event)}</code></li>' for event in events)
    event_block = f'<details><summary>Raw new event lines ({len(events)})</summary><ul>{content or "<li>No new event lines.</li>"}</ul></details>' if delta.get('valid') else ''
    before_count = before.get('event_count') if before.get('event_count') is not None else '--'
    after_count = after.get('event_count') if after.get('event_count') is not None else '--'
    delta_count = delta.get('new_event_count') if delta.get('new_event_count') is not None else '--'
    return f'<div class="sel-panel"><h3>LOOP SEL comparison</h3><div class="tablewrap"><table><thead><tr><th>Stage</th><th>Status</th><th>Event count</th><th>Evidence</th></tr></thead><tbody><tr><td>Before-cycle SEL collection</td><td>{badge(before_status)}</td><td>{esc(before_count)}</td><td>{_record_evidence(record, before.get("evidence"))}</td></tr><tr><td>POST SEL collection</td><td>{badge(after_status)}</td><td>{esc(after_count)}</td><td>{_record_evidence(record, after.get("evidence"))}</td></tr><tr><td>Delta comparison</td><td>{badge(delta.get("status", "UNKNOWN"))}</td><td>{esc(delta_count)}</td><td>{_record_evidence(record, delta.get("evidence"))}</td></tr></tbody></table></div><p><strong>{esc(result)}</strong> · {esc(review)}</p>{event_block}</div>'


def record_html(record, node_index, baseline=None):
    phase = _phase_kind(record)
    loop_number = _loop_number(record)
    phase_id = f"node-{node_index}-" + ("pre" if phase == "PRE" else "start" if phase == "START" else f"loop-{loop_number or 'unknown'}")
    evidence = ''.join('<li>' + _record_evidence(record, p) + '</li>' for p in dict.fromkeys(record.get("evidence", [])))
    identity_rows = ''.join(f'<tr><td>{esc(role.upper())}</td><td>{esc(values.get("hostname", "Not recorded"))}</td><td><code>{esc(values.get("boot_id", "Not recorded"))}</code></td></tr>' for role, values in record.get('identities', {}).items())
    identity = '<h3>Verified identities</h3><div class="tablewrap"><table><thead><tr><th>Endpoint</th><th>Hostname</th><th>Boot ID</th></tr></thead><tbody>' + (identity_rows or '<tr><td colspan="3">No identity record</td></tr>') + '</tbody></table></div>'
    collection = ''.join(f'<li><strong>{esc(name)}</strong> {badge("COLLECTION FAILED")}<pre class="snippet">{esc(cmd.get("output_excerpt") or "No output captured; check the command evidence.")}</pre></li>' for name, cmd in record.get('commands', {}).items() if not cmd.get('valid', True) and name not in {'hardware', 'sel_before', 'sel'} and not name.startswith('cycle_'))
    collection = '<details><summary>Collection failures</summary><ul>' + collection + '</ul></details>' if collection else ''
    action = _render_action(record)
    sel = _render_sel(record) + _render_redfish(record)
    return f'''<details id="{phase_id}"><summary><strong>{esc(record['phase'])}</strong> {badge(record['status'])}<span class="phase-count">{esc(_finding_summary(record))} · {esc(duration(record.get('duration_seconds')))} · {esc(record.get('finished') or 'Not finished')}</span></summary><div class="detail-body">
      {_render_summary_groups(record)}{_render_pci_group(record, baseline) if phase != 'START' or record.get('pci') or record.get('pci_devices') else ''}<h3>Findings</h3>{_finding_html(record)}{collection}{sel}<details><summary>{'START preparation and verified identities' if phase == 'START' else 'Cycle action and verified identities' if phase == 'LOOP' else 'Verified identities'}</summary>{action}{identity}</details>
      <p class="muted">{esc(record.get('sel_review', ''))}</p><details><summary>Original evidence files</summary><ul class="evidence-list">{evidence or '<li>Evidence paths were not recorded.</li>'}</ul></details></div></details>'''

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
            phase_id = f"node-{i}-" + (f"loop-{loop.group(1)}" if event['phase'] != 'PRE' and loop else 'start' if event['phase'] == 'START' else 'pre')
            if event['phase'] == 'RECOVERY':
                phase_id = f'node-{i}-recovery'
            source = f'<pre class="snippet">{esc(event["snippet"])}</pre>' if event.get('snippet') else ''
            occurrences.append(f'<tr><td><a href="#{phase_id}" data-panel="node-{i}">{esc(event["phase"])}</a></td><td>{esc(event["detail"])}{source}</td><td>{evidence_link(event["evidence"])}</td></tr>')
        scope = ', '.join(phases) or 'Unknown phase'
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
        records = record_html(node['pre'], i, node['pre']) + (record_html(node['start'], i, node['pre']) if node.get('start') else '') + ''.join(record_html(r, i, node['pre']) for r in node['loops'])
        if node.get('recovery_issues'):
            records += f'<details id="node-{i}-recovery"><summary>Recovery integrity {badge("FAIL")}</summary><ul>' + ''.join(f'<li>{esc(item["detail"])}</li>' for item in node['recovery_issues']) + '</ul></details>'
        last = node['loops'][-1] if node['loops'] else node['pre']
        times = [r['duration_seconds'] for r in node['loops'] if r.get('post_complete') and r.get('duration_seconds') is not None]
        notice = f'<p class="notice">{esc("; ".join(node["blocked"]) or node["stop_reason"])}</p>' if node['blocked'] or node['stop_reason'] else ''
        panels.append(f'''<article class="node-panel" id="node-{i}" aria-labelledby="heading-node-{i}"><h2 id="heading-node-{i}">{esc(node['key'])} {badge(health_value)}</h2>{notice}{facts([('BMC', node['target']['bmc_ip']), ('OS', node['target']['os_ip']), ('Node elapsed (PRE to last POST)', duration(elapsed(node['pre']['started'], last.get('finished')))), ('Average completed loop', duration(sum(times) / len(times) if times else None))])}<h3>PRE and cycle history</h3><p class="muted">POST uses the original PRE baseline. PRE-EXISTING findings become KNOWN when repeated.</p>{records}</article>''')
    outcome = f'''<div class="sheet"><div class="outcome"><div><h2>Campaign outcome</h2><p>{esc(campaign.get('stop_reason') or 'Campaign is in progress.')}</p></div><div class="outcome-badges"><div><span class="label">Execution</span>{badge(result['completion'])}</div><div><span class="label">Health</span>{badge(result['health'])}</div></div></div>{facts([('Cycle / channel', f"{campaign['cycle_mode']} / {campaign['channel']}"), ('Requested limits', f"{campaign['limits']['loops'] or 'No'} loop limit / {campaign['limits']['hours'] or 'No'} hour limit"), ('Campaign elapsed', duration(elapsed(campaign['started'], campaign.get('finished') or now()))), ('POST completed', result['completed_node_loops']), ('Attempts', result['attempted_node_loops']), ('Boot confirmed', result['boot_confirmed_node_loops']), ('Valid cycles', result['valid_node_cycles']), ('Worsened groups', result['worsened']), ('Selected / approved nodes', f"{len(nodes)} / {sum(not n['blocked'] for n in nodes)}"), ('PRE-existing issue groups', result['known']), ('New issue groups during cycling', result['new'])])}</div>'''
    overview = f'''<section role="tabpanel" id="overview" aria-labelledby="tab-overview">{outcome}<div class="sheet"><h2>Target results</h2><p class="muted">All selected nodes. Filters in other views do not change this overview.</p><div class="tablewrap"><table id="target-results"><thead><tr><th>Target / OS address</th><th>Health</th><th>Execution</th><th>Completed loops</th><th>Findings</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div><div class="sheet"><h2>Problems to review</h2><p>FAIL first, then WARN. Repeated findings are grouped within each node; KNOWN still affects health.</p>{issue_cards(items, indices)}</div></section>'''
    node_panel = f'''<section role="tabpanel" id="nodes" aria-labelledby="tab-nodes"><div class="sheet node-browser"><aside><h2>Find a node</h2><label for="node-search">Node name</label><input id="node-search" type="search" placeholder="Search nodes"><label for="node-health">Health</label><select id="node-health"><option value="">All nodes</option><option>FAIL</option><option>WARN</option><option>PASS</option></select><p id="node-count" aria-live="polite">{len(nodes)} nodes</p><nav class="node-list" aria-label="Select a node">{''.join(choices)}</nav></aside><div class="node-content">{''.join(panels)}</div></div></section>'''
    issues_panel = f'''<section role="tabpanel" id="issues" aria-labelledby="tab-issues"><div class="sheet"><h2>Issue review</h2><div class="filterbar"><label>Search node, component or finding<input id="issue-search" type="search" placeholder="Search issues"></label><label>Severity<select id="severity-filter"><option value="">All severities</option><option>FAIL</option><option>WARN</option></select></label><label>Classification<select id="class-filter"><option value="">Known and new</option><option>KNOWN</option><option>NEW</option><option>WORSENED</option></select></label></div><p id="issue-count" aria-live="polite">{len(items)} matching issues</p>{issue_cards(items, indices)}<p id="no-matches" hidden>No matching issues. Clear the filters to show all findings.</p></div></section>'''
    console_panel = f'''<details class="console-panel"><summary>Console log <span class="muted">{len(console_log.splitlines()) if console_log else 0} lines</span></summary><div class="console-tools"><label for="console-search">Search console log<input id="console-search" type="search" placeholder="Search console output"></label><button id="download-console" type="button">Download console.log</button></div><pre id="console-log">{esc(console_log) if console_log else 'Console log is not available for this report.'}</pre></details>'''
    overview = overview.replace('</section>', console_panel + '</section>', 1)
    css = (ASSETS / 'report.css').read_text(encoding='utf-8')
    js = (ASSETS / 'report.js').read_text(encoding='utf-8')
    logo = _wistron_logo()
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>{esc(campaign['run_id'])} | Cycle review</title><style>{css}</style></head><body>
    <a class="skip" href="#main">Skip to report</a>{'<div class="sample">SYNTHETIC DEMONSTRATION — no hardware was operated</div>' if campaign.get('synthetic') else ''}
    <div class="brandbar"><div class="brand-lockup">{logo}<span class="brand-caption">System validation</span></div><span>Engineering / Cycle review</span></div><header><a class="spec-link" href="CYCLE_VALIDATION_SPECIFICATION.html">Validation Specification<br><span>驗證規範</span></a><button id="print-report" class="print-button">Print report</button><h1>Cycle review</h1><div class="runline"><code>{esc(campaign['run_id'])}</code><span class="muted">Started {esc(campaign['started'])}</span></div><nav class="tabs" role="tablist" aria-label="Campaign views">{tab_html}</nav></header>
    <main id="main">{overview}{node_panel}{issues_panel}</main><footer><p>Generated {esc(now())}. Offline report. Keep this HTML with its evidence folders to use log links.</p><p>Hardware script SHA-256: <code>{esc(campaign['script_sha256'])}</code></p></footer><script>{js}</script></body></html>'''

def write_reports(root, campaign):
    with report_writer_lock(root, wait=True):
        _write_reports(root, campaign)


def _write_reports(root, campaign):
    root = Path(root)
    # Missing-file annotations belong to the rendered snapshot, not reviewed PRE.
    campaign = copy.deepcopy(campaign)
    for node in campaign['nodes']:
        for record in [node['pre'], *([node['start']] if node.get('start') else []), *node['loops']]:
            record['missing_evidence'] = [p for p in record['evidence'] if not (root / p).is_file()]
    result = status(campaign)
    # The journal is independent of HTML generation and is written first.
    write_json(root / "campaign.json", campaign)
    # ``cycle_summary.json`` is a portable overview, not a second journal: it
    # keeps campaign metadata and per-node counts but drops ``pre``/``start``
    # and every ``loops`` body, which live once in campaign.json and the
    # loop*/report.json files. ``summary`` carries the aggregated verdict.
    summary_campaign = {k: v for k, v in campaign.items() if k != 'nodes'}
    summary_campaign['nodes'] = [
        {k: v for k, v in node.items() if k not in ('pre', 'start', 'loops')}
        for node in campaign['nodes']
    ]
    write_json(root / "cycle_summary.json", {**summary_campaign, "summary": result})
    lines = [f"Run ID: {campaign['run_id']}", f"Execution: {result['completion']}", f"Health: {result['health']}",
             f"Requested limits: {campaign['limits']}", f"Completed node-loops: {result['completed_node_loops']}",
             f"Attempts: {result['attempted_node_loops']}; boot confirmed: {result['boot_confirmed_node_loops']}; valid cycles: {result['valid_node_cycles']}",
             f"Stop reason: {campaign.get('stop_reason', '')}", f"Unique issues: {len(result['issues'])}", f"Campaign elapsed: {duration(elapsed(campaign['started'], campaign.get('finished')))}"]
    for node in campaign['nodes']:
        node_lines = [f"Target: {node['key']}", f"Completed loops: {node['completed']}",
                      f"Attempts: {node.get('attempts', 0)}; boot confirmed: {node.get('boot_confirmed', 0)}; valid cycles: {node.get('valid_cycles', 0)}",
                      f"Blocked: {'; '.join(node['blocked']) or 'No'}", f"Stop reason: {node['stop_reason']}"]
        for record in [node['pre'], *([node['start']] if node.get('start') else []), *node['loops']]:
            node_lines.append(f"{record['phase']}: {record['status']} ({len(record['issues'])} findings)")
        node_lines.extend('Recovery: ' + note for note in node.get('recovery_notes', []))
        atomic_write(root / node['key'] / "node_summary.txt", '\n'.join(node_lines) + '\n')
        lines += node_lines
    atomic_write(root / "cycle_summary.txt", '\n'.join(lines) + '\n')
    atomic_write(root / "CYCLE_REVIEW_REPORT.md", '# Cycle review\n\n' + '\n\n'.join(lines) + '\n\nSee CYCLE_REVIEW_REPORT.html for expandable evidence and issue recurrence.\n')
    for classification in ('KNOWN', 'NEW', 'WORSENED'):
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
    # The specification is generic and self-contained, but ships beside every
    # campaign report so the two formal documents can use relative links.
    from cycle_specification import write_specification
    write_specification(root)

def rebuild(root, runtime_root=None):
    # Read, ownership check, merge and publication share one writer lock.
    with report_writer_lock(root):
        root = Path(root)
        campaign = json.loads((root / 'campaign.json').read_text(encoding='utf-8'))
        reject_live_rebuild(root, campaign, runtime_root)
        from cycle_recovery import recover_records
        campaign = recover_records(root, campaign)
        _write_reports(root, campaign)
        return campaign
