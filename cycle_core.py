"""Pure inventory, baseline and issue evaluation. No remote side effects."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from collections import Counter

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cycle_dmesg import dmesg_issues

ROLES = ("bmc", "os", "lily_bmc", "lily_os")

LOG_TIMEZONE = timezone(timedelta(hours=8), name="UTC+8")

def now():
    """Return operator-facing timestamps in the rack lab timezone (UTC+8)."""
    return datetime.now(LOG_TIMEZONE).isoformat(timespec="seconds")

def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(text, encoding="utf-8")
    temp.replace(path)

def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, ensure_ascii=True) + "\n")

def digest(data):
    return hashlib.sha256(data).hexdigest()

@dataclass(frozen=True)
class Target:
    tray: str
    node: str
    bmc_ip: str
    os_ip: str
    bmc_hostname: str = ""
    os_hostname: str = ""
    lily_bmc_ip: str = ""
    lily_os_ip: str = ""
    lily_bmc_hostname: str = ""
    lily_os_hostname: str = ""

    @property
    def key(self):
        return f"{self.tray}_{self.node}"

    def endpoints(self):
        return [(r, getattr(self, r + "_ip"), getattr(self, r + "_hostname"))
                for r in ROLES if getattr(self, r + "_ip")]

def load_inventory(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"tray", "node", "bmc_ip", "os_ip", "bmc_hostname", "os_hostname"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Inventory missing columns: " + ", ".join(sorted(required - set(reader.fieldnames or []))))
        rows = []
        seen = set()
        for line, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f"Inventory line {line}: too many columns")
            item = Target(**{k: (row.get(k) or "").strip() for k in Target.__dataclass_fields__})
            if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", x) for x in (item.tray, item.node)):
                raise ValueError(f"Inventory line {line}: tray/node must use letters, digits, dots or hyphens")
            if item.key.lower() in seen:
                raise ValueError(f"Duplicate tray/node: {item.key}")
            seen.add(item.key.lower())
            for role, addr, host in item.endpoints():
                try:
                    ipaddress.ip_address(addr)
                except ValueError as exc:
                    raise ValueError(f"{item.key}: invalid {role} IP: {addr}") from exc
                if host and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host):
                    raise ValueError(f"{item.key}: invalid {role} hostname")
            rows.append(item)
    if not rows:
        raise ValueError("Inventory has no targets")
    return rows

def select_targets(targets, selections):
    if selections == ["all"]:
        return targets
    chosen = []
    for name in selections:
        matches = [t for t in targets if name in (t.key, t.node, f"{t.tray}/{t.node}")]
        if len(matches) != 1:
            raise ValueError(f"Unknown or ambiguous target '{name}'; use tray/node")
        if matches[0] in chosen:
            raise ValueError(f"Duplicate selection: {matches[0].key}")
        chosen.append(matches[0])
    if not chosen:
        raise ValueError("Select at least one target")
    return chosen

def inventory_blocks(targets):
    blocked = {t.key: [] for t in targets}
    addresses = {}
    for t in targets:
        for role in ("bmc", "os"):
            if not getattr(t, role + "_ip"):
                blocked[t.key].append(f"Missing {role} IP")
        for role, addr, host in t.endpoints():
            if not host:
                blocked[t.key].append(f"Missing expected {role} hostname")
            addresses.setdefault(str(ipaddress.ip_address(addr)), []).append((t.key, role))
    for addr, uses in addresses.items():
        if len(uses) > 1:
            reason = f"Duplicate endpoint {addr}: " + ", ".join(f"{key}/{role}" for key, role in uses)
            for key, _ in uses:
                blocked[key].append(reason)
    return {k: v for k, v in blocked.items() if v}

def issue(code, component, detail, severity="FAIL", evidence="", snippet=""):
    return dict(code=code, component=component, detail=detail, severity=severity, evidence=evidence,
                snippet=snippet)

def health(issues):
    return "FAIL" if any(i["severity"] == "FAIL" for i in issues) else "WARN" if issues else "PASS"

def parse_policy(text):
    rules = []
    for line in text.splitlines():
        cells = [v.strip() for v in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[3] in {"KNOWN", "NEW"} and cells[5].lower() == "yes":
            rules.append(dict(zip(("project", "code", "component", "classification", "reason", "active"), cells, strict=True)))
    return rules

def classify(items, project, rules):
    for item in items:
        item.update(classification="NEW", known_reason="")
        for rule in rules:
            if all(rule[k] in ("*", v) for k, v in (("project", project), ("code", item["code"]), ("component", item["component"]))):
                item.update(classification=rule["classification"], known_reason=rule["reason"])
                break
    return items

def issue_key(item):
    return (item['code'], item['component'], item['fingerprint']) if item.get('fingerprint') else (item['code'], item['component'])


def issue_baseline(items):
    result = {}
    for item in items:
        value = result.setdefault(issue_key(item), dict(count=0, severity='WARN', native_rank=0))
        value['count'] += item.get('occurrence_count', 1)
        rank = {'info': 0, 'corrected': 1, 'recoverable': 2, 'unknown': 3,
                'uncorrected': 4, 'uncorrectable': 4, 'fatal': 5}
        value['native_rank'] = max(value['native_rank'], rank.get(item.get('native_severity'), 0))
        if item['severity'] == 'FAIL':
            value['severity'] = 'FAIL'
    return result


def classify_against_pre(items, pre_keys):
    """PRE comparison describes observations, never cycle causation."""
    counts = issue_baseline(items)
    for item in items:
        key = issue_key(item)
        item["classification"] = "KNOWN" if key in pre_keys else "NEW"
        item["known_reason"] = "Present in PRE baseline" if key in pre_keys else ""
        if isinstance(pre_keys, dict) and key in pre_keys:
            old, current = pre_keys[key], counts[key]
            if (current['count'] > old['count'] or current['native_rank'] > old.get('native_rank', 0)
                    or (current['severity'] == 'FAIL' and old['severity'] != 'FAIL')):
                item.update(classification='WORSENED', known_reason='Count or severity increased relative to PRE')
    return items

def parse_sensors(text):
    """Keep incomplete and puzzling rows so the evaluator cannot silently pass them."""
    rows = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if "|" not in line:
            # ipmitool exit code 0 does not guarantee table rows; a stray
            # diagnostic line must surface instead of quietly shrinking the list.
            rows.append(dict(name=line.strip(), reading="", unit="", status="", line=lineno,
                             raw=line,
                             format_error=f"Expected a table row; received: {line.strip()}"))
            continue
        cells = [v.strip() for v in line.split("|")]
        fields = cells + [""] * max(0, 4 - len(cells))
        row = dict(name=fields[0] or "(unnamed sensor)", reading=fields[1],
                   unit=fields[2], status=fields[3].lower(), line=lineno, raw=line)
        if len(cells) < 4 or not cells[0]:
            row["format_error"] = f"Expected sensor name, reading, unit and status; received: {line.strip()}"
        rows.append(row)
    return rows

def _known_no_reading(row, unreadable):
    """Recognize only documented Vera no-value rows, not generic ``na``.

    Garbled names (U+FFFD replacement characters) are deliberately NOT
    whitelisted: a corrupted sensor name means the row cannot be trusted, so
    it must surface as SENSOR_UNREADABLE rather than pass as known-good.
    """
    reading = row["reading"].strip().lower()
    status = row["status"].strip().lower()
    if reading not in unreadable or status not in unreadable:
        return False
    return bool(re.fullmatch(r'PrMo\d+CP\d+CorUti\d*', row['name'], re.I))

def _snippet(row):
    """One-line, greppable pointer back to the exact evidence row."""
    raw = (row.get("raw") or "").strip()
    line = row.get("line")
    if raw and line:
        return f"line {line}: {raw}"
    return raw or (f"line {line}" if line else "")

def sensor_issues(rows):
    found = []
    if not rows:
        return [issue("SENSOR_EMPTY", "sensors", "No valid sensor rows returned")]
    failures = {"cr", "critical", "nr", "non-recoverable", "non recoverable", "lcr", "ucr", "lnr", "unr"}
    warnings = {"nc", "non-critical", "non critical", "lnc", "unc"}
    unreadable = {"ns", "na", "n/a", "no reading", "unknown", ""}
    counts = Counter(r["name"] for r in rows)
    for name, count in counts.items():
        if count <= 1:
            continue
        dup_rows = [r for r in rows if r["name"] == name]
        found.append(issue("SENSOR_DUPLICATE", name,
                           f"{count} rows share this sensor name; review each row", "WARN",
                           snippet="\n".join(_snippet(r) for r in dup_rows)))
    for r in rows:
        if '\ufffd' in r['name'] or any(ord(c) < 32 for c in r['name']):
            found.append(issue('SENSOR_NAME_MALFORMED', r['name'], 'Sensor identity contains invalid characters', snippet=_snippet(r)))
            continue
        if r.get("format_error"):
            found.append(issue("SENSOR_MALFORMED", r["name"], r["format_error"], snippet=_snippet(r)))
            continue
        state = r["status"]
        if state in failures:
            found.append(issue("SENSOR_CRITICAL", r["name"], f"Status {state}; reading {r['reading']}", snippet=_snippet(r)))
        elif state in warnings:
            found.append(issue("SENSOR_NONCRITICAL", r["name"], f"Status {state}; reading {r['reading']}", "WARN", snippet=_snippet(r)))
        elif _known_no_reading(r, unreadable):
            # Vera emits these platform-defined no-value rows while healthy.
            # Keep the raw row in evidence, but do not turn it into a failure.
            continue
        elif state in unreadable or r["reading"].lower() in unreadable:
            found.append(issue("SENSOR_UNREADABLE", r["name"], f"Status {state or '(empty)'}; reading {r['reading']}", snippet=_snippet(r)))
        elif r["unit"].strip().lower() == "discrete" and re.fullmatch(r"0x[0-9a-f]+", state):
            # ipmitool reports discrete states as hexadecimal bit fields (for
            # example 0x0100); threshold status names do not apply here.
            continue
        elif state not in {"ok", "0x0000"}:
            found.append(issue("SENSOR_UNRECOGNIZED", r["name"], f"Unrecognized status {state}; review raw sensor output", snippet=_snippet(r)))
    return found

def missing_sensors(baseline, current):
    return Counter(r["name"] for r in baseline) - Counter(r["name"] for r in current)

def compare_sensors(baseline, initial, confirmation=None):
    items = sensor_issues(initial)
    missing = missing_sensors(baseline, initial)
    if confirmation is not None:
        items += sensor_issues(confirmation)
    remaining = missing_sensors(baseline, confirmation) if confirmation is not None else missing
    baseline_by_name = {}
    for row in baseline:
        baseline_by_name.setdefault(row["name"], []).append(row)
    for name, count in missing.items():
        gone = "\n".join(_snippet(r) for r in baseline_by_name.get(name, []))
        if remaining[name]:
            items.append(issue("SENSOR_MISSING", name,
                               f"Missing {remaining[name]} baseline row(s) after confirmation",
                               snippet=gone))
        else:
            items.append(issue("SENSOR_RECOVERED", name,
                               f"Missing {count} row(s) returned on immediate reread", "WARN",
                               snippet=gone))
    # Confirmation can reveal a different disappeared row; never silently discard it.
    for name, count in (remaining - missing).items():
        gone = "\n".join(_snippet(r) for r in baseline_by_name.get(name, []))
        items.append(issue("SENSOR_MISSING", name,
                           f"Missing {count} baseline row(s) in confirmation", snippet=gone))
    return items

def parse_pci(text):
    rows = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+.*?\[([0-9a-f]{4}:[0-9a-f]{4})\]", line, re.I)
        if match:
            rows[match[1].lower()] = dict(id=match[2].lower(), raw=line.strip())
    return rows

def pci_issues(baseline, current):
    found = []
    for bdf in sorted(baseline.keys() | current.keys()):
        old, new = baseline.get(bdf), current.get(bdf)
        if (old or {}).get('id') != (new or {}).get('id'):
            old_id = old["id"] if old else "absent"
            new_id = new["id"] if new else "absent"
            lines = []
            if old: lines.append(f"PRE  {old['raw']}")
            if new: lines.append(f"POST {new['raw']}")
            found.append(issue("PCI_DRIFT", bdf, f"PRE {old_id} -> POST {new_id}",
                               snippet="\n".join(lines)))
    return found

def _check_snippet(line):
    """Turn a ``CHECK|<component>|key=value|...`` line into a one-line pointer
    to what the hardware script measured. A missing device has no offending
    row to quote, so the measured counts are the useful evidence."""
    fields = line.split("|")
    if len(fields) < 3:
        return ""
    values = {}
    for field in fields[2:]:
        if "=" in field:
            key, _, value = field.partition("=")
            values[key] = value
    if not values:
        return ""
    actual = values.pop("actual", "")
    expected = values.pop("minimum", values.pop("exact", ""))
    if not actual and not expected:
        return f"{fields[1]}: " + ", ".join(f"{k}={v}" for k, v in values.items())
    head = f"measured {fields[1]} actual={actual}" + (f", expected {expected}" if expected else "")
    sources = values.pop("sources", "")
    extras = ", ".join(f"{k}={v}" for k, v in values.items())
    tail = "; ".join(x for x in (extras, f"sources: {sources}" if sources else "") if x)
    return head + (f" — {tail}" if tail else "")

def config_issues(text, code):
    items = []
    checks = {}
    for line in text.splitlines():
        if line.startswith("CHECK|"):
            fields = line.split("|")
            if len(fields) >= 3:
                snippet = _check_snippet(line)
                checks.setdefault(fields[1], snippet)
                # Some checks (for example PCIE_DOWNGRADE) key the issue by BDF,
                # not by the check name, so index those under the BDF too.
                for field in fields[2:]:
                    if field.startswith("bdf="):
                        checks.setdefault(field[4:], snippet)
        elif line.startswith("ISSUE|"):
            fields = line.split("|", 3)
            if len(fields) == 4:
                items.append(issue(fields[1], fields[2], fields[3], snippet=checks.get(fields[2], "")))
    if code != 0 and not items:
        items.append(issue("CONFIG_FAILED", "hardware", f"Hardware script exited {code}"))
    if "RESULT|FAIL" in text and not items:
        items.append(issue("CONFIG_FAILED", "hardware", "Hardware script returned RESULT|FAIL"))
    if "RESULT|" not in text:
        items.append(issue("CONFIG_INCOMPLETE", "hardware", "Hardware script did not return a final structured result"))
    # Legacy scripts may omit structured issues. Restrict the fallback to an
    # explicitly identified endpoint's LnkSta, never bridges or general prose.
    bdf, endpoint = "", False
    for line in text.splitlines():
        header = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s", line, re.I)
        if header:
            bdf, endpoint = header[1], False
        elif re.search(r"Express.*(?:Legacy\s+)?Endpoint", line):
            endpoint = True
        elif endpoint and "LnkSta:" in line:
            link_code = "PCIE_DOWNGRADE" if re.search(r"down[\s-]*grad|degrad", line, re.I) else "PCIE_LINK_UNAVAILABLE" if re.search(r"Speed\s+unknown|Width\s+x0\b", line, re.I) else None
            if link_code and not any(i['code'] == link_code and i['component'] == bdf for i in items):
                items.append(issue(link_code, bdf, line.strip(), snippet=line.strip()))
    return items

def sel_delta(previous, current):
    # Complete record text includes record ID and timestamp; reused IDs remain visible.
    old = Counter(line.strip() for line in previous.splitlines() if "|" in line)
    result = []
    for line in current.splitlines():
        key = line.strip()
        if "|" not in key:
            continue
        if old[key]:
            old[key] -= 1
        else:
            result.append(line)
    return "\n".join(result) + ("\n" if result else "")

def aggregate_issues(campaign):
    merged = {}
    for node in campaign["nodes"]:
        # Keep the PRE comparison separate from severity and causation.
        pre_keys = issue_baseline(node['pre']['issues'])
        for record in [node["pre"], *([node['start']] if node.get('start') else []), *node["loops"]]:
            classified = classify_against_pre([i.copy() for i in record['issues']], pre_keys)
            for item in classified:
                key = (node["key"], *issue_key(item))
                entry = merged.setdefault(key, {**item, "node": node["key"], "occurrences": []})
                if item["severity"] == "FAIL":
                    entry["severity"] = "FAIL"
                if entry.get('classification') != 'WORSENED':
                    entry['classification'] = item['classification']
                    entry['known_reason'] = item['known_reason']
                    if item['classification'] == 'WORSENED':
                        entry['detail'] = item['detail']
                        entry['native_severity'] = item.get('native_severity')
                entry["occurrences"].append(dict(phase=record["phase"], detail=item["detail"],
                                                  evidence=item.get("evidence", ""),
                                                  snippet=item.get("snippet", "")))
    return list(merged.values())
