"""Pure inventory, baseline and issue evaluation. No remote side effects."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROLES = ("bmc", "os", "lily_bmc", "lily_os")

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

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

def issue(code, component, detail, severity="FAIL", evidence=""):
    return dict(code=code, component=component, detail=detail, severity=severity, evidence=evidence)

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

def parse_sensors(text):
    """Keep incomplete table rows so the evaluator cannot silently pass them."""
    rows = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        cells = [v.strip() for v in line.split("|")]
        fields = cells + [""] * max(0, 4 - len(cells))
        row = dict(name=fields[0] or "(unnamed sensor)", reading=fields[1],
                   unit=fields[2], status=fields[3].lower())
        if len(cells) < 4 or not cells[0]:
            row["format_error"] = f"Expected sensor name, reading, unit and status; received: {line.strip()}"
        rows.append(row)
    return rows

def sensor_issues(rows):
    found = []
    if not rows:
        return [issue("SENSOR_EMPTY", "sensors", "No valid sensor rows returned")]
    failures = {"cr", "critical", "nr", "non-recoverable", "non recoverable", "lcr", "ucr", "lnr", "unr"}
    warnings = {"nc", "non-critical", "non critical", "lnc", "unc"}
    unreadable = {"ns", "na", "n/a", "no reading", "unknown", ""}
    counts = Counter(r["name"] for r in rows)
    for name, count in counts.items():
        if count > 1:
            found.append(issue("SENSOR_DUPLICATE", name, f"{count} rows share this sensor name; every row is evaluated", "WARN"))
    for r in rows:
        if r.get("format_error"):
            found.append(issue("SENSOR_MALFORMED", r["name"], r["format_error"]))
            continue
        state = r["status"]
        if state in failures:
            found.append(issue("SENSOR_CRITICAL", r["name"], f"Status {state}; reading {r['reading']}"))
        elif state in warnings:
            found.append(issue("SENSOR_NONCRITICAL", r["name"], f"Status {state}; reading {r['reading']}", "WARN"))
        elif state in unreadable or r["reading"].lower() in unreadable:
            found.append(issue("SENSOR_UNREADABLE", r["name"], f"Status {state or '(empty)'}; reading {r['reading']}"))
        elif r["unit"].strip().lower() == "discrete" and re.fullmatch(r"0x[0-9a-f]+", state):
            # ipmitool reports discrete states as hexadecimal bit fields (for
            # example 0x0100); threshold status names do not apply here.
            continue
        elif state not in {"ok", "0x0000"}:
            found.append(issue("SENSOR_UNRECOGNIZED", r["name"], f"Unrecognized status {state}; review raw sensor output"))
    return found

def missing_sensors(baseline, current):
    return Counter(r["name"] for r in baseline) - Counter(r["name"] for r in current)

def compare_sensors(baseline, initial, confirmation=None):
    items = sensor_issues(initial)
    missing = missing_sensors(baseline, initial)
    if confirmation is not None:
        items += sensor_issues(confirmation)
    remaining = missing_sensors(baseline, confirmation) if confirmation is not None else missing
    for name, count in missing.items():
        if remaining[name]:
            items.append(issue("SENSOR_MISSING", name, f"Missing {remaining[name]} baseline row(s) after confirmation"))
        else:
            items.append(issue("SENSOR_RECOVERED", name, f"Missing {count} row(s) returned on immediate reread", "WARN"))
    # Confirmation can reveal a different disappeared row; never silently discard it.
    for name, count in (remaining - missing).items():
        items.append(issue("SENSOR_MISSING", name, f"Missing {count} baseline row(s) in confirmation"))
    return items

def parse_pci(text):
    rows = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+.*?\[([0-9a-f]{4}:[0-9a-f]{4})\]", line, re.I)
        if match:
            rows[match[1].lower()] = match[2].lower()
    return rows

def pci_issues(baseline, current):
    found = []
    for bdf in sorted(baseline.keys() | current.keys()):
        if baseline.get(bdf) != current.get(bdf):
            found.append(issue("PCI_DRIFT", bdf, f"PRE {baseline.get(bdf, 'absent')} -> POST {current.get(bdf, 'absent')}"))
    return found

def config_issues(text, code):
    items = []
    for line in text.splitlines():
        if line.startswith("ISSUE|"):
            fields = line.split("|", 3)
            if len(fields) == 4:
                items.append(issue(fields[1], fields[2], fields[3]))
    if code != 0 and not items:
        items.append(issue("CONFIG_FAILED", "hardware", f"Hardware script exited {code}"))
    if "RESULT|FAIL" in text and not items:
        items.append(issue("CONFIG_FAILED", "hardware", "Hardware script returned RESULT|FAIL"))
    if "RESULT|" not in text:
        items.append(issue("CONFIG_INCOMPLETE", "hardware", "Hardware script did not return a final structured result"))
    if not any(i['code'] == 'PCIE_DOWNGRADE' for i in items) and re.search(r"down[\s-]*grad|degrad", text, re.I):
        items.append(issue("PCIE_DOWNGRADE", "PCIe", "Hardware script reported link downgrade"))
    return items

def dmesg_issues(text):
    pattern = re.compile(r"AER:.*(?:Uncorrected|Fatal)|Machine check events logged|Hardware Error|nvme.*(?:I/O.*(?:error|timeout)|controller is down)|Memory failure:|Kernel panic|BUG:|Call Trace:", re.I)
    return [issue("DMESG_HARDWARE", "dmesg", line.strip()) for line in text.splitlines() if pattern.search(line)]

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
        for record in [node["pre"], *node["loops"]]:
            for item in record["issues"]:
                key = (node["key"], item["code"], item["component"])
                entry = merged.setdefault(key, {**item, "node": node["key"], "occurrences": []})
                if item["severity"] == "FAIL":
                    entry["severity"] = "FAIL"
                entry["occurrences"].append(dict(phase=record["phase"], detail=item["detail"], evidence=item.get("evidence", "")))
    return list(merged.values())
