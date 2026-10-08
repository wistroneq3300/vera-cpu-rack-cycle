"""Pure inventory, baseline and issue evaluation. No remote side effects."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
import os
import tempfile
import unicodedata
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
    fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)

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
    # ``identity`` lets a family whose issue *code* changes with severity (e.g. a
    # Redfish event going Warning -> Critical) still compare as the same event,
    # so a severity escalation is recognised as the same finding rather than a
    # second unrelated one. Families without an identity keep the original
    # code+component(+fingerprint) key.
    if item.get('identity'):
        return ('identity', item['component'], item['identity'])
    return (item['code'], item['component'], item['fingerprint']) if item.get('fingerprint') else (item['code'], item['component'])


def issue_baseline(items):
    result = {}
    for item in items:
        value = result.setdefault(issue_key(item), dict(count=0, severity='WARN', native_rank=0, native_error_count=0))
        value['count'] += item.get('occurrence_count', 1)
        value['native_error_count'] += item.get('native_error_count', 0)
        rank = {'info': 0, 'corrected': 1, 'recoverable': 2, 'unknown': 3,
                'uncorrected': 4, 'uncorrectable': 4, 'fatal': 5}
        value['native_rank'] = max(value['native_rank'], rank.get(item.get('native_severity'), 0))
        if item['severity'] == 'FAIL':
            value['severity'] = 'FAIL'
    return result


def classify_against_pre(items, pre_keys):
    """Classify each finding as KNOWN (seen before) or NEW (first seen now).

    Only two classifications exist; the previous WORSENED label was removed
    because occurrence-count churn (sensor confirmations, retries) made it
    fire on findings whose content had not actually changed. A finding already
    present as FAIL stays KNOWN even if its count grows.

    Two baselines are honoured:

    * Redfish event findings carry a per-loop delta marker (``per_loop_new``).
      Their classification reflects whether the event appeared in *this loop's*
      before-cycle -> POST delta, so a long-lived critical event is reported
      every loop but only classifies NEW on the loop that introduced it.
    * Every other family compares against the PRE baseline.

    A severity escalation (WARN -> FAIL) is NEW because no FAIL form existed
    before; the transition is preserved as metadata rather than hidden.
    """
    counts = issue_baseline(items)
    for item in items:
        key = issue_key(item)
        escalated = (isinstance(pre_keys, dict) and key in pre_keys
                     and counts[key]['severity'] == 'FAIL'
                     and pre_keys[key]['severity'] != 'FAIL')
        per_loop = item.get('per_loop_new')
        if escalated:
            # A finding that was only WARN before and is FAIL now is a new
            # failure: no failing form existed at baseline. The transition is
            # recorded rather than collapsing it into a bare KNOWN.
            item['classification'] = 'NEW'
            item['known_reason'] = 'Escalated from a lower severity seen in PRE'
            item['severity_changed'] = True
            item['previous_severity'] = pre_keys[key]['severity']
            item['current_severity'] = 'FAIL'
        elif per_loop is None:
            known = key in pre_keys
            item["classification"] = "KNOWN" if known else "NEW"
            item["known_reason"] = "Present in PRE baseline" if known else ""
        else:
            item["classification"] = "NEW" if per_loop else "KNOWN"
            item["known_reason"] = ("" if per_loop
                                    else "Introduced in an earlier loop of this campaign")
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
        if '\ufffd' in r['name'] or any(unicodedata.category(c) == 'Cc' for c in r['name']):
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
    return dedup_phase(items)

def dedup_phase(items):
    """Collapse identical findings observed more than once in one phase.

    A sensor read is taken twice per phase (initial, then a confirmation
    reread); both reads surface the same duplicate/malformed rows, so the same
    finding would otherwise be appended twice. Identity is code + component +
    detail: findings that differ in any of those (e.g. a reread that turns a
    "missing" into a "recovered", or an escalated severity) are genuinely
    different observations and are all retained.
    """
    seen = set()
    result = []
    for item in items:
        key = (item['code'], item['component'], item['detail'])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result

def parse_pci(text):
    rows = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+(.*)$", line, re.I)
        if match:
            bdf, description = match[1].lower(), match[2].strip()
            ids = re.search(r"\[([0-9a-f]{4}:[0-9a-f]{4})\]", description, re.I)
            if not ids:
                continue
            class_match = re.match(r"(.*?)\s+\[([0-9a-f]{4})\]:\s*(.*?)\s+\[[0-9a-f]{4}:[0-9a-f]{4}\]", description, re.I)
            if class_match:
                class_name, class_id, device_name = (v.strip() for v in class_match.groups())
            else:
                class_name = description.split(" [", 1)[0].strip()
                class_id = ""
                device_name = class_name
            rows[bdf] = dict(id=ids[1].lower(), raw=line.strip(), device_name=device_name,
                             raw_name=device_name,
                             class_name=class_name, class_id=class_id.lower())
    return rows


def parse_pci_verbose(text):
    """Parse only link/device facts already returned by ``lspci -Dvvv``.

    This is deliberately a bounded parser.  It never probes a device and it
    leaves an unknown link state visible when a verbose block is incomplete.
    """
    rows, current = {}, None
    for line in text.splitlines():
        header = re.match(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+(.*)$", line, re.I)
        if header:
            current = header[1].lower()
            rows[current] = dict(bdf=current, verbose_available=True, capabilities_seen=False,
                                 device_name_explicit=False, access_denied=False,
                                 device_name=header[2].strip(),
                                 pcie_type=None, link_capability=None, link_current=None,
                                 link_result='UNKNOWN', link_reason='Link capability was not classified')
            continue
        if not current:
            continue
        item = rows[current]
        if re.search(r"access denied|permission denied", line, re.I):
            item.update(access_denied=True, link_result='UNKNOWN', link_reason='lspci verbose output was access denied')
            continue
        if re.search(r"^\s*Capabilities:\s*", line, re.I):
            item['capabilities_seen'] = True
        express = re.search(r"Capabilities:\s*\[[^]]+\]\s+Express\s+\([^)]*\)\s+(.+?)(?:,|$)", line, re.I)
        if express:
            item['pcie_type'] = express[1].strip()
            continue
        cap = re.search(r"\bLnkCap:\s*(.*)$", line, re.I)
        if cap:
            item['link_capability'] = cap[1].strip()
            continue
        sta = re.search(r"\bLnkSta:\s*(.*)$", line, re.I)
        if sta:
            item['link_current'] = sta[1].strip()
            continue
        name = re.search(r"^\s*DeviceName:\s*(.*)$", line, re.I)
        if name and name[1].strip():
            item['device_name'] = name[1].strip()
            item['device_name_explicit'] = True

    endpoint_re = re.compile(r"(?:Legacy\s+)?Endpoint$", re.I)
    integrated_re = re.compile(r"Root Complex Integrated Endpoint|Root Complex Event Collector", re.I)
    for item in rows.values():
        pcie_type = item.get('pcie_type') or ''
        current_link = item.get('link_current') or ''
        capability = item.get('link_capability') or ''
        if current_link:
            if re.search(r"Speed\s+unknown|Width\s+x0\b", current_link, re.I):
                item.update(link_result='FAIL', link_reason='Current link reports unknown speed or x0 width')
            elif re.search(r"down[\s-]*grad|degrad", current_link, re.I):
                item.update(link_result='FAIL', link_reason='Current link is reported as downgraded')
            elif not re.search(r"Speed\s+\S+.*Width\s+x\d+", current_link, re.I):
                item.update(link_result='FAIL', link_reason='Current link status does not include a usable speed and width')
            else:
                item.update(link_result='PASS', link_reason='Current link status was evaluated')
        elif integrated_re.search(pcie_type) and not capability:
            item.update(link_result='N/A', link_reason='This integrated device has no reported physical link capability')
        elif endpoint_re.search(pcie_type) or capability:
            item.update(link_result='FAIL', link_reason='Required LnkSta is missing from the verbose record')
        elif pcie_type:
            item.update(link_result='N/A', link_reason='This PCIe type does not expose an end-device link check')
        else:
            item.update(link_result='UNKNOWN', link_reason='Verbose record is insufficient to determine link applicability')
    return rows


def filter_pci_verbose(text):
    """Reduce an ``lspci -Dvvv`` dump to the end-device blocks the report shows.

    Kept blocks are exactly those the cycle report renders as PCIe End Device
    rows: any device that is not a PCI bridge. Bridges and other switch fabric
    are dropped, while their full plain-text form remains embedded in
    ``hardware.txt`` via the hardware script's own ``lspci`` evidence. Whole
    blank-line-separated blocks are kept so each surviving record stays a
    valid, self-contained lspci entry.
    """
    blocks, current = [], []
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        blocks.append(current)

    header_re = re.compile(r"^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+(.*)$", re.I)
    kept = []
    for block in blocks:
        header = header_re.match(block[0])
        if not header:
            continue
        descriptor = header[2]
        # Mirrors cycle_report._pci_devices: PCI bridge class 06 and anything
        # whose descriptor names a bridge are switch fabric, not end devices.
        class_id = re.search(r"\[([0-9a-f]{4})\]", descriptor, re.I)
        if class_id and class_id[1].startswith('06'):
            continue
        if 'bridge' in descriptor.lower():
            continue
        kept.append('\n'.join(block))
    return '\n\n'.join(kept) + ('\n' if kept else '')

def merge_pci_devices(pci, verbose):
    """Join the two already-captured lspci views without inventing devices."""
    merged = {}
    for bdf, base in (pci or {}).items():
        item = dict(base)
        base_name = item.get('device_name')
        item.setdefault('raw_name', base_name or base.get('raw', bdf))
        item.setdefault('device_name', base.get('raw', bdf))
        item.setdefault('class_name', '')
        item.setdefault('class_id', '')
        verbose_item = (verbose or {}).get(bdf, {})
        item.update(verbose_item)
        if verbose_item and not verbose_item.get('device_name_explicit') and base_name:
            item['device_name'] = base_name
        if item.get('access_denied') and not str(item.get('class_id', '')).startswith('06'):
            if re.search(r'Root Complex Integrated Endpoint|Root Complex Event Collector', str(item.get('pcie_type') or ''), re.I):
                item.update(link_result='UNKNOWN', link_reason='Access denied; RCiEP/RCEC link applicability cannot be confirmed')
            else:
                item.update(link_result='FAIL', link_reason='Access denied while reading the PCIe link record')
        item['bdf'] = bdf
        # A complete verbose record for a display function can prove that no
        # PCIe Express/link capability was advertised.  Keep this conditional
        # on the captured capabilities evidence; a truncated/unknown record
        # must remain UNKNOWN rather than being guessed as N/A.
        if (item.get('link_result') == 'UNKNOWN' and item.get('verbose_available')
                and item.get('capabilities_seen') and str(item.get('class_id', '')).lower() == '0300'
                and not item.get('pcie_type') and not item.get('link_capability')
                and not item.get('link_current')):
            item.update(link_result='N/A',
                        link_reason='Verbose record shows no PCIe Express/link capability for this display function')
        merged[bdf] = item
    return merged

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

def nic_slot_issues(baseline, current):
    """Compare the PRE NIC slot inventory against the current loop's.

    ``baseline``/``current`` map a NIC slot BDF (the upstream root port that owns
    the card) to its ``state`` string as emitted by the hardware script's
    ``CHECK|NIC_SLOT|slot=<bdf>|state=<PRESENT|DEGRADED|MISSING>`` lines.

    A slot that was healthy at PRE and is now absent is a real removal
    (NIC_MISSING); a slot that flipped to a non-Vera device type is
    present-but-degraded (NIC_DEGRADED). Both name the BDF, so a report can say
    exactly which NIC dropped instead of only "one fewer card".
    """
    found = []
    for bdf in sorted(set(baseline) | set(current)):
        old, new = baseline.get(bdf), current.get(bdf)
        was_present = old is not None and old != 'MISSING'
        is_present = new is not None and new != 'MISSING'
        if was_present and not is_present:
            found.append(issue("NIC_MISSING", "NIC",
                               f"PRE NIC at slot {bdf} is absent after the loop (missing slot {bdf})",
                               snippet=f"PRE NIC slot {bdf} state={old}; POST absent"))
            continue
        if was_present and is_present and old != new:
            found.append(issue("NIC_DEGRADED", "NIC",
                               f"root port {bdf} -> downstream NIC changed state at PRE={old} -> POST={new} "
                               f"(degraded slot {bdf})",
                               snippet=f"PRE NIC slot {bdf} state={old}; POST state={new}"))
    return found

def parse_usb(text):
    """Parse ``lsusb`` output into a ``{usb_id: row}`` map.

    ``lsusb`` prints one device per line:

        Bus 002 Device 002: ID 0bda:8153 Realtek RTL8153 Gigabit Ethernet Adapter

    The identity used for comparison is the ``vid:pid`` pair (e.g. ``0bda:8153``).
    Multiple devices of the same model collapse onto one key, which is the right
    granularity here: a device that disappears is what matters, not which of two
    identical sticks survived.
    """
    rows = {}
    for line in text.splitlines():
        match = re.match(r"^Bus\s+\d+\s+Device\s+\d+:\s+ID\s+([0-9a-f]{4}:[0-9a-f]{4})\s*(.*)$", line.strip(), re.I)
        if not match:
            continue
        usb_id, description = match[1].lower(), match[2].strip()
        rows[usb_id] = dict(id=usb_id, raw=line.strip(), description=description)
    return rows


def usb_issues(baseline, current):
    """Report a USB device present at PRE that is gone in the current loop.

    Only removals are findings. A device that appears after PRE is ignored by
    operator decision (the BMC KVM keyboard/mouse is hotplugged whenever a
    console is opened, so additions are expected noise). Comparison is by
    ``vid:pid`` identity from :func:`parse_usb`.
    """
    found = []
    for usb_id in sorted(set(baseline) - set(current)):
        old = baseline[usb_id]
        found.append(issue("USB_DRIFT", "usb",
                           f"USB device {usb_id} present at PRE is absent after the loop",
                           snippet=f"PRE USB {usb_id}: {old['raw']}"))
    return found


def parse_network(text):
    """Parse ``ip address show`` output into a ``{ifname: row}`` map.

    Only the interface name is compared (operator decision). The name plus its
    state and addresses are retained as evidence.
    """
    rows = {}
    for line in text.splitlines():
        match = re.match(r"^\d+:\s+([^:@]+)(?:@[^:]+)?:\s+<([^>]*)>\s*(.*)$", line)
        if not match:
            continue
        name = match[1].strip()
        rows[name] = dict(name=name, flags=match[2], raw=line.strip())
    return rows


def network_issues(baseline, current):
    """Report a network interface present at PRE that is gone in the loop.

    Comparison is by interface name only (operator decision); additions are
    ignored, matching the USB contract.
    """
    found = []
    for name in sorted(set(baseline) - set(current)):
        old = baseline[name]
        found.append(issue("NET_DRIFT", "network",
                           f"Network interface {name} present at PRE is absent after the loop",
                           snippet=f"PRE interface {name}: {old['raw']}"))
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

# Redfish log entries carry a vendor Severity of OK/Warning/Critical. Rank them
# like dmesg native severity so both sources share one "worst wins" verdict.
REDFISH_SEVERITY_RANK = {"ok": 0, "warning": 1, "critical": 2}

def redfish_entries(payload):
    """Parse a Redfish LogService Entries collection into normalised records.

    Accepts the decoded JSON payload (dict) and returns a list of entries with
    the fields needed for comparison and display. Vendor id/severity/message are
    kept verbatim; missing pieces become empty strings rather than guesses.
    """
    members, valid, _ = redfish_collection(payload)
    if not valid:
        return []
    entries = []
    for item in members:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("Severity", "") or "")
        entries.append(dict(
            id=str(item.get("Id", "") or ""),
            severity=severity,
            severity_key=severity.strip().lower(),
            created=str(item.get("Created", "") or ""),
            message=str(item.get("Message", "") or ""),
            resolved=bool(item.get("Resolved", False)),
        ))
    return entries

def redfish_collection(payload):
    """Validate a decoded Redfish collection payload and extract its members.

    Returns ``(entry_source, valid, reason)``. ``entry_source`` is the raw
    ``Members`` list when the payload is a well-formed collection, else an empty
    list. A payload that merely *contains* the word "Members" (a truncated
    ``{"Members"`` or ``{"Members": "not-an-array"}``) is NOT a valid empty
    collection: it is unreadable, and callers must surface it rather than let it
    look like "collected successfully and found zero entries".

    Member validity is enforced too: every member must be a JSON object. A list
    like ``[null, 7]`` is a corrupt collection, not "successfully collected,
    zero entries", so it is rejected here instead of being silently filtered
    down to an empty (and therefore PASS-looking) result downstream.
    """
    if not isinstance(payload, dict):
        return [], False, "Redfish payload is not a JSON object"
    if "Members" not in payload:
        return [], False, "Redfish payload has no Members collection"
    members = payload.get("Members")
    if not isinstance(members, list):
        return [], False, "Redfish Members is not a list"
    for index, member in enumerate(members):
        if not isinstance(member, dict):
            return [], False, f"Redfish Members[{index}] is not an object (got {type(member).__name__})"
    return members, True, ""


def redfish_member_kind(member):
    """Classify an already-validated Redfish member object.

    Returns ``"reference"`` for a bare ``@odata.id`` link that still needs to be
    fetched, ``"entry"`` for an expanded object carrying log fields, or
    ``"unusable"`` for an object with neither (which must not be counted as a
    silent zero-event).
    """
    if not isinstance(member, dict):
        return "unusable"
    has_ref = bool(str(member.get("@odata.id", "") or "").strip())
    has_fields = any(key in member for key in ("Id", "Severity", "Message", "Created", "EntryType"))
    if has_fields:
        return "entry"
    if has_ref:
        return "reference"
    return "unusable"


def redfish_page_next_link(payload):
    """Return the odata nextLink of a Redfish collection, if any."""
    if not isinstance(payload, dict):
        return ""
    for key in ("Members@odata.nextLink", "@odata.nextLink"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def redfish_verdict(entries):
    """Return (verdict, counts) for a list of parsed Redfish entries.

    Worst severity wins, matching dmesg policy: any Critical -> FAIL, else any
    Warning -> WARN, else PASS (including empty). ``counts`` tallies each raw
    severity so console summaries can show Critical/Warning/OK breakdowns.
    """
    counts = {"Critical": 0, "Warning": 0, "OK": 0, "Other": 0}
    worst = 0
    for entry in entries:
        key = entry.get("severity_key") or ""
        rank = REDFISH_SEVERITY_RANK.get(key, 0)
        if key == "critical":
            counts["Critical"] += 1
        elif key == "warning":
            counts["Warning"] += 1
        elif key == "ok":
            counts["OK"] += 1
        else:
            counts["Other"] += 1
        worst = max(worst, rank)
    verdict = "FAIL" if worst >= 2 else "WARN" if worst == 1 else "PASS"
    return verdict, counts

def redfish_delta(previous, current):
    """Return entries present in ``current`` but not ``previous``.

    Event identity is Id + Message, deliberately excluding severity so a reused
    Id whose message is unchanged is recognised as the same event even after a
    severity change (WARN -> Critical). Timestamps are excluded from the primary
    key because RTC-less BMCs (e.g. 2000-01-03) make time-based diffing
    unreliable.

    When the BMC's Id space wraps or resets, a fresh event can reuse an Id that
    still exists in the previous snapshot with an identical message. To avoid
    silently dropping that genuine new event, the comparison falls back to the
    timestamp for entries whose Id+Message already matched: a different
    ``created`` value then counts as new. This is a fail-safe only; it never
    turns the whole historical log into "new".
    """
    # Severity is intentionally excluded: an event that escalated WARN -> Critical
    # keeps the same identity. The timestamp is included so a genuine
    # re-occurrence that reuses an Id+Message (BMC Id wrap/reset) is still seen
    # as new, while the historical entry with the same timestamp is not.
    def key(entry):
        return (entry.get("id", ""), entry.get("message", ""), entry.get("created", ""))
    old = Counter(key(e) for e in previous)
    result = []
    for entry in current:
        k = key(entry)
        if old[k]:
            old[k] -= 1
        else:
            result.append(entry)
    return result

def _redfish_delta_ids(record):
    """Ids introduced this record's before->POST delta, or None if unavailable.

    Prefers the explicit top-level marker written at capture time; falls back to
    the per-service meta so records captured before the marker existed still
    classify Redfish findings against their loop delta. ``None`` means no
    comparable delta, so the caller keeps the PRE baseline.
    """
    marker = record.get('eventlog_delta_ids')
    if marker is not None:
        return {str(i) for i in marker}
    ids = set()
    seen_meta = False
    for stem in ('eventlog_meta', 'sel_delta_meta'):
        meta = record.get(stem)
        if not meta:
            continue
        seen_meta = True
        delta = meta.get('delta') or {}
        if delta.get('status') == 'UNAVAILABLE':
            return None
        for entry in delta.get('new_entries', []):
            ids.add(str(entry.get('id', '')))
    return ids if seen_meta else None

def aggregate_issues(campaign):
    merged = {}
    for node in campaign["nodes"]:
        # Keep the PRE comparison separate from severity and causation.
        pre_keys = issue_baseline(node['pre']['issues'])
        for record in [node["pre"], *([node['start']] if node.get('start') else []), *node["loops"],
                       dict(phase='RECOVERY', issues=node.get('recovery_issues', []))]:
            delta_ids = _redfish_delta_ids(record)
            classified = classify_against_pre([i.copy() for i in record['issues']], pre_keys)
            for item in classified:
                # Redfish findings classify against this loop's before->POST
                # delta, not the PRE baseline, so a long-lived event is NEW only
                # on the loop that introduced it. An UNAVAILABLE delta leaves the
                # marker absent, so the PRE baseline still applies.
                if delta_ids is not None and item.get('identity'):
                    event_id = item['identity'].split('|')[1] if '|' in item['identity'] else ''
                    item['per_loop_new'] = event_id in delta_ids
                    item['classification'] = 'NEW' if item['per_loop_new'] else 'KNOWN'
                    item['known_reason'] = ('' if item['per_loop_new']
                                            else 'Introduced in an earlier loop of this campaign')
                key = (node["key"], *issue_key(item))
                entry = merged.setdefault(key, {**item, "node": node["key"], "occurrences": []})
                if item["severity"] == "FAIL":
                    entry["severity"] = "FAIL"
                # NEW wins over KNOWN when the same finding is observed across
                # phases, so the group surfaces where it was first introduced.
                if entry.get('classification') != 'NEW':
                    entry['classification'] = item['classification']
                    entry['known_reason'] = item['known_reason']
                if item.get('severity_changed'):
                    entry['severity_changed'] = True
                    entry['previous_severity'] = item.get('previous_severity')
                    entry['current_severity'] = item.get('current_severity')
                entry["occurrences"].append(dict(phase=record["phase"], detail=item["detail"],
                                                  classification=item.get("classification", ""),
                                                  evidence=item.get("evidence", ""),
                                                  snippet=item.get("snippet", "")))
    return list(merged.values())
