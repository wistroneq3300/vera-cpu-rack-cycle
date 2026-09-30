"""Kernel event extraction; native severity and raw positions survive policy."""
import hashlib
import re

HEADER = re.compile(r'Hardware error from APEI.*Source:\s*(\S+)', re.I)
HW = re.compile(r'\[Hardware Error\]:', re.I)
TOKEN = re.compile(r'\{(\d+)\}\s*\[Hardware Error\]')
SEVERITY = re.compile(r'(?:event severity|error severity|severity|(?<!section )type):\s*(info|corrected|recoverable|fatal|uncorrected|uncorrectable|unknown)\b', re.I)
BDF = re.compile(r'\b(?:[0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b', re.I)
PATTERNS = [
    ('KERNEL', 'panic', r'Kernel panic'),
    ('KERNEL', 'oops', r'\bOops:|\bBUG:|Call Trace:|soft lockup|hard LOCKUP|blocked for more than \d+ seconds'),
    ('ARM', 'serror', r'\bSError\b.*(?:Interrupt|exception)|Asynchronous SError'),
    ('MCE', 'machine_check', r'Machine check events logged|Machine Check Exception|\bMCE:.*(?:error|bank)'),
    ('EDAC', 'memory', r'\bEDAC\b.*\b(?:UE|CE|uncorrected|corrected|uncorrectable)\b|Memory failure:'),
    ('PCIE', 'aer', r'\b(?:AER:|PCIe Bus Error:).*(?:corrected|correctable|uncorrected|uncorrectable|fatal)'),
    ('PCIE', 'dpc', r'\bDPC:.*(?:containment event|unmasked uncorrectable|recovery failed)'),
    ('NVME', 'io', r'\bnvme\S*.*(?:I/O.*(?:error|timeout)|controller is down|reset controller|timeout|timed out)|I/O error, dev nvme\S*'),
    ('NIC', 'mlx5_health', r'\bmlx5\S*.*(?:fatal|health.*(?:error|failed)|firmware.*(?:error|failed))'),
    ('GPU', 'xid', r'\bNVRM:.*\bXid\b'),
]
PATTERNS = [(family, subtype, re.compile(pattern, re.I)) for family, subtype, pattern in PATTERNS]


def _message(line):
    return re.sub(r'^\s*(?:<\d+>)?\s*\[\s*\d+(?:\.\d+)?\]\s*', '', line).strip()


def _event(family, subtype, block, source=''):
    raw = '\n'.join(line for _, line in block)
    native = [m.lower() for m in SEVERITY.findall(raw)]
    if family == 'APEI' and native and all(s == 'info' for s in native):
        return None
    if family != 'APEI' and not native:
        if re.search(r'\b(?:uncorrected|uncorrectable|fatal|UE)\b', raw, re.I):
            native = ['uncorrected']
        elif re.search(r'\b(?:corrected|correctable|recoverable|CE)\b', raw, re.I):
            native = ['corrected']
        else:
            native = ['unknown']
    rank = {'info': 0, 'corrected': 1, 'recoverable': 2, 'unknown': 3,
            'uncorrected': 4, 'uncorrectable': 4, 'fatal': 5}
    severity = max(native or ['unknown'], key=lambda v: rank[v])
    disposition = 'WARN' if severity in {'corrected', 'recoverable'} else 'FAIL'
    locators = sorted(set(v.lower() for v in BDF.findall(raw)))
    locators += sorted(set(re.findall(r'\b(?:DIMM\S*|nvme\d+(?:n\d+)?|port[ :]+\d+|Xid[^\n]*?:\s*\d+)\b', raw, re.I)))
    # Preserve device/subtype numbers. Remove only printk timestamps, event
    # sequence tags and native severity (severity growth is WORSENED).
    signature = '\n'.join(_message(line) for _, line in block if HW.search(line)) if family == 'APEI' else _message(raw)
    signature = re.sub(r'\{\d+\}', '', signature)
    signature = re.sub(r'\b(?:fatal|uncorrected|uncorrectable|corrected|correctable|recoverable|info|unknown)\b', '<severity>', signature, flags=re.I)
    fingerprint = hashlib.sha256((family + '|' + subtype + '|' + source + '|' + signature).encode()).hexdigest()
    return dict(code='DMESG_' + family, component=','.join(locators) or family.lower(),
                family=family, subtype=subtype, device=locators, source=source,
                native_severity=severity, native_severities=native, severity=disposition,
                fingerprint=fingerprint, detail=f'{family} {source}: {severity}; ' + _message(block[0][1]),
                evidence='', snippet=f'dmesg line {block[0][0]}: {raw}',
                raw_start=block[0][0], raw_end=block[-1][0], raw_lines=[n for n, _ in block],
                raw=raw, occurrence_count=1)


def dmesg_issues(text):
    """Separate adjacent events and associate interleaved GHES sequence tags.

    Untagged GHES continuation belongs to the last untagged event. Orphaned
    or unknown blocks are visible FAIL findings, never silently accepted.
    """
    groups, active, found = [], {}, []
    for number, line in enumerate(text.splitlines(), 1):
        if HW.search(line):
            token = TOKEN.search(line)
            key = token[1] if token else ''
            header = HEADER.search(line)
            if header or key not in active:
                group = [header[1] if header else 'orphan', []]
                groups.append(group)
                active[key] = group
            active[key][1].append((number, line))
            continue
        for family, subtype, pattern in PATTERNS:
            if pattern.search(line):
                found.append(_event(family, subtype, [(number, line)]))
                break
    for source, block in groups:
        event = _event('APEI', 'cper', block, source)
        if event:
            found.append(event)
    return sorted(found, key=lambda item: item['raw_start'])
