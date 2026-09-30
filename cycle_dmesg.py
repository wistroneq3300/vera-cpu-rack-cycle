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
    ('NVME', 'io', r'\bnvme\S*.*(?:I/O(?:\s+tag)?\s*\d*.*(?:error|timeout|timed out)|controller is down|(?:reset|resetting).*\b(?:failed|failure)\b|\b(?:Abort|Device not ready|controller)\b.*\b(?:timeout|timed out)\b)|I/O error, dev nvme\S*'),
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
    metadata = {}
    if family == 'PCIE' and subtype == 'aer':
        bits = sorted(set((int(n), name) for n, name in re.findall(BDF.pattern + r':\s*\[\s*(\d+)\]\s+([A-Za-z][A-Za-z0-9_+-]*)', raw, re.I)))
        status = re.search(r'error status/mask=([0-9a-f]+)/([0-9a-f]+)', raw, re.I)
        subtypes = [f'{n}:{name}' for n, name in bits]
        metadata.update(error_bits=[dict(bit=n, name=name) for n, name in bits],
                        error_status=status[1].lower() if status else None,
                        error_mask=status[2].lower() if status else None)
        subtype = ','.join(subtypes) or ('status:' + status[1].lower() if status else 'aer_unspecified')
        # Event identity excludes severity, timestamps and diagnostic payloads.
        # Status bits are a fallback when named bit lines were not captured.
        if bits or status:
            signature = '|'.join(locators) + '|' + subtype
    if family == 'EDAC':
        count = re.search(r'\bEDAC\s+MC\d+:\s*(\d+)\s+(CE|UE)\b', raw, re.I)
        if count:
            metadata['native_error_count'] = int(count[1])
            subtype = count[2].upper()
            signature = re.sub(r'(\bEDAC\s+MC\d+:\s*)\d+(\s+(?:CE|UE)\b)', r'\1<count>\2', signature, flags=re.I)
    fingerprint = hashlib.sha256((family + '|' + subtype + '|' + source + '|' + signature).encode()).hexdigest()
    return dict(code='DMESG_' + family, component=','.join(locators) or family.lower(),
                family=family, subtype=subtype, device=locators, source=source,
                native_severity=severity, native_severities=native, severity=disposition,
                fingerprint=fingerprint, detail=f'{family} {source}: {severity}; ' + _message(block[0][1]) + (f'; {subtype}' if family == 'PCIE' else ''),
                evidence='', snippet=f'dmesg line {block[0][0]}: {raw}',
                raw_start=block[0][0], raw_end=block[-1][0], raw_lines=[n for n, _ in block],
                raw=raw, occurrence_count=1, **metadata)


def dmesg_issues(text):
    """Separate adjacent events and associate interleaved GHES sequence tags.

    Untagged GHES continuation belongs to the last untagged event. Orphaned
    or unknown blocks are visible FAIL findings, never silently accepted.
    """
    groups, active, found = [], {}, []
    aer_groups, aer_active = [], {}
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
        device = re.search(BDF.pattern + r'(?=\s*:)', line, re.I)
        device = device[0].lower() if device else None
        if device and device in aer_active:
            group = aer_active[device]
            continuation = re.search(r'(?:device \[[0-9a-f:]+\] error status/mask=|:\s*\[\s*\d+\]\s+[A-Za-z]|TLP Header:)', line, re.I)
            if continuation and number - group[-1][0] <= 32:
                group.append((number, line))
                continue
            # A different message from this function ends the bounded event.
            del aer_active[device]
        for family, subtype, pattern in PATTERNS:
            if pattern.search(line):
                if family == 'PCIE' and subtype == 'aer':
                    group = [(number, line)]
                    aer_groups.append(group)
                    if device:
                        aer_active[device] = group
                else:
                    found.append(_event(family, subtype, [(number, line)]))
                break
    found.extend(_event('PCIE', 'aer', group) for group in aer_groups)
    for source, block in groups:
        event = _event('APEI', 'cper', block, source)
        if event:
            found.append(event)
    return sorted(found, key=lambda item: item['raw_start'])
