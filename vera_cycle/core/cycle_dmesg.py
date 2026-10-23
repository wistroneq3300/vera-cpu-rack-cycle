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

# Fallback sweep. Any line that greps as an error/failure and is NOT claimed by
# a family above would otherwise be dropped silently -- and the drop was real:
# on the Vera CPU rack 92 of 103 error/fail lines were invisible (PCI io-window
# ``failed to assign``, ipmi_ssif probe failures, tegra-bpmp debugfs, ...).
# Rather than one finding per line, unclassified lines are collapsed into ONE
# ``DMESG_BUNDLE`` finding per capture. Everything is FAIL for now: the operator
# refines a per-project allowlist of known-benign lines later, rather than the
# parser guessing up-front.
BUNDLE_KEYWORDS = re.compile(
    r'\b(?:error|errors|failed|failure|failing|fail|fault|faulty|unable|refused|'
    r'denied|timeout|timed out|corrupt|corrupted|invalid|cannot)\b', re.I)
# Announces an error word but is a normal capability/init message.
BUNDLE_BENIGN = [
    re.compile(r'\berror reporting\b', re.I),
    re.compile(r'\bOS supports\b.*\[.*\]', re.I),
    re.compile(r'\bdoes not support\b.*\[.*ErrorReporting.*\]', re.I),
    re.compile(r'Error Record Serialization Table.*initialized', re.I),
    re.compile(r'Error INJection is initialized', re.I),
    re.compile(r'\b(?:0|no)\s+errors?\b', re.I),
    re.compile(r'\bfeatures: detected:.*timeout\b', re.I),
    re.compile(r'\bInitialized with .*timeout\b', re.I),
    re.compile(r'\btimeout set to\b', re.I),
    re.compile(r'\bset to \d+\s*seconds?\b', re.I),
    # AER/PCIe continuation markers are NOT benign by themselves. Excluding the
    # whole prefix hid real failures such as ``AER: device recovery failed`` and
    # ``PCIe Bus Error: severity=Recoverable`` as INFO, because the family
    # pattern only claims lines carrying corrected/uncorrected/fatal. Only the
    # exact capability banners and the status/mask companion of an AER event the
    # family pattern already claimed are benign; every other AER line reaches
    # the bundle and stays a FAIL.
    re.compile(r'\bAER:\s*(?:Enabled|Capabilit(?:y|ies)|\S+:\s*Enabled)\b', re.I),
    re.compile(r'\bAER:\s*error status/mask=[0-9a-f]+/[0-9a-f]+\b', re.I),
]
# IPMI/SSIF transport failures are functional, not noise: a broken SSIF leaves
# /dev/ipmi0 present but unusable, so ``ipmitool`` fails outright. They are not
# special-cased -- they flow into the one bundle like every other stray line --
# but they are why a bundle containing them must be treated as real, not noise.
BUNDLE_TS = re.compile(r'^\s*(?:<\d+>)?\s*\[\s*\d+(?:\.\d+)?\]\s*')


def _bundle_event(lines, code, family, severity):
    """One finding carrying a group of error/fail lines, deduped by message.

    Identical messages from the same device collapse into a single entry with a
    count and the line number of their first occurrence, so a repeated boot-time
    complaint is one row in the report rather than dozens.

    Identity has two levels, and they must not be confused:

    * ``observations`` -- one ``(device, message)`` pair per distinct occurrence.
      This is what the engine's cross-capture delta compares. It keeps the BDF,
      because 0000:01:00.0 and 0000:02:00.0 failing the same way are two devices
      failing, not one repeated message.
    * ``raw`` / ``fingerprint`` -- normalised, BDF-free, used only for grouping
      and for PRE comparison. Folding a BDF into these would make a pre-existing
      bundle look NEW on every boot when enumeration order shifts.
    """
    counts, first, order = {}, {}, []
    observations, devices = [], []
    for number, line in lines:
        key = BUNDLE_TS.sub('', line).strip()
        # Keep the device address in the entry: two NICs or two PCIe cards that
        # log the same failure text are two distinct findings, and collapsing
        # them by message alone hid the second card entirely.
        key = re.sub(r'\b0x[0-9a-f]+\b', '<hex>', key, flags=re.I)
        if key not in counts:
            first[key] = number
            order.append(key)
        counts[key] = counts.get(key, 0) + 1
        device = _bdf_of(key)
        if device and device not in devices:
            devices.append(device)
        observations.append(f'{device or "<none>"}|{_strip_count(key)}')
    entries = [dict(line=first[k], count=counts[k], text=k,
                    device=_bdf_of(k)) for k in order]
    # The fingerprint identifies the *group of message types*, not the device
    # addresses: it must not change when a run's BDF enumeration differs, or a
    # pre-existing bundle would be reclassified NEW on every boot. Device
    # identity is carried by the entries above, not by the fingerprint.
    signature = '\n'.join(sorted({_strip_bdf(text) for text in counts}))
    fingerprint = hashlib.sha256((family + '||errors|' + signature).encode()).hexdigest()
    detail = (f'{family}: {len(order)} distinct error/fail line(s), '
              f'{sum(counts.values())} occurrence(s)')
    return dict(code=code, component=family.lower(), family=family,
                subtype='errors', device=devices, source='', native_severity='unknown',
                native_severities=['unknown'], severity=severity,
                fingerprint=fingerprint, detail=detail, evidence='',
                snippet=f'dmesg line {entries[0]["line"]}: {entries[0]["text"]}',
                raw_start=entries[0]['line'], raw_end=entries[-1]['line'],
                raw_lines=[e['line'] for e in entries], raw=signature,
                observations=observations,
                occurrence_count=sum(counts.values()), entries=entries)


def _bdf_of(text):
    found = re.search(r'\b(?:(?:[0-9a-f]{4}):)?([0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b', text, re.I)
    return found[0].lower() if found else ''


def _strip_bdf(text):
    text = re.sub(r'\b(?:[0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b', '<bdf>', text, flags=re.I)
    return re.sub(r'\b[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\b', '<bdf>', text, flags=re.I)


def _strip_count(text):
    """Drop the counters that make a repeat differ from its first occurrence."""
    text = re.sub(r'\b0x[0-9a-f]+\b', '<hex>', text, flags=re.I)
    return re.sub(r'\b(I/O|QID|error status/mask)\s*\d+', r'\1 <n>', text, flags=re.I)


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
    # sequence tags and native severity (so the same event with a different
    # native severity still shares a signature).
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
    consumed = set()
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
            consumed.add(number)
            continue
        device = re.search(BDF.pattern + r'(?=\s*:)', line, re.I)
        device = device[0].lower() if device else None
        if device and device in aer_active:
            group = aer_active[device]
            continuation = re.search(r'(?:device \[[0-9a-f:]+\] error status/mask=|:\s*\[\s*\d+\]\s+[A-Za-z]|TLP Header:)', line, re.I)
            if continuation and number - group[-1][0] <= 32:
                group.append((number, line))
                consumed.add(number)
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
                consumed.add(number)
                break
    found.extend(_event('PCIE', 'aer', group) for group in aer_groups)
    for group in aer_groups:
        consumed.update(number for number, _ in group)
    for source, block in groups:
        event = _event('APEI', 'cper', block, source)
        if event:
            found.append(event)
    candidates = [(number, line) for number, line in enumerate(text.splitlines(), 1)
                  if number not in consumed and BUNDLE_KEYWORDS.search(line)]
    stray = [(n, line) for n, line in candidates
             if not any(b.search(line) for b in BUNDLE_BENIGN)]
    if stray:
        found.append(_bundle_event(stray, 'DMESG_BUNDLE', 'BUNDLE', 'FAIL'))
    # Benign-looking error lines (matched by BUNDLE_BENIGN) are NOT dropped: the
    # allowlist is a heuristic, so the operator keeps them visible as an INFO
    # ``DMESG_NOISE`` finding instead of losing them silently. They never affect
    # the health verdict -- only the FAIL bundle does.
    noise = [(n, line) for n, line in candidates
             if any(b.search(line) for b in BUNDLE_BENIGN)]
    if noise:
        found.append(_bundle_event(noise, 'DMESG_NOISE', 'BUNDLE', 'INFO'))
    return sorted(found, key=lambda item: item['raw_start'])
