"""Campaign node execution, with immutable PRE and durable evidence."""
from __future__ import annotations

from contextlib import contextmanager
from collections import Counter
from datetime import datetime
import re
import shlex
import threading
import time
from pathlib import Path

from vera_cycle import paths
from vera_cycle.core.cycle_core import (
    atomic_write,
    bmc_usb_issues,
    classify_against_pre,
    compare_sensors,
    config_issues,
    dmesg_issues,
    filter_pci_verbose,
    health,
    issue,
    issue_baseline,
    mctp_check_issues,
    mctp_stress_issues,
    merge_pci_devices,
    missing_sensors,
    network_issues,
    nic_slot_issues,
    now,
    parse_bmc_lsusb,
    parse_network,
    parse_pci,
    parse_pci_verbose,
    parse_sensors,
    parse_usb,
    pci_issues,
    usb_issues,
    redfish_collection,
    redfish_delta,
    redfish_entries,
    redfish_member_kind,
    redfish_page_next_link,
    redfish_verdict,
    sel_delta,
    sensor_issues,
    write_json,
)
from vera_cycle.core.cycle_transport import Command, IdentityUnsafe

# P5032 MCTP stressor: BMC-side PLDM GetFirmwareParameters stressor. EID 16/17
# are CPU0/CPU1 on the saved P5032 BMC configuration.
MCTP_STRESSOR = "/usr/local/bin/mctp-stressor-p5032.sh"
MCTP_TARGETS = (("16", "0"), ("17", "1"))
# Diagnostic-only BMC dmesg grep: retained with the loop evidence so a stress
# failure can be explained, but never judged (only the stressor decides
# PASS/FAIL). ``|| true`` keeps grep's no-match exit 1 from surfacing as a
# collection failure on an otherwise clean loop.
MCTP_DMESG_GREP = ("dmesg -c | grep -iE 'mctp|musb|error -71|USB disconnect|"
                   "usb device|renamed from|reset|timeout' || true")

# BMC I2C inventory. Every bus is probed read-only once per PRE and once per
# loop; the output is retained as evidence under ``i2cdetect/`` and never
# produces a finding, because which addresses are populated legitimately varies
# between trays and batches. Probing is read-byte only (``-y -r``), so no device
# register is written and a bound driver (``UU``) is never disturbed. Each bus
# is individually bounded by ``timeout`` so one wedged bus cannot stall a loop.
I2C_SCAN = ("set -u; for b in $(i2cdetect -l | awk '{print $1}' | sed 's/i2c-//' | sort -n); do "
            "echo \"@BUS $b\"; timeout 15 i2cdetect -y -r \"$b\" 2>&1 || echo \"@ERROR i2c-$b exit $?\"; done")

# OS-side hardware/firmware inventory, run once per PRE. The repository copy is
# pushed to its own path so it can never overwrite the operator's
# /root/Config-Neutrino.sh - the two are maintained separately. Output is
# retained as PRE evidence only: it reports the current state and is never
# judged, so this produces no finding and cannot block a node.
# The path is a bare file under /root on purpose: SFTP does not create parent
# directories, so a dedicated subdirectory fails to upload on a node that has
# never been seeded.
HWFW_REMOTE = "/root/vera_hwfw_inventory.sh"
HWFW_RUN = f"bash {HWFW_REMOTE}"

# The inventory script colours its section headers, so every parser below reads
# ANSI-stripped text; otherwise "[FW Version]" never matches its own line.
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _plain(text):
    return _ANSI_RE.sub('', text)

# Redfish members arrive with vendor casing (Id/Severity/Created/Message) and
# are normalised to lowercase once; read either spelling so no evidence line is
# blanked when a raw entry reaches a writer through a failure path.
_REDFISH_FIELDS = {'id': ('id', 'Id'), 'severity': ('severity', 'Severity'),
                   'created': ('created', 'Created'), 'message': ('message', 'Message'),
                   'severity_key': ('severity_key', 'Severity')}


def _bus_sort_key(bus):
    """Numeric bus order, so i2c-87 sorts after i2c-9 rather than before it."""
    try:
        return (0, int(bus))
    except (TypeError, ValueError):
        return (1, str(bus))


def _entry_field(entry, field):
    if not isinstance(entry, dict):
        return ""
    for key in _REDFISH_FIELDS.get(field, (field,)):
        if key in entry and entry[key] is not None:
            return entry[key]
    return ""


PACKAGES = {"lspci": "pciutils", "dmidecode": "dmidecode", "nvme": "nvme-cli",
            "ipmitool": "ipmitool", "lsusb": "usbutils", "ip": "iproute2"}
SENSOR_RETRY_DELAY = 10
IDENTITY = "printf 'HOSTNAME='; hostname; printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id"
CAPTURES = {
    "pci": ("lspci -Dnn", False), "pci_tree": ("lspci -Dtv", False),
    "pci_verbose": ("lspci -Dvvv", True),
    "disks": ("lsblk", False), "nvme": ("nvme list", True),
    "usb": ("lsusb", False), "memory": ("free -m", False),
    "network": ("ip address show", False), "dmesg": ("dmesg", True),
    "firmware": ("dmidecode -t bios", True),
    "system": ("uname -a; cat /etc/os-release; lscpu", False),
}

class BootNotConfirmed(ConnectionError):
    """The power action was issued but the OS never came back on a new boot ID."""


def new_record(phase):
    return dict(phase=phase, started=now(), finished=None, status="PENDING", issues=[],
                evidence=[], commands={}, identities={}, identity_observations=[],
                observation_status={}, pci={}, pci_devices={}, sensors=[], action=[], recovery={},
                # Marks records written by the SEL evidence-aware schema.  The
                # renderer uses this to distinguish an unfinished new record
                # from an old record that never retained SEL metadata.
                sel_evidence_schema=1)

class AuxCycleGate:
    """Space aux-cycle commands across nodes instead of firing them together.

    An auxiliary AC cycle momentarily drops the standby rail of the whole tray,
    so issuing it to several nodes at the same instant has been observed to
    take the other nodes of that tray down with it. Only the power command is
    spaced here: PRE, POST, evidence collection and dmesg keep running
    concurrently, so a staggered campaign costs (nodes - 1) x interval, not a
    fully sequential run.

    One instance is shared by every NodeSession of a campaign and is safe to
    call from the per-node worker threads.
    """

    def __init__(self, interval):
        self.interval = max(0.0, float(interval or 0.0))
        self._lock = threading.Lock()
        self._last = None

    def wait(self, stage=None, cancelled=None):
        """Block until the current thread may issue its command.

        Holding the mutex while sleeping is deliberate: two nodes must never
        pass the gate at the same moment, which is exactly the fault being
        fixed. ``stage`` is called once on entry so the 30 s progress summary
        can attribute the wait; the countdown itself is not reported, because
        one line per second per node buries the rest of the console log.
        ``cancelled()`` lets an operator stop abort before the command is sent.
        """
        if self.interval <= 0:
            return
        with self._lock:
            if self._last is not None:
                remaining = self.interval - (time.monotonic() - self._last)
                if remaining > 0 and stage:
                    stage(f"aux cycle stagger: waiting {remaining:.0f}s")
                while remaining > 0:
                    if cancelled is not None and cancelled():
                        raise AuxCycleCancelled('Aux-cycle stagger cancelled before the command was sent')
                    time.sleep(min(1.0, remaining))
                    remaining = self.interval - (time.monotonic() - self._last)
            if cancelled is not None and cancelled():
                raise AuxCycleCancelled('Aux-cycle stagger cancelled before the command was sent')
            self._last = time.monotonic()


class AuxCycleCancelled(RuntimeError):
    """Raised when a staggered command is dropped before it reaches a node."""


class NodeSession:
    def __init__(self, target, transport, root, run_id, script, script_hash, options, rules,
                 aux_gate=None, stop_requested=None):
        self.target, self.transport, self.root = target, transport, Path(root)
        self.run_id, self.script, self.script_hash = run_id, script, script_hash
        self.options, self.rules = options, rules
        self.aux_gate = aux_gate
        self.stop_requested = stop_requested
        self.remote = f"/var/tmp/vera-{run_id}-{target.key}-{script_hash[:12]}.sh"
        # Optional stage reporter set by the campaign; keeps one_loop silent when
        # a NodeSession is driven directly (tests, dry-run).
        self.progress = None
        self.node = dict(key=target.key, target=target.__dict__, blocked=[], active=True,
                         pre=new_record("PRE"), loops=[], completed=0, attempts=0, boot_confirmed=0, valid_cycles=0, stop_reason="", stage="",
                         persistence='OK', persistence_detail='')
        self.baseline = None
        self.pre_issue_keys = {}
        self.upload_attempted = False
        self.script_verified = False
        self.hardware_execution_complete = False
        self.dmesg_seen = {}
        self.expected_boot = None
        self.cleanup_safe = True
        self.persistence_failures = []

    def stage(self, text):
        """Report the current phase for this node so the operator can see where
        the loop is, or where it is stuck. Never raises."""
        self.node["stage"] = text
        if self.progress:
            try:
                self.progress(f"{self.target.key} | {text}")
            except Exception:
                pass

    def folder(self, record):
        if record["phase"] == "START":
            return self.root / self.target.key / "start"
        return self.root / self.target.key / ("" if record["phase"] == "PRE" else f"loop{record['loop']:04d}")

    def cleanup_remote(self):
        """Remove the temporary hardware script this run pushed to the node.
        Best effort: a node that is offline or reprovisioned must not turn
        teardown into an error. Only this run's own file is touched, and a
        node that was never used (blocked at PRE) is not contacted at all."""
        if self.node["blocked"] or not self.cleanup_safe:
            return
        script = shlex.quote(self.remote)
        try:
            self.transport.ssh(self.target, "os", f"rm -f {script}", 30, True)
        except Exception:
            pass

    def persist(self, record):
        record['revision'] = record.get('revision', 0) + 1
        if record["phase"] == "PRE":
            classify_against_pre(record["issues"], set())
        else:
            classify_against_pre(record["issues"], self.pre_issue_keys)
        # A failed write must not abort the loop. Losing this sidecar is
        # recoverable (--report rebuilds from what did land), but silently
        # losing it is not: the campaign records DEGRADED and keeps cycling.
        path = self.folder(record) / ("pre_report.json" if record["phase"] == "PRE" else "report.json")
        try:
            write_json(path, record)
        except Exception as exc:
            self.note_persistence_failure(f'{path.relative_to(self.root).as_posix()}: {type(exc).__name__}: {exc}')
            record.setdefault('persistence', {})['state'] = 'FAILED'
            record['persistence']['detail'] = str(exc)
            return
        record.setdefault('persistence', {})['state'] = 'OK'

    def note_persistence_failure(self, detail):
        """Record that a record could not be archived, without disturbing the run."""
        self.persistence_failures.append(detail)
        self.node['persistence'] = 'DEGRADED'
        self.node['persistence_detail'] = self.persistence_failures[-1]


    def finish(self, record, preserve_timing=False):
        finished = record.get("finished") if preserve_timing else None
        record.update(status=health(record["issues"]), finished=finished or now())
        began = record.get("cycle_started", record["started"])
        record["duration_seconds"] = max(0, (datetime.fromisoformat(record["finished"]) - datetime.fromisoformat(began)).total_seconds())
        record['check_summary'] = {name: ('PASS' if command.get('valid') else 'FAIL')
                                   for name, command in record['commands'].items()}
        record['check_summary'].update(record.get('hardware_checks', {}))
        # Redfish logs report their own worst-severity verdict. A service that is
        # confirmed absent (merged BMC build) stays PASS; one we could not
        # discover or could not collect fully is UNAVAILABLE, never PASS.
        for stem in ('eventlog', 'redfish_sel'):
            meta = record.get(f'{stem}_meta')
            if not meta:
                continue
            if meta.get('present') is False:
                record['check_summary'][stem] = 'PASS'
            elif not (meta.get('valid') and meta.get('complete')):
                record['check_summary'][stem] = 'UNAVAILABLE'
            elif meta.get('verdict'):
                record['check_summary'][stem] = meta['verdict']
        for item in record['issues']:
            code, component = item['code'], item['component']
            stem = ('dmesg' if code.startswith('DMESG_') or 'dmesg' in component else
                    'sensor' if code.startswith('SENSOR_') else
                    'pci' if code in {'PCI_DRIFT', 'PCI_EMPTY'} else
                    'usb' if code == 'USB_DRIFT' else
                    'bmc_usb' if code == 'BMC_USB_DRIFT' else
                    'mctp' if code.startswith('MCTP_') else
                    'network' if code == 'NET_DRIFT' else
                    'eventlog' if code.startswith('REDFISH_') and component == 'eventlog' else
                    'redfish_sel' if code.startswith('REDFISH_') and component == 'redfish_sel' else
                    component if component in record['commands'] else
                    'recovery' if component == 'recovery' else 'hardware')
            if record['check_summary'].get(stem) != 'FAIL':
                record['check_summary'][stem] = item['severity']
        record['dmesg_delta'] = {severity: sum(i.get('occurrence_count', 1) for i in record['issues']
                                            if i['code'].startswith('DMESG_') and i['severity'] == severity)
                                  for severity in ('WARN', 'FAIL')}
        record['dmesg_native_error_counts'] = {severity: sum(i.get('native_error_count', 0) for i in record['issues']
                                            if i['code'].startswith('DMESG_') and i['severity'] == severity)
                                  for severity in ('WARN', 'FAIL')}
        if record['commands'].get('hardware', {}).get('state') == 'BLOCKED':
            record['check_summary']['hardware'] = 'BLOCKED'
        self.persist(record)
        return record

    def add(self, record, code, component, detail, severity="FAIL", evidence="", snippet=""):
        record["issues"].append(issue(code, component, detail, severity, evidence, snippet))

    def wait_sensor_retry(self):
        delay = getattr(self.options, 'sensor_retry_delay', SENSOR_RETRY_DELAY)
        if delay > 0:
            time.sleep(delay)

    def command(self, record, stem, role, cmd, sudo=False, timeout=90, check=True,
                save_evidence=True, record_command=True, include_output=True, filter_output=None):
        try:
            result = (self.transport.oob(self.target, cmd, timeout) if role == "oob" else
                      self.transport.ssh(self.target, role, cmd, timeout, sudo))
        except IdentityUnsafe:
            raise
        except (ConnectionError, TimeoutError, OSError) as exc:
            if not check:
                raise
            result = Command(255, f'{type(exc).__name__}: {exc}', 'NOT_ISSUED')
        evidence = ""
        if save_evidence:
            filename = f"pre_{stem}.txt" if record["phase"] == "PRE" else f"{stem}.txt"
            path = self.folder(record) / filename
            evidence = path.relative_to(self.root).as_posix()
            body = result.output if include_output else "[Command output suppressed; status retained in this evidence file.]\n"
            if filter_output is not None:
                body = filter_output(body)
            atomic_write(path, f"UTC+8: {now()}\nRole: {role}\nCommand: {cmd}\nExit: {result.code}\nState: {result.state}\nDuration: {result.duration:.2f}s\n\n{body}")
            record["evidence"].append(evidence)
        ipmi_error = (role == "oob" or cmd.startswith("ipmitool ")) and bool(re.search(r"(?:Get .+ command failed|Unable to establish|Error:|No response from|Invalid command)", result.output, re.I))
        valid = result.code == 0 and not ipmi_error
        if record_command:
            record["commands"][stem] = {"command": cmd, "role": role, "code": result.code,
                                        "state": result.state, "evidence": evidence, "valid": valid,
                                        "output_excerpt": result.output[-2000:] if not valid else ""}
        if check and result.code != 0:
            self.add(record, "COLLECTION_FAILED", stem, f"Exit {result.code} ({result.state}); see evidence", evidence=evidence)
            record['issues'][-1]['snippet'] = result.output[-2000:]
        elif check and ipmi_error:
            self.add(record, "IPMI_REPORTED_ERROR", stem, "IPMI reported a transport/command error despite exit zero; see evidence", evidence=evidence)
            record['issues'][-1]['snippet'] = result.output[-2000:]
        self.persist(record)
        return result

    def identity(self, record, role, stem=None, timeout=30, save_evidence=True, record_command=True,
                 strict_hostname=False):
        expected = getattr(self.target, role + "_hostname")
        try:
            result = self.command(record, stem or (role + "_identity"), role, IDENTITY, timeout=timeout,
                                  check=False, save_evidence=save_evidence, record_command=record_command)
        except (ConnectionError, TimeoutError, OSError):
            if record_command or stem is not None:
                record.setdefault('identity_observations', []).append(dict(
                    role=role, stage=stem or (role + '_identity'),
                    expected=expected or '', actual='', result='UNAVAILABLE',
                ))
            raise
        if result.code:
            if record_command or stem is not None:
                record.setdefault('identity_observations', []).append(dict(
                    role=role, stage=stem or (role + '_identity'),
                    expected=expected or '', actual='', result='UNAVAILABLE',
                ))
            raise ConnectionError(f"{role} identity unavailable: exit {result.code} ({result.state})")
        values = dict(re.findall(r"^(HOSTNAME|BOOT_ID)=(.*)$", result.output, re.M))
        actual = values.get("HOSTNAME", "").strip()
        boot_id = values.get("BOOT_ID", "").strip()
        # PRE is the last moment before anything on the node is touched (log
        # clearing runs right after precheck), so a wrong machine must be a hard
        # stop there. START is strict for the same reason: no cycle action may be
        # issued after an identity mismatch. During a loop the mismatch is a
        # health FAIL but is deliberately non-fatal; the node completes the
        # cycle and later nodes/loops continue. Boot-ID safety remains separate.
        mismatch = bool(expected and (
            (not actual) or actual.lower().rstrip(".") != expected.lower().rstrip(".")
        ))
        invalid_boot_id = role == 'os' and not re.fullmatch(r"[0-9a-fA-F-]{36}", boot_id)
        # Retain a compact trace of meaningful identity checks.  Polling while
        # waiting for a boot can run hundreds of times, so successful anonymous
        # polls are omitted; named stages, normal recorded checks, and every
        # mismatch are kept.  The final ``identities`` snapshot below remains
        # backward-compatible and still describes the latest check.
        if record_command or stem is not None or mismatch or invalid_boot_id:
            record.setdefault('identity_observations', []).append(dict(
                role=role, stage=stem or (role + '_identity'),
                expected=expected or '', actual=actual,
                result=('MISMATCH' if mismatch else
                        'INVALID_BOOT_ID' if invalid_boot_id else 'MATCH'),
            ))
        if expected:
            if mismatch:
                seen = actual or "<empty>"
                detail = (f"{role} hostname mismatch: inventory says '{expected}', "
                          f"host reports '{seen}'")
                if strict_hostname:
                    raise IdentityUnsafe(detail + "; PRE blocked before any changes were made")
                if not any(i.get('code') == 'HOSTNAME_MISMATCH' and i.get('component') == role
                           for i in record.get('issues', [])):
                    # Evidence is only kept for a real mismatch: at 4 nodes x 280
                    # loops a file per loop would be pure noise until it matters.
                    self.add(record, 'HOSTNAME_MISMATCH', role,
                             detail + '; loop continues, but this round remains failed',
                             severity='FAIL',
                             evidence=record.get('commands', {}).get(stem or (role + "_identity"), {}).get('evidence', ''))
        if invalid_boot_id:
            raise IdentityUnsafe("OS did not provide a valid boot ID")
        record["identities"][role] = dict(hostname=actual, boot_id=boot_id)
        return record["identities"][role]

    def dependencies(self, record):
        probe = "; ".join(f"command -v {tool} >/dev/null 2>&1 || printf 'MISSING={tool}\\n'" for tool in PACKAGES)
        result = self.command(record, "dependencies", "os", probe, check=False)
        if result.code:
            self.add(record, "DEPENDENCY_CHECK", "packages", "Could not inspect OS dependencies")
            return
        missing = re.findall(r"^MISSING=(\w+)$", result.output, re.M)
        if missing:
            packages = " ".join(sorted({PACKAGES[name] for name in missing}))
            cmd = "command -v apt-get >/dev/null && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y " + packages
            installed = self.command(record, "package_install", "os", cmd, sudo=True, timeout=900, check=False)
            if installed.code:
                self.add(record, "PACKAGE_INSTALL_FAILED", "packages", f"Automatic install failed for {packages}; exit {installed.code}")
            # The subsequent full capture is always after the installation attempt.
            verified = self.command(record, "dependencies_after_install", "os", probe, check=False)
            if verified.code or "MISSING=" in verified.output:
                self.add(record, "DEPENDENCY_MISSING", "packages", "Required OS tools remain unavailable; see installation evidence")
        mst = self.command(record, "mst_available", "os", "command -v mst", check=False)
        if mst.code:
            self.add(record, "MST_MISSING", "MST", "mst is expected in the OS image; automatic MFT installation is disabled")

    def ensure_verified_script(self, record):
        """Upload once; all later executions require the same safe file and SHA."""
        self.script_verified = False
        if not self.upload_attempted:
            self.upload_attempted = True
            self.transport.upload(self.target, self.script, self.remote)
        remote = shlex.quote(self.remote)
        safety = self.command(record, 'script_safety', 'os',
                              f'test -f {remote} && test ! -L {remote} && '
                              f'test "$(stat -c %u:%a {remote})" = "$(id -u):700"')
        if safety.code:
            raise RuntimeError('Hardware script type, owner or permissions are unsafe')
        verify = self.command(record, 'script_sha256', 'os', 'sha256sum ' + remote)
        words = verify.output.split()
        if verify.code or not words or words[0] != self.script_hash:
            raise RuntimeError('Remote hardware script hash verification failed; no execution')
        self.script_verified = True

    def collect_dmesg(self, record, stem, clear=False, save_evidence=None, evidence_stem=None,
                      wipe_only=False):
        # The plain ``dmesg`` read only establishes the baseline count; its
        # buffer is re-read verbatim by ``dmesg -c`` moments later, so keeping
        # both files would double the largest evidence artefact. Only the
        # clear variant is retained on disk, and events seen by the non-clear
        # read cite that retained file instead.
        #
        # ``wipe_only`` uses ``dmesg -C`` to discard the buffer without reading
        # its contents, so the pre-clear backlog never becomes a finding. It
        # still writes an execution certificate (output suppressed) so the
        # operator can confirm the wipe ran and its exit status.
        if save_evidence is None:
            save_evidence = clear or wipe_only
        command = 'dmesg -C' if wipe_only else 'dmesg -c' if clear else 'dmesg'
        result = self.command(record, stem, 'os', command, sudo=True,
                              save_evidence=save_evidence, include_output=not wipe_only)
        if result.code:
            record.setdefault('observation_status', {})['dmesg'] = 'UNAVAILABLE'
            # A failed read is not "no findings". Without this the loop looks
            # clean when in fact nothing was collected, which is indistinguishable
            # from a healthy kernel log.
            self.add(record, 'DMESG_COLLECT_FAILED', 'dmesg',
                     f'Kernel log collection failed: exit {result.code} ({result.state})',
                     severity='WARN', evidence=record['commands'].get(stem, {}).get('evidence', ''))
            return
        if wipe_only:
            self.dmesg_seen = {}
            return
        record.setdefault('observation_status', {})['dmesg'] = 'AVAILABLE'
        boot = record['identities'].get('os', {}).get('boot_id', '')
        events = dmesg_issues(result.output)
        # key -> observation -> times that observation has been read. A multiset
        # over observations, keyed by the normalised signature only for grouping.
        counts = {}
        for event in events:
            # The delta is over observations, not over the normalised signature.
            # A bundle's ``raw`` folds the BDF away so a PRE bundle is not
            # reclassified NEW on every boot, but that also made
            # ``0000:02:00.0: BAR assignment failed`` indistinguishable from a
            # repeat of ``0000:01:00.0`` and the second card never reached the
            # report. Observations keep the device, so a new one counts as new.
            entries = event.get('entries') or []
            capture_observations = [
                f'{entry.get("device") or "<none>"}|{entry.get("text", "")}'
                for entry in entries
                for _ in range(int(entry.get('count', 1) or 1))
            ]
            if entries:
                # Bundle ``raw`` is the set of message *types*.  It changes
                # when an overlapping second read contains A+B instead of A,
                # so using it as the outer delta key recounts A.  Bundle
                # captures instead share one stable family bucket and compare
                # their exact timestamp-free entry multisets inside it.
                key = (boot, event.get('code', ''), event.get('family', ''),
                       event.get('subtype', ''))
                observations = capture_observations
            else:
                key = (boot, event['raw'])
                observations = event.get('observations') or [event['raw']]
            before = self.dmesg_seen.get(key, {})
            after = counts.setdefault(key, {})
            pending = []
            for observation in observations:
                after[observation] = after.get(observation, 0) + 1
                if after[observation] > before.get(observation, 0):
                    pending.append(observation)
            if not pending:
                continue
            # ``pending`` is the multiset delta, not the full second capture.
            # Keep only its counts in the finding. Otherwise a first read with
            # one line followed by an overlapping read-and-clear with two lines
            # would be archived as 1 + 2 occurrences even though only two real
            # messages existed.
            event['occurrence_count'] = len(pending)
            if event.get('entries'):
                new_counts = Counter(pending)
                entries = []
                logical_pending = []
                for entry in event['entries']:
                    capture_key = (f'{entry.get("device") or "<none>"}|'
                                   f'{entry.get("text", "")}')
                    count = new_counts.get(capture_key, 0)
                    if not count:
                        continue
                    entries.append({**entry, 'count': count})
                    logical_pending.extend([entry.get('observation', '')] * count)
                event['entries'] = entries
                event['observations'] = logical_pending
                # The parser's snippet points at the first line in the full
                # capture.  An overlapping read can filter that line out as
                # already seen, so keep the finding's primary summary aligned
                # with the first retained entry while the complete raw capture
                # and evidence file remain untouched.
                if entries:
                    event['snippet'] = (f'dmesg line {entries[0].get("line", "?")}: '
                                        f'{entries[0].get("text", "")}')
                event['device'] = list(dict.fromkeys(
                    entry.get('device') for entry in entries if entry.get('device')
                ))
                family = event.get('family', 'BUNDLE')
                event['detail'] = (f'{family}: {len(entries)} distinct error/fail line(s), '
                                   f'{len(pending)} occurrence(s)')
            else:
                event['observations'] = pending
            retention = record['commands'][stem]['evidence']
            if not retention and evidence_stem:
                folder = self.folder(record).relative_to(self.root).as_posix()
                retention = f'{folder}/{evidence_stem}.txt'
            event.update(boot_id=boot, phase=stem, evidence=retention)
            if event.get('observations'):
                event['new_observations'] = list(event['observations'])
            record['issues'].append(event)
        if clear:
            self.dmesg_seen = {}
        else:
            self.dmesg_seen = counts

    def collect_bmc_i2c(self, record):
        """Retain one ``i2cdetect -y -r`` capture per BMC I2C bus.

        Evidence only: the populated address set differs legitimately between
        trays and SSD batches, so nothing here is judged. Files land in
        ``i2cdetect/`` beside the other evidence of the same loop: one file per
        bus (``i2c-81.txt``) plus the combined ``all.txt`` for quick reading.
        A probe failure is recorded as evidence, never as a finding, so a
        misbehaving bus cannot stop an otherwise healthy node.
        """
        result = self.command(record, 'bmc_i2c', 'bmc', I2C_SCAN,
                             timeout=180, check=False, save_evidence=True)
        folder = self.folder(record) / 'i2cdetect'
        sections = self._split_i2c_scan(result.output)
        for bus in sorted(sections, key=_bus_sort_key):
            atomic_write(folder / f'i2c-{bus}.txt',
                         f"UTC+8: {now()}\nBMC: {self.target.bmc_hostname or self.target.bmc_ip}\n"
                         f"Bus: i2c-{bus}\nCommand: i2cdetect -y -r {bus}\n\n{sections[bus]}")
        atomic_write(folder / 'all.txt',
                     f"UTC+8: {now()}\nBMC: {self.target.bmc_hostname or self.target.bmc_ip}\n"
                     f"Exit: {result.code}  State: {result.state}\n\n{result.output}")
        record.setdefault('i2c', {}).update(
            buses=sorted(sections, key=_bus_sort_key), count=len(sections),
            path=(folder.relative_to(self.root).as_posix()),
            state='COLLECTED' if sections else 'EMPTY')

    @staticmethod
    def _split_i2c_scan(output):
        """Split the combined scan into ``{bus_number: text}``.

        The remote loop emits ``@BUS <n>`` before each bus and ``@ERROR <bus>``
        when the probe itself failed, so a wedged bus keeps a visible section
        instead of silently disappearing from the report.
        """
        sections, current, body = {}, None, []
        for line in output.splitlines():
            marker = line.strip()
            if marker.startswith('@BUS '):
                if current is not None:
                    sections[current] = '\n'.join(body).rstrip() + '\n'
                current, body = marker.removeprefix('@BUS ').strip(), []
            elif marker.startswith('@ERROR ') and current is not None:
                body.append(line)
            elif current is not None:
                body.append(line)
        if current is not None:
            sections[current] = '\n'.join(body).rstrip() + '\n'
        return sections

    def collect_bmc_dmesg(self, record):
        """Retain the BMC's MCTP/USB dmesg grep as diagnostic evidence only.

        The BMC dmesg buffer is read-and-clear (``dmesg -c``), so PRE wipes the
        boot-time backlog first and each LOOP later keeps only its own events.
        This never produces a finding: the operator reads it to explain a
        stressor FAIL; the stressor alone decides PASS/FAIL.
        """
        self.command(record, 'bmc_dmesg', 'bmc', MCTP_DMESG_GREP,
                     timeout=60, check=False, save_evidence=True)

    def ensure_mctp_stressor(self, record):
        """Make the P5032 stressor available on the BMC before PRE uses it.

        The script lives on the BMC at ``/usr/local/bin``. When it is missing we
        push this repo's copy (hash-verified) instead of failing the run; a
        present copy is left untouched. A push failure is recorded but does not
        block the node - the stressor result will simply surface as a FAIL.
        """
        probe = self.command(record, 'mctp_stressor_probe', 'bmc',
                             f'test -x {MCTP_STRESSOR} && sha256sum {MCTP_STRESSOR}',
                             timeout=30, check=False)
        if probe.code == 0:
            record['mctp_stressor_present'] = True
            return
        local = paths.mctp_stressor_path()
        try:
            data = local.read_bytes()
            self.transport.upload_replace(self.target, 'bmc', data,
                                          MCTP_STRESSOR, mode=0o755)
        except Exception as exc:
            self.add(record, 'MCTP_STRESSOR_PUSH_FAILED', 'mctp',
                     f'Could not place {MCTP_STRESSOR} on the BMC: {exc}', severity='WARN')
            record['mctp_stressor_present'] = False
            return
        record['mctp_stressor_present'] = True
        record['mctp_stressor_pushed'] = True
        self.stage('MCTP stressor pushed to BMC')

    def ensure_hwfw_script(self, record):
        """Place this repo's hardware/firmware script on the node if it is absent.

        The operator maintains their own copy at /root/Config-Neutrino.sh; this
        one lives under its own directory and file name so neither can overwrite
        the other. A node that already carries the script is left untouched.
        """
        probe = self.command(record, 'hwfw_probe', 'os',
                             f'test -s {HWFW_REMOTE} && sha256sum {HWFW_REMOTE}',
                             timeout=30, check=False, save_evidence=False,
                             record_command=False)
        if probe.code == 0:
            record['hwfw_present'] = True
            return True
        try:
            data = paths.hwfw_script_path().read_bytes()
            self.transport.upload_replace(self.target, 'os', data, HWFW_REMOTE, mode=0o755)
        except Exception as exc:
            record['hwfw_present'] = False
            record['hwfw_state'] = 'UNAVAILABLE'
            record['hwfw_reason'] = f'Could not place {HWFW_REMOTE} on the node: {exc}'
            return False
        record['hwfw_present'] = True
        record['hwfw_pushed'] = True
        return True

    def collect_hwfw(self, record):
        """Retain the node's current hardware and firmware inventory at PRE.

        This reports the state of the machine, nothing more: no threshold is
        compared, no issue is raised and the verdict is untouched. The script's
        own ``[Fail]`` section is its expectation list rather than a measurement,
        so it is kept in the raw evidence but never promoted to a finding here.
        """
        if not self.ensure_hwfw_script(record):
            record.setdefault('hwfw', {}).update(state='UNAVAILABLE',
                                                 reason=record.get('hwfw_reason', ''))
            return
        result = self.command(record, 'hw_fw', 'os', HWFW_RUN, timeout=300,
                              check=False, save_evidence=True, record_command=False)
        text = result.output
        # ``record_command=False`` keeps this out of ``commands``, which
        # ``finish()`` turns into PASS/FAIL rows. The inventory is evidence, so
        # its path is recorded on its own and no verdict row is produced.
        evidence = next((p for p in reversed(record['evidence']) if 'hw_fw' in p), '')
        record['hwfw'] = dict(state='COLLECTED' if result.code == 0 else 'PARTIAL',
                              code=result.code,
                              totals=self._parse_hwfw_totals(text),
                              firmware=self._parse_hwfw_firmware(text),
                              evidence=evidence)

    @staticmethod
    def _parse_hwfw_totals(text):
        """``[Pass]`` rows as ``[(type, component, qty)]`` for the summary table.

        Format is ``TYPE: component xN``. The quantity is always the rightmost
        ``xN`` token, because a component name can itself contain one
        (``HFS3T8GFPGX229N 0x1 x2`` is two NVMe drives, not one).
        """
        rows, inside = [], False
        for line in _plain(text).splitlines():
            stripped = line.strip()
            if stripped == '[Pass]':
                inside = True
                continue
            if stripped.startswith('[') and stripped.endswith(']'):
                if inside:
                    break
                continue
            if not inside or not stripped:
                continue
            match = re.match(r'^(?P<kind>[A-Za-z0-9_]+)\s*:\s*(?P<body>.+)$', stripped)
            if not match:
                continue
            body = match.group('body').strip()
            qty_match = re.search(r'\s+x(\d+)$', body)
            if qty_match:
                rows.append((match.group('kind'), body[:qty_match.start()].strip(), int(qty_match.group(1))))
            else:
                rows.append((match.group('kind'), body, None))
        return rows

    @staticmethod
    def _parse_hwfw_sections(text):
        """``[Info] <name>`` blocks with their body lines, in script order."""
        sections, current = {}, None
        for line in _plain(text).splitlines():
            stripped = line.strip()
            if stripped.startswith('[Info]'):
                current = stripped.removeprefix('[Info]').strip()
                sections[current] = []
            elif stripped.startswith('[') and stripped.endswith(']'):
                current = None
            elif current is not None and stripped:
                sections[current].append(line.rstrip())
        return sections

    @staticmethod
    def _parse_hwfw_firmware(text):
        """Rows of the ``[FW Version]`` table as ``{component: version}``."""
        rows, inside = {}, False
        for line in _plain(text).splitlines():
            stripped = line.strip()
            if stripped.startswith('[FW Version]'):
                inside = True
                continue
            if inside and stripped.startswith('[') and stripped.endswith(']'):
                break
            if not inside or not stripped or stripped.startswith('---') or stripped.startswith('Component'):
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[0] != 'BMC':
                rows[parts[0]] = parts[1].strip()
        return rows

    @staticmethod
    def _parse_hwfw_expectation(text):
        """The script's own ``[Pass]``/``[Fail]`` summary lines.

        Kept separately from the measurements so the report can show what the
        script itself considered expected without implying this harness judged
        anything.
        """
        blocks, current = {}, None
        for line in _plain(text).splitlines():
            stripped = line.strip()
            if stripped in ('[Pass]', '[Fail]'):
                current = stripped.strip('[]')
                blocks[current] = []
            elif stripped.startswith('[') and stripped.endswith(']'):
                current = None
            elif current is not None and stripped:
                blocks[current].append(stripped)
        return blocks

    def run_mctp_stressor(self, record, label, eid, cpu, mode, judge):
        """Run one stressor invocation and (optionally) judge it.

        ``mode`` is ``--check`` or ``--stop-pldmd``. Only the stressor decides
        PASS/FAIL; the raw output is retained as evidence under ``label``.
        """
        cmd = f'{MCTP_STRESSOR} {eid} {mode}'
        result = self.command(record, label, 'bmc', cmd, timeout=180,
                              check=False, save_evidence=True)
        # Keep the tail of the output so the report can show the SUMMARY/iteration
        # counts even when the invocation succeeded (command() drops the excerpt
        # for a valid command). The stressor decides PASS/FAIL, not the exit code.
        if label in record['commands']:
            record['commands'][label]['output_excerpt'] = result.output[-2000:]
        if judge:
            checker = mctp_check_issues if mode == '--check' else mctp_stress_issues
            record['issues'] += checker(eid, cpu, result.output, result.code)
        return result

    def capture(self, record, post=False):
        self.hardware_execution_complete = False
        record['hardware_execution_complete'] = False
        # PRE retains its baseline. A normal loop deliberately does not read the
        # kernel buffer here: its one collection is the final ``dmesg -c`` after
        # every POST and MCTP check. This preserves the approved timing and avoids
        # adding a before-reboot or early-POST capture.
        if not post:
            self.collect_dmesg(record, 'dmesg', save_evidence=True)
        # BMC I2C inventory: once for PRE and once per loop, retained as evidence
        # only (never judged). A loop's only capture() call is the POST one, so
        # this must run on either pass; ``i2c`` on the record marks it done and
        # keeps a record from scanning its buses twice.
        if 'i2c' not in record:
            self.collect_bmc_i2c(record)
        for stem, (cmd, sudo) in CAPTURES.items():
            if stem == 'dmesg':
                continue
            # ``pci_verbose`` is parsed in full from the in-memory output; only
            # the on-disk evidence is narrowed to link-bearing end devices so
            # the artefact stays reviewable without duplicating hardware.txt.
            result = self.command(record, stem, "os", cmd, sudo=sudo,
                                  filter_output=filter_pci_verbose if stem == 'pci_verbose' else None)
            if stem == "pci":
                record["pci"] = parse_pci(result.output) if result.code == 0 else {}
                record['observation_status']['pci'] = (
                    'AVAILABLE' if result.code == 0 and bool(record['pci']) else 'UNAVAILABLE')
                record["pci_devices"] = merge_pci_devices(record["pci"], record.get("pci_verbose", {}))
                if not record["pci"]:
                    self.add(record, "PCI_EMPTY", "PCIe", "No valid full-BDF PCI inventory")
                elif post:
                    record["issues"] += pci_issues(self.baseline["pci"], record["pci"])
            elif stem == "pci_verbose" and result.code == 0:
                record["pci_verbose"] = parse_pci_verbose(result.output)
                record["pci_devices"] = merge_pci_devices(record.get("pci", {}), record["pci_verbose"])
            elif stem == "usb" and result.code == 0:
                record["usb"] = parse_usb(result.output)
                record['observation_status']['usb'] = 'AVAILABLE'
                if post:
                    record["issues"] += usb_issues(self.baseline["usb"], record["usb"])
            elif stem == "usb":
                record['observation_status']['usb'] = 'UNAVAILABLE'
            elif stem == "network" and result.code == 0:
                record["network_ifaces"] = parse_network(result.output)
                record['observation_status']['network'] = 'AVAILABLE'
                if post:
                    record["issues"] += network_issues(self.baseline["network"], record["network_ifaces"])
            elif stem == "network":
                record['observation_status']['network'] = 'UNAVAILABLE'
        # BMC-side USB tree: PRE builds the baseline, each LOOP compares it. The
        # BMC sees the CPU MCTP endpoints behind its virtual hub, so a vanished
        # endpoint names the EID path that dropped. Identity is port + vid:pid.
        # check=True matches the OS usb/network captures: a failed inventory is a
        # COLLECTION_FAILED finding, not a silent skip of the drift comparison.
        bmc_usb = self.command(record, "bmc_usb", "bmc", "lsusb -tv", timeout=60,
                               save_evidence=True)
        if bmc_usb.code == 0:
            record["bmc_usb"] = parse_bmc_lsusb(bmc_usb.output)
            record['observation_status']['bmc_usb'] = 'AVAILABLE'
            if post:
                record["issues"] += bmc_usb_issues(self.baseline["bmc_usb"], record["bmc_usb"])
        else:
            record['observation_status']['bmc_usb'] = 'UNAVAILABLE'
        try:
            self.ensure_verified_script(record)
        except IdentityUnsafe:
            raise
        except Exception as exc:
            self.add(record, 'SCRIPT_VALIDATION_FAILED', 'hardware', str(exc))
            record['commands']['hardware'] = dict(valid=False, state='BLOCKED', evidence='')
            self.node.update(active=False, stop_reason='Hardware script validation failed')
            if not post:
                self.node['blocked'].append('Cannot run the verified hardware script')
        if self.script_verified:
            ratio = getattr(self.options, 'memory_min_ratio', 0.9)
            config = self.command(record, "hardware", "os", f"MEMORY_MIN_RATIO={ratio} bash " + shlex.quote(self.remote), sudo=True, timeout=180, check=False)
            findings = config_issues(config.output, config.code)
            record["issues"] += findings
            lines = [line.strip() for line in config.output.splitlines() if line.strip()]
            results = [line for line in lines if line.startswith('RESULT|')]
            expected_result = {0: 'RESULT|PASS', 1: 'RESULT|FAIL'}.get(config.code)
            self.hardware_execution_complete = bool(
                config.state == 'RETURNED' and expected_result and results == [expected_result]
                and lines[-1] == expected_result
                and not (config.code == 0 and findings))
            record['hardware_execution_complete'] = self.hardware_execution_complete
            if not self.hardware_execution_complete:
                self.add(record, 'HARDWARE_EXECUTION_INCOMPLETE', 'hardware',
                         f'Execution not confirmed: state={config.state}, exit={config.code}, final result={results}',
                         evidence=record['commands']['hardware']['evidence'])
                self.node.update(active=False, stop_reason='Hardware script execution incomplete')
                if not post:
                    self.node['blocked'].append('Hardware script execution incomplete')
            record['hardware_checks'] = {}
            record['hardware_check_details'] = {}
            record['nic_slots'] = {}
            for line in config.output.splitlines():
                if line.startswith('CHECK|'):
                    cells = line.split('|')
                    name = cells[1]
                    values = dict(c.split('=', 1) for c in cells[2:] if '=' in c)
                    if name == 'NIC_SLOT' and 'slot' in values:
                        record['nic_slots'][values['slot'].lower()] = values.get('state', 'PRESENT')
                        continue
                    # Raw per-slot evidence, not a health validation: the mst row
                    # and a non-NIC device (GPU) on a NIC position must not be
                    # badged PASS/FAIL as a hardware check. Their content stays
                    # in the hardware.txt evidence and the NIC slot inventory.
                    if name in {'NIC_MST_ROW', 'NIC_NON_CARD'}:
                        continue
                    component = values.get('bdf', name)
                    state = 'UNSUPPORTED' if values.get('state') == 'unsupported' else 'PASS'
                    # NIC_DEGRADED is a validation whose finding component is
                    # 'NIC'; without this mapping it defaults to PASS while its
                    # own NIC finding is FAIL.
                    related = {'CPU_ONLINE': 'CPU', 'MEMORY_VISIBLE': 'DIMM', 'BF4_IDENTITIES': 'BF4',
                               'NIC_DEGRADED': 'NIC', 'NIC_MISSING': 'NIC'}.get(name, component)
                    if any(i['component'] in {component, related} for i in findings):
                        state = 'FAIL'
                    key = f'{name}/{component}' if 'bdf' in values else name
                    record['hardware_checks'][key] = state
                    record['hardware_check_details'][key] = dict(name=name, values=values, raw=line, status=state)
            # Compare the NIC slot inventory against the PRE baseline so a card
            # that is present at PRE but absent (removed) or degraded (non-Vera
            # device type) after a loop is named by BDF, not just counted.
            if post and self.baseline and 'nic' in self.baseline:
                record['issues'] += nic_slot_issues(self.baseline['nic'], record.get('nic_slots', {}))
        record['script_verified'] = self.script_verified
        sensor = self.command(record, "sensor", "oob", "sensor list")
        sensor_valid = record['commands']['sensor']['valid']
        record["sensors"] = parse_sensors(sensor.output) if sensor_valid else []
        # PRE has no baseline to confirm against, but a transport/command
        # failure is still safe to retry once just like the LOOP path.  Keep
        # the first failure and both evidence files; a successful retry only
        # supplies the rows used for the current phase's validation.
        if not post and not sensor_valid:
            self.wait_sensor_retry()
            retry = self.command(record, 'sensor_retry', 'oob', 'sensor list')
            sensor_valid = record['commands']['sensor_retry']['valid']
            if sensor_valid:
                record['sensors'] = parse_sensors(retry.output)
        if post:
            valid = record['commands']['sensor']['valid']
            if not valid:
                self.wait_sensor_retry()
                retry = self.command(record, 'sensor_retry', 'oob', 'sensor list')
                valid = record['commands']['sensor_retry']['valid']
                if valid:
                    record['sensors'] = parse_sensors(retry.output)
            confirmation = None
            if valid and missing_sensors(self.baseline["sensors"], record["sensors"]):
                self.wait_sensor_retry()
                retry = self.command(record, "sensor_confirm", "oob", "sensor list")
                if record['commands']['sensor_confirm']['valid']:
                    confirmation = parse_sensors(retry.output)
                    record['sensor_confirmation'] = confirmation
                else:
                    valid = False
                    self.add(record, 'SENSOR_CONFIRM_FAILED', 'sensors', 'Reread failed; sensor disappearance cannot be confirmed from a failed collection')
            if valid:
                record["issues"] += compare_sensors(self.baseline["sensors"], record["sensors"], confirmation)
            else:
                record['issues'] += sensor_issues(record['sensors'])
        else:
            record["issues"] += sensor_issues(record["sensors"])
        sensor_observation_valid = valid if post else sensor_valid
        sensor_observation_rows = (record.get('sensor_confirmation')
                                   if 'sensor_confirmation' in record else record['sensors'])
        sensor_content_usable = bool(sensor_observation_rows) and all(
            not row.get('format_error') for row in sensor_observation_rows
        )
        record['observation_status']['sensor'] = (
            'AVAILABLE' if sensor_observation_valid and sensor_content_usable else 'UNAVAILABLE')
        sel = self.sel_command(record, "sel", "list", save_evidence=True)
        sel_meta = self._sel_metadata(record, 'sel', sel.output, 'POST' if post else 'PRE')
        if post:
            record['sel_post_meta'] = sel_meta
        else:
            record['sel_collection'] = sel_meta
        if post:
            valid = record['commands']['sel']['valid'] and record.get('sel_before_valid', False)
            record['sel_status'] = 'REVIEW REQUIRED' if valid else 'COLLECTION FAILED'
            record['sel_events'] = sel_delta(record.get('sel_before', ''), sel.output).splitlines() if valid else None
            if valid:
                path = self.folder(record) / "sel_delta.txt"
                atomic_write(path, "\n".join(record['sel_events']) or "No new SEL records.\n")
                record['evidence'].append(path.relative_to(self.root).as_posix())
                record['sel_delta_meta'] = dict(phase='LOOP', status='COMPARED', valid=True,
                                                new_event_count=len(record['sel_events']),
                                                evidence=path.relative_to(self.root).as_posix(),
                                                reason='Before-cycle and POST SEL snapshots were valid')
            else:
                reason = 'Before-cycle SEL collection was unavailable'
                if not record['commands']['sel'].get('valid', False):
                    reason = 'POST SEL collection was unavailable or malformed'
                record['sel_delta_meta'] = dict(phase='LOOP', status='UNAVAILABLE', valid=False,
                                                new_event_count=None, evidence='', reason=reason)
            record.pop('sel_before', None)
        # Redfish EventLog/SEL: collection failure is a finding, but an absent
        # service (merged build) or a benign entry is not. Verdict is by worst
        # severity; POST adds a content delta against the before-cycle snapshot.
        try:
            self.collect_redfish(record)
        except Exception as exc:
            self.add(record, 'REDFISH_UNAVAILABLE', 'eventlog',
                     f'Redfish BMC log collection unavailable: {exc}')
            for stem in ('eventlog', 'redfish_sel'):
                record.setdefault('commands', {}).setdefault(stem, {"command": "redfish", "role": "oob",
                    "code": 255, "state": "NOT_ISSUED", "evidence": "", "valid": False, "output_excerpt": str(exc)})
                record.setdefault(f'{stem}_meta', dict(
                    phase='COLLECT', status='UNAVAILABLE', present=None,
                    verdict='UNAVAILABLE',
                    counts={"Critical": 0, "Warning": 0, "OK": 0, "Other": 0},
                    evidence='', entries=[], complete=False, valid=False,
                    reason=str(exc),
                ))
        if post:
            self._redfish_loop_delta(record)
        self.command(record, "bmc_firmware", "oob", "mc info")
        power = self.command(record, "power", "oob", "power status")
        record["power_on"] = record['commands']['power']['valid'] and bool(re.search(r"Chassis Power is on", power.output, re.I))
        if not record["power_on"]:
            self.add(record, "POWER_NOT_ON", "power", "BMC did not confirm chassis power on")
        bmc = self.command(record, "host_power", "bmc", "/usr/bin/powerctrl.sh power_status")
        if bmc.code == 0 and not ("Host: Running" in bmc.output and "Chassis Power: On" in bmc.output):
            self.add(record, "HOST_NOT_RUNNING", "power", "BMC power_status did not confirm Host: Running and Chassis Power: On")
        # dmesg is NOT read here. One read-and-clear per loop, at the very end of
        # the loop (see ``one_loop``), captures the whole boot -- including the
        # MCTP stress that runs after this capture.
        for item in record["issues"]:
            if not item.get("evidence"):
                component = item["component"]
                stem = component if component in record['commands'] else "sensor" if item["code"].startswith("SENSOR") else "pci" if item["code"] == "PCI_DRIFT" else "dmesg" if component == "dmesg" else "hardware"
                item["evidence"] = record["commands"].get(stem, {}).get("evidence", "")

    def _prepare_clean_state(self, record):
        """Clear dmesg, IPMI SEL and Redfish logs before the PRE baseline.

        dmesg: `dmesg -C` discards the pre-PRE backlog without reading it, so
        the boot-to-PRE noise never enters the PRE baseline (previously
        `dmesg -c` read and cleared, making that backlog a finding).

        IPMI SEL: `sel clear` does NOT return the contents, and blindly clearing
        an erroring SEL would destroy unread evidence, so SEL is read first
        (`sel list`); only a healthy SEL is cleared.

        Redfish clear is driven from collect_redfish(clear=True).
        """
        # dmesg: `dmesg -C` wipes only; failure means no clear.
        self.collect_dmesg(record, "pre_dmesg_clear", wipe_only=True)
        if not record['commands']['pre_dmesg_clear']['valid']:
            self.add(record, 'CLEAR_SKIPPED', 'dmesg', 'PRE dmesg could not be cleared', severity='WARN')
        # IPMI SEL: read first; `sel clear` returns no contents, so a broken SEL
        # must be left intact rather than wiped blind. The probe keeps its
        # output (the pre-clear SEL contents); the clear keeps an execution
        # certificate so the operator can confirm it ran.
        self.sel_command(record, "pre_sel_probe", "list", save_evidence=True)
        if record['commands']['pre_sel_probe']['valid']:
            self.sel_command(record, "pre_sel_clear", "clear", save_evidence=True, include_output=False)
        else:
            self.add(record, 'CLEAR_SKIPPED', 'sel', 'PRE SEL read failed; original was not cleared', severity='WARN')
        # Redfish EventLog/SEL: collect_redfish(clear=True, history=True) reads
        # the pre-existing backlog then clears it. The backlog is clean-start
        # history, so it is kept for diagnosis only and never enters the PRE
        # baseline findings; a failed read/clear still surfaces.
        try:
            self.collect_redfish(record, clear=True, history=True)
        except Exception as exc:
            self.add(record, 'CLEAR_SKIPPED', 'eventlog',
                     f'Redfish logs could not be read/cleared before PRE: {exc}', severity='WARN')

    def precheck(self):
        record = self.node["pre"]
        self.persist(record)
        try:
            # Identity first, and strictly: PRE runs before any log is cleared,
            # so this is the last chance to refuse a machine that does not match
            # the inventory without having touched it.
            for role, _, _ in self.target.endpoints():
                self.identity(record, role, strict_hostname=True)
            uid = self.command(record, "root_uid", "os", "id -u", sudo=True, check=False)
            if uid.code or uid.output.strip() != "0":
                self.add(record, "ROOT_UNAVAILABLE", "privileges", "Root execution is unavailable; privileged checks may fail")
            self.dependencies(record)
            # Clean-start policy: clear dmesg, IPMI SEL and the BMC Redfish logs
            # BEFORE the PRE baseline is captured, so the baseline (and every
            # later loop delta) reflect only this campaign. No pre-clear backlog
            # is retained by operator decision. Each log is probed first so a
            # log we cannot read is never wiped blind.
            self._prepare_clean_state(record)
            self.capture(record)
            # Sensor parse/health failures remain visible PRE FAIL findings. The
            # operator must be able to review them and decide whether to run;
            # only the PCI baseline is required to keep cycle comparisons safe.
            if not record["pci"]:
                self.node["blocked"].append("PRE PCI baseline is unavailable")
            self.baseline = dict(pci=record["pci"].copy(), sensors=[r.copy() for r in record["sensors"]],
                                 nic=dict(record.get("nic_slots", {})),
                                 usb=dict(record.get("usb", {})),
                                 network=dict(record.get("network_ifaces", {})),
                                 bmc_usb=dict(record.get("bmc_usb", {})))
            # Hardware/firmware inventory: reports what the node currently
            # carries. Never compared against anything, so it cannot change a
            # verdict and a missing script cannot block the node.
            self.collect_hwfw(record)
            # P5032 MCTP/USB preflight. The 4 stressor runs are the test baseline
            # (operator: their PASS/FAIL is the criterion), so a failure here is a
            # real FAIL. BMC dmesg grep is diagnostic evidence only.
            self.ensure_mctp_stressor(record)
            self.collect_bmc_dmesg(record)
            for eid, cpu in MCTP_TARGETS:
                self.run_mctp_stressor(record, f'mctp_check_{eid}', eid, cpu, '--check', judge=True)
            for eid, cpu in MCTP_TARGETS:
                self.run_mctp_stressor(record, f'mctp_stress_{eid}', eid, cpu, '--stop-pldmd', judge=True)
            self.pre_issue_keys = issue_baseline(record["issues"])
            self.expected_boot = record['identities']['os']['boot_id']
        except Exception as exc:
            if isinstance(exc, IdentityUnsafe):
                self.cleanup_safe = False
            self.node["blocked"].append(str(exc))
            self.add(record, "PRE_BLOCKED", "identity", str(exc))
        # PRE timing ends when the PRE capture finishes. Clearing dmesg/SEL is
        # campaign preparation and must not inflate the displayed PRE duration.
        self.finish(record, preserve_timing=True)
        return self.node

    def _sel_metadata(self, record, stem, output, phase):
        command = record.get('commands', {}).get(stem, {})
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        event_count = sum(1 for line in lines if '|' in line and re.match(r'^[0-9a-f]+\s*\|', line, re.I))
        valid = bool(command.get('valid'))
        return dict(phase=phase, status='COLLECTED' if valid else 'FAILED', valid=valid,
                    command=command.get('command', 'sel list'),
                    state=command.get('state', 'UNKNOWN'), code=command.get('code'),
                    evidence=command.get('evidence', ''), event_count=event_count if valid else None,
                    reason='' if valid else 'SEL command failed or returned an unrecognized format')

    def sel_command(self, record, stem, action, **kwargs):
        # SEL is always collected over OOB (ipmitool -I lanplus to the BMC), even
        # for the inband power channel: the OS-side ipmitool path needs /dev/ipmi0,
        # which is absent on this reworked platform and returned no entries.
        result = self.command(record, stem, 'oob', 'sel ' + action, **kwargs)
        if action == 'list' and record['commands'][stem]['valid']:
            lines = [line.strip() for line in result.output.splitlines() if line.strip()]
            empty = len(lines) == 1 and lines[0].lower().rstrip('.') == 'sel has no entries'
            # One SEL entry per line. A line must be a record (leading id + pipe);
            # any other non-empty line -- in particular a multi-role footer such
            # as ``Root|...`` -- is a malformed capture, not an entry, so the
            # capture is rejected as unrecognized rather than counted.
            records = bool(lines) and all(re.match(r'^[0-9a-f]+\s*\|', line, re.I) for line in lines)
            if not empty and not records:
                record['commands'][stem].update(valid=False, output_excerpt=result.output[-2000:])
                self.add(record, 'SEL_FORMAT_ERROR', stem, 'SEL list returned empty or unrecognized output; event count is unavailable', evidence=record['commands'][stem]['evidence'])
                record['issues'][-1]['snippet'] = result.output[-2000:] or '(empty output)'
                self.persist(record)
        return result

    # --- Redfish BMC log services (EventLog / SEL) -----------------------
    # Different vendors' OpenBMC builds use different resource IDs and may or
    # may not expose a separate SEL service, so nothing here is hard-coded:
    # we discover the System id and its LogServices, then fetch whatever exists.

    def _redfish_discover(self, token):
        """Return dict(system_id, services={name: odata_id}, token, listing_valid, reason).

        A failed or unreadable discovery is NOT the same as an empty service
        list: ``listing_valid`` stays false and callers must not conclude that
        any particular service is absent. Only a successfully read, structurally
        valid LogServices collection lets us say a service is NOT PRESENT.

        The caller owns the session: ``token`` is the already-issued X-Auth-Token
        and is reused for every request below (never a second login), so the
        caller can guarantee its release even if any of these steps raise.
        """
        systems = self.transport.redfish_get(self.target, "/redfish/v1/Systems", token)
        if systems.code or not systems.output:
            raise RuntimeError("Redfish /Systems unavailable")
        payload = self._redfish_json(systems.output)
        members, valid, reason = redfish_collection(payload)
        if not valid or not members:
            raise RuntimeError(reason or "Redfish /Systems returned no members")
        first = members[0] if isinstance(members[0], dict) else {}
        system_id = str(first.get("@odata.id", "")).rstrip("/").split("/")[-1]
        if not system_id:
            raise RuntimeError("Redfish /Systems member has no @odata.id")
        listing_path = f"/redfish/v1/Systems/{system_id}/LogServices"
        # LogServices can itself be paginated; a nextLink on page 1 must be
        # followed, otherwise a service that only appears on page 2 would be
        # wrongly reported as NOT PRESENT.
        collected = self._redfish_fetch_collection(listing_path, token, expect='reference')
        if not (collected['valid'] and collected['complete']):
            return dict(system_id=system_id, services={}, token=token, listing_valid=False,
                        reason=f"LogServices listing incomplete: {collected.get('reason', '')}")
        mapping = {}
        for entry in collected['entries']:
            path = str(entry.get('path') or entry.get('odata_id') or '')
            if path:
                mapping[path.rstrip("/").split("/")[-1]] = path
        return dict(system_id=system_id, services=mapping, token=token, listing_valid=True, reason="")

    def _redfish_token(self):
        return self.transport.redfish_login(self.target)

    def _redfish_logout(self, token, record=None):
        """Release a Redfish session, downgrading logout failure to evidence.

        A logout that fails (or a BMC that does not expose a DELETE path) must
        never turn a valid collection into a FAIL and must never re-trigger any
        power/cycle action. The worst case is a WARN finding so an operator can
        see the leak instead of it silently exhausting the BMC session table.

        A transport-level failure (HTTP 500, timeout, lost response) is returned
        as a non-zero ``Command`` rather than raised, so the return value is
        inspected too: any unconfirmed release is a WARN, never a silent
        success.
        """
        if not token:
            return
        try:
            result = self.transport.redfish_logout(self.target, token)
            released = result is None or not getattr(result, 'code', 1)
            reason = None if released else f"state={getattr(result, 'state', 'UNKNOWN')}, exit={getattr(result, 'code', '?')}"
        except Exception as exc:
            released, reason = False, str(exc)
        if released:
            return
        if record is not None:
            self.add(record, 'REDFISH_LOGOUT_FAILED', 'redfish',
                     f'Redfish session logout not confirmed; session may remain open on the BMC: {reason}',
                     severity='WARN')

    @contextmanager
    def _redfish_session(self, record=None):
        """Discover a session and guarantee logout, whatever the caller does.

        The login happens *before* the ``try`` so its token can be released in
        ``finally`` even when discovery itself raises: the previous shape logged
        in inside ``_redfish_discover`` and only entered the ``try`` afterwards,
        so a /Systems failure leaked one BMC session per collection. When login
        itself fails there is no session to release and no fabricated logout.
        """
        token = self._redfish_token()
        try:
            disc = self._redfish_discover(token)
            yield disc
        finally:
            self._redfish_logout(token, record=record)

    @staticmethod
    def _redfish_json(text):
        import json as _json
        start = text.find("{")
        if start < 0:
            return None
        try:
            return _json.loads(text[start:])
        except ValueError:
            return None

    @staticmethod
    def _redfish_valid_entry(item):
        """True when a referenced member is a structurally valid LogEntry.

        A JSON-decoded object that carries no event identity/content (e.g. an
        empty ``{}`` or a payload missing both Id and Message) is unreadable: it
        is not "an event with no problems". Treating it as a valid OK entry would
        let a malformed referenced member turn a collection into a false PASS, so
        it must fail closed instead. A vendor entry with an unknown/blank
        Severity is still valid - only the identity/content keys are required,
        so a legacy ``{Id, Message, Severity:""}`` entry is never misjudged.
        """
        return isinstance(item, dict) and any(k in item for k in ("Id", "Message"))

    # Bound pagination so an anomalous BMC nextLink cannot loop forever.
    REDFISH_MAX_PAGES = 20

    def _redfish_fetch_collection(self, path, token, expect='entry'):
        """Fetch a (possibly paginated) Redfish collection.

        Follows ``Members@odata.nextLink`` until the collection is complete.
        Returns dict(entries, valid, complete, reason, pages). A page-1 success
        with a failing page 2 is INCOMPLETE, never a complete PASS; the entries
        already gathered are retained for evidence.

        ``expect`` selects how members are interpreted:

          * ``'entry'``  - log entries. Expanded objects are normalised; bare
            ``@odata.id`` references are fetched and normalised. Entries are
            normalised on *every* return path - including failure paths - so the
            evidence writer always sees id/severity/message instead of raw vendor
            keys and never renders a blank line for an event it did receive.

          * ``'reference'`` - a service listing whose members are ``@odata.id``
            links (the LogServices case). The links are kept as ``path`` values,
            not fetched, so the caller can address the service directly.
        """
        entries = []
        seen = set()
        pages = 0
        current = path
        while current and current not in seen:
            if pages >= self.REDFISH_MAX_PAGES:
                return dict(entries=entries, valid=True, complete=False,
                            reason=f"pagination exceeded {self.REDFISH_MAX_PAGES} pages", pages=pages)
            seen.add(current)
            pages += 1
            result = self.transport.redfish_get(self.target, current, token)
            if result.code:
                return dict(entries=entries, valid=False, complete=False,
                            reason=f"collection page failed: HTTP {getattr(result, 'http_status', 0) or result.code} ({result.state})",
                            pages=pages, failed_path=current)
            payload = self._redfish_json(result.output)
            members, valid, reason = redfish_collection(payload)
            if not valid:
                return dict(entries=entries, valid=False, complete=False,
                            reason=f"collection page unreadable: {reason}", pages=pages, failed_path=current)
            resolved, bad = self._redfish_resolve_members(members, token, expect)
            if bad:
                # A member we cannot interpret is not "zero events".
                return dict(entries=entries, valid=False, complete=False,
                            reason=f"collection page has unusable member: {bad}", pages=pages, failed_path=current)
            entries.extend(resolved)
            link = redfish_page_next_link(payload)
            if not link:
                return dict(entries=entries, valid=True, complete=True,
                            reason="", pages=pages)
            # A relative nextLink (e.g. "/redfish/v1/...") is used verbatim; an
            # absolute URL is reduced to its path so the request still goes to
            # the same BMC endpoint over the authenticated session.
            current = self._redfish_link_path(link)
        if current in seen:
            return dict(entries=entries, valid=True, complete=False,
                        reason="pagination loop detected (repeated nextLink)", pages=pages)
        return dict(entries=entries, valid=True, complete=True, reason="", pages=pages)

    def _redfish_resolve_members(self, members, token, expect='entry'):
        """Normalise members according to ``expect``.

        Returns ``(entries, problem)``. ``problem`` is a message when a member is
        neither an expanded entry nor a resolvable reference - the caller must
        treat that collection as unreadable rather than as zero events.
        """
        entries = []
        for index, member in enumerate(members):
            kind = redfish_member_kind(member)
            if kind == "entry":
                entry = self._redfish_normalise_entry(member)
                if expect == 'reference':
                    # An expanded service object: keep its own address.
                    entry['path'] = str(member.get("@odata.id", "") or "")
                entries.append(entry)
                continue
            if kind == "reference":
                ref = str(member.get("@odata.id", "") or "").strip()
                if expect == 'reference':
                    entries.append(dict(path=ref))
                    continue
                result = self.transport.redfish_get(self.target, self._redfish_link_path(ref), token)
                if result.code:
                    return entries, f"reference {ref} could not be fetched (HTTP {getattr(result, 'http_status', 0) or result.code})"
                target = self._redfish_json(result.output)
                if not self._redfish_valid_entry(target):
                    # A referenced member that is unreadable (truncated JSON,
                    # empty object, or missing both Id and Message) is a
                    # collection integrity failure, not "an event with nothing
                    # wrong". Fail closed so it can never become a false PASS.
                    return entries, f"reference {ref} is not a valid LogEntry"
                entries.append(self._redfish_normalise_entry(target))
                continue
            return entries, f"Members[{index}] has no Id/Severity/Message and no @odata.id"
        return entries, ""

    @staticmethod
    def _redfish_link_path(link):
        link = link.strip()
        if link.startswith("http://") or link.startswith("https://"):
            from urllib.parse import urlsplit
            split = urlsplit(link)
            return split.path + (("?" + split.query) if split.query else "")
        return link

    @staticmethod
    def _redfish_normalise_entry(item):
        """Normalise one validated member object to the lowercase entry schema."""
        severity = str(item.get("Severity", "") or "")
        return dict(
            id=str(item.get("Id", "") or ""),
            severity=severity,
            severity_key=severity.strip().lower(),
            created=str(item.get("Created", "") or ""),
            message=str(item.get("Message", "") or ""),
            resolved=bool(item.get("Resolved", False)),
        )

    def _redfish_stem(self, name):
        return 'eventlog' if name == 'EventLog' else 'redfish_sel'

    def collect_redfish(self, record, clear=False, history=False):
        """Fetch EventLog and (if present) SEL for this node.

        Called once per phase. On ``clear`` the same entries are fetched first
        (already handled by callers storing evidence) and then each service is
        cleared. Three states are kept distinct:

          * a service confirmed absent (valid listing, no such member) is
            NOT PRESENT / PASS  - the merged-BMC layout, not a failure;
          * a service whose discovery or collection failed is UNAVAILABLE /
            FAIL - "we do not know", never "we confirmed there is nothing";
          * a service collected successfully with severity Critical/Warning
            contributes a canonical FAIL/WARN issue so the record status and
            campaign health reflect it (not just the Redfish sub-verdict).

        ``history=True`` is the pre-PRE clean-state read: the entries fetched
        here are the pre-existing backlog that is about to be cleared, so they
        are evidence of the clean-up step only. They must NOT enter the PRE
        baseline's issue list or health (clean-start policy), and their
        evidence goes to a separate file so the later post-clear capture of
        ``pre_eventlog.txt`` cannot overwrite it. Collection/clear failures
        still surface - only the *historical event findings* are suppressed.
        """
        with self._redfish_session(record) as disc:
            record['redfish_system_id'] = disc['system_id']
            record['redfish_services'] = sorted(disc['services'])
            if history:
                record['redfish_preclear'] = {}
            for name in ('EventLog', 'SEL'):
                path = disc['services'].get(name)
                stem = self._redfish_stem(name)
                if not path:
                    if disc['listing_valid']:
                        # Confirmed absent on a readable listing: not a failure.
                        record['commands'][stem] = {"command": f"redfish {name}", "role": "oob",
                                                    "code": 0, "state": "NOT_PRESENT", "evidence": "",
                                                    "valid": True, "output_excerpt": ""}
                        record[f'{stem}_meta'] = dict(phase='COLLECT', status='NOT PRESENT', present=False,
                                                      verdict='PASS', counts={"Critical": 0, "Warning": 0, "OK": 0, "Other": 0},
                                                      entries=[], complete=True, valid=True,
                                                      reason=f'No {name} log service on this BMC')
                    else:
                        # Discovery failed: we cannot tell whether the service exists.
                        record['commands'][stem] = {"command": f"redfish {name}", "role": "oob",
                                                    "code": 1, "state": "UNAVAILABLE", "evidence": "",
                                                    "valid": False, "output_excerpt": disc.get('reason', '')}
                        record[f'{stem}_meta'] = dict(phase='COLLECT', status='UNAVAILABLE', present=None,
                                                      verdict='UNAVAILABLE', counts={"Critical": 0, "Warning": 0, "OK": 0, "Other": 0},
                                                      entries=[], complete=False, valid=False,
                                                      reason=disc.get('reason') or 'Redfish LogServices discovery failed')
                        self.add(record, 'REDFISH_UNAVAILABLE', stem,
                                 f'Redfish {name} service could not be discovered; see reason',
                                 snippet=disc.get('reason', ''))
                    record[f'{stem}_entries'] = []
                    continue
                entries_path = path + "/Entries"
                fetched = self._redfish_fetch_collection(entries_path, disc['token'])
                entries = fetched['entries']
                valid = fetched['valid']
                complete = fetched['complete']
                verdict, counts = redfish_verdict(entries) if (valid and complete) else (
                    "UNAVAILABLE", {"Critical": 0, "Warning": 0, "OK": 0, "Other": 0})
                evidence = self._write_redfish_evidence(record, stem, name, entries_path, fetched, verdict, counts,
                                                        history=history)
                record['commands'][stem] = {"command": f"redfish {name} ({entries_path})", "role": "oob",
                                            "code": 0 if (valid and complete) else 1,
                                            "state": 'COLLECTED' if (valid and complete) else 'UNAVAILABLE',
                                            "evidence": evidence, "valid": valid and complete,
                                            "output_excerpt": "" if (valid and complete) else fetched.get('reason', '')}
                record[f'{stem}_meta'] = dict(phase='COLLECT', status='COLLECTED' if (valid and complete) else 'UNAVAILABLE',
                                              present=True, verdict=verdict, counts=counts, evidence=evidence,
                                              entries=entries, path=entries_path, complete=complete, valid=valid,
                                              reason='' if (valid and complete) else fetched.get('reason', 'Redfish collection incomplete'))
                record[f'{stem}_entries'] = entries
                if history:
                    # Record the pre-clear backlog as diagnostic metadata only; it is
                    # not a PRE finding (it is about to be cleared).
                    record['redfish_preclear'][stem] = dict(
                        status=record[f'{stem}_meta']['status'], counts=counts, evidence=evidence,
                        entry_count=len(entries), valid=valid, complete=complete)
                if not (valid and complete):
                    self.add(record, 'REDFISH_COLLECTION_FAILED', stem,
                             f'Redfish {name} collection failed or incomplete; see evidence',
                             evidence=evidence, snippet=fetched.get('reason', ''))
                elif not history:
                    # Propagate severity into the canonical issue model so record
                    # status and campaign health cannot stay PASS behind a failing
                    # EventLog/SEL sub-verdict. Pre-clear history is excluded.
                    self._redfish_severity_issues(record, name, stem, entries, evidence)
                if clear and valid and complete:
                    self._redfish_clear_service(record, name, path, disc['token'], stem)
            if history:
                # The clear-state read is diagnosis only; it must not define the
                # baseline meta/verdict. Restore the pre-clear keys so the later
                # post-clear capture() populates the real PRE baseline.
                for name in ('EventLog', 'SEL'):
                    stem = self._redfish_stem(name)
                    record.pop(f'{stem}_meta', None)
                    record.pop(f'{stem}_entries', None)
            self.persist(record)

    def _redfish_severity_issues(self, record, name, stem, entries, evidence):
        """Emit one FAIL/WARN issue per distinct Critical/Warning entry.

        Event identity (Id + message, severity excluded), the vendor message and
        the evidence file are kept so the finding is traceable and classifies as
        KNOWN/NEW against the loop's before-cycle -> POST delta. collect_redfish
        runs more than once per record (PRE clean-state, then capture), so an
        already-recorded finding is not added again.
        """
        existing = {(i['code'], i['component'], i['detail']) for i in record['issues']}
        for entry in entries:
            severity = str(entry.get('severity_key', ''))
            if severity not in ('critical', 'warning'):
                continue
            code = 'REDFISH_CRITICAL' if severity == 'critical' else 'REDFISH_WARNING'
            level = 'FAIL' if severity == 'critical' else 'WARN'
            detail = f"Redfish {name}: {entry.get('id','')} {entry.get('message','')}".strip()
            if (code, stem, detail) in existing:
                continue
            existing.add((code, stem, detail))
            self.add(record, code, stem, detail, severity=level, evidence=evidence,
                     snippet=f"{entry.get('id','')} | {entry.get('severity','')} | {entry.get('created','')} | {entry.get('message','')}")
            # Comparison identity is the event (source + Id + message) and must
            # NOT include severity, so the same event going Warning -> Critical
            # is recognised as the same finding (reported as an escalation, not
            # a second unrelated issue). ``identity`` drives issue_key; the issue
            # code stays as the current severity so the report and recovery
            # journal keep their existing shape.
            record['issues'][-1]['identity'] = f"{name}|{entry.get('id','')}|{entry.get('message','')}"

    def _write_redfish_evidence(self, record, stem, name, entries_path, fetched, verdict, counts, history=False):
        # Plain-text transcript (header + one line per entry), not JSON: keep a
        # .txt suffix so the file is served as text/plain rather than parsed as
        # application/json by the browser's JSON viewer.
        if record['phase'] == 'PRE':
            suffix = f"pre_{stem}_preclear.txt" if history else f"pre_{stem}.txt"
        else:
            suffix = f"{stem}.txt" if not history else f"{stem}_preclear.txt"
        path = self.folder(record) / suffix
        # Entries are already normalised to the lowercase schema by
        # _redfish_fetch_collection; read both spellings so a raw entry that
        # slipped through a failure path still renders its Id/Severity/Message.
        entries = fetched.get('entries', [])
        lines = [f"UTC+8: {now()}", f"Role: oob", f"Source: Redfish {name}",
                 f"Path: {entries_path}", f"Pages: {fetched.get('pages', 0)}",
                 f"Valid: {fetched.get('valid', False)}", f"Complete: {fetched.get('complete', False)}",
                 f"Entries: {len(entries)}", f"Verdict: {verdict}",
                 f"Counts: Critical={counts['Critical']} Warning={counts['Warning']} OK={counts['OK']}",
                 f"Reason: {fetched.get('reason', '')}",
                 ""]
        for entry in entries:
            lines.append(" | ".join(str(_entry_field(entry, field)) for field in ('id', 'severity', 'created', 'message')))
        if not (fetched.get('valid') and fetched.get('complete')):
            lines.append("[incomplete or unreadable collection; reason above]")
        atomic_write(path, "\n".join(lines) + "\n")
        rel = path.relative_to(self.root).as_posix()
        record['evidence'].append(rel)
        return rel

    def _redfish_clear_service(self, record, name, path, token, stem):
        result = self.transport.redfish_clear(self.target, path + "/Actions/LogService.ClearLog", token)
        ok = result.code == 0
        record[f'{stem}_clear'] = dict(status='SUCCEEDED' if ok else 'FAILED', command=f"ClearLog {name}",
                                       code=result.code, state=result.state)
        if not ok:
            self.add(record, 'REDFISH_CLEAR_FAILED', stem,
                     f'Redfish {name} clear failed: state={result.state} exit={result.code}', severity='WARN')

    def _redfish_before_snapshot(self, record):
        """Capture the pre-cycle EventLog/SEL entries for delta comparison.

        Each service records its own validity/completeness. A failed read is
        marked UNAVAILABLE with ``valid=False`` rather than left as an empty
        snapshot, so the later delta can never mistake "we failed to read" for
        "read fine, no entries".
        """
        try:
            with self._redfish_session(record) as disc:
                snapshot = {"available": True, "eventlog": [], "sel": [],
                            "eventlog_valid": False, "sel_valid": False}
                for name, key in (('EventLog', 'eventlog'), ('SEL', 'sel')):
                    path = disc['services'].get(name)
                    if not path:
                        # Only a confirmed-absent service (valid discovery) is "not
                        # applicable"; a service we could not discover stays invalid.
                        snapshot[key + '_valid'] = bool(disc['listing_valid'])
                        continue
                    fetched = self._redfish_fetch_collection(path + "/Entries", disc['token'])
                    snapshot[key] = fetched['entries']
                    snapshot[key + '_valid'] = bool(fetched['valid'] and fetched['complete'])
        except Exception as exc:
            record['redfish_before'] = dict(available=False, reason=str(exc), eventlog=[], sel=[],
                                            eventlog_valid=False, sel_valid=False)
            record['redfish_before_meta'] = dict(phase='BEFORE_CYCLE', status='UNAVAILABLE', reason=str(exc),
                                                 eventlog_valid=False, sel_valid=False)
            self.persist(record)
            return
        record['redfish_before'] = snapshot
        record['redfish_before_meta'] = dict(phase='BEFORE_CYCLE',
                                             status='COLLECTED' if (snapshot['eventlog_valid'] or snapshot['sel_valid']) else 'UNAVAILABLE',
                                             available=True,
                                             eventlog_count=len(snapshot['eventlog']), sel_count=len(snapshot['sel']),
                                             eventlog_valid=snapshot['eventlog_valid'], sel_valid=snapshot['sel_valid'])
        self.persist(record)

    def _redfish_loop_delta(self, record):
        """Compare POST entries with the before-cycle snapshot for each service.

        COMPARED is only meaningful when BOTH the before-cycle and the POST
        collection are valid and complete for that service; otherwise the delta
        is UNAVAILABLE with a new_count of ``None`` (never 0, which would read as
        "compared successfully and found nothing new").
        """
        before = record.get('redfish_before') or {}
        for name, stem, key in (('EventLog', 'eventlog', 'eventlog'), ('SEL', 'redfish_sel', 'sel')):
            meta = record.get(f'{stem}_meta')
            if not meta:
                continue
            current = record.get(f'{stem}_entries') or []
            if meta.get('present') is False:
                meta['delta'] = dict(status='NOT_APPLICABLE', new_count=0, new_entries=[],
                                     reason='Service confirmed not present on this BMC')
                continue
            before_valid = bool(before.get('available') and before.get(key + '_valid'))
            post_valid = bool(meta.get('valid') and meta.get('complete'))
            if not before_valid or not post_valid:
                reason = ('Before snapshot unavailable or incomplete' if not before_valid
                          else 'POST snapshot unavailable or incomplete')
                meta['delta'] = dict(status='UNAVAILABLE', new_count=None, new_entries=[],
                                     reason=reason)
                continue
            new = redfish_delta(before.get(key, []), current)
            meta['delta'] = dict(status='COMPARED', new_count=len(new), new_entries=new,
                                 reason='Before-cycle and POST snapshots compared by content')
            # Record the ids introduced this loop so findings can classify
            # against the per-loop delta rather than the (cleared) PRE baseline.
            # Only COMPARED deltas feed classification; an UNAVAILABLE delta
            # leaves the marker unset so nothing is mislabelled NEW. A sorted
            # list keeps the record JSON-serialisable.
            #
            # Ids are qualified with the service name (``<name>|<id>``): the
            # EventLog and SEL are separate id spaces, so an unqualified id
            # shared by both sources would mark a finding NEW against the wrong
            # service's delta. ``eventlog_delta_ids`` keeps the legacy flat list
            # so previously written journals still read.
            ids = {str(e.get('id', '')) for e in new}
            merged_ids = set(record.get('eventlog_delta_ids', [])) | ids
            record['eventlog_delta_ids'] = sorted(merged_ids)
            qualified = {f'{name}|{str(e.get("id", ""))}' for e in new}
            merged_qualified = set(record.get('redfish_delta_ids', [])) | qualified
            record['redfish_delta_ids'] = sorted(merged_qualified)
            if new:
                path = self.folder(record) / f"{stem}_delta.txt"
                atomic_write(path, "\n".join(
                    f"{e.get('id','')} | {e.get('severity','')} | {e.get('message','')}" for e in new) + "\n")
                record['evidence'].append(path.relative_to(self.root).as_posix())
        self.persist(record)

    def start(self):
        record = new_record('START')
        self.node['start'] = record
        try:
            # START re-verifies identity before the first loop; the operator is
            # about to hand the run over, so a wrong machine still stops here.
            for role, _, _ in self.target.endpoints():
                self.identity(record, role, strict_hostname=True)
            if self.expected_boot and record['identities']['os']['boot_id'] != self.expected_boot:
                raise IdentityUnsafe('OS rebooted while awaiting PRE approval; reviewed baseline is no longer current')
        except IdentityUnsafe:
            self.cleanup_safe = False
            raise
        # Log clearing moved to PRE (_prepare_clean_state): the baseline and all
        # loop deltas now reflect a clean start. START only re-verifies identity.
        self.finish(record)

    def wait_boot(self, record, old_boot, deadline):
        attempts = 0
        boot_changed = False
        while time.monotonic() < deadline:
            attempts += 1
            try:
                current = self.identity(
                    record, "os", timeout=min(20, max(1, deadline - time.monotonic())),
                    save_evidence=False, record_command=False,
                )
                if current["boot_id"] != old_boot:
                    boot_changed = True
                    record["recovery"].update(boot_changed=True, new_boot_id=current["boot_id"], attempts=attempts)
                    # Aux cycles can leave the BMC or Lily SSH service behind the
                    # host boot. Retry transient transport failures to the same
                    # deadline, without requiring their boot IDs to change.
                    for role, _, _ in self.target.endpoints():
                        if role != 'os':
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise ConnectionError('Recovery deadline reached')
                            self.identity(record, role, timeout=min(20, remaining),
                                          save_evidence=False, record_command=False)
                    return True
            except IdentityUnsafe:
                raise
            except ConnectionError:
                pass
            time.sleep(min(self.options.poll_interval, max(0, deadline - time.monotonic())))
        record["recovery"].update(boot_changed=boot_changed, attempts=attempts)
        self.add(record, "BOOT_TIMEOUT", "recovery", f"Selected endpoints did not recover with a changed OS boot ID within {self.options.boot_timeout}s")
        return False

    def recover_log_tail(self, record):
        """Best-effort kernel-log capture after the cycle failed to confirm boot.

        The node is not back, so its kernel log is the only record of why. That
        window closes as soon as an operator retry runs ``dmesg -C`` again, so
        it is captured here, at the end of the failed loop, and never inside
        the verdict: the loop already failed for a known reason and these
        events are reported for reading, not for judging.

        Skipped when the node answered as unreachable rather than slow --
        reading a log from a dead node only burns another timeout.
        """
        if not record.get('action'):
            return False   # no power action was issued, so no boot to explain
        try:
            self.stage("Recovery log")
            tail = self.command(record, 'recovery_dmesg', 'os', 'dmesg -c', timeout=60,
                                save_evidence=True, check=False)
        except Exception as exc:
            self.add(record, 'RECOVERY_LOG_FAILED', 'recovery',
                     f"Boot log could not be read after the failed cycle: {type(exc).__name__}: {exc}",
                     severity='INFO')
            return False
        if tail.state == 'NOT_ISSUED' or tail.code:
            self.add(record, 'RECOVERY_LOG_FAILED', 'recovery',
                     f"Boot log could not be read after the failed cycle: exit {tail.code} ({tail.state})",
                     severity='INFO')
            return False
        evidence = record['commands'].get('recovery_dmesg', {}).get('evidence', '')
        for event in dmesg_issues(tail.output):
            event['phase'] = 'recovery'
            event['evidence'] = evidence
            record['issues'].append(event)
        return bool(tail.output.strip())

    def dispatch(self, record, label, role, cmd, sudo=False, timeout=30):
        record.setdefault("cycle_started", now())
        result = self.command(record, label, role, cmd, sudo=sudo, timeout=timeout, check=False)
        if record['commands'][label]['valid']:
            state = "SENT"
        elif result.state in {"RESPONSE_LOST", "NOT_ISSUED"}:
            state = result.state
        else:
            state = "COMMAND_FAILED"
        record["action"].append(dict(command=cmd, role=role, state=state, code=result.code))
        if state in {"NOT_ISSUED", "COMMAND_FAILED"}:
            self.add(record, "CYCLE_COMMAND_FAILED", "cycle", f"{cmd}: {state}, exit {result.code}")
        self.persist(record)
        return state

    def one_loop(self, number):
        if not self.node['active'] or self.node['blocked']:
            raise RuntimeError('Node is stopped or blocked; no additional cycle action allowed')
        record = new_record(f"LOOP {number}")
        record["loop"] = number
        self.node["loops"].append(record)
        self.persist(record)
        try:
            # Re-verify every selected endpoint before issuing another power
            # action. This check is strict for the same reason PRE and START are:
            # a machine that reports the wrong hostname is not the machine the
            # operator reviewed, so it must not be power-cycled. Raising
            # IdentityUnsafe deactivates only this node; the other nodes continue.
            for role, _, _ in self.target.endpoints():
                self.identity(record, role, role + "_before_cycle",
                              save_evidence=False, record_command=False,
                              strict_hostname=True)
            if self.expected_boot and record['identities']['os']['boot_id'] != self.expected_boot:
                raise IdentityUnsafe('Unexpected OS boot transition between captures')
            # Kernel log is read ONCE per loop, at the end (after MCTP stress), so
            # one read-and-clear covers the whole boot and every step of this
            # loop. A pre-action read here would duplicate that capture and put
            # the previous loop's tail on this loop's record.
            before = self.sel_command(record, 'sel_before', 'list', save_evidence=True)
            record['sel_before_valid'] = record['commands']['sel_before']['valid']
            record['sel_before'] = before.output if record['sel_before_valid'] else ''
            record['sel_before_meta'] = self._sel_metadata(record, 'sel_before', before.output, 'BEFORE_CYCLE')
            self._redfish_before_snapshot(record)
            old_boot = record["identities"]["os"]["boot_id"]
            record["recovery"]["old_boot_id"] = old_boot
            deadline = time.monotonic() + self.options.boot_timeout
            mode, channel = self.options.cycle_mode, self.options.channel
            # Short label for the stage line; "sent" (not "issued") so operators
            # never read it as a problem report.
            cycle_label = {"aux_cycle": "aux cycle", "reboot": "reboot",
                           "power_cycle": "power cycle"}.get(mode, mode)
            self.node["attempts"] += 1
            if mode == "aux_cycle":
                if self.aux_gate is not None:
                    self.aux_gate.wait(stage=self.stage,
                                       cancelled=lambda: bool(self.stop_requested and self.stop_requested()))
                state = self.dispatch(record, "cycle_command", "bmc", "/usr/bin/stbypowerctrl.sh aux_cycle")
            elif mode == "reboot" and channel == "outband":
                state = self.dispatch(record, "cycle_command", "oob", "power reset")
            else:
                inband = channel == "inband"
                if mode == "reboot":
                    command = "reboot"
                elif inband:
                    command = "ipmitool power cycle"
                else:
                    # Outband power_cycle via the BMC's own helper over SSH rather
                    # than IPMI-over-LAN: the BMC SSH path has proven reliable on
                    # this platform where the IPMI service is flaky after cycles.
                    command = "/usr/bin/powerctrl.sh power_cycle"
                state = self.dispatch(record, "cycle_command",
                                      "bmc" if (not inband and mode == "power_cycle") else ("os" if inband else "oob"),
                                      command, sudo=inband)
            if state in {"SENT", "RESPONSE_LOST"}:
                self.stage(f"{cycle_label} sent")
                self.stage("waiting OS boot")
                recovered = self.wait_boot(record, old_boot, deadline)
                if not recovered:
                    raise BootNotConfirmed('Boot recovery was not confirmed; POST hardware execution blocked')
            else:
                self.stage(f"{cycle_label} not sent")
                recovered = False
                record["recovery"]["boot_changed"] = False
            # Even a rejected power action receives POST while the OS is available.
            self.identity(record, "os", "os_after_cycle",
                          save_evidence=False, record_command=False)
            for role, _, _ in self.target.endpoints():
                if role != "os":
                    self.identity(record, role, role + "_after_cycle",
                                  save_evidence=False, record_command=False)
            expected_post_boot = record['recovery']['new_boot_id'] if recovered else old_boot
            record['recovery']['post_entry_boot_id'] = record['identities']['os']['boot_id']
            if record['identities']['os']['boot_id'] != expected_post_boot:
                self.add(record, 'UNEXPECTED_BOOT_TRANSITION', 'recovery',
                         f"Expected POST boot {expected_post_boot}; observed {record['identities']['os']['boot_id']}")
                raise IdentityUnsafe('Additional OS boot transition before POST')
            post_boot = record['identities']['os']['boot_id']
            record['boot_confirmed'] = bool(recovered)
            self.node['boot_confirmed'] += int(recovered)
            self.stage("OS up, system check running")
            self.capture(record, post=True)
            self.identity(record, 'os', 'os_after_checks')
            if record['identities']['os']['boot_id'] != post_boot:
                raise IdentityUnsafe('Additional OS boot transition during POST')
            # P5032 MCTP/USB stress. The stressor's PASS/FAIL is the criterion;
            # the BMC dmesg grep runs AFTER the stress so it can capture any
            # messages the PLDM traffic produced, and is retained with this
            # loop's evidence but never judged. EID 16 and 17 run separately
            # because the stressor serializes on pldmd via its own lock.
            for eid, cpu in MCTP_TARGETS:
                self.stage(f"MCTP stress EID {eid}")
                self.run_mctp_stressor(record, f'mctp_stress_{eid}', eid, cpu, '--stop-pldmd', judge=True)
            self.collect_bmc_dmesg(record)
            self.expected_boot = post_boot
            self.stage("system check done")
            if recovered and record.get("power_on"):
                for action in record["action"]:
                    if action["state"] == "RESPONSE_LOST":
                        action["state"] = "RECONCILED"
                        self.add(record, "COMMAND_RECONCILED", "cycle", "Reply lost; changed OS boot ID and power-on state confirmed recovery", "WARN")
            elif any(a["state"] == "RESPONSE_LOST" for a in record["action"]):
                self.add(record, "COMMAND_UNCONFIRMED", "cycle", "Lost response could not be reconciled with boot and power evidence")
            record['independent_checks_complete'] = True
            record["post_complete"] = self.hardware_execution_complete
            self.node["completed"] += int(record['post_complete'])
            record['boot_confirmed'] = bool(recovered)
            record['valid_cycle'] = bool(recovered and record.get('power_on') and self.script_verified and self.hardware_execution_complete)
            self.node['valid_cycles'] += int(record['valid_cycle'])
        except AuxCycleCancelled as exc:
            # Nothing reached the node, so this is a deliberate stop, not a node
            # failure: no recovery, no power evidence, no boot-log tail.
            self.add(record, "STOP_REQUESTED", "cycle", str(exc))
            self.node.update(active=False, stop_reason=str(exc))
            record["post_complete"] = False
            record['boot_confirmed'] = False
            record['valid_cycle'] = False
        except Exception as exc:
            code = "IDENTITY_UNSAFE" if isinstance(exc, IdentityUnsafe) else "NODE_UNAVAILABLE"
            if isinstance(exc, IdentityUnsafe):
                self.cleanup_safe = False
            self.add(record, code, "recovery", str(exc))
            # The cycle is already judged; this only preserves the log that
            # explains why the node did not come back.
            kept = (not isinstance(exc, IdentityUnsafe)) and self.recover_log_tail(record)
            self.node.update(active=False, stop_reason=str(exc) + ('; boot log retained' if kept else ''))
            record["post_complete"] = False
            # BMC evidence can still explain a failed OS recovery; never touch an
            # endpoint whose identity just failed verification.
            if not isinstance(exc, IdentityUnsafe):
                try:
                    self.identity(record, "bmc", "bmc_failure_identity")
                    self.sel_command(record, "failure_sel", "list")
                    self.command(record, "failure_power", "oob", "power status")
                except Exception as bmc_exc:
                    self.add(record, "BMC_UNAVAILABLE", "recovery", str(bmc_exc))
        # The single kernel-log read for this loop. It sits outside the main
        # try/except so a failing log read never rewrites the loop verdict: the
        # POST either succeeded or it did not, independently of whether the log
        # could be collected. ``dmesg -c`` here covers the whole boot plus the
        # MCTP stress that ran a few lines above; collect_dmesg records its own
        # failure, so nothing is raised from here.
        self.collect_dmesg(record, 'dmesg_clear', clear=True)
        result = self.finish(record)
        self.stage("DONE")
        return result
