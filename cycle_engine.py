"""Campaign node execution, with immutable PRE and durable evidence."""
from __future__ import annotations

import re
import shlex
import time
from pathlib import Path

from cycle_core import (
    atomic_write,
    classify,
    compare_sensors,
    config_issues,
    dmesg_issues,
    health,
    issue,
    missing_sensors,
    now,
    parse_pci,
    parse_sensors,
    pci_issues,
    sel_delta,
    sensor_issues,
    write_json,
)
from cycle_transport import IdentityUnsafe

PACKAGES = {"lspci": "pciutils", "dmidecode": "dmidecode", "nvme": "nvme-cli",
            "ipmitool": "ipmitool", "lsusb": "usbutils", "ip": "iproute2"}
IDENTITY = "printf 'HOSTNAME='; hostname; printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id"
CAPTURES = {
    "pci": ("lspci -Dnn", False), "pci_tree": ("lspci -Dtv", False),
    "pci_verbose": ("lspci -Dvvv", True), "pci_config": ("lspci -Dxxx", True),
    "disks": ("lsblk", False), "nvme": ("nvme list", True),
    "usb": ("lsusb", False), "memory": ("free -m", False),
    "network": ("ip address show", False), "dmesg": ("dmesg", True),
    "firmware": ("dmidecode -t bios", True),
    "system": ("uname -a; cat /etc/os-release; lscpu", False),
}

def new_record(phase):
    return dict(phase=phase, started=now(), finished=None, status="PENDING", issues=[],
                evidence=[], commands={}, identities={}, pci={}, sensors=[], action=[], recovery={})

class NodeSession:
    def __init__(self, target, transport, root, run_id, script, script_hash, options, rules):
        self.target, self.transport, self.root = target, transport, Path(root)
        self.run_id, self.script, self.script_hash = run_id, script, script_hash
        self.options, self.rules = options, rules
        self.remote = f"/tmp/vera-{run_id}-{target.key}-{script_hash[:12]}.sh"
        self.node = dict(key=target.key, target=target.__dict__, blocked=[], active=True,
                         pre=new_record("PRE"), loops=[], completed=0, stop_reason="")
        self.previous_sel = ""
        self.baseline = None

    def folder(self, record):
        return self.root / self.target.key / ("" if record["phase"] == "PRE" else f"loop{record['loop']:04d}")

    def persist(self, record):
        classify(record["issues"], self.options.project, self.rules)
        write_json(self.folder(record) / ("pre_report.json" if record["phase"] == "PRE" else "report.json"), record)

    def finish(self, record):
        record.update(status=health(record["issues"]), finished=now())
        self.persist(record)
        return record

    def add(self, record, code, component, detail, severity="FAIL", evidence=""):
        record["issues"].append(issue(code, component, detail, severity, evidence))

    def command(self, record, stem, role, cmd, sudo=False, timeout=90, check=True):
        result = (self.transport.oob(self.target, cmd, timeout) if role == "oob" else
                  self.transport.ssh(self.target, role, cmd, timeout, sudo))
        prefix = "pre" if record["phase"] == "PRE" else "post"
        path = self.folder(record) / f"{prefix}_{stem}.txt"
        evidence = path.relative_to(self.root).as_posix()
        atomic_write(path, f"UTC: {now()}\nRole: {role}\nCommand: {cmd}\nExit: {result.code}\nState: {result.state}\nDuration: {result.duration:.2f}s\n\n{result.output}\n")
        record["evidence"].append(evidence)
        ipmi_error = role == "oob" and bool(re.search(r"(?:Get .+ command failed|Unable to establish|Error:|No response from|Invalid command)", result.output, re.I))
        record["commands"][stem] = {"code": result.code, "state": result.state, "evidence": evidence, "valid": result.code == 0 and not ipmi_error}
        if check and result.code != 0:
            self.add(record, "COLLECTION_FAILED", stem, f"Exit {result.code} ({result.state}); see evidence", evidence=evidence)
        elif check and ipmi_error:
            self.add(record, "IPMI_REPORTED_ERROR", stem, "IPMI reported a transport/command error despite exit zero; see evidence", evidence=evidence)
        self.persist(record)
        return result

    def identity(self, record, role, stem=None, timeout=30):
        result = self.command(record, stem or (role + "_identity"), role, IDENTITY, timeout=timeout, check=False)
        if result.code:
            raise ConnectionError(f"{role} identity unavailable: exit {result.code} ({result.state})")
        values = dict(re.findall(r"^(HOSTNAME|BOOT_ID)=(.*)$", result.output, re.M))
        expected = getattr(self.target, role + "_hostname")
        actual = values.get("HOSTNAME", "").strip()
        if not expected or actual.lower().rstrip(".") != expected.lower().rstrip("."):
            raise IdentityUnsafe(f"{role} hostname mismatch: expected '{expected}', received '{actual}'")
        if role == "os" and not re.fullmatch(r"[0-9a-fA-F-]{36}", values.get("BOOT_ID", "").strip()):
            raise IdentityUnsafe("OS did not provide a valid boot ID")
        record["identities"][role] = dict(hostname=actual, boot_id=values.get("BOOT_ID", "").strip())
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

    def capture(self, record, post=False):
        for stem, (cmd, sudo) in CAPTURES.items():
            result = self.command(record, stem, "os", cmd, sudo=sudo)
            if stem == "pci":
                record["pci"] = parse_pci(result.output) if result.code == 0 else {}
                if not record["pci"]:
                    self.add(record, "PCI_EMPTY", "PCIe", "No valid full-BDF PCI inventory")
                elif post:
                    record["issues"] += pci_issues(self.baseline["pci"], record["pci"])
            elif stem == "dmesg":
                if result.code == 0:
                    record["issues"] += dmesg_issues(result.output)
                    if post:
                        cleared = self.command(record, "dmesg_clear", "os", "dmesg -c", sudo=True)
                        # Read-and-clear also saves messages arriving between the
                        # first read and clearing; -C alone would discard them.
                        if cleared.code == 0:
                            existing = {(i['code'], i['detail']) for i in record['issues']}
                            record['issues'] += [i for i in dmesg_issues(cleared.output) if (i['code'], i['detail']) not in existing]
        config = self.command(record, "hardware", "os", "bash " + shlex.quote(self.remote), sudo=True, timeout=180, check=False)
        record["issues"] += config_issues(config.output, config.code)
        sensor = self.command(record, "sensor", "oob", "sensor list")
        record["sensors"] = parse_sensors(sensor.output) if record['commands']['sensor']['valid'] else []
        if post:
            valid = record['commands']['sensor']['valid']
            if not valid:
                retry = self.command(record, 'sensor_retry', 'oob', 'sensor list')
                valid = record['commands']['sensor_retry']['valid']
                if valid:
                    record['sensors'] = parse_sensors(retry.output)
            confirmation = None
            if valid and missing_sensors(self.baseline["sensors"], record["sensors"]):
                retry = self.command(record, "sensor_confirm", "oob", "sensor list")
                if record['commands']['sensor_confirm']['valid']:
                    confirmation = parse_sensors(retry.output)
                else:
                    valid = False
                    self.add(record, 'SENSOR_CONFIRM_FAILED', 'sensors', 'Reread failed; sensor disappearance cannot be confirmed from a failed collection')
            if valid:
                record["issues"] += compare_sensors(self.baseline["sensors"], record["sensors"], confirmation)
            else:
                record['issues'] += sensor_issues(record['sensors'])
        else:
            record["issues"] += sensor_issues(record["sensors"])
        sel = self.command(record, "sel", "oob", "sel elist")
        if record['commands']['sel']['valid']:
            delta = sel_delta(self.previous_sel, sel.output)
            self.previous_sel = sel.output
            path = self.folder(record) / ("post_sel_delta.txt" if post else "pre_sel_delta.txt")
            atomic_write(path, delta or "No new SEL records.\n")
            record["evidence"].append(path.relative_to(self.root).as_posix())
            record["sel_review"] = "REVIEW REQUIRED: cumulative SEL and delta are evidence; event correctness is not automatically judged."
        self.command(record, "bmc_firmware", "oob", "mc info")
        power = self.command(record, "power", "oob", "power status")
        record["power_on"] = record['commands']['power']['valid'] and bool(re.search(r"Chassis Power is on", power.output, re.I))
        if not record["power_on"]:
            self.add(record, "POWER_NOT_ON", "power", "BMC did not confirm chassis power on")
        bmc = self.command(record, "host_power", "bmc", "/usr/bin/powerctrl.sh power_status")
        if bmc.code == 0 and not ("Host: Running" in bmc.output and "Chassis Power: On" in bmc.output):
            self.add(record, "HOST_NOT_RUNNING", "power", "BMC power_status did not confirm Host: Running and Chassis Power: On")
        for item in record["issues"]:
            if not item.get("evidence"):
                component = item["component"]
                stem = "sensor" if item["code"].startswith("SENSOR") else "pci" if item["code"] == "PCI_DRIFT" else "dmesg" if component == "dmesg" else "hardware"
                item["evidence"] = record["commands"].get(stem, {}).get("evidence", "")

    def precheck(self):
        record = self.node["pre"]
        self.persist(record)
        try:
            for role, _, _ in self.target.endpoints():
                self.identity(record, role)
            uid = self.command(record, "root_uid", "os", "id -u", sudo=True, check=False)
            if uid.code or uid.output.strip() != "0":
                self.add(record, "ROOT_UNAVAILABLE", "privileges", "Root execution is unavailable; privileged checks may fail")
            self.dependencies(record)
            try:
                self.transport.upload(self.target, self.script, self.remote)
                verify = self.command(record, "script_sha256", "os", "sha256sum " + shlex.quote(self.remote))
                if verify.code or verify.output.split()[0] != self.script_hash:
                    raise RuntimeError("Remote hardware script hash verification failed")
            except Exception as exc:
                self.add(record, "SCRIPT_UPLOAD_FAILED", "hardware", str(exc))
                self.node["blocked"].append("Cannot run the verified hardware script")
            self.capture(record)
            if not record["pci"] or not any(not row.get('format_error') for row in record["sensors"]):
                self.node["blocked"].append("PRE PCI or sensor baseline is unavailable")
            self.baseline = dict(pci=record["pci"].copy(), sensors=[r.copy() for r in record["sensors"]])
        except Exception as exc:
            self.node["blocked"].append(str(exc))
            self.add(record, "PRE_BLOCKED", "identity", str(exc))
        self.finish(record)
        return self.node

    def start(self):
        record = self.node["pre"]
        # Clear only successfully captured evidence. Do not erase unread evidence.
        for stem, role, cmd, sudo in (("dmesg", "os", "dmesg -c", True), ("sel", "oob", "sel clear", False)):
            if record["commands"].get(stem, {}).get("valid"):
                result = self.command(record, "start_" + stem + "_clear", role, cmd, sudo=sudo)
                if stem == 'dmesg' and result.code == 0:
                    existing = {(i['code'], i['detail']) for i in record['issues']}
                    record['issues'] += [i for i in dmesg_issues(result.output) if (i['code'], i['detail']) not in existing]
                if stem == "sel" and record['commands']['start_sel_clear']['valid']:
                    self.previous_sel = ""
            else:
                self.add(record, "CLEAR_SKIPPED", stem, "PRE capture failed; original evidence was not cleared")
        self.finish(record)

    def wait_boot(self, record, old_boot, deadline):
        attempts = 0
        boot_changed = False
        while time.monotonic() < deadline:
            attempts += 1
            try:
                current = self.identity(record, "os", f"boot_poll_{attempts:03d}", min(20, max(1, deadline - time.monotonic())))
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
                            self.identity(record, role, f"{role}_boot_poll_{attempts:03d}", min(20, remaining))
                    return True
            except IdentityUnsafe:
                raise
            except ConnectionError:
                pass
            time.sleep(min(self.options.poll_interval, max(0, deadline - time.monotonic())))
        record["recovery"].update(boot_changed=boot_changed, attempts=attempts)
        self.add(record, "BOOT_TIMEOUT", "recovery", f"Selected endpoints did not recover with a changed OS boot ID within {self.options.boot_timeout}s")
        self.node.update(active=False, stop_reason="Boot recovery timeout")
        return False

    def dispatch(self, record, label, role, cmd, sudo=False, timeout=30):
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
        record = new_record(f"LOOP {number}")
        record["loop"] = number
        self.node["loops"].append(record)
        self.persist(record)
        try:
            # Re-verify every selected endpoint before issuing another power action.
            for role, _, _ in self.target.endpoints():
                self.identity(record, role, role + "_before_cycle")
            old_boot = record["identities"]["os"]["boot_id"]
            record["recovery"]["old_boot_id"] = old_boot
            deadline = time.monotonic() + self.options.boot_timeout
            mode, channel = self.options.cycle_mode, self.options.channel
            if mode == "aux_cycle":
                state = self.dispatch(record, "cycle_command", "bmc", "/usr/bin/stbypowerctrl.sh aux_cycle")
            elif mode == "reboot" and channel == "outband":
                state = self.dispatch(record, "cycle_soft", "oob", "power soft")
                if state in {"SENT", "RESPONSE_LOST"}:
                    off = False
                    attempt = 0
                    while time.monotonic() < deadline:
                        attempt += 1
                        power = self.command(record, f"power_off_poll_{attempt:03d}", "oob", "power status", timeout=min(20, max(1, deadline-time.monotonic())), check=False)
                        if power.code == 0 and re.search(r"Chassis Power is off", power.output, re.I):
                            off = True
                            break
                        time.sleep(min(self.options.poll_interval, max(0, deadline-time.monotonic())))
                    if off:
                        record["recovery"]["power_off_observed"] = True
                        state = self.dispatch(record, "cycle_on", "oob", "power on")
                    else:
                        self.add(record, "POWER_OFF_TIMEOUT", "cycle", "ACPI shutdown did not reach confirmed off state; no power-on command sent")
            else:
                command = "reboot" if mode == "reboot" else "ipmitool power cycle" if channel == "inband" else "power cycle"
                state = self.dispatch(record, "cycle_command", "os" if channel == "inband" else "oob", command, sudo=channel == "inband")
            if state in {"SENT", "RESPONSE_LOST"}:
                recovered = self.wait_boot(record, old_boot, deadline)
            else:
                recovered = False
                record["recovery"]["boot_changed"] = False
            # Even a rejected power action receives POST while the OS is available.
            self.identity(record, "os", "os_after_cycle")
            for role, _, _ in self.target.endpoints():
                if role != "os":
                    self.identity(record, role, role + "_after_cycle")
            self.capture(record, post=True)
            if recovered and record.get("power_on"):
                for action in record["action"]:
                    if action["state"] == "RESPONSE_LOST":
                        action["state"] = "RECONCILED"
                        self.add(record, "COMMAND_RECONCILED", "cycle", "Reply lost; changed OS boot ID and power-on state confirmed recovery", "WARN")
            elif any(a["state"] == "RESPONSE_LOST" for a in record["action"]):
                self.add(record, "COMMAND_UNCONFIRMED", "cycle", "Lost response could not be reconciled with boot and power evidence")
            record["post_complete"] = True
            self.node["completed"] += 1
        except Exception as exc:
            code = "IDENTITY_UNSAFE" if isinstance(exc, IdentityUnsafe) else "NODE_UNAVAILABLE"
            self.add(record, code, "recovery", str(exc))
            self.node.update(active=False, stop_reason=str(exc))
            record["post_complete"] = False
            # BMC evidence can still explain a failed OS recovery; never touch an
            # endpoint whose identity just failed verification.
            if not isinstance(exc, IdentityUnsafe):
                try:
                    self.identity(record, "bmc", "bmc_failure_identity")
                    self.command(record, "failure_sel", "oob", "sel elist")
                    self.command(record, "failure_power", "oob", "power status")
                except Exception as bmc_exc:
                    self.add(record, "BMC_UNAVAILABLE", "recovery", str(bmc_exc))
        return self.finish(record)
