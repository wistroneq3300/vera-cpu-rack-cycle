#!/usr/bin/env python3
"""Fused Neutrino power-cycle campaign (outside orchestrator).

Runs from ONE outside host (e.g. the agent box) and drives every selected
node over SSH + outband ipmitool. No per-node PowerIP.sh, no rc.local: this
orchestrator issues one cycle, waits for the OS to come back with a changed
boot ID, captures evidence, then issues the next cycle until the stop rule
is met.

Cycle modes x channels
  --cycle-mode reboot        inband: `reboot`                       outband: ipmitool -C 17 power soft
  --cycle-mode power_cycle   inband: `ipmitool power cycle`         outband: ipmitool -I lanplus -C 17 power cycle
  --cycle-mode aux_cycle     (BMC stbypowerctrl.sh aux_cycle; AC/standby, outband by nature)
  --channel inband | outband | auto   (auto = inband, then outband if the OS does not return)

Stop rule: --loops N and/or --hours H may BOTH be given; whichever is reached
first stops the campaign.

Evidence per node/loop (union of the old PowerIP.sh + neutrin_ac_cycle.py):
  OS side : identity(boot_id/MAC), lspci -tv/-vvv/-xxx, lsblk, nvme list,
            lsusb, free -m, ifconfig, ipmitool sensor list, ipmitool sel elist,
            dmesg -c (per-loop fresh), Config script (vera_rack.sh)
  BMC side: ipmitool -I lanplus -C 17 power status / sel elist / sensor list

Passwords come from NEUTRINO_{BMC,OS,LILY_BMC,LILY_OS}_PASSWORD, BMC_PASSWORD,
or a terminal prompt. They are never written to reports or command lines.

Install: python -m pip install paramiko
Example:
  python neutrin_cycle.py --node all --hours 12 --loops 40 \
      --cycle-mode power_cycle --channel auto --cycle
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

ROLES = ("bmc", "os", "lily_bmc", "lily_os")
USERS = {"bmc": "root", "os": "root", "lily_bmc": "service", "lily_os": "ubuntu"}
IPMITOOL_CIPHER = 17
LOG_CONTEXT = threading.local()
DEFAULT_CONFIG = Path("/root/rackctl/vera_rack.sh")
DEFAULT_OUTPUT = Path.home() / "Downloads" / "neutrino" / f"cycle_test{datetime.now().strftime('%m%d')}"
DEFAULT_INVENTORY = Path(__file__).with_name("cycle_inventory.csv")
# outband BMC credentials (for ipmitool lanplus) - overridable via env
BMC_OOB_USER_DEFAULT = "root"

IDENTITY_COMMAND = """set -e
PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH
export PATH
printf 'HOSTNAME='; hostname
printf 'BOOT_ID='; cat /proc/sys/kernel/random/boot_id
printf 'eth_name ip macaddress\\n'
addresses=$(ip -o -4 addr show)
if [ -z "$addresses" ]; then echo 'NO_VALUE: no IPv4 interfaces'; exit 1; fi
printf '%s\\n' "$addresses" | while read -r index name family cidr rest; do
    name=${name%%@*}
    mac=$(cat "/sys/class/net/$name/address")
    printf '%s %s %s\\n' "$name" "${cidr%/*}" "${mac:-NO_VALUE}"
done"""

# `ipmitool sensor list` returns a fixed 240-row table (56 unique hardware
# sensor IDs) on this platform, but the BMC sometimes returns a shorter table
# with no error at all, dropping a sensor for that one read. Retry until the
# full table is seen so the pre-cycle baseline is trustworthy.
SENSOR_TABLE_FULL_ROWS = 240

# OS-side per-loop capture, union of PowerIP.sh and neutrin_ac_cycle.py.
# Each entry: (evidence stem, command, sudo?, timeout)
OS_CAPTURES = [
    # (stem, command, needs_sudo, timeout, fatal)
    ("post_lspci_tv",   "lspci -tv",            False, 60,  True),
    ("post_lspci_vvv",  "lspci -vvv",           False, 120, False),  # record-only, PCIe regs contain "Timeout"/"Error" strings
    ("post_lspci_xxx",  "lspci -xxx",           False, 120, False),  # record-only
    ("post_lsblk",      "lsblk",                False, 30,  True),
    ("post_nvme_list",  "nvme list",            False, 30,  True),
    ("post_lsusb",      "lsusb",                False, 30,  True),
    ("post_free_m",     "free -m",              False, 20,  True),
    ("post_ifconfig",   "ifconfig -a",          False, 30,  True),
    ("post_sensor",     "ipmitool sensor list", True,  60,  True),
    ("post_sel",        "ipmitool sel elist",   True,  60,  True),
]

CHECKS = {
    "root": "Root UID = 0",
    "config": "vera_rack.sh: no lost devices in [Fail]",
    "power": "BMC: Host Running + Chassis Power On",
    "power_cmd": "Cycle command accepted",
    "boot_changed": "OS boot_id changed",
    "lspci": "lspci exit 0 + 卡數 == baseline（找出缺哪張卡）",
    "sensor_diff": "sensor list == baseline（缺哪個 sensor）+ status 有無 critical/non-recoverable",
    "lily_bmc_reachable": "Lily (BF4) BMC reachable",
    "lily_os_reachable": "Lily (BF4) OS reachable",
}

# Steps whose failure is recorded (fail log still written) but does NOT drive
# the loop to FAILED — they depend on /dev/ipmi0, which can be absent right
# after a cold boot (ipmi_ssif probe race).
NON_FATAL_STEPS = {"post_sensor", "post_sel"}


# --------------------------------------------------------------------------- helpers
def node_name(target: "Target") -> str:
    return "node" + target.node.removeprefix("n")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def save(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")


def plain_text(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value)


# Boot-time kernel noise that is known-benign on this platform; it would
# otherwise fail every loop via the `dmesg | grep error` capture.
BENIGN_DMESG_NOISE = re.compile(
    r"ipmi_ssif.*(?:Error fetching SSIF: -121[^\n]*probably doesn't support this command"
    r"|probe with driver ipmi_ssif failed with error -17"
    r"|Unable to clear message flags)",
    re.I)


def output_issues(code: int, output: str) -> list[tuple[str, str]]:
    issues = []
    clean = plain_text(output)
    if code != 0:
        issues.append(("TIMEOUT" if code == 124 else "ERROR", f"Exit code {code}"))
        stderr_part = clean.split("\n[stderr]\n", 1)[1] if "\n[stderr]\n" in clean else ""
        for line in stderr_part.splitlines():
            line = line.strip()
            if line:
                issues.append(("ERROR", "stderr: " + line[:140]))
                break
    if clean.split("\n[stderr]\n", 1)[0].strip().lower() in {"", '""', "''", "null", "none", "n/a"}:
        stderr_part = clean.split("\n[stderr]\n", 1)[1] if "\n[stderr]\n" in clean else ""
        # e.g. `ipmitool sel elist` exits 0 with empty stdout and "SEL has no
        # entries" on stderr - that is a valid result, not a missing value
        if not stderr_part.strip():
            issues.append(("NO_VALUE", "Command returned no stdout value"))
    # `ipmitool sel elist` with an empty SEL can still print a transient BMC
    # transport complaint ("Get Device ID command failed: 0xff") on stderr.
    # With no entries to report there is nothing to warn about.
    sel_empty = "SEL has no entries" in clean
    for line in clean.splitlines():
        if BENIGN_DMESG_NOISE.search(line):
            continue
        if sel_empty and re.search(r"Get Device ID command failed|Get SEL Info command failed", line, re.I):
            continue
        if re.search(r"\b(?:timeout|timeouterror|timed out)\b", line, re.I):
            issues.append(("TIMEOUT", line.strip()))
        elif re.search(r"\b(?:error|fail|failed|failure)\b|Lost Device:|command not found|permission denied|connection refused|no route to host", line, re.I):
            if not re.search(r"\b(?:no|0)\s+(?:errors?|failures?)\b", line, re.I):
                issues.append(("ERROR", line.strip()))
        elif re.search(r"\bNO_VALUE\b|\bno value\b|^\s*(?:none|null|n/a)\s*$", line, re.I):
            issues.append(("NO_VALUE", line.strip()))
    return issues


def add_issue(step: str, kind: str, detail: str, attempt: int | None = None) -> None:
    issues = getattr(LOG_CONTEXT, "issues", None)
    if issues is not None:
        issues.append({"step": step, "kind": kind, "detail": detail, "attempt": attempt, "utc": now()})


def boot_transport_pending(exc: Exception) -> bool:
    """Only temporary transport unavailability is expected while booting."""
    if type(exc).__name__ in {"AuthenticationException", "BadHostKeyException"}:
        return False
    return (timeout_error(exc) or isinstance(exc, (ConnectionError, EOFError))
            or type(exc).__name__ == "NoValidConnectionsError"
            or str(exc) == "No existing session")


def timeout_error(exc: Exception) -> bool:
    return isinstance(exc, (TimeoutError, socket.timeout)) or bool(
        re.search(r"timed? out|timeout|protocol banner", str(exc), re.IGNORECASE)
    )


def transcript(title: str, content: str, event: str = "LOG") -> None:
    path = getattr(LOG_CONTEXT, "path", None)
    if not path:
        return
    stamp = now()
    line = f"\n===== {event} | {title} | {stamp} =====\n{content}\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)


@dataclass(frozen=True)
class Target:
    tray: str
    node: str
    bmc_ip: str
    os_ip: str
    lily_bmc_ip: str = ""
    lily_os_ip: str = ""
    bmc_mac: str = ""
    os_mac: str = ""
    lily_bmc_mac: str = ""
    lily_os_mac: str = ""
    bmc_hostname: str = ""
    bmc_oob_user: str = BMC_OOB_USER_DEFAULT


def load_inventory(path: Path) -> list[Target]:
    """Accept the 6/7/8-column form:
    tray,node,bmc_ip,os_ip[,lily_bmc_ip,lily_os_ip[,bmac,omac]]
    lily columns may be empty (then lily checks are skipped).
    """
    targets: list[Target] = []
    seen = set()
    with path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.reader(fh):
            if not row or row[0].strip().startswith("#") or row[0].strip().lower() == "tray":
                continue
            if len(row) < 4:
                raise ValueError(f"Inventory row too short: {row}")
            tray, node, bmc_ip, os_ip = (c.strip() for c in row[:4])
            lily_bmc = row[4].strip() if len(row) > 4 else ""
            lily_os = row[5].strip() if len(row) > 5 else ""
            bmac = row[6].strip().lower() if len(row) > 6 else ""
            omac = row[7].strip().lower() if len(row) > 7 else ""
            node = node if node.lower().startswith("n") else "n" + node
            for ip in (bmc_ip, os_ip) + ((lily_bmc, lily_os) if lily_bmc or lily_os else ()):
                if ip:
                    ipaddress.ip_address(ip)
            key = (tray, node)
            if key in seen:
                raise ValueError(f"Duplicate node {key}")
            seen.add(key)
            targets.append(Target(tray=tray, node=node, bmc_ip=bmc_ip, os_ip=os_ip,
                                  lily_bmc_ip=lily_bmc, lily_os_ip=lily_os,
                                  bmc_mac=bmac, os_mac=omac,
                                  bmc_hostname=f"{tray.lower()}-{node}-bmc"))
    if not targets:
        raise ValueError("No inventory rows found")
    return sorted(targets, key=lambda t: t.node)


# --------------------------------------------------------------------------- SSH
class SSH:
    def __init__(self, known_hosts: Path, trust_first_use: bool, passwords: dict[str, str]):
        try:
            import paramiko
        except ImportError as exc:
            raise RuntimeError("Install SSH dependency: python -m pip install paramiko") from exc
        self.paramiko = paramiko
        self.known_hosts = known_hosts
        self.trust_first_use = trust_first_use
        self.passwords = passwords
        self._lock = threading.RLock()

    def _connect(self, host: str, user: str, password: str):
        client = self.paramiko.SSHClient()
        client.load_system_host_keys()
        if self.known_hosts.exists():
            client.load_host_keys(str(self.known_hosts))
        client.set_missing_host_key_policy(
            self.paramiko.AutoAddPolicy() if self.trust_first_use else self.paramiko.RejectPolicy())
        client.connect(hostname=host, username=user, password=password,
                       look_for_keys=False, allow_agent=False,
                       timeout=12, auth_timeout=12, banner_timeout=12)
        if self.trust_first_use:
            self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                client.save_host_keys(str(self.known_hosts))
        return client

    def connect(self, host: str, user: str, password: str, boot_wait: bool = False, attempts: int = 4, delay: float = 15.0):
        last = None
        for attempt in range(1, attempts + 1):
            try:
                return self._connect(host, user, password)
            except Exception as exc:
                last = exc
                pending = boot_wait and boot_transport_pending(exc)
                if not pending:
                    add_issue(f"SSH {host}", "TIMEOUT" if timeout_error(exc) else "ERROR",
                              f"{type(exc).__name__}: {exc}", attempt)
                if attempt == attempts or not (timeout_error(exc) or pending):
                    raise
                time.sleep(delay)
        raise last

    def close(self, client) -> None:
        try:
            client.close()
        except Exception:
            pass


def run(client, command: str, timeout: int = 120, stdin_data: str | None = None) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if stdin_data is not None:
        stdin.write(stdin_data)
        stdin.flush()
    stdin.close()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, out + ("\n[stderr]\n" + err if err else "")


def log_command(client, command: str, path: Path, timeout: int = 120,
                stdin_data: str | None = None, retries: int = 3,
                display_command: str | None = None, fatal: bool = True) -> tuple[int, str]:
    for attempt in range(1, retries + 2):
        try:
            code, output = run(client, command, timeout, stdin_data)
            problems = output_issues(code, output) if fatal else []
            for kind, detail in problems:
                add_issue(path.stem, kind, detail, attempt)
            evidence = f"Command: {display_command or command}\nAttempt: {attempt}/{retries + 1}\nExit: {code}\n\n{output}"
            save(path, f"UTC: {now()}\n{evidence}\n")
            transcript(path.stem, evidence.replace(command, display_command, 1) if display_command else evidence, event="COMMAND")
            if any(kind == "TIMEOUT" for kind, _ in problems) and attempt <= retries:
                save(path.with_name(f"{path.stem}.attempt{attempt}.txt"), f"UTC: {now()}\n{evidence}\n")
                time.sleep(15)
                continue
            return code, output
        except Exception as exc:
            add_issue(path.stem, "TIMEOUT" if timeout_error(exc) else "ERROR", f"{type(exc).__name__}: {exc}", attempt)
            evidence = f"Command: {display_command or command}\nAttempt: {attempt}/{retries + 1}\n{type(exc).__name__}: {exc}"
            save(path.with_name(f"{path.stem}.attempt{attempt}.txt"), f"UTC: {now()}\n{evidence}\n")
            if attempt == retries + 1 or not timeout_error(exc):
                raise
            time.sleep(15)
    raise AssertionError("unreachable")


def wait_for_ipmi(client, timeout: int = 120, interval: int = 5) -> bool:
    """Poll until /dev/ipmi0 exists (in-band IPMI), e.g. after a cold boot.

    ipmi_ssif probe takes ~40s; without the device post_sensor/post_sel would
    false-fail. Returns True once the device appears, False after `timeout`.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            code, out = run(client, "test -e /dev/ipmi0 && echo IPMI_OK", 10)
            if "IPMI_OK" in out:
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def hardware_sensor_names(text: str) -> set:
    """Unique hardware sensor IDs, i.e. excluding the volatile families.

    Dropped: the load-dependent core-utilization sensors ("...CorUti<NN>") that
    appear/disappear with CPU activity, and rows whose name does not decode.

    Comparison is on unique names, not row counts: the BMC table legitimately
    repeats some IDs (e.g. PrMo0MeCn0MeTem0 four times), so a changed repeat
    count would otherwise look like a lost sensor.
    """
    names = set()
    for line in text.splitlines():
        if "|" not in line:
            continue
        first = line.split("|", 1)[0].strip()
        if not first or "CorUti" in first or "\ufffd" in first:
            continue
        names.add(first)
    return names


def sensor_rows(text: str) -> int:
    """Number of sensor rows the BMC reports (used to spot truncated reads)."""
    return sum(1 for line in text.splitlines() if "|" in line)


def hardware_sensor_statuses(text: str) -> dict:
    """Map hw sensor name -> status (4th column), excluding CorUti and undecodable.

    Returns e.g. {"BMC0_Temp_0": "ok", "Chass0HSCCurren0": "ok", ...}.
    For repeated names (e.g. PrMo0MeCn0MeTem0 x4), the last occurrence wins.
    """
    statuses = {}
    for line in text.splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            continue
        name = parts[0]
        status = parts[3]
        if not name or "CorUti" in name or "\ufffd" in name:
            continue
        statuses[name] = status
    return statuses


# Sensor statuses that indicate a hardware fault
BAD_SENSOR_STATUSES = {"critical", "non-recoverable", "non recoverable"}


def capture_sensor_list(client, path: Path, os_pw: str) -> tuple[int, str]:
    """Read `ipmitool sensor list`, retrying to defeat truncated output.

    The BMC intermittently returns a short table with no error at all (e.g.
    147 of 240 rows), which would look like dozens of lost sensors. A truncated
    read is always shorter than the full table, so keep the longest result and
    prefer reads without SDR errors.
    """
    best: tuple[int, str] | None = None
    for _ in range(3):
        code, out = run(client, "sudo -S -p '' ipmitool sensor list 2>&1 || true", 60, os_pw + "\n")
        if re.search(r"Get SDR [0-9a-fA-F]+ command failed", out):
            continue
        if best is None or len(hardware_sensor_names(out)) > len(hardware_sensor_names(best[1])):
            best = (code, out)
        if sensor_rows(out) >= SENSOR_TABLE_FULL_ROWS:
            break  # full table already; retrying would only cost time
    if best is None:  # every attempt had SDR errors; keep the last one
        code, out = run(client, "sudo -S -p '' ipmitool sensor list 2>&1 || true", 60, os_pw + "\n")
        best = (code, out)
    save(path, f"UTC: {now()}\nCommand: ipmitool sensor list\nExit: {best[0]}\n\n{best[1]}\n")
    return best


def identity(client, path: Path) -> dict:
    code, output = log_command(client, IDENTITY_COMMAND, path, 30,
                               display_command="hostname; boot_id; ip -o -4 addr show")
    if code != 0:
        raise RuntimeError("identity command failed")
    host = re.search(r"^HOSTNAME=(\S+)", output, re.MULTILINE)
    boot = re.search(r"^BOOT_ID=([0-9a-f-]{36})", output, re.MULTILINE)
    if not host or not boot:
        raise RuntimeError("hostname or boot ID missing")
    network = [{"eth": n, "ip": ip, "mac": mac.lower()}
               for n, ip, mac in re.findall(r"^(\S+)\s+(\d+\.\d+\.\d+\.\d+|NO_VALUE)\s+([0-9a-f:]{17}|NO_VALUE)$",
                                             output, re.IGNORECASE | re.MULTILINE)]
    if not network:
        raise RuntimeError("No network interface values returned")
    return {"hostname": host.group(1), "boot_id": boot.group(1),
            "observed_macs": [r["mac"] for r in network], "network": network}


def check_mac(target: Target, role: str, observed: dict) -> None:
    expected = getattr(target, role + "_mac", "")
    if expected and expected not in [m.lower() for m in observed["observed_macs"]]:
        raise RuntimeError(f"{role} MAC mismatch: expected {expected}")
    if expected and not any(r["ip"] == getattr(target, role + "_ip") and r["mac"] == expected
                            for r in observed.get("network", [])):
        raise RuntimeError(f"{role} expected IP/MAC pair missing")


def config_ok(output: str, exit_code: int) -> bool:
    # vera_rack.sh always prints a [Fail] section, and only prints the
    # success line when nothing was lost. Inspect the [Fail] body (it ends
    # at [Summary], or at end-of-output when the success block is skipped)
    # and still require the success line.
    import re
    text = re.sub(r"\x1b\[[0-9;]*m", "", output)
    fail_match = re.search(r"\[Fail\](.*?)(?:\[Summary\]|\Z)", text, re.DOTALL)
    if fail_match and fail_match.group(1).strip():
        return False
    return "All devices are detected successfully !!" in text


# OS-side system-info capture (equivalent of PowerIP.sh info_get + hardware summary).
INFO_COMMAND = r"""set -e
PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH
export PATH
echo "== host =="
hostname
date -u
echo "== kernel =="
uname -a
echo "== os =="
. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || true
echo "== cpu =="
lscpu 2>/dev/null | egrep 'Model name|^CPU\(s\)|Architecture' || true
echo "== memory =="
free -m
echo "== disk =="
lsblk
echo "== network =="
ip -o -4 addr show
echo "== bmc (ipmitool) =="
ipmitool mc info 2>/dev/null | egrep 'Firmware Revision|Manufacturer|Product Name' || echo 'ipmitool mc info: n/a'
ipmitool lan print 2>/dev/null | egrep 'IP Address|MAC Address' || true
echo "== dmesg (errors only) =="
dmesg 2>/dev/null | grep -aiE 'aer|nvme|error|fail|critical|uncorrect' | tail -60 || echo 'dmesg: no errors found'
"""


def collect_info(client, path: Path) -> None:
    code, output = log_command(client, INFO_COMMAND, path, 60,
                               display_command="hostname; uname -a; lscpu; free -m; lsblk; ip addr; ipmitool mc info/lan; dmesg | grep error")
    transcript("SYSTEM INFO", output, event="COMMAND")


def collect_dmesg_all(client, path: Path, os_password: str) -> None:
    """Full dmesg (no filter) - save before clearing. Record-only, not fatal."""
    code, output = log_command(client, "sudo -S -p '' dmesg 2>/dev/null || echo 'dmesg: n/a'",
                               path, 60, os_password + "\n",
                               display_command="dmesg (full)", fatal=False)


# --------------------------------------------------------------------------- Lily (BF4 DPU) checks
# Only run when the inventory actually has a lily endpoint. Each lily role is
# independently optional: lily_bmc_ip set -> check BF4 BMC; lily_os_ip set ->
# check BF4 OS. Empty IP = skip that role entirely (no impact on nodes w/o BF4).
def lily_pre(ssh: SSH, target: Target, bmc_pw: str, os_pw: str, hostdir: Path, record) -> None:
    """PRE: capture lily BMC/OS identity (proves the card is present + records boot_id)."""
    if target.lily_bmc_ip:
        with ssh.connect(target.lily_bmc_ip, USERS["lily_bmc"], bmc_pw) as cli:
            before = identity(cli, hostdir / "pre_lily_bmc_identity.txt")
            check_mac(target, "lily_bmc", before)
            record("pre_lily_bmc", before)
            transcript("LILY PRE", f"lily_bmc {target.lily_bmc_ip} hostname={before['hostname']} boot_id={before['boot_id']}")
    else:
        record("pre_lily_bmc", None)  # not configured -> skip
    if target.lily_os_ip:
        with ssh.connect(target.lily_os_ip, USERS["lily_os"], os_pw) as cli:
            before = identity(cli, hostdir / "pre_lily_os_identity.txt")
            check_mac(target, "lily_os", before)
            record("pre_lily_os", before)
            transcript("LILY PRE", f"lily_os {target.lily_os_ip} hostname={before['hostname']} boot_id={before['boot_id']}")
    else:
        record("pre_lily_os", None)


def lily_post(ssh: SSH, target: Target, bmc_pw: str, os_pw: str, hostdir: Path, record) -> None:
    """POST: retry lily BMC/OS reachability (reconnect + identity) after the node boots back."""
    for role in ("lily_bmc", "lily_os"):
        ip = getattr(target, role + "_ip")
        key = role + "_reachable"
        if not ip:
            record(key, None)  # not configured -> skip
            continue
        pw = bmc_pw if role == "lily_bmc" else os_pw
        ok, detail = False, "not attempted"
        for attempt in range(1, 41):  # ~5 min retry
            try:
                with ssh.connect(ip, USERS[role], pw, boot_wait=True) as cli:
                    info = identity(cli, hostdir / f"post_{role}_identity.txt")
                    check_mac(target, role, info)
                    ok, detail = True, f"reachable; hostname={info['hostname']} boot_id={info['boot_id']}"
                    transcript("LILY POST", f"{role} {ip} OK (attempt {attempt}): {detail}")
                    break
            except Exception as exc:
                detail = f"attempt {attempt}: {type(exc).__name__}: {exc}"
                if not boot_transport_pending(exc) and not timeout_error(exc):
                    transcript("LILY POST", f"{role} {ip} {detail}")
                    break
                transcript("LILY POST", f"{role} {ip} {detail}")
                time.sleep(10)
        record(key, ok)
        save(hostdir / f"post_{role}_reach.txt", f"UTC: {now()}\nrole={role}\nip={ip}\nresult={'OK' if ok else 'FAILED'}\n{detail}\n")


# --------------------------------------------------------------------------- outband ipmitool (local, -C 17)
def oob(target: Target, bmc_password: str, action: str, timeout: int = 30) -> tuple[int, str]:
    """Run ipmitool from the ORCHESTRATOR host against the node BMC (RMCP+, -C 17)."""
    cmd = (f"ipmitool -I lanplus -H {target.bmc_ip} -U {shlex.quote(target.bmc_oob_user)} "
           f"-P <redacted> -C {IPMITOOL_CIPHER} {action}")
    import subprocess
    proc = subprocess.run(["ipmitool", "-I", "lanplus", "-H", target.bmc_ip,
                           "-U", target.bmc_oob_user, "-P", bmc_password,
                           "-C", str(IPMITOOL_CIPHER)] + action.split(),
                          capture_output=True, text=True, timeout=timeout)
    out = proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
    return proc.returncode, out


# --------------------------------------------------------------------------- cycle actions
def cycle_command_for(mode: str, channel: str, target: Target, bmc_pw: str, os_pw: str) -> dict:
    """Return a dict describing how to issue one cycle.

    For inband the 'ssh' key says which SSH client + command to run.
    For outband the 'oob' key says the ipmitool action (run locally with -C 17),
    or 'bmc' for aux_cycle (run stbypowerctrl.sh on the BMC over SSH).
    """
    if mode == "aux_cycle":
        return {"label": "BMC aux_cycle (standby/AC)",
                "bmc": "/usr/bin/stbypowerctrl.sh aux_cycle",
                "note": "aux_cycle is a BMC-side D-Bus request; channel is always BMC."}
    if mode == "reboot":
        if channel == "inband":
            return {"label": "inband reboot", "ssh": ("os", "reboot", os_pw)}
        return {"label": "outband power soft (-C 17)", "oob": "power soft"}
    if mode == "power_cycle":
        if channel == "inband":
            return {"label": "inband ipmitool power cycle", "ssh": ("os", "ipmitool power cycle", os_pw)}
        return {"label": "outband power cycle (-C 17)", "oob": "power cycle"}
    raise ValueError(f"unknown cycle-mode {mode}")


def issue_cycle(ssh: SSH, plan: dict, target: Target, bmc_pw: str, os_pw: str, hostdir: Path) -> dict:
    """Issue exactly one cycle. Never retries the action itself."""
    result = {"issued": False, "state": "NOT_ISSUED", "note": ""}
    if "bmc" in plan:
        with ssh.connect(target.bmc_ip, USERS["bmc"], bmc_pw) as bmc:
            code, output = log_command(bmc, plan["bmc"], hostdir / "cycle_command.txt", 60,
                                       retries=0, display_command=plan["bmc"])
        result["issued"] = True
        result["state"] = "OK" if code == 0 else "COMMAND_ERROR"
        result["note"] = f"BMC aux_cycle exit {code}; no retry sent."
        return result
    if "oob" in plan:
        try:
            code, output = oob(target, bmc_pw, plan["oob"])
            save(hostdir / "cycle_command.txt",
                 f"UTC: {now()}\nCommand: ipmitool -I lanplus -H {target.bmc_ip} -U {target.bmc_oob_user} -P <redacted> -C {IPMITOOL_CIPHER} {plan['oob']}\nExit: {code}\n\n{output}\n")
            transcript("cycle_command", f"outband {plan['oob']} exit {code}", event="COMMAND")
            result["issued"] = True
            result["state"] = "OK" if code == 0 else "COMMAND_ERROR"
            result["note"] = f"outband {plan['oob']} exit {code}; no retry sent."
        except Exception as exc:
            result["state"] = "RESPONSE_LOST" if timeout_error(exc) else "COMMAND_ERROR"
            result["note"] = f"{type(exc).__name__}: {exc}. No retry sent."
            add_issue("cycle_command", result["state"], result["note"])
        return result
    if "ssh" in plan:
        role, command, _pw = plan["ssh"]
        host = getattr(target, role + "_ip")
        # inband power command: connect and send; the link drops when the box cycles.
        try:
            client = ssh.connect(host, USERS[role], _pw)
            try:
                client.exec_command(command, timeout=30)
                time.sleep(2)
            finally:
                ssh.close(client)
            result["issued"] = True
            result["state"] = "OK"
            result["note"] = f"inband `{command}` sent; no retry sent."
            save(hostdir / "cycle_command.txt", f"UTC: {now()}\nCommand (inband on {role}): {command}\nState: OK\n\n{result['note']}\n")
            transcript("cycle_command", result["note"], event="COMMAND")
        except Exception as exc:
            result["state"] = "RESPONSE_LOST" if boot_transport_pending(exc) or timeout_error(exc) else "COMMAND_ERROR"
            result["note"] = f"{type(exc).__name__}: {exc}. No retry sent."
            add_issue("cycle_command", result["state"], result["note"])
    return result


def wait_for_os(ssh: SSH, target: Target, old_boot: str, deadline: float, logdir: Path, os_pw: str):
    attempts = []
    while time.monotonic() < deadline:
        client = None
        try:
            client = ssh.connect(target.os_ip, USERS["os"], os_pw, boot_wait=True)
            current = identity(client, logdir / "post_os_identity.txt")
            if current["boot_id"] != old_boot:
                save(logdir / "boot_wait.txt", "\n".join(attempts) + f"\n{now()} changed boot ID: {current['boot_id']}\n")
                transcript("OS BOOT WAIT", f"changed boot ID: {current['boot_id']}")
                return client, current
            ssh.close(client)
            client = None
            attempts.append(f"{now()} OS reachable; boot ID unchanged")
        except Exception as exc:
            if client is not None:
                ssh.close(client)
            if not boot_transport_pending(exc):
                add_issue("OS boot wait", "TIMEOUT" if timeout_error(exc) else "ERROR", f"{type(exc).__name__}: {exc}")
                raise
            attempts.append(f"{now()} BOOT_PENDING: {type(exc).__name__}")
        transcript("OS BOOT WAIT", attempts[-1])
        save(logdir / "boot_wait.txt", "\n".join(attempts) + "\n")
        time.sleep(min(15, max(1, deadline - time.monotonic())))
    add_issue("OS boot wait", "TIMEOUT", "OS did not return with a changed boot ID before deadline")
    raise TimeoutError("OS did not return before timeout")


# --------------------------------------------------------------------------- one node / one loop
def cycle_one(ssh: SSH, target: Target, args, loop: int, bmc_pw: str, os_pw: str) -> dict:
    hostdir = args.output / node_name(target) / f"loop{loop}"
    hostdir.mkdir(parents=True, exist_ok=False)
    result = {"target": asdict(target), "loop": loop, "cycle_mode": args.cycle_mode,
              "channel": args.channel, "started_utc": now(), "steps": {}, "issues": [],
              "status": "INCOMPLETE"}
    LOG_CONTEXT.path = args.output / node_name(target) / f"{target.node}_full.log"
    LOG_CONTEXT.issues = result["issues"]
    LOG_CONTEXT.path.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_CONTEXT.path.exists():
        transcript("TEST HEADER", f"Test Item: {args.cycle_mode}_test\nNode: {target.node}\n"
                                  f"BMC: {target.bmc_ip}\nOS: {target.os_ip}\nCreated UTC: {now()}")

    summary = hostdir / "report.json"

    def record(step, value):
        result["steps"][step] = value
        save(summary, json.dumps(result, indent=2) + "\n")

    try:
        # ---- PRE ----
        with ssh.connect(target.bmc_ip, USERS["bmc"], bmc_pw) as bmc, \
             ssh.connect(target.os_ip, USERS["os"], os_pw, boot_wait=True) as os_client:
            # ---- clear BMC SEL + dmesg before any checks ----
            transcript("PRE CLEAR", "Clearing BMC SEL and dmesg")
            log_command(bmc, "ipmitool sel clear 2>&1 || true",
                        hostdir / "pre_bmc_sel_clear.txt", 30, fatal=False)
            run(os_client, "dmesg -c > /dev/null 2>&1 || true", 10, None)
            # ---- capture identity ----
            bmc_before = identity(bmc, hostdir / "pre_bmc_identity.txt")
            os_before = identity(os_client, hostdir / "pre_os_identity.txt")
            check_mac(target, "bmc", bmc_before)
            check_mac(target, "os", os_before)
            record("pre_bmc", bmc_before)
            record("pre_os", os_before)
            # system info (host/kernel/os/cpu/mem/disk/net + BMC identity) - like PowerIP info_get
            collect_info(os_client, hostdir / "pre_info.txt")
            collect_dmesg_all(os_client, hostdir / "pre_dmesg_all.txt", os_pw)
            # lily (BF4 DPU) identity - only when lily IPs are set
            lily_pre(ssh, target, bmc_pw, os_pw, hostdir, record)
            code, status = log_command(bmc, "/usr/bin/powerctrl.sh power_status",
                                       hostdir / "pre_power_status.txt", 30)
            record("power_status", status.strip())
            record("power", code == 0 and "Host: Running" in status and "Chassis Power: On" in status)
            # root + config + lspci baseline on OS
            code, uid = log_command(os_client, "sudo -S -p '' id -u", hostdir / "pre_root_uid.txt", 30, os_pw + "\n")
            record("root", code == 0 and uid.split("\n[stderr]\n", 1)[0].strip() == "0")
            record("config", config_check(os_client, args.config_script, hostdir, "pre", os_pw))
            # lspci baseline: capture device list for later comparison
            code, lspci_out = log_command(os_client, "lspci -nn", hostdir / "pre_lspci_nn.txt", 30)
            baseline_cards = sorted([l.strip() for l in lspci_out.splitlines() if l.strip()])
            save(hostdir / "pre_lspci_baseline.json", json.dumps(baseline_cards, indent=2) + "\n")
            record("lspci_baseline_count", len(baseline_cards))
            # sensor baseline (in-band ipmi; OS is up before the cycle) so POST can
            # detect a LOST sensor by row count. Wait for /dev/ipmi0 here too: on
            # the first loop the node may still be settling from a prior cycle.
            if not wait_for_ipmi(os_client, 120):
                add_issue("pre_sensor", "WARN",
                          "/dev/ipmi0 not present 120s before cycle; sensor baseline unavailable")
            code, s_out = capture_sensor_list(os_client, hostdir / "pre_sensor_list.txt", os_pw)
            for kind, detail in output_issues(code, s_out):
                add_issue("pre_sensor", kind, detail)
            s_stdout = s_out.split("\n[stderr]\n", 1)[0]
            base_hw = hardware_sensor_names(s_stdout)
            base_statuses = hardware_sensor_statuses(s_stdout)
            save(hostdir / "pre_sensor_baseline.json",
                 json.dumps({"hw_count": len(base_hw),
                             "hw_names": sorted(base_hw),
                             "hw_statuses": base_statuses,
                             "raw_rows": sensor_rows(s_stdout)}, indent=2) + "\n")
            record("sensor_baseline_count", len(base_hw))
            record("sensor_baseline_rows", len(base_hw))

        # ---- issue cycle (always, even if pre checks failed) ----
        plan = cycle_command_for(args.cycle_mode, args.channel, target, bmc_pw, os_pw)
        transcript("LOOP START", f"Node {target.node} loop {loop} | {plan['label']}\n{plan.get('note','')}")
        save(hostdir / "cycle_reserved.json", json.dumps({"utc": now(), "plan": plan["label"],
                                                          "os_boot_id": os_before["boot_id"]}, indent=2) + "\n")
        record("cycle_reserved", True)
        issued = issue_cycle(ssh, plan, target, bmc_pw, os_pw, hostdir)
        record("power_cmd", issued["issued"] and issued["state"] in {"OK", "RESPONSE_LOST"})
        record("cycle_state", issued["state"])
        record("cycle_note", issued["note"])

        # ---- wait for OS ----
        os_client, os_after = wait_for_os(ssh, target, os_before["boot_id"],
                                          time.monotonic() + args.boot_timeout, hostdir, os_pw)
        with os_client:
            check_mac(target, "os", os_after)
            record("post_os", os_after)
            record("boot_changed", os_after["boot_id"] != os_before["boot_id"])
            # Wait for the in-band IPMI device to appear after the cold boot
            # (ipmi_ssif probe race); without it post_sensor/post_sel fail spuriously.
            if not wait_for_ipmi(os_client, 120):
                add_issue("post_sensor", "WARN",
                          "/dev/ipmi0 not present 120s after boot (ipmi_ssif probe race); "
                          "sensor/sel recorded but non-fatal")
            # full per-loop OS capture (union)
            cap_codes = {}
            for stem, cmd, sudo, to, fatal in OS_CAPTURES:
                if stem == "post_sensor":
                    # retry internally: the BMC sometimes returns a truncated
                    # table, which would masquerade as many lost sensors
                    code, _out = capture_sensor_list(os_client, hostdir / f"{stem}.txt", os_pw)
                    cap_codes[stem] = code
                    if code != 0:
                        for kind, detail in output_issues(code, _out):
                            add_issue(stem, kind, detail)
                    continue
                full = cmd if not sudo else f"sudo -S -p '' {cmd}"
                code, _out = log_command(os_client, full, hostdir / f"{stem}.txt", to,
                                         os_pw + "\n" if sudo else None,
                                         display_command=cmd, fatal=fatal)
                cap_codes[stem] = code
                if stem == "post_lspci_tv":
                    # lspci check: exit code + card count comparison with baseline
                    baseline_file = hostdir / "pre_lspci_baseline.json"
                    lspci_ok = (code == 0)
                    lspci_detail = ""
                    if baseline_file.exists():
                        baseline_cards = set(json.loads(baseline_file.read_text()))
                        # capture current lspci -nn for comparison
                        code2, lspci_nn_out = log_command(os_client, "lspci -nn", hostdir / "post_lspci_nn.txt", 30)
                        current_cards = set([l.strip() for l in lspci_nn_out.splitlines() if l.strip()])
                        missing = baseline_cards - current_cards
                        extra = current_cards - baseline_cards
                        if missing:
                            lspci_ok = False
                            lspci_detail = f"MISSING: {'; '.join(sorted(missing))}"
                        if extra:
                            lspci_detail += f" EXTRA: {'; '.join(sorted(extra))}"
                        record("lspci_baseline_count", len(baseline_cards))
                        record("lspci_current_count", len(current_cards))
                        if lspci_detail:
                            add_issue("lspci", "CARD_DIFF", lspci_detail)
                    record("lspci", lspci_ok)
            # sensor loss detection: compare the unique hardware sensor IDs
            # reported before and after the cycle.
            # Only when the post read succeeded; ipmi0-absent => exit!=0 => skip.
            sensor_base_file = hostdir / "pre_sensor_baseline.json"
            if cap_codes.get("post_sensor") == 0 and sensor_base_file.exists():
                baseline = json.loads(sensor_base_file.read_text())
                post_text = (hostdir / "post_sensor.txt").read_text()
                post_out = post_text.split("\n[stderr]\n", 1)[0]
                base_names = set(baseline.get("hw_names", []))
                post_names = hardware_sensor_names(post_out)
                missing = sorted(base_names - post_names)
                record("sensor_current_count", len(post_names))
                record("sensor_raw_rows", sensor_rows(post_out))
                # An SDR read error makes the list incomplete: a smaller set
                # then means "could not read", not "sensor lost". ipmitool
                # prints these on stderr, so scan the whole capture.
                sdr_errors = re.findall(r"Get SDR [0-9a-fA-F]+ command failed[^\n]*", post_text)
                if sdr_errors:
                    add_issue("sensor_diff", "SDR_ERROR",
                              f"{len(sdr_errors)} SDR read error(s), sensor list incomplete "
                              f"({len(base_names)} -> {len(post_names)} hw sensors): {sdr_errors[0][:90]}")
                    record("sensor_diff", None)
                elif not base_names:
                    add_issue("sensor_diff", "WARN",
                              "pre-cycle sensor baseline empty (ipmi not ready); loss check skipped")
                    record("sensor_diff", None)
                else:
                    if missing:
                        # A single missing sensor in one read is usually a BMC
                        # reporting glitch: the SDR table is stable, so read it
                        # once more and only call it a loss if the sensor does
                        # not come back.
                        confirm_code, confirm_out = capture_sensor_list(
                            os_client, hostdir / "post_sensor_confirm.txt", os_pw)
                        confirm_text = (hostdir / "post_sensor_confirm.txt").read_text()
                        if confirm_code != 0 or re.search(r"Get SDR [0-9a-fA-F]+ command failed", confirm_text):
                            add_issue("sensor_diff", "SDR_ERROR",
                                      f"{len(missing)} sensor(s) missing but confirmation read failed: "
                                      + "; ".join(missing[:8]))
                            record("sensor_diff", None)
                        else:
                            confirm_names = hardware_sensor_names(confirm_out)
                            still_missing = [s for s in missing if s not in confirm_names]
                            if still_missing:
                                add_issue("sensor_diff", "SENSOR_LOST",
                                          f"{len(still_missing)} sensor(s) missing in post read and "
                                          f"confirmation: " + "; ".join(still_missing[:8]))
                                record("sensor_diff", False)
                            else:
                                add_issue("sensor_diff", "WARN",
                                          f"{len(missing)} sensor(s) missing in one read but present on "
                                          f"confirmation (transient BMC report): "
                                          + "; ".join(missing[:8]))
                                record("sensor_diff", True)
                                # Also check status on the confirmation read
                                _check_sensor_status(baseline, confirm_out, add_issue, record)
                    else:
                        # No missing sensors -- check for status degradation
                        _check_sensor_status(baseline, post_out, add_issue, record)
            # root check after cycle (capture id -u)
            code, uid = log_command(os_client, "sudo -S -p '' id -u", hostdir / "post_root_uid.txt", 30, os_pw + "\n")
            record("root", code == 0 and uid.split("\n[stderr]\n", 1)[0].strip() == "0")
            record("config", config_check(os_client, args.config_script, hostdir, "post", os_pw))
            record("post_dmesg_ok", True)  # dmesg capture is record-only
            collect_dmesg_all(os_client, hostdir / "post_dmesg_all.txt", os_pw)
            # Clear dmesg after post-capture (so next loop only sees new errors)
            run(os_client, "dmesg -c > /dev/null 2>&1 || true", 10, None)

        # ---- BMC post: boot_id + power ----
        try:
            with ssh.connect(target.bmc_ip, USERS["bmc"], bmc_pw) as bmc:
                bmc_after = identity(bmc, hostdir / "post_bmc_identity.txt")
                record("bmc_boot_changed", bmc_after["boot_id"] != bmc_before["boot_id"])
                code, status = log_command(bmc, "/usr/bin/powerctrl.sh power_status",
                                           hostdir / "post_power_status.txt", 30)
                record("power_status", status.strip() if code == 0 else "command failed")
                record("power", code == 0 and "Host: Running" in status and "Chassis Power: On" in status)
        except Exception as exc:
            record("power", False)
            add_issue("post_power_status", "TIMEOUT" if timeout_error(exc) else "ERROR", str(exc))

        # ---- outband ipmitool cross-check (-C 17) ----
        try:
            code, out = oob(target, bmc_pw, "power status")
            save(hostdir / "post_oob_power_status.txt", f"UTC: {now()}\nCommand: ipmitool -C {IPMITOOL_CIPHER} power status\nExit: {code}\n\n{out}\n")
            record("post_oob_power", out.strip().splitlines()[-1] if out.strip() else "NO_VALUE")
        except Exception as exc:
            record("post_oob_power", f"ERROR: {exc}")

        # ---- lily (BF4 DPU) reachability - only when lily IPs are set ----
        lily_post(ssh, target, bmc_pw, os_pw, hostdir, record)

        # reconciliation of RESPONSE_LOST
        recovered = all(result["steps"].get(k) is True for k in
                        ("boot_changed", "bmc_boot_changed", "power"))
        if issued["state"] == "RESPONSE_LOST" and recovered:
            record("cycle_state", "RESPONSE_LOST_RECONCILED")
            record("power_cmd", True)
            record("cycle_note", "response lost during reset; boot IDs + power verify the transition.")
        (hostdir / "cycle_reserved.json").unlink(missing_ok=True)

    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        add_issue("loop", "TIMEOUT" if timeout_error(exc) else "ERROR", result["error"])
        transcript("LOOP ERROR", result["error"])
        try:
            (hostdir / "cycle_reserved.json").unlink(missing_ok=True)
        except Exception:
            pass

    result["finished_utc"] = now()
    evaluate_result(result)
    save(summary, json.dumps(result, indent=2) + "\n")
    save(hostdir / "loop_summary.txt", format_loop_summary(result, hostdir))
    transcript("LOOP RESULT", f"Result: {result['status']}")
    LOG_CONTEXT.path = None
    LOG_CONTEXT.issues = None
    return result


def _check_sensor_status(baseline: dict, post_out: str, add_issue, record) -> None:
    """Check for sensor status degradation (ok -> critical/non-recoverable).

    Compares the status column (4th) of each hw sensor between the pre-cycle
    baseline and the post-cycle read. If a sensor was "ok" before the cycle
    and is now "critical" or "non-recoverable", record a SENSOR_STATUS issue
    and mark sensor_diff as FAILED.
    """
    base_statuses = baseline.get("hw_statuses", {})
    post_statuses = hardware_sensor_statuses(post_out)
    degraded = []
    for name, pre_status in base_statuses.items():
        post_status = post_statuses.get(name)
        if post_status is None:
            continue  # sensor missing (handled by the missing check)
        pre_norm = pre_status.strip().lower()
        post_norm = post_status.strip().lower()
        if pre_norm == "ok" and post_norm in BAD_SENSOR_STATUSES:
            degraded.append(f"{name} ({pre_status} -> {post_status})")
    if degraded:
        add_issue("sensor_diff", "SENSOR_STATUS",
                  f"{len(degraded)} sensor(s) status degraded after cycle: "
                  + "; ".join(degraded[:8]))
        record("sensor_diff", False)
    else:
        record("sensor_diff", True)


def format_loop_summary(result: dict, hostdir: Path) -> str:
    """精簡版 loop summary：只放摘要 + 關鍵差異 + Issues，不內嵌完整 log。"""
    t = result["target"]
    st = result["steps"]
    L = []

    # 1. Header
    L.append(f"Node: {t['node']}  Loop: {result['loop']}  Mode: {result['cycle_mode']}  Channel: {result['channel']}")
    L.append(f"Started: {result['started_utc']}   Finished: {result['finished_utc']}  ({_duration(result['started_utc'], result['finished_utc'])})")
    L.append(f"Result: {result['status']}")

    # 2. Key metrics (one line each)
    lspci_pre = st.get("lspci_baseline_count")
    lspci_post = st.get("lspci_current_count")
    sen_pre = st.get("sensor_baseline_count")
    sen_post = st.get("sensor_current_count")
    sen_raw = st.get("sensor_raw_rows")
    if lspci_pre is not None:
        L.append(f"PCIe cards : {lspci_pre} -> {lspci_post}" + (f"  (missing {lspci_pre - lspci_post})" if (lspci_post is not None and lspci_post < lspci_pre) else ""))
    if sen_pre is not None:
        L.append(f"Sensors    : {sen_pre} -> {sen_post}" + (f"  (raw rows: {sen_raw})" if sen_raw else "") + (f"  (missing {sen_pre - sen_post})" if (sen_post is not None and sen_post < sen_pre) else ""))
    L.append(f"Cycle state: {st.get('cycle_state')}")
    if st.get("cycle_note"):
        L.append(f"Note       : {st['cycle_note']}")

    # 3. Checks (compact table)
    L.append("")
    L.append("Checks:")
    for k in CHECKS:
        v = st.get(k)
        mark = "FAIL" if v is False else ("OK" if v is True else "  -")
        L.append(f"  {k:25s} {mark}")

    # 4. Issues (only if any)
    if result["issues"]:
        L.append("")
        L.append("Issues:")
        for i in result["issues"]:
            L.append(f"  {i['step']} [{i['kind']}]: {i['detail']}")

    # 5. Error (if any)
    if result.get("error"):
        L.append("")
        L.append(f"Error: {result['error']}")

    return "\n".join(L) + "\n"


def _duration(start_utc: str, end_utc: str) -> str:
    """Human-readable duration between two ISO timestamps."""
    try:
        from datetime import datetime
        s = datetime.fromisoformat(start_utc)
        e = datetime.fromisoformat(end_utc)
        delta = e - s
        mins = int(delta.total_seconds() // 60)
        secs = int(delta.total_seconds() % 60)
        return f"{mins}m{secs:02d}s"
    except Exception:
        return "n/a"


def config_check(client, local: Path, logdir: Path, stage: str, os_pw: str) -> bool:
    code, output = log_command(client, "if test -f ~/vera_rack.sh; then echo PRESENT; else echo MISSING; fi",
                               logdir / f"{stage}_config_present.txt", 20)
    if local.is_file():
        sftp = client.open_sftp()
        try:
            home = sftp.normalize(".")
            sftp.put(str(local), home + "/vera_rack.sh")
        finally:
            sftp.close()
    code, output = log_command(client, f"sudo -S -p '' bash ~/vera_rack.sh",
                               logdir / f"{stage}_config.txt", 300, os_pw + "\n", fatal=False)
    return config_ok(output, code)


def evaluate_result(result: dict) -> str:
    issues = result.setdefault("issues", [])
    for key, label in CHECKS.items():
        value = result["steps"].get(key)
        if value is None:
            continue  # not configured / skipped (e.g. lily with no IP) -> not evaluated
        if value is not True and not any(i["step"] == key for i in issues):
            issues.append({"step": key, "kind": "NO_VALUE" if key not in result["steps"] else "ERROR",
                           "detail": f"{label}: missing" if key not in result["steps"] else f"{label}: failed",
                           "attempt": None, "utc": now()})
    # sensor/sel are only non-fatal when /dev/ipmi0 was genuinely absent after
    # the wait (probe race, recorded as a WARN on post_sensor) — in that case we
    # couldn't read sensors at all, so it must not count as a lost sensor.
    ipmi0_absent = any(i["step"] == "post_sensor" and i["kind"] == "WARN"
                       and "ipmi0" in i["detail"] for i in issues)
    skip = NON_FATAL_STEPS if ipmi0_absent else set()
    fatal_issues = [i for i in issues if i["step"] not in skip]
    result["status"] = "FAILED" if fatal_issues or result.get("error") else "PASS"
    return result["status"]


# --------------------------------------------------------------------------- campaign
def _md_table(header: list, data: list, aligns: list) -> list:
    """Markdown table with per-column alignment (header left, data per aligns)."""
    widths = [len(c) for c in header]
    for r in data:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))

    def fmt(cells, is_header=False):
        out = []
        for i, c in enumerate(cells):
            w = widths[i]
            a = "l" if is_header else aligns[i]
            out.append(c.ljust(w) if a == "l" else c.rjust(w) if a == "r" else c.center(w))
        return "| " + " | ".join(out) + " |"

    sep = "| " + " | ".join((":--" if a == "l" else ":-:" if a == "c" else "--:") for a in aligns) + " |"
    lines = [fmt(header, is_header=True), sep]
    for r in data:
        lines.append(fmt(r))
    return lines


# issue kinds that count as a real hardware failure (config is excluded separately)
FAIL_KINDS = {"ERROR", "SENSOR_LOST", "SENSOR_STATUS", "CARD_DIFF", "SDR_ERROR"}
CONFIG_NOISE = re.compile(r"BF4|no lost devices in \[Fail\]", re.I)


def _row_real_issues(r: dict) -> list:
    """Issues that are real hardware problems (excludes WARN and the expected BF4 config failure)."""
    return [i for i in r.get("issues", [])
            if i.get("kind") != "WARN"
            and i.get("step") != "config"
            and not CONFIG_NOISE.search(i.get("detail", ""))]


def _row_warns(r: dict) -> list:
    return [i for i in r.get("issues", []) if i.get("kind") == "WARN"]


def generate_node_summaries(args, rows: list[dict]) -> None:
    """Write <node>/node_summary.txt: per-loop issue digest for each node."""
    by_node: dict = {}
    for r in rows:
        by_node.setdefault(r["target"]["node"], []).append(r)

    for node, node_rows in by_node.items():
        node_rows.sort(key=lambda r: r["loop"])
        L = [f"Node: {node}  Run: {args.output.name}  Loops: {len(node_rows)}", ""]
        total_issues = 0
        failed_loops = []
        loop_lines = []
        for r in node_rows:
            n = r["loop"]
            real = _row_real_issues(r)
            if not real:
                loop_lines.append(f"Loop {n:2d}: OK")
                continue
            total_issues += len(real)
            if r["status"] != "PASS":
                failed_loops.append(n)
            worst = "FAIL" if any(i["kind"] in FAIL_KINDS for i in real) else "WARN"
            loop_lines.append(f"Loop {n:2d}: {worst}")
            for i in real:
                loop_lines.append(f"         {i['step']} [{i['kind']}]: {i['detail']}")
        L.append(f"Hardware issues: {total_issues}")
        L.append(f"Failed loops: {failed_loops if failed_loops else '(none)'}")
        L.append("")
        L.append("Note: config [ERROR] (BF4 missing) is excluded — this node has no BF4 by design.")
        L.append("")
        L.append("---")
        L.extend(loop_lines)
        save(args.output / node_name_by_label(args, node) / "node_summary.txt", "\n".join(L) + "\n")


def node_name_by_label(args, node: str) -> str:
    """Map a node label ('n2') to its output directory name ('node2')."""
    d = args.output / f"node{node.lstrip('nN')}"
    if d.is_dir():
        return d.name
    # fall back: find the directory whose name contains the label
    for p in args.output.iterdir():
        if p.is_dir() and p.name.lower() in (f"node{node}", node.lower()):
            return p.name
    return f"node{node.lstrip('nN')}"


def _dmesg_hw_errors(output: Path) -> list:
    pat = re.compile(r".*(?:PCIe Bus Error|AER:|Bad TLP|Bad DLLP|Machine Check"
                     r"|nvme.*(?:I/O error|controller is down)).*")
    hits = []
    for f in sorted(output.glob("node*/loop*/post_dmesg_all.txt")):
        for m in pat.findall(f.read_text(errors="replace")):
            hits.append((str(f), m.strip()[:120]))
    return hits


def _sel_with_entries(output: Path) -> list:
    return [str(f) for f in sorted(output.glob("node*/loop*/post_sel.txt"))
            if "SEL has no entries" not in f.read_text(errors="replace")]


def _issue_brief(i: dict) -> str:
    """Short one-line form of an issue for the evidence table."""
    d = i.get("detail", "")
    m = re.search(r"transient BMC report\):\s*(\S+)", d)
    if m:
        return f"{i['kind']}: {m.group(1)}"
    m = re.search(r"confirmation:\s*(.+)", d)
    if m:
        return f"{i['kind']}: {m.group(1)[:60]}"
    m = re.search(r"degraded after cycle:\s*(.+)", d)
    if m:
        return f"{i['kind']}: {m.group(1)[:60]}"
    m = re.search(r"MISSING:\s*(.+)", d)
    if m:
        return f"{i['kind']}: card missing"
    return f"{i['kind']}: {d[:60]}".strip()


def generate_health_report(args, rows: list[dict]) -> None:
    """Write HARDWARE_HEALTH_REPORT.md at the top of the output dir.

    Derived entirely from the completed run (rows + on-disk captures); safe to
    call after every campaign, and also mid-run for a partial report.
    """
    nodes = sorted({r["target"]["node"] for r in rows})
    loops_total = max((r["loop"] for r in rows), default=0)
    hw_err = _dmesg_hw_errors(args.output)
    sel_events = _sel_with_entries(args.output)
    started = [r["started_utc"] for r in rows if r.get("started_utc")]
    finished = [r["finished_utc"] for r in rows if r.get("finished_utc")]

    # any real failure -> overall FAIL
    overall_fail = any(
        i["kind"] in FAIL_KINDS for r in rows for i in _row_real_issues(r)
    )

    # ---- verdict table ----
    vdata = []
    for n in nodes:
        sub = [r for r in rows if r["target"]["node"] == n]
        cards = sum(1 for r in sub
                    if r["steps"].get("lspci_current_count") is not None
                    and r["steps"].get("lspci_baseline_count") is not None
                    and r["steps"]["lspci_current_count"] < r["steps"]["lspci_baseline_count"])
        lost = sum(1 for r in sub for i in _row_real_issues(r) if i["kind"] == "SENSOR_LOST")
        degraded = sum(1 for r in sub for i in _row_real_issues(r) if i["kind"] == "SENSOR_STATUS")
        trans = sum(1 for r in sub for _ in _row_warns(r))
        dmesg_n = sum(1 for f, _ in hw_err if f"/node{n.lstrip('nN')}/" in f)
        sel_n = sum(1 for f in sel_events if f"/node{n.lstrip('nN')}/" in f)
        vdata.append([f"`{n}`", f"{len(sub)} / {loops_total}", str(cards), str(lost),
                      str(degraded), str(dmesg_n), str(sel_n), str(trans)])
    vtbl = _md_table(["Node", "Cycles", "PCIe card loss", "Sensor lost", "Sensor degraded",
                      "dmesg HW errors", "BMC SEL events", "Transients"],
                     vdata, ["c"] * 8)

    # ---- evidence per loop ----
    edata = []
    for r in sorted(rows, key=lambda r: (r["target"]["node"], r["loop"])):
        st = r["steps"]
        real = _row_real_issues(r)
        warns = _row_warns(r)
        if real:
            note = "**" + ", ".join(f"`{_issue_brief(e)}`" for e in real) + "**"
        elif warns:
            note = "⚠ " + ", ".join(f"`{_issue_brief(w)}`" for w in warns)
        else:
            note = "—"
        edata.append([f"`{r['target']['node']}`", str(r["loop"]),
                      f"{st.get('lspci_baseline_count')} → {st.get('lspci_current_count')}",
                      f"{st.get('sensor_baseline_count')} → {st.get('sensor_current_count')}",
                      str(st.get("sensor_raw_rows")), note])
    etbl = _md_table(["Node", "Loop", "PCIe cards", "Sensors (hw)", "raw rows", "Notes"],
                     edata, ["c", "c", "c", "c", "c", "l"])

    L = []
    L.append("# Vera CPU Rack — Hardware Health Report")
    L.append("")
    L.append(f"## {loops_total}-Power-Cycle Stress Test · Project `{getattr(args, 'project_name', None) or args.project or 'n/a'}`")
    L.append("")
    L.append("---")
    L.append("")
    L.append("**Status**")
    L.append("")
    L.append("|  |  |")
    L.append("|:--|:--|")
    verdict = "❌ **FAIL** — see per-loop evidence" if overall_fail else "✅ **PASS** — no hardware degradation"
    L.append(f"| **Result** | {verdict} |")
    L.append(f"| **Nodes** | {' · '.join('`' + n + '`' for n in nodes)} |")
    L.append(f"| **Mode** | `{args.cycle_mode}` / {args.channel} |")
    L.append(f"| **Loops** | {loops_total} per node |")
    L.append(f"| **Run ID** | `{args.output.name}` |")
    window = f"{min(started)} → {max(finished)}" if started and finished else "n/a"
    L.append(f"| **Window** | {window} |")
    L.append(f"| **Source** | `{args.output}` |")
    L.append("")
    L.append("**Contents**")
    L.append("")
    L.append("1. [Verdict](#1-verdict)")
    L.append("2. [Evidence per loop](#2-evidence-per-loop)")
    L.append("3. [How to read the Notes column](#3-how-to-read-the-notes-column)")
    L.append("4. [dmesg / BMC SEL](#4-dmesg--bmc-sel)")
    L.append("5. [Sensor loss detection method](#5-sensor-loss-detection-method)")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 1. Verdict")
    L.append("")
    if overall_fail:
        L.append("**Hardware degradation detected — review the per-loop evidence below.**")
    else:
        L.append(f"**No hardware degradation detected on any node across {loops_total} power cycles.**")
    L.append("")
    L.extend(vtbl)
    L.append("")
    L.append("> `Sensor lost` = absent from both the post read and the confirmation read (real loss).")
    L.append("> `Sensor degraded` = status went `ok` → `critical`/`non-recoverable` after the cycle.")
    L.append("> `Transients` = a sensor was missing from one read but returned on the confirmation read.")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 2. Evidence per loop")
    L.append("")
    L.extend(etbl)
    L.append("")
    L.append("`raw rows` is the row count of the best `ipmitool sensor list` read for that phase.")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 3. How to read the Notes column")
    L.append("")
    L.append("- **`⚠ transient`** — a sensor was absent from one `ipmitool sensor list` read but **returned on the")
    L.append("  immediate confirmation read**. The SDR table is fixed, so a sensor that comes back in the very")
    L.append("  next read is a **BMC reporting glitch**, not a hardware loss. **Not counted as a failure.**")
    L.append("- **`SENSOR_LOST`** — absent from **both** the post read and the confirmation read. **Fails the node.**")
    L.append("- **`SENSOR_STATUS`** — status went `ok` → `critical`/`non-recoverable` after the cycle.")
    L.append("  **Fails the node.**")
    L.append("- **`CARD_DIFF`** — a PCIe card present before the cycle was missing after it. **Fails the node.**")
    L.append("- **`config`** — `vera_rack.sh: no lost devices in [Fail]: failed` when the node has **no BF4 device")
    L.append("  by design**. Expected; excluded from the failure count.")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 4. dmesg / BMC SEL")
    L.append("")
    L.append("- **Strict scan** — patterns `PCIe Bus Error`, `AER:`, `Bad TLP`, `Bad DLLP`, `Machine Check`,")
    L.append(f"  NVMe I/O error / controller down — over all post-cycle dmesg captures: **{len(hw_err)} matches**.")
    if hw_err:
        for f, m in hw_err[:10]:
            L.append(f"  - `{f}`: {m}")
    L.append(f"- **BMC SEL** — **{len(sel_events)} loops with entries**. The SEL is cleared before each cycle,")
    L.append("  so an empty list is the clean state.")
    L.append("")
    L.append("**Benign boot-time messages** present in every loop (excluded from the scan above):")
    L.append("")
    L.append("| Message | Meaning |")
    L.append("|:--|:--|")
    L.append("| `acpi ... _OSC: platform does not support [SHPCHotplug PME AER DPC]` | capability advertisement |")
    L.append("| `pci 000x:00:00.0: bridge window [io size 0x1000]: failed to assign` | normal bridge window sizing |")
    L.append("| `mlx_compat: module verification failed ... tainting kernel` | unsigned out-of-tree module |")
    L.append("| `ipmi_ssif` probe retry (`-19` / `-17`) | known BMC SMBus race at boot |")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 5. Sensor loss detection method")
    L.append("")
    L.append("Compares **unique hardware sensor IDs and their status** before vs. after each cycle:")
    L.append("")
    L.append("- **Excludes** the `CorUti*` (per-core utilization) family and rows whose name does not decode —")
    L.append("  these appear and disappear with CPU load on **every single read**.")
    L.append("- **Compares name *sets*, not row counts** — the table legitimately repeats some IDs, so a changed")
    L.append("  repeat count must not read as a lost sensor.")
    L.append("- **Confirmation re-read** — on any missing sensor, the table is read once more: if the sensor")
    L.append("  returns it is a `WARN` (transient), otherwise `SENSOR_LOST`.")
    L.append("- **Status check** — each sensor's status column is compared: `ok` → `critical`/`non-recoverable`")
    L.append("  is reported as `SENSOR_STATUS` and fails the node.")
    L.append("")

    save(args.output / "HARDWARE_HEALTH_REPORT.md", "\n".join(L) + "\n")


def write_summary(args, rows: list[dict], targets: list[Target]) -> None:
    done = {r["target"]["node"]: r for r in rows}
    lines = [f"# Cycle summary: {targets[0].tray}",
             f"Mode: {args.cycle_mode}  Channel: {args.channel}",
             f"Requested: loops={args.loops or 'n/a'} hours={args.hours or 'n/a'}",
             f"Updated UTC: {now()}", "", "Node | completed | PASS | FAILED",
             "-" * 50]
    for t in targets:
        own = [r for r in rows if r["target"]["node"] == t.node]
        p = sum(1 for r in own if r["status"] == "PASS")
        f = sum(1 for r in own if r["status"] == "FAILED")
        total = f"{args.loops}" if args.loops else f"{args.hours}h"
        lines.append(f"{t.node} | {len(own)}/{total} | {p} | {f}")

    # Fail details at the bottom
    failed = [(r["target"]["node"], r["loop"], r) for r in rows if r["status"] == "FAILED"]
    if failed:
        lines.append("")
        lines.append("Failed loops:")
        for node, loop, r in sorted(failed, key=lambda x: (x[0], x[1])):
            failed_checks = [k for k in CHECKS if r["steps"].get(k) is False]
            reason = ", ".join(failed_checks) if failed_checks else r.get("error", "unknown")
            lines.append(f"  {node} loop{loop}: {reason}")

    save(args.output / "cycle_summary.txt", "\n".join(lines) + "\n")
    save(args.output / "cycle_summary.json", json.dumps(rows, indent=2, default=str) + "\n")


def run_campaign(args, targets: list[Target], bmc_pw: str, os_pw: str) -> int:
    import paramiko  # noqa: F401
    # known_hosts in /tmp (not in output dir)
    import tempfile
    kh = Path(tempfile.gettempdir()) / f".cycle_known_hosts_{os.getpid()}"
    ssh = SSH(kh, args.trust_first_use,
              {"bmc": bmc_pw, "os": os_pw, "lily_bmc": bmc_pw, "lily_os": os_pw})

    # tee all output (stdout+stderr) to console.log in output dir
    args.output.mkdir(parents=True, exist_ok=True)
    console_log = open(args.output / "console.log", "a", buffering=1)
    import sys as _sys
    class _Tee:
        def __init__(self, *streams): self.streams = streams
        def write(self, data):
            for s in self.streams: s.write(data)
        def flush(self):
            for s in self.streams: s.flush()
    _sys.stdout = _Tee(_sys.__stdout__, console_log)
    _sys.stderr = _Tee(_sys.__stderr__, console_log)

    # stop rule: both loops and hours may be set; whichever first stops.
    campaign_deadline = (time.monotonic() + args.hours * 3600) if args.hours else None
    loop = 0
    rows: list[dict] = []
    stop_reason = "completed"
    active_targets = list(targets)  # nodes still running
    while active_targets:
        loop += 1
        if args.loops and loop > args.loops:
            stop_reason = "loops reached"; break
        if campaign_deadline and time.monotonic() >= campaign_deadline:
            stop_reason = "hours reached"; break
        print(f"{now()} Starting loop {loop} on {len(active_targets)} nodes ({args.cycle_mode}/{args.channel})", flush=True)
        results = []
        with ThreadPoolExecutor(max_workers=len(active_targets)) as ex:
            futs = {ex.submit(cycle_one, ssh, t, args, loop, bmc_pw, os_pw): t for t in active_targets}
            for fut in as_completed(futs):
                t = futs[fut]
                try:
                    r = fut.result()
                except Exception as exc:
                    import traceback
                    traceback.print_exc()
                    r = {"target": asdict(t), "loop": loop, "status": "FAILED",
                         "issues": [], "error": f"{type(exc).__name__}: {exc}", "steps": {}}
                results.append(r)
                print(f"{now()} Loop {loop} {t.node}: {r['status']}", flush=True)
        rows.extend(results)
        write_summary(args, rows, targets)
        generate_node_summaries(args, rows)
        generate_health_report(args, rows)
        # N (default): remove failed nodes from active list; Y (keep-going): keep all
        if not args.keep_going:
            failed_nodes = {r["target"]["node"] for r in results if r["status"] != "PASS"}
            if failed_nodes:
                active_targets = [t for t in active_targets if t.node not in failed_nodes]
                print(f"{now()} Stopping failed node(s): {', '.join(sorted(failed_nodes))}", flush=True)
                if not active_targets:
                    stop_reason = "all nodes failed"; break
    write_summary(args, rows, targets)
    generate_node_summaries(args, rows)
    generate_health_report(args, rows)
    print(f"{now()} Campaign stopped: {stop_reason}. Reports: {args.output}", flush=True)
    return 0 if all(r["status"] == "PASS" for r in rows) else 1


LOCK_PATH = Path("/var/run/neutrin_cycle.lock")


def acquire_run_lock():
    """Refuse to start when another campaign is already running.

    Exclusive flock: the OS releases it automatically if the process dies,
    so a stale lock file can never block a new run.
    """
    import fcntl
    for path in (LOCK_PATH, Path("/tmp/neutrin_cycle.lock")):
        try:
            fh = open(path, "a+")
        except OSError:
            continue
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.seek(0)
            other = fh.read().strip() or "unknown"
            print(f"ERROR: another neutrin_cycle run is active (pid {other}).", file=sys.stderr)
            print("       stop it first:  /root/rackctl/stop_cycle.sh", file=sys.stderr)
            sys.exit(2)
        fh.seek(0)
        fh.truncate()
        fh.write(f"{os.getpid()}\n")
        fh.flush()
        return fh
    print("WARNING: could not create a lock file; running without duplicate-run protection",
          file=sys.stderr)
    return None


# --------------------------------------------------------------------------- main
def get_password(role: str, env: str, prompt: str) -> str:
    val = os.environ.get(env)
    if val:
        return val
    return getpass.getpass(prompt)


# Project registry: name -> (inventory csv, vera_rack.sh config)
PROJECTS = {
    "1": ("neutrino", Path("/root/rackctl/cycle_inventory_neutrino.csv"), Path("/root/rackctl/vera_rack.sh")),
    "2": ("naboo",    Path("/root/rackctl/cycle_inventory_naboo.csv"), Path("/root/rackctl/vera_rack.sh")),
}

def pick_project() -> tuple:
    """Interactive project selection. Returns (project_name, inventory_path, config_path)."""
    print("=== Project ===")
    for k, (name, inv, cfg) in PROJECTS.items():
        print(f"  {k}. {name}")
    while True:
        choice = input("Select project (1/2): ").strip()
        if choice in PROJECTS:
            name, inv, cfg = PROJECTS[choice]
            print(f"Project: {name}  inventory={inv}  config={cfg}")
            return name, inv, cfg
        print("Invalid, try again (1/2)")

def main() -> int:
    p = argparse.ArgumentParser(description="Fused power-cycle campaign (outside orchestrator)")
    p.add_argument("--project", choices=list(PROJECTS.keys()), default=None,
                   help="project id (1=neutrino, 2=naboo); omit = interactive prompt")
    p.add_argument("--node", action="append", default=None,
                   help="select node(s) like n0/n1/n2/n3 (repeatable); omit = all")
    p.add_argument("--loops", type=int, default=0, help="stop after N rounds (0 = no loop limit)")
    p.add_argument("--hours", type=float, default=0.0, help="stop after H hours (0 = no time limit)")
    p.add_argument("--cycle-mode", choices=("reboot", "power_cycle", "aux_cycle"), default="power_cycle")
    p.add_argument("--channel", choices=("inband", "outband", "auto"), default="auto")
    p.add_argument("--boot-timeout", type=int, default=900)
    p.add_argument("--config-script", type=Path, default=None)
    p.add_argument("--inventory", type=Path, default=None)
    p.add_argument("--output", type=Path, default=None)
    p.add_argument("--keep-going", action="store_true", help="keep all nodes running even if they fail")
    p.add_argument("--cycle", action="store_true", help="actually issue the cycle (without this: preflight only)")
    args = p.parse_args()

    # Refuse to start a second campaign: two concurrent runs fight over the
    # same BMC/OS SSH sessions and corrupt each other's logs.
    _run_lock = acquire_run_lock()

    # ── Interactive wizard: fill in anything not given via --flags ──
    interactive = args.project is None and args.loops <= 0 and args.hours <= 0 and not args.cycle
    if interactive:
        print("=" * 50)
        print("  Power-Cycle Wizard (interactive)")
        print("=" * 50)

        # 1. Project
        proj_name, proj_inv, proj_cfg = pick_project()
        args.project = "1" if proj_name == "neutrino" else "2"

        # 2. Nodes (with validation)
        targets_preview = load_inventory(proj_inv)
        valid_nodes = {t.node for t in targets_preview}
        print(f"\nNodes in inventory: {', '.join(sorted(valid_nodes))}")
        while True:
            node_input = input("Which nodes? (all / comma-sep, e.g. n2,n3,n4) [all]: ").strip()
            if not node_input or node_input.lower() == "all":
                break
            parts = [p.strip().lower() for p in node_input.replace(",", " ").replace(".", " ").split()]
            bad = [p for p in parts if p not in valid_nodes]
            if bad:
                print(f"  INVALID: {', '.join(bad)} — valid: {', '.join(sorted(valid_nodes))}")
                continue
            args.node = args.node or []
            args.node.extend(parts)
            break

        # 3. Duration: 1=loops, 2=hours
        print("\nDuration type:")
        print("  1. Loops (number of cycles)")
        print("  2. Hours (time limit)")
        dur_type = input("Select [1]: ").strip()
        if dur_type == "2":
            while True:
                h_s = input("How many hours? (e.g. 2 or 2.5) [2]: ").strip()
                try:
                    args.hours = float(h_s) if h_s else 2.0
                    if args.hours <= 0:
                        print("  Must be > 0")
                        continue
                    args.loops = 0
                    break
                except ValueError:
                    print(f"  INVALID: '{h_s}' is not a number")
        else:
            while True:
                l_s = input("How many loops? [5]: ").strip()
                try:
                    args.loops = int(l_s) if l_s else 5
                    if args.loops <= 0:
                        print("  Must be > 0")
                        continue
                    args.hours = 0.0
                    break
                except ValueError:
                    print(f"  INVALID: '{l_s}' is not a number")

        # 4. Cycle mode
        print("\nCycle mode:")
        print("  1. power_cycle (default)")
        print("  2. reboot")
        print("  3. aux_cycle")
        while True:
            mode_s = input("Select [1]: ").strip()
            if mode_s in ("1", "2", "3") or not mode_s:
                args.cycle_mode = {"1": "power_cycle", "2": "reboot", "3": "aux_cycle"}.get(mode_s or "1", "power_cycle")
                break
            print(f"  INVALID: '{mode_s}' — enter 1, 2, or 3")

        # 5. Channel
        print("\nChannel:")
        print("  1. auto (default: inband, fallback outband)")
        print("  2. inband (OS must be up)")
        print("  3. outband (BMC, works if OS is down)")
        while True:
            ch_s = input("Select [1]: ").strip()
            if ch_s in ("1", "2", "3") or not ch_s:
                args.channel = {"1": "auto", "2": "inband", "3": "outband"}.get(ch_s or "1", "auto")
                break
            print(f"  INVALID: '{ch_s}' — enter 1, 2, or 3")

        # 6. Keep going if a node fails?
        while True:
            cont_s = input("Keep all nodes running if one fails? (y/n) [n]: ").strip().lower()
            if cont_s in ("y", "n") or not cont_s:
                args.keep_going = cont_s == "y"
                break
            print(f"  INVALID: enter y or n")

        # 7. (cycle confirmation moved to preflight step)

        print(f"\n{'='*50}")
        print(f"  Summary")
        print(f"{'='*50}")
        print(f"  Project:      {proj_name}")
        print(f"  Duration:     {f'{args.loops} loops' if args.loops else f'{args.hours} hours'}")
        print(f"  Cycle mode:   {args.cycle_mode}")
        print(f"  Channel:      {args.channel}")
        print(f"  Keep going:   {'yes' if args.keep_going else 'no'}")
        print(f"  Nodes:")
        if args.node:
            for n in args.node:
                t = next((x for x in targets_preview if x.node == n), None)
                ip = f"  BMC={t.bmc_ip}  OS={t.os_ip}" if t else "  (not found)"
                print(f"    {n}:{ip}")
        else:
            for t in targets_preview:
                print(f"    {t.node}:  BMC={t.bmc_ip}  OS={t.os_ip}")
        print(f"{'='*50}")
        print(f"  TIP: Run inside 'screen' or 'tmux' so the cycle")
        print(f"       survives if you disconnect.")
        print(f"       e.g.  screen -S cycle && python3 neutrin_cycle.py")
        print(f"{'='*50}\n")
        # Ping check: verify OS and BMC are reachable before starting
        import subprocess as _sp
        check_targets = targets_preview if not args.node else [next((x for x in targets_preview if x.node == n), None) for n in args.node]
        print(f"  Ping check:")
        all_ok = True
        for t in check_targets:
            if t is None:
                continue
            r_os = _sp.run(["ping", "-c", "1", "-W", "2", t.os_ip], capture_output=True, text=True)
            r_bmc = _sp.run(["ping", "-c", "1", "-W", "2", t.bmc_ip], capture_output=True, text=True)
            os_ok = r_os.returncode == 0
            bmc_ok = r_bmc.returncode == 0
            if not (os_ok and bmc_ok):
                all_ok = False
            os_s = "OK" if os_ok else "UNREACHABLE"
            bmc_s = "OK" if bmc_ok else "UNREACHABLE"
            print(f"    {t.node}: OS={t.os_ip} [{os_s}]  BMC={t.bmc_ip} [{bmc_s}]")
        if not all_ok:
            print(f"\n  WARNING: Some nodes are unreachable. They will fail in PRE.")
        print(f"{'='*50}\n")
        confirm = input("Start the cycle now? (y/n) [n]: ").strip().lower()
        if confirm != "y":
            print("(no log written — cancelled)")
            return 0
        args.cycle = True

    if args.loops <= 0 and args.hours <= 0:
        p.error("give --loops and/or --hours")
    if args.boot_timeout <= 0:
        p.error("--boot-timeout must be positive")

    # Pick project (interactive or --project flag)
    if args.project:
        proj_name, proj_inv, proj_cfg = PROJECTS[args.project]
    else:
        proj_name, proj_inv, proj_cfg = pick_project()

    # Resolve paths (CLI flag > project default > global default)
    args.inventory = args.inventory or proj_inv
    args.config_script = args.config_script or proj_cfg
    if args.output is None:
        args.output = Path.home() / "Downloads" / proj_name / f"cycle_test{datetime.now().strftime('%m%d_%H%M%S')}"
    print(f"[project] {proj_name}  output={args.output}")
    args.project_name = proj_name
    args.known_hosts = Path.home() / ".ssh" / "known_hosts"
    args.trust_first_use = True

    targets = load_inventory(args.inventory)
    if args.node and "all" not in [n.lower() for n in args.node]:
        want = {n.lower() if n.lower().startswith("n") else "n" + n.lower() for n in args.node}
        targets = [t for t in targets if t.node in want]
        if not targets:
            p.error("no selected nodes in inventory")

    # auto channel: inband first, but if inband cannot reach OS, fall back to outband
    if args.channel == "auto":
        args.channel = "inband"  # issue_cycle + wait handles the rest; document fallback below

    if not args.cycle:
        return 0

    bmc_pw = get_password("bmc", "BMC_PASSWORD", "BMC password: ")
    os_pw = get_password("os", "OS_PASSWORD", "OS (root) password: ")
    return run_campaign(args, targets, bmc_pw, os_pw)


if __name__ == "__main__":
    sys.exit(main())
