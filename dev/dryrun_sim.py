#!/usr/bin/env python3
"""Dry-run simulation with BASELINE DIFF (read-only, no power action):
Per node, take a baseline snapshot, then for each loop compare current vs
baseline and report the delta (dropped/added MST endpoints, lspci/NVMe cards,
BF4 change, new dmesg errors, new SEL entries minus Watchdog noise, power
change). Read-only: NO reboot, NO power off, NO config change.

Outputs per run dir /root/dryrun_<stamp>/:
  <node>_baseline.log        full baseline evidence
  <node>_loop<N>.log         full loop evidence
  <node>_summary.txt         per-node baseline-vs-loop diff table + verdict
  summary.txt                unified 3-node diff table + verdict
"""
from __future__ import annotations
import csv, datetime, os, re, subprocess, sys, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

USERS = {"bmc": "root", "os": "root"}

def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        sys.exit(f"{name} is not set — export it before running (no credentials in source).")
    return val

BMC_PW = _require_env("BMC_PASSWORD")
OS_PW = _require_env("OS_PASSWORD")
NIC_MIN = 22      # Vera CPU PCIe/RDMA endpoints (mt12181/82/83/84) via mst status -v
BF4_MIN = 1       # BlueField-4 DPU: expected 1 card. Missing -> FAIL.
SEL_NOISE = ("watchdog1", "watchdog2", "watchdog")  # known noise: excluded from "new SEL" diff

def now():
    tz = datetime.timezone(datetime.timedelta(hours=8))
    return datetime.datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S UTC+8")

def ssh(role, ip, cmd, timeout=60):
    """Run cmd via sshpass+ssh. Returns (code, output). Read-only only.
    Quiet: -q suppresses SSH warnings; host-key noise filtered out."""
    user = USERS[role]
    pw = BMC_PW if role == "bmc" else OS_PW
    full = (f"sshpass -p {pw} ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ConnectTimeout=20 {user}@{ip} {cmd!r}")
    try:
        p = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=timeout)
        out = p.stdout
        err = p.stderr
        # Filter out SSH host-key / connection warnings (noise, not real errors)
        if err.strip():
            err_lines = [l for l in err.splitlines()
                         if not re.search(r"Permanently added|Warning: Permanently|To clear this|fingerprint", l, re.I)]
            err = "\n".join(err_lines)
        return p.returncode, (out + (("\n[stderr]\n" + err) if err.strip() else ""))
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"

def count_mst(out):
    return len(re.findall(r"/dev/mst/", out))

def mst_set(out):
    """Set of MST endpoint paths (set-diff catches dropped/added, not just count)."""
    return set(re.findall(r"/dev/mst/\S+", out))

def lspci_cards(out):
    """Set of 'slot vid:did' for lspci set-diff."""
    s = set()
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]{1,4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])\s+.*\[([0-9a-f]{4}:[0-9a-f]{4})\]", line)
        if m:
            s.add(f"{m.group(1)} {m.group(2)}")
    return s

def bf_count(out):
    return len(re.findall(r"Device 15b3:a2dc", out))

def nvme_set(out):
    return set(re.findall(r"nvme[0-9]+", out))

def dmesg_err_set(out):
    s = set()
    for line in out.splitlines():
        l = line.strip()
        if re.search(r"aer|nvme|error|fail|critical|uncorrect", l, re.I):
            s.add(l)
    return s

def sel_entries(out, exclude_noise=True):
    s = set()
    for line in out.splitlines():
        l = line.strip()
        if not l:
            continue
        if exclude_noise and any(n in l.lower() for n in SEL_NOISE):
            continue
        s.add(l)
    return s

def power_state(out):
    return ("Running" if "Host: Running" in out else
            "Off" if "Host: Off" in out else "Unknown")

def snapshot(node, bmc, os_ip, tag, outdir):
    """One full read-only snapshot. Returns data dict (diffable) + writes evidence log."""
    lines = [f"===== {node} {tag}  {now()} ====="]
    d = {}
    code, out = ssh("os", os_ip, "hostname && cat /proc/sys/kernel/random/boot_id")
    lines.append(f"[os] hostname/boot_id:\n{out.strip()}")
    lines.append("")
    code, lspci = ssh("os", os_ip, "lspci -nn")
    lines.append(f"[os] lspci -nn:\n{lspci.strip()}")
    d["lspci"] = lspci_cards(lspci)
    d["bf"] = bf_count(lspci)
    lines.append("")
    code, mst_out = ssh("os", os_ip, "mst start > /dev/null 2>&1; mst status -v")
    d["mst"] = mst_set(mst_out)
    d["mst_cnt"] = count_mst(mst_out)
    lines.append(f"[os] Vera MST (mst status -v): {d['mst_cnt']} endpoints")
    lines.extend("  " + e for e in sorted(d["mst"]))
    lines.append("")
    code, out = ssh("os", os_ip, "lsscsi")
    lines.append(f"[os] lsscsi:\n{out.strip()}")
    d["nvme"] = nvme_set(out)
    lines.append("")
    code, out = ssh("os", os_ip, "dmesg | grep -aiE 'aer|nvme|error|fail|critical|uncorrect' | tail -60")
    lines.append(f"[os] dmesg (aer/nvme/error) tail:\n{out.strip() or '(none)'}")
    d["dmesg_err"] = dmesg_err_set(out)
    lines.append("")
    code, out = ssh("os", os_ip, "lscpu | egrep 'Model name|Socket|Core|Thread|CPU\\(s\\)'")
    lines.append(f"[os] lscpu summary:\n{out.strip()}")
    lines.append("")
    code, out = ssh("os", os_ip, "df -h / && free -m")
    lines.append(f"[os] disk/mem:\n{out.strip()}")
    lines.append("")
    code, out = ssh("os", os_ip, "ip -o -4 addr show")
    lines.append(f"[os] ip addr:\n{out.strip()}")
    lines.append("")
    code, out = ssh("bmc", bmc, "/usr/bin/powerctrl.sh power_status")
    lines.append(f"[bmc] power_status:\n{out.strip()}")
    d["power"] = power_state(out)
    lines.append("")
    code, out = ssh("bmc", bmc, "ipmitool sel elist")
    lines.append(f"[bmc] sel elist:\n{out.strip()}")
    d["sel"] = sel_entries(out, exclude_noise=True)
    lines.append("")
    code, out = ssh("bmc", bmc, "ipmitool mc info | egrep 'Firmware|Manufacturer'")
    lines.append(f"[bmc] mc info:\n{out.strip()}")
    (outdir / f"{node}_{tag}.log").write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")
    return d

def diff_snap(base, cur):
    """Compare cur vs base -> (delta_str, n_diffs). '無差異' if none."""
    diffs = []
    dropped = base["mst"] - cur["mst"]; added = cur["mst"] - base["mst"]
    if dropped: diffs.append(f"MST -{len(dropped)} 掉: {', '.join(sorted(dropped))}")
    if added: diffs.append(f"MST +{len(added)} 多: {', '.join(sorted(added))}")
    dl = base["lspci"] - cur["lspci"]; al = cur["lspci"] - base["lspci"]
    if dl: diffs.append(f"lspci -{len(dl)} 掉卡: {', '.join(sorted(dl))}")
    if al: diffs.append(f"lspci +{len(al)} 多卡: {', '.join(sorted(al))}")
    if cur["bf"] != base["bf"]: diffs.append(f"BF4 {base['bf']}->{cur['bf']}")
    dl = base["nvme"] - cur["nvme"]; al = cur["nvme"] - base["nvme"]
    if dl: diffs.append(f"NVMe -{len(dl)} 掉: {', '.join(sorted(dl))}")
    if al: diffs.append(f"NVMe +{len(al)} 多: {', '.join(sorted(al))}")
    new_err = cur["dmesg_err"] - base["dmesg_err"]
    if new_err:
        shown = sorted(new_err)[:5]
        diffs.append(f"新 dmesg 錯 +{len(new_err)}: " + "; ".join(shown) + ("..." if len(new_err) > 5 else ""))
    new_sel = cur["sel"] - base["sel"]
    if new_sel:
        shown = sorted(new_sel)[:5]
        diffs.append(f"新 SEL +{len(new_sel)}: " + "; ".join(shown) + ("..." if len(new_sel) > 5 else ""))
    if cur["power"] != base["power"]: diffs.append(f"power {base['power']}->{cur['power']}")
    if not diffs: return "無差異", 0
    return "; ".join(diffs), len(diffs)

def status_of(cur):
    ok = (cur["mst_cnt"] >= NIC_MIN) and (cur["bf"] >= BF4_MIN) and (cur["power"] == "Running")
    return "OK" if ok else "FAIL"

def run_node(t, loops, root, unified):
    """One node: baseline + loops, parallel-safe. Returns (node, verdict, lines)."""
    node, bmc, os_ip = t["node"], t["bmc_ip"], t["os_ip"]
    lines = []
    # Clear BMC SEL once before baseline (so post-run SEL = pure new events).
    ssh("bmc", bmc, "ipmitool sel clear 2>&1; echo SEL_CLEARED")
    print(f"[{node}] SEL cleared before baseline", flush=True)
    print(f"[{node}] taking baseline...", flush=True)
    base = snapshot(node, bmc, os_ip, "baseline", root)
    base_line = (f"[{node}] baseline: MST={base['mst_cnt']} BF4={base['bf']} lspci卡={len(base['lspci'])} "
                 f"NVMe={len(base['nvme'])} dmesg錯={len(base['dmesg_err'])} SEL={len(base['sel'])} power={base['power']}")
    print(base_line, flush=True)
    lines.append(base_line)
    node_lines = [f"=== {node} ({os_ip}) baseline 對照 ===",
                  f"baseline: MST={base['mst_cnt']} BF4={base['bf']} lspci卡={len(base['lspci'])} "
                  f"NVMe={len(base['nvme'])} dmesg錯={len(base['dmesg_err'])} SEL={len(base['sel'])} power={base['power']}",
                  f"{'loop':5} {'status':8} {'MST':>4} {'BF4':>4}  vs_baseline", ""]
    n_diff = 0
    for loop in range(1, loops + 1):
        cur = snapshot(node, bmc, os_ip, f"loop{loop}", root)
        status = status_of(cur)
        delta, n = diff_snap(base, cur)
        if n > 0: n_diff += 1
        line = f"{loop:<5} {status:8} {cur['mst_cnt']:>4} {cur['bf']:>4}  {delta}"
        print(line, flush=True)
        node_lines.append(line)
        unified.append(f"{node:6} {loop:<5} {status:8} {cur['mst_cnt']:>4} {cur['bf']:>4}  {delta}")
        if loop < loops:
            print(f"[{node}] ... interval 180s before loop {loop+1} ...", flush=True)
            time.sleep(180)
    verdict = f"[{node}] 結論: {loops} 輪中 {n_diff} 輪有差異" + (" -> 穩定" if n_diff == 0 else " -> ⚠ 有漂移/掉卡風險")
    node_lines.append("")
    node_lines.append(verdict)
    (root / f"{node}_summary.txt").write_text("\n".join(node_lines) + "\n", encoding="utf-8", errors="replace")
    print(verdict, flush=True)
    return node, f"{node}: {n_diff}/{loops} 輪有差異"

def main():
    if len(sys.argv) < 2:
        print("usage: dryrun_sim.py <loops>"); return 2
    loops = int(sys.argv[1])
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    root = Path(f"/root/dryrun_{stamp}")
    root.mkdir(parents=True, exist_ok=True)
    print(f"dry-run (NO power action) loops={loops} out={root}  [baseline diff mode, PARALLEL 3 nodes]\n", flush=True)
    inv = [r for r in csv.DictReader(open("/root/rackctl/cycle_inventory_neutrino.csv")) if r.get("node")]
    unified = ["dry-run summary (read-only, no cycle) — baseline diff, parallel",
               "stamp: " + stamp, "",
               f"{'node':6} {'loop':5} {'status':8} {'MST':>4} {'BF4':>4}  vs_baseline"]
    node_verdicts = []
    with ThreadPoolExecutor(max_workers=len(inv)) as ex:
        futs = {ex.submit(run_node, t, loops, root, unified): t["node"] for t in inv}
        for fut in futs:
            node, verdict = fut.result()
            node_verdicts.append(verdict)
    # unified is shared list (thread-appended); write once
    unified.append("")
    unified.append("=== 總結論 ===")
    unified.extend(node_verdicts)
    (root / "summary.txt").write_text("\n".join(unified) + "\n", encoding="utf-8", errors="replace")
    print(f"\ndone. logs at {root}")
    print(f"  per-node: <node>_summary.txt (baseline 對照)")
    print(f"  unified:  summary.txt")

if __name__ == "__main__":
    sys.exit(main())
