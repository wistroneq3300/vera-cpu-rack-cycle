"""Offline defect probes: no SSH, IPMI, or node commands are executed.
Run from repo root with Python 3.10+ and --shell <bash executable>.
Assertions confirm current defects, not desired behavior.
"""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import neutrin_cycle as nc

with patch.dict(os.environ, {"BMC_PASSWORD": "offline-only", "OS_PASSWORD": "offline-only"}):
    import dryrun_sim as ds

parser = argparse.ArgumentParser()
parser.add_argument("--shell", required=True)
args = parser.parse_args()
observations = []


def confirm(name, condition, detail):
    assert condition, f"Reproduction did not match: {name}: {detail}"
    observations.append({"name": name, "observed": detail})


def shell_probe(body):
    definitions = (ROOT / "neutrino_config.sh").read_text(encoding="utf-8").split("### Start ###")[0]
    env = dict(os.environ)
    env["PATH"] = str(Path(args.shell).resolve().parent) + os.pathsep + env.get("PATH", "")
    return subprocess.run([args.shell], input=definitions + "\n" + body,
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=30)


with tempfile.TemporaryDirectory(prefix="vera-offline-review-") as td:
    out = Path(td)
    result = shell_probe("""
mst(){ echo 'BlueField4 /dev/mst/mock 0001:01:00.0'; }
lspci(){ :; }
BF4_fun
CPU_Qty=2; DIMM_Qty=16; NVMe_Qty=2; MLNX_Qty=22; PCIeFAB_Qty=20; USB_Qty=1; BMC_Qty=1; MLNX_ERROR=0
Sum_fun
echo "DETECTED=$BF4_Qty ERROR_TAG=$BF4_ERROR_TAG"
""")
    confirm("BF4 present still prevents config success", "DETECTED=1 ERROR_TAG=1" in result.stdout
            and not nc.config_ok(result.stdout, result.returncode), result.stdout.strip())

    result = shell_probe("""
dmidecode(){ for ((i=1;i<=16;i++)); do printf 'Memory Device\n Size: No Module Installed\n Locator: DIMM%s\n' "$i"; done; }
DIMM_fun
Lost_fun DIMM "$DIMM_Qty" "$DIMM_MIN"
echo "COUNT=$DIMM_Qty LOST=$Lost_tag"
""")
    confirm("16 empty DIMM slots counted as populated", "COUNT=16 LOST=" in result.stdout
            and "Lost Device" not in result.stdout, result.stdout.strip())

    result = shell_probe("""
mst(){ echo 'ConnectX7 /dev/mst/mock 0001:01:00.0'; }
lspci(){ :; }
BF4_fun
echo "BF4_COUNT=$BF4_Qty"
""")
    confirm("non-Vera NIC falsely detected as BF4", "BF4_COUNT=1" in result.stdout, result.stdout.strip())

    for status in ("cr", "nr", "na", "ns"):
        steps, issues = {}, []
        nc._check_sensor_status({"hw_statuses": {"Temp": "ok"}}, f"Temp | 100 | degrees C | {status}",
                                lambda *x: issues.append(x), lambda k, v: steps.update({k: v}))
        confirm(f"sensor ok->{status} passes", steps["sensor_diff"] is True and not issues, steps)

    statuses = nc.hardware_sensor_statuses("Temp | 100 | C | critical\nTemp | 40 | C | ok")
    confirm("duplicate sensor healthy row overwrites critical", statuses == {"Temp": "ok"}, statuses)

    confirm("config exit code ignored", nc.config_ok("[Fail]\n[Summary]\nAll devices are detected successfully !!", 2), "exit 2 accepted")

    row = {"steps": {}, "issues": []}
    confirm("missing mandatory checks pass", nc.evaluate_result(row) == "PASS", row)

    row = {"steps": {"sensor_diff": True}, "issues": [{"step": "sensor_diff", "kind": "WARN", "detail": "transient"}]}
    confirm("WARN fails runtime", nc.evaluate_result(row) == "FAILED", row)

    def health_row(issues, **extras):
        return {"target": {"node": "n1"}, "loop": 1, "steps": {}, "issues": issues, "status": "FAILED", **extras}

    report_args = SimpleNamespace(output=out, project="1", cycle_mode="reboot", channel="inband")
    for name, row in (
        ("config NVMe loss hidden", health_row([{"step": "config", "kind": "ERROR", "detail": "Lost Device: NVMe x1"}])),
        ("boot timeout health PASS", health_row([{"step": "loop", "kind": "TIMEOUT", "detail": "OS did not return"}], error="TimeoutError")),
        ("uncaught worker error health PASS", health_row([], error="FileExistsError")),
    ):
        nc.generate_health_report(report_args, [row])
        report = (out / "HARDWARE_HEALTH_REPORT.md").read_text(encoding="utf-8")
        confirm(name, "**PASS**" in report, "FAILED input -> health report PASS")

    dmesg = out / "node1" / "loop1" / "post_dmesg_all.txt"
    dmesg.parent.mkdir(parents=True)
    dmesg.write_text("AER: Uncorrected (Fatal) error received\n", encoding="utf-8")
    nc.generate_health_report(report_args, [health_row([])])
    report = (out / "HARDWARE_HEALTH_REPORT.md").read_text(encoding="utf-8")
    confirm("fatal AER found but health PASS", "**1 matches**" in report and "**PASS**" in report,
            "dmesg scan finds fatal AER, verdict stays PASS")

    nc.LOG_CONTEXT.issues = []
    nc.LOG_CONTEXT.path = None
    fake_ssh = Mock()
    def fake_timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
    with patch("subprocess.run", side_effect=fake_timeout):
        issued = nc.issue_cycle(fake_ssh, {"oob": "power cycle"}, nc.Target("t", "n1", "192.0.2.1", "192.0.2.2"),
                                "DUMMY_SECRET_FOR_PROBE", "offline-only", out)
    confirm("OOB timeout exposes password", "DUMMY_SECRET_FOR_PROBE" in issued["note"],
            "TimeoutExpired string includes password argument (synthetic credential only)")
    nc.LOG_CONTEXT.issues = None

    def fake_sensor_run(client, command, *unused):
        assert "|| true" in command
        return 0, "Could not open device at /dev/ipmi0"
    with patch.object(nc, "run", side_effect=fake_sensor_run):
        code, output = nc.capture_sensor_list(None, out / "sensor.txt", "offline-only")
    confirm("sensor read failure returned as success", code == 0 and not nc.hardware_sensor_names(output),
            {"exit": code, "names": list(nc.hardware_sensor_names(output))})

    inventory = out / "inventory.csv"
    inventory.write_text("tray,node,bmc_ip,os_ip\nt1,n1,192.0.2.1,192.0.2.2\nt2,n1,192.0.2.3,192.0.2.4\n")
    targets = nc.load_inventory(inventory)
    confirm("distinct trays collide in output", len(targets) == 2 and nc.node_name(targets[0]) == nc.node_name(targets[1]),
            [nc.node_name(t) for t in targets])

    snapshot = {"mst": set(), "mst_cnt": 0, "bf": 0, "lspci": set(), "nvme": set(), "dmesg_err": set(), "sel": set(), "power": "Unknown"}
    calls = []
    with patch.object(ds, "ssh", side_effect=lambda *a, **kw: (calls.append(a) or (0, "mock"))), \
         patch.object(ds, "snapshot", return_value=snapshot), contextlib.redirect_stdout(io.StringIO()):
        ds.run_node({"node": "n1", "bmc_ip": "192.0.2.1", "os_ip": "192.0.2.2"}, 1, out, [])
    text = (out / "n1_summary.txt").read_text(encoding="utf-8")
    confirm("dryrun clears SEL", any("sel clear" in c[2] for c in calls), calls)
    confirm("dryrun unchanged total failure called stable", "FAIL" in text and "穩定" in text, text)

    cards = ds.lspci_cards("01:00.0 Ethernet controller [0200]: Vendor [15b3:a2dc]")
    confirm("dryrun drops domainless PCI address", not cards, "01:00.0 -> empty set")

    # Fully mocked loop: exercises real control flow without node access.
    from contextlib import ExitStack
    from unittest.mock import MagicMock
    loop_args = SimpleNamespace(output=out / "mock_campaign", cycle_mode="power_cycle", channel="inband",
                                config_script=ROOT / "neutrino_config.sh", boot_timeout=1)
    loop_target = nc.Target("t", "n1", "192.0.2.1", "192.0.2.2")
    fake_client = MagicMock()
    fake_loop_ssh = Mock()
    fake_loop_ssh.connect.return_value = fake_client
    identity_old = {"hostname": "offline", "boot_id": "old", "observed_macs": [], "network": []}
    identity_new = {**identity_old, "boot_id": "new"}
    cycle_calls = []
    def mock_log(client, command, path, *a, **kw):
        if "power_status" in command:
            output = "Host: Running\nChassis Power: On"
        elif "id -u" in command:
            output = "0"
        elif command == "lspci -nn":
            output = "0001:01:00.0 Ethernet controller [0200]: Mock [1234:5678]"
        else:
            output = "mock evidence"
        nc.save(path, output)
        return 0, output
    def mock_sensor(client, path, password):
        output = "Temp | 40 | degrees C | ok"
        nc.save(path, output)
        return 0, output
    def mock_issue(*a):
        cycle_calls.append("cycle issued")
        return {"issued": True, "state": "OK", "note": "mock"}
    with ExitStack() as stack:
        replacements = {
            "log_command": mock_log, "run": lambda *a, **kw: (0, "mock"),
            "identity": lambda *a: identity_old, "collect_info": lambda *a: None,
            "collect_dmesg_all": lambda client, path, pw: nc.save(path, "AER: Uncorrected (Fatal)"),
            "lily_pre": lambda *a: None, "lily_post": lambda *a: None,
            "wait_for_ipmi": lambda *a: True, "capture_sensor_list": mock_sensor,
            "issue_cycle": mock_issue, "wait_for_os": lambda *a: (fake_client, identity_new),
            "oob": lambda *a: (0, "Chassis Power is on"),
        }
        for name, replacement in replacements.items():
            stack.enter_context(patch.object(nc, name, replacement))
        stack.enter_context(patch.object(nc, "config_check", side_effect=[False, True]))
        loop_result = nc.cycle_one(fake_loop_ssh, loop_target, loop_args, 1, "offline", "offline")
    confirm("failed preflight still issues power and gets overwritten",
            cycle_calls == ["cycle issued"] and loop_result["steps"]["config"] is True and loop_result["status"] == "PASS",
            {"cycle_calls": cycle_calls, "final_config": loop_result["steps"]["config"], "status": loop_result["status"]})
    confirm("runtime ignores fatal dmesg", loop_result["status"] == "PASS"
            and "Fatal" in (loop_args.output / "node1/loop1/post_dmesg_all.txt").read_text(),
            "fully mocked loop containing fatal AER returns PASS")

    with patch.object(nc, "acquire_run_lock", return_value=None), \
         patch.object(nc, "load_inventory", return_value=[loop_target]), \
         patch.object(nc, "run_campaign") as campaign, \
         patch.object(sys, "argv", ["neutrin_cycle.py", "--project", "1", "--loops", "1"]), \
         contextlib.redirect_stdout(io.StringIO()):
        return_code = nc.main()
    confirm("CLI preflight performs no connectivity checks", return_code == 0 and not campaign.called,
            "without --cycle only parses inventory and returns 0")

    with patch.object(nc, "acquire_run_lock", return_value=None), \
         patch.object(nc, "load_inventory", return_value=[loop_target]), \
         patch.object(nc, "get_password", return_value="offline"), \
         patch.object(nc, "run_campaign", return_value=0) as campaign, \
         patch.object(sys, "argv", ["neutrin_cycle.py", "--project", "1", "--loops", "1", "--node", "n1", "--node", "n99", "--cycle"]), \
         contextlib.redirect_stdout(io.StringIO()):
        nc.main()
    confirm("auto rewritten to inband and nonexistent node silently dropped",
            campaign.call_args.args[0].channel == "inband" and len(campaign.call_args.args[1]) == 1,
            {"channel": campaign.call_args.args[0].channel, "nodes": [t.node for t in campaign.call_args.args[1]]})

output = ROOT / "review" / "offline_observations.json"
output.write_text(json.dumps(observations, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Confirmed {len(observations)} offline observations. Details: {output}")
