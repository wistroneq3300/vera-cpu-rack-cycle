# Vera CPU Rack — Power-Cycle Stress Test

Automated power-cycle stress testing for an **NVIDIA Vera CPU Rack** (neutrino).
One host drives every node over SSH + out-of-band `ipmitool`, cycling power and
diffing hardware state (PCIe cards, BMC sensors, dmesg, BMC SEL) before and
after each cycle.

## Components

| File | Purpose |
| --- | --- |
| `neutrin_cycle.py` | The campaign orchestrator. Runs the cycles, captures evidence, evaluates pass/fail, and writes the reports. |
| `vera_rack.sh` | Node-side inventory script. Counts PCIe fabric, DIMMs, NVMe, NICs (via `mst status -v`), USB, and the BlueField-4 DPU; prints a Pass/Fail summary. |
| `dryrun_sim.py` | Read-only simulation. Takes a baseline and reports per-loop drift without ever cycling power. |
| `stop_cycle.sh` | Kills any running `neutrin_cycle.py` / `dryrun_sim.py`. |
| `cycle_inventory_*.csv` | Per-project node lists (`tray,node,bmc_ip,os_ip`). |

## Requirements

- Python 3.10+
- `paramiko` (`python -m pip install paramiko`)
- `sshpass` (only for `dryrun_sim.py`)
- Reachability to every node over SSH (BMC + OS) and to each BMC's IPMI over LAN

## Usage

Credentials are **never** stored in the source. Provide them via environment
variables, or let the script prompt:

```bash
export OS_PASSWORD='...'
export BMC_PASSWORD='...'
```

Run a campaign:

```bash
python3 neutrin_cycle.py \
    --project 1 \
    --node n2 --node n3 --node n4 \
    --loops 10 \
    --cycle-mode aux_cycle --channel inband \
    --keep-going --cycle
```

Launch it detached so it survives your session ending:

```bash
OS_PASSWORD='...' BMC_PASSWORD='...' setsid nohup python3 -u neutrin_cycle.py \
    --project 1 --node n2 --node n3 --node n4 --loops 10 \
    --cycle-mode aux_cycle --channel inband --keep-going --cycle \
    > /tmp/cycle_run.log 2>&1 < /dev/null &
```

Stop it with `./stop_cycle.sh` (a PID lock at `/var/run/neutrin_cycle.lock`
prevents a second instance).

### Cycle modes

| Mode | Inband | Outband |
| --- | --- | --- |
| `reboot` | `reboot` | `ipmitool -C 17 power soft` |
| `power_cycle` | `ipmitool power cycle` | `ipmitool -I lanplus -C 17 power cycle` |
| `aux_cycle` | BMC `stbypowerctrl.sh aux_cycle` (AC/standby) | same (outband by nature) |

`--channel inband|outband|auto` — `auto` tries inband first and falls back to
outband if the OS does not come back.

## Output layout

```
cycle_test<MMDD_HHMMSS>/
  console.log
  cycle_summary.txt / .json
  HARDWARE_HEALTH_REPORT.md      # auto-generated campaign report
  node2/
    node_summary.txt             # auto-generated per-node digest
    loop1/
      report.json                # machine-readable result
      loop_summary.txt
      pre_sensor_baseline.json   # sensor name set + per-sensor status
      post_sensor.txt
      post_sensor_confirm.txt    # re-read taken when a sensor looks missing
      post_dmesg_all.txt
      post_sel.txt
      ...
```

## Pass/fail model

Each loop records a per-check result. The checks are:

| Check | Meaning |
| --- | --- |
| `root` | OS root UID is 0 |
| `config` | `vera_rack.sh` reports no lost devices |
| `power` / `power_cmd` | BMC reports host running / cycle command accepted |
| `boot_changed` | OS `boot_id` changed across the cycle |
| `lspci` | exit 0 and card count == baseline |
| `sensor_diff` | sensor set unchanged and no degraded status |
| `lily_*` | BlueField-4 (Lily) BMC/OS reachable |

### Sensor policy

A read of `ipmitool sensor list` on this platform is expected to be a fixed
240-row table (56 unique hardware sensors). `CorUti*` (per-core utilization)
rows and undecodable names are excluded, since they legitimately appear and
disappear with CPU load.

| Case | Verdict |
| --- | --- |
| Sensor missing in one read, **returns on the confirmation re-read** | `WARN` (transient BMC glitch — not a failure) |
| Sensor missing in both the post read and the confirmation read | **`FAIL`** (`SENSOR_LOST`) |
| Sensor status `ok` → `critical` / `non-recoverable` | **`FAIL`** (`SENSOR_STATUS`) |

The status column is compared, **not** the numeric value — temperatures and
currents legitimately move with load.

Sensor *names* are compared as a set, not by row count, because the BMC
occasionally mis-spells a name and the table legitimately repeats some IDs
(e.g. `PrMo0MeCn0MeTem0` four times).

### Expected failures

A node with **no BlueField-4 DPU by design** will always fail the `config`
step (`vera_rack.sh: no lost devices in [Fail]: failed`). This is a known
finding, not a cycling problem, and the report excludes it from the failure
count.

## Generated reports

Both `run_campaign` milestones (after every loop, and at the end of the
campaign) regenerate:

- **`nodeX/node_summary.txt`** — per-loop `OK` / `WARN` / `FAIL` with the issue
  detail, naming the missing sensor when there is one.
- **`HARDWARE_HEALTH_REPORT.md`** — verdict table, per-loop evidence table,
  how-to-read notes, dmesg / BMC SEL scan, and the sensor detection method.

Nodes and loop count are discovered from the collected results, so no
configuration is needed for a different rack or loop count.

## Benign boot-time noise

These messages appear on every boot and are not hardware faults:

- `acpi ... _OSC: platform does not support [SHPCHotplug PME AER DPC]`
- `pci 000x:00:00.0: bridge window [io size 0x1000]: failed to assign`
- `mlx_compat: module verification failed ... tainting kernel`
- `ipmi_ssif` probe retry (`-19` / `-17`)
