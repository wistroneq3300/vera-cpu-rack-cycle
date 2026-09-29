# Real hardware fixtures — Vera CPU Rack (15A-ETF1)

Captured from three running rack nodes on 2026-09-29 (UTC+8). These are the
**actual** `ipmitool sensor list` outputs from healthy, idle machines. They are
provided so the sensor evaluator can be validated against real platform output
instead of only synthetic rows.

| File | Node | BMC IP | BMC hostname | OS hostname | Rows |
| --- | --- | --- | --- | --- | --- |
| `n1_sensor_list.txt` | n1 | 10.35.228.149 | `vc-256-bmc-n1` | `neutrino-n2` (see note) | 240 |
| `n2_sensor_list.txt` | n2 | 10.35.228.151 | `vc-256-bmc-n2` | `neutrino-n2` | 240 |
| `n3_sensor_list.txt` | n3 | 10.35.228.153 | `vc-256-bmc-n3` | `neutrino-n3` | 240 |

Note on hostnames: the OS hostname of the first node is currently `neutrino-n2`
(it is being renumbered to `neutrino-n1` later, together with the operator).
The BMC hostnames are final.

## Result of feeding these files to the current evaluator

Using the current `cycle_core.parse_sensors` + `sensor_issues`, all three
**healthy** machines are reported as **FAIL**:

```
n1: rows=240 health=FAIL {'SENSOR_DUPLICATE': 4, 'SENSOR_UNRECOGNIZED': 2}
n2: rows=240 health=FAIL {'SENSOR_DUPLICATE': 4, 'SENSOR_UNRECOGNIZED': 2}
n3: rows=240 health=FAIL {'SENSOR_DUPLICATE': 4, 'SENSOR_UNRECOGNIZED': 2}
```

Expected: PASS (or at most WARN for the known duplicate IDs). These are false
failures; the machines passed a full 10-loop campaign on the same day.

## Why they fail

### 1. Discrete sensors use hex status values (false `SENSOR_UNRECOGNIZED`)

Real rows (this is normal output):

```
NVMeE1SSSD0STS0    |             0x1 | discrete   | 0x0100| na | na | ...
NVMeE1SSSD1STS0    |             0x1 | discrete   | 0x0100| na | na | ...
```

The evaluator treats any status other than `ok` / `0x0000` as unrecognized:

```python
elif state not in {"ok", "0x0000"}:
    found.append(issue("SENSOR_UNRECOGNIZED", ...))   # -> FAIL
```

A discrete sensor normally reads `0x0100` (and other hex codes). These are not
faults. The threshold-based `ok / nc / cr / nr / ns` vocabulary does not apply
to discrete sensors.

### 2. A reading/status of `na` is normal, not a failure

Some rows have `na` in the value and status columns, and some rows have an
undecodable name (replacement characters). The evaluator marks these FAIL:

```python
unreadable = {"ns", "na", "no reading", "unknown", ""}
...
found.append(issue("SENSOR_UNREADABLE", ...))   # -> FAIL
```

`na` in `ipmitool sensor list` means "no reading", which is normal for sensors
without a numeric value. It must not fail the node.

### 3. Known duplicate IDs (noise every loop)

Rows such as `PrMo0MeCn0MeTem0` legitimately repeat (up to 4 times). The
evaluator emits a `SENSOR_DUPLICATE` WARN for each. This is expected platform
behaviour and should not be reported as a finding on every loop.
