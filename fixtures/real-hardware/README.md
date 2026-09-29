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

## Result of feeding these files to the evaluator

### Before the fixes (commit `1d7a313`)

All three **healthy** machines were reported **FAIL**:

```
n1: health=FAIL {'SENSOR_DUPLICATE': 4, 'SENSOR_UNRECOGNIZED': 2}
n2: health=FAIL {'SENSOR_DUPLICATE': 4, 'SENSOR_UNRECOGNIZED': 2}
n3: health=FAIL {'SENSOR_DUPLICATE': 4, 'SENSOR_UNRECOGNIZED': 2}
```

### After `f8e819c` + `46bc906`

```
n1: health=WARN {'SENSOR_DUPLICATE': 4}
n2: health=WARN {'SENSOR_DUPLICATE': 4}
n3: health=WARN {'SENSOR_DUPLICATE': 4}
```

The false `SENSOR_UNRECOGNIZED` / `SENSOR_UNREADABLE` findings are gone. Only
the known duplicate-ID WARN remains, which matches expected platform behaviour.
The same data set (a full 30-loop campaign from 2026-09-29) went from
`FAIL 8 / WARN 22` to `WARN 30/30`.

Expected: PASS (or at most WARN for the known duplicate IDs).

## Why they used to fail (now fixed)

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
evaluator emits a `SENSOR_DUPLICATE` WARN for each capture. This is expected
platform behaviour, remains visible per the project policy, and does not make
the node FAIL.
