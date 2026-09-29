# Vera CPU Rack Cycle

Run reboot, DC power-cycle and auxiliary AC-cycle campaigns from one **external Linux orchestrator**. Select nodes, review one PRE baseline, confirm the listed issues, then run all requested loops. Each POST compares to the original PRE. Failures remain visible even when the operator chooses to continue.

## Quick start

```bash
python3 -m pip install -r requirements.txt
chmod +x vera_rack.sh stop_cycle.sh
python3 neutrin_cycle.py
```

The wizard selects project, targets, mode, channel and limits before PRE. Enter credentials at the prompts, or set `OS_PASSWORD` and `BMC_PASSWORD` in the environment. Optional Lily credentials are `LILY_OS_PASSWORD` and `LILY_BMC_PASSWORD`. Project-prefixed variables such as `NEUTRINO_OS_PASSWORD` take precedence. Users default to root for OS/BMC, ubuntu for Lily OS, service for Lily BMC; override with `OS_USER`, `BMC_USER`, `LILY_OS_USER`, `LILY_BMC_USER`. A non-root OS account needs working sudo.

First fill the real `bmc_hostname` and `os_hostname` in the inventory. The checked-in hostnames are deliberately blank: the runner will block those rows rather than invent identities. IP reachability alone is insufficient. SSH host keys are trusted on first contact within a run and pinned for that run; hostname validation is also required.

Example using explicit options:

```bash
python3 neutrin_cycle.py --project neutrino \
  --node L105-21R/n1 --node L105-21R/n2 \
  --loops 40 --hours 12 --cycle-mode power_cycle --channel inband --cycle
```

`--project 1` is neutrino, `--project 2` is naboo. Naboo inventory is an empty template. Bare node names work only when unambiguous. Unknown or repeated selections are rejected. `--node all` means all inventory rows. A loop limit and hour limit may be combined; the first reached ends the run **after current POST**. There must be at least one positive limit. Hardware findings always continue; `--keep-going` is accepted for old callers but is redundant.

Without `--cycle`, explicit-option invocation runs PRE only and discards temporary results. Normal wizard invocation enables cycling but still requires confirmation **after** PRE. There is no automatic confirmation flag. Use a persistent terminal such as tmux for long interactive campaigns; do not pipe away the confirmation prompt.

## PRE and confirmation

Only selected targets are checked, concurrently. The console shows identity/connectivity status, result, issue classification and short reasons, not raw command output. Full evidence is staged temporarily. A simplified display looks like:

```text
L105-21R_n1 | PRE | FAIL
  Identity: BMC SSH OK | OS SSH OK
  FAIL [KNOWN] BF4: Expected at least 1; detected 0
L105-21R_n2 | PRE | FAIL
  Identity: BMC SSH OK | OS SSH OK
  FAIL [NEW] 000c:80:00.0: LnkSta: Speed 16GT/s (downgraded), Width x8
Start neutrino_<timestamp>_<suffix> on 2 runnable target(s), accepting the listed findings and exclusions? [y/N]:
```

Missing/wrong hostnames, inaccessible identities, overlapping endpoints, locked endpoints, an unusable PCI baseline or inability to upload the verified hardware script block a target. Sensor read/format/health failures remain visible as PRE FAIL findings, including when the whole sensor table is malformed; the operator sees the summary and decides whether to continue. Other targets may proceed only after the operator sees the exclusions and confirms. All blocked means no campaign starts. Hardware FAIL, unreadable individual sensors and dependency-install failures remain FAIL; they do not by themselves forbid an otherwise usable PRE.

Missing standard OS tools are installed with apt when possible (`pciutils`, `dmidecode`, `nvme-cli`, `ipmitool`, `usbutils`, `iproute2`). Local orchestrator `ipmitool` is installed similarly. Installation output is captured; failure is reported. A full PRE capture follows the installation attempt. MFT/mst must already be in the OS image; the runner does not install it. Cancelling PRE removes local staged evidence and performs no cycle/log clearing; already installed packages remain installed. The run-specific uploaded hardware script may remain under `/tmp` for OS cleanup.

After confirmation, evidence is promoted to the printed output directory. PRE dmesg/SEL must be saved successfully before each respective log is cleared. Both are cleared once at campaign start. Each POST captures dmesg and clears it only after successful capture. **SEL is never cleared inside loops**. Each loop retains cumulative SEL and a delta relative to the previous successful capture. An empty SEL is valid; command/transport errors are not. Event correctness is explicitly **manual review**, not an invented PASS/FAIL rule.

## Cycle modes

| Mode | Inband | Outband |
| --- | --- | --- |
| `reboot` | OS `reboot` | BMC `power soft`, confirmed Off, then one `power on` |
| `power_cycle` | OS `ipmitool power cycle` | IPMI LAN `power cycle` |
| `aux_cycle` | BMC `/usr/bin/stbypowerctrl.sh aux_cycle` | Same BMC controller action |

Only `inband` and `outband` are supported. Aux cycle is intrinsically BMC-side regardless of the selected channel. There is no automatic fallback and no retry of an ambiguous power command. A lost response is reconciled using a changed OS boot ID and confirmed power-on state. A normal reboot/DC cycle does not require the BMC boot ID to change. `--boot-timeout` defaults to 900 seconds and includes recovery polling; evidence capture has separate bounded command timeouts.

PRE and each loop verify expected hostnames before actions. During recovery, transient connections are retried until the deadline. An identity/authentication failure or a target that cannot recover is stopped and reported; other nodes continue. Hardware/FW collection failures do not remove an otherwise usable node. **COMPLETE** means the approved scope reached its requested execution limit, not that hardware passed. An early stop, crash or unrecoverable node produces **INCOMPLETE**. Reports separately list excluded targets and health.

## Hardware verdicts

`vera_rack.sh` owns the expected counts. It runs all selected checks, emits `ISSUE|code|component|reason`, and returns nonzero if any fail. Options `-S`, `-N`, `-B`, `-F` select shorter inventory sets; normal campaigns use the full script.

- CPU at least 2; **installed SOCAMM exactly 16** (empty memory slots are not counted).
- NVMe at least 2 controllers (multiple namespaces are deduplicated), Vera MST endpoints at least 22, NVIDIA PCI bridges at least 20, USB controller at least 1, AST1150 at least 1.
- BF4 at least 1, identified only by explicit `BlueField-4` / `BlueField4` / `BF4` model text. Generic BlueField, BF3, DPU, ConnectX and arbitrary non-Vera MST devices do not qualify. An unrecognized device remains missing until actual BF4 identity can be verified; no undocumented PCI IDs are guessed.
- Any reported PCIe `LnkSta` downgrade/degradation fails, even if device count is correct.
- PCI comparison uses full domain:bus:device.function plus vendor/device ID; changed, added and missing entries fail.
- Sensors `cr/critical/nr/non-recoverable` and lower/upper critical variants fail; `nc/non-critical` warns. `ns/na/no reading` and unrecognized statuses fail. Incomplete table rows remain visible and fail with `SENSOR_MALFORMED`; a completely malformed table remains a PRE FAIL finding for operator review. Duplicate names are reported and every row evaluated. Missing rows are immediately re-read: recovered warns, still missing fails. Without globally unique sensor IDs, loss detection uses name multiplicities rather than overwriting duplicates.
- Specific kernel hardware/fatal diagnostics fail; complete dmesg is preserved. Firmware versions are recorded; there is no expected-version/downgrade policy yet.

The local hardware script is snapshotted once, SHA-256 verified after upload and executed from a unique remote run path. PRE/POST do not depend on an old shared `~/vera_rack.sh`. Editing the source affects later runs only.

## Inventory and parallel users

CSV columns are named and order-independent:

```csv
tray,node,bmc_ip,os_ip,bmc_hostname,os_hostname,lily_bmc_ip,lily_os_ip,lily_bmc_hostname,lily_os_hostname
```

Lily endpoints are optional; when supplied their expected hostnames are required. Same node labels on different trays are allowed. Duplicate tray/node or ambiguous selections are rejected. Duplicate IP endpoints in selected rows are listed and blocked. Names used in paths accept letters, digits, dots and hyphens.

Run IDs include project, a UTC timestamp ending in `Z` and a random collision suffix (for example `neutrino_20260929_080000Z_a1b2c3`). Console and evidence timestamps also use UTC (`+00:00`), and the console states the time zone. Every target folder includes tray and node. On Linux, endpoint locks are advisory file locks in `/tmp/vera-cycle-runtime` (mode `1777`); lock files are shared across users and are **not deleted on release**, avoiding inode races. A crashed process releases its OS-held locks. Failure to open or acquire a lock blocks that target; there is no fallback lock directory.

All operators on the **same orchestrator** must use the same runtime path. If `/tmp` is isolated per user/service, provision a shared local directory and set `VERA_RUNTIME_DIR` consistently. Locks do not coordinate separate orchestrator machines. Registry directories are owner-only. Never remove live endpoint lock files or use independent runtime paths to bypass an active run.

The runner prints this exact stop command for its Run ID:

```bash
./stop_cycle.sh neutrino_<timestamp>_<suffix>
# equivalent:
python3 neutrin_cycle.py --stop neutrino_<timestamp>_<suffix>
```

Only the campaign owner can request the stop. It completes current POST and starts no next loop. Ctrl+C/SIGTERM behave the same way. It never uses broad `pkill`, never kills other campaigns, and does not stop `dryrun_sim.py`. A hard kill/power loss cannot generate a final report at the moment it occurs; once the process is stopped, rebuild from the retained journal:

```bash
python3 neutrin_cycle.py --report campaigns/<run_id>
```

Do not rebuild a live campaign. A recovered unfinished journal is INCOMPLETE. Restarting always creates a new campaign; no resume path reuses an old baseline.

## Reports

```text
campaigns/<run_id>/
  console.log
  campaign.json
  cycle_summary.json / cycle_summary.txt
  CYCLE_REVIEW_REPORT.html / CYCLE_REVIEW_REPORT.md
  known_issues.md / new_issues.md
  issue_policy.snapshot.md
  vera_rack.snapshot.sh
  pre_orchestrator_dependencies.txt
  <tray>_<node>/
    pre_report.json
    pre_pci.txt / pre_sensor.txt / pre_dmesg.txt / pre_sel.txt / ...
    node_summary.txt
    loop0001/
      report.json
      post_hardware.txt / post_sensor.txt / post_sensor_confirm.txt / ...
      post_dmesg.txt / post_sel.txt / post_sel_delta.txt
```

There is no extra PRE directory. Loop files are always retained. All formats use the same evaluator. The HTML has overview/node/issue tabs, collapsible phases, known/new and severity filters, action/recovery records and evidence links. CSS/JS are inline; it opens offline. Keep the HTML with its sibling log folders when sharing evidence links. Text from devices is escaped, not interpreted as HTML. Sample data is labeled **SYNTHETIC**.

`issue_policy.md` is a readable automatic-classification table. Exact project/code/component rules, with `*` wildcard, classify known issues. Unmatched issues are NEW. The current neutrino BF4-missing rule records that the card has not arrived; remove/deactivate it after installation. Every run snapshots the policy. Classification never changes severity; a known FAIL is still FAIL. Recurrences merge by node/code/component and retain their phase and evidence.

## Offline development checks

```bash
python3 -m unittest discover -s tests -v
bash -n vera_rack.sh stop_cycle.sh
python3 tests/make_demo.py
```

Tests use fake transports and shell PATH fixtures. They do not contact rack equipment. Hardware shell tests use Bash; set `VERA_TEST_SHELL` if it is not on PATH. For browser verification install Playwright in the development environment, then run `node tests/check_report.cjs`; `VERA_TEST_BROWSER=chrome` uses an installed Chrome. A synthetic report is generated at `test-results/demo/CYCLE_REVIEW_REPORT.html`.

This refactor was verified offline on Windows with Python, Git Bash and Chrome. Deployment is intended for Linux; real rack acceptance still needs actual hostnames, installed MFT, platform BMC paths, real command responses and a controlled run. Existing `review/offline_review.py` documents **pre-refactor** defects and is not the current regression suite. `dryrun_sim.py` is an independent legacy utility, unchanged here; its named CSV reader continues to use the original inventory fields and does not inherit the campaign lock/confirmation behavior.
