# AGENTS.md — vera-cpu-rack-cycle

Agent-facing notes for this repository. Keep this file current; it is the
first thing a new agent session should read.

## What this is

AC/aux power-cycle test harness for 3 NVIDIA Vera CPU nodes (n1/n2/n3,
aarch64 Ubuntu). It runs a PRE baseline → repeated cycles (BMC standby, or
inband/outband reboot) → per-loop POST comparison → HTML/JSON report.

Repo: `github.com/wistroneq3300/vera-cpu-rack-cycle` (local `/root/vera-cycle`).
Nodes: OS `root/password`, BMC `root/0penBmc`.

## Running

- Tests: `python3 -m unittest discover -s dev/tests -p 'test_*.py'` (169 tests).
  Single test: `python3 -m unittest dev.tests.test_cycle.ClassName.method` from repo root.
- Cycles: `python3 neutrino_cycle.py` (interactive wizard), or non-interactively:
  `CD` to repo root and use **`/usr/bin/python3`** — the system Python is the one
  with `paramiko`; the uv-managed python on PATH does not have it and SSH will
  fail with `ModuleNotFoundError: No module named 'paramiko'`.
- Credentials via env: `OS_PASSWORD=... BMC_PASSWORD=... BMC_USER=root OS_USER=root`
  (project-scoped `<PROJECT>_<ROLE>_PASSWORD` also accepted).
- Output lands in `campaigns/<run_id>/` (gitignored).
- `campaigns/` is gitignored; do not `git add` run output into the repo.

## Layout (root keeps only operator-facing files)

- `neutrino_cycle.py` — CLI/wizard, campaign orchestrator, console output.
- `cycle_engine.py` — `NodeSession`: precheck/start/one_loop, capture, Redfish.
- `cycle_core.py` — parsing + issue/delta/verdict logic (pure functions).
- `cycle_report.py` — HTML report renderer (reads `report.css`/`report.js` from
  the same directory; do NOT move those assets).
- `cycle_transport.py` — SSH/paramiko + OOB ipmitool + Redfish (curl) transport.
- `<project>_config.sh` — per-project node-side hardware check (`neutrino_config.sh`,
  `naboo_config.sh`). New project = copy one, adjust the expected-count
  constants, add to `--project` choices. Do not guess counts; inspect real hardware.
- `dev/tests/` — offline regression suite.

## Key design rules (do not regress)

- Issue classification compares against the **PRE baseline** (`aggregate_issues`),
  not `issue_policy.md` (retired).
- Cycle command dispatch, boot_id semantics, and per-mode power state are
  documented in detail in `.openhands/memory/MEMORY.md` and
  `.openhands/memory/2026-09-30.md` (kept locally, not committed).
- Sensor judgement rules and the `coruti` no-reading whitelist live in
  `cycle_core.py`; garbled (`U+FFFD`) sensor names are always FAIL.
- BF4 detection uses two sources (`mst status -v` + `lspci -nn`).
- Hostname is a **soft check**: if the inventory `bmc_hostname`/`os_hostname`
  does not match what the host reports, the node is NOT blocked — a
  `HOSTNAME_MISMATCH` WARN is recorded and the run continues (a blank expected
  hostname means "do not check"). Boot-ID validation is still a hard stop
  (it guards against a real reboot). `inventory_blocks` still blocks a row with
  no hostname at all (placeholder semantics).

## Redfish EventLog / SEL (added 2026-10-02)

- Collects BMC Redfish **EventLog (always, if present)** and **SEL (only if the
  service exists)** — "有什麼撈什麼". Does NOT fetch PostCodes/Journal/HostLogger/Dump.
- Dynamic discovery, no hardcoded IDs: resolve `/redfish/v1/Systems` → System ID
  (e.g. `System_0`), then list `/LogServices` members. Fetches `.../Entries`.
- Auth: login per capture via `SessionService/Sessions` → `X-Auth-Token`
  (token is short-lived; re-login each cycle). Credentials never enter argv/evidence.
- Verdict by worst severity: **Critical → FAIL, Warning → WARN, else PASS**.
  An absent service (merged BMC layout) is PASS, not a failure. A cleared-log
  trace (`Logging.Cleared`, OK) is retained and does not affect the verdict.
- Console shows **one summary line per service** (`EventLog: FAIL · Critical:2
  Warning:1 OK:21 · new:23`), never one line per event.
- Log clearing for dmesg / IPMI SEL / Redfish logs happens **in PRE, before the
  baseline** (`_prepare_clean_state`) so the run starts clean. Each source is
  probed before clearing and skipped (recorded `CLEAR_SKIPPED`) if unreadable.
  Note: this means a cancelled campaign has already cleared logs on the node.
- Loops do NOT re-clear; the per-loop delta (`new:N`) is the meaningful number.

## Environment notes

- Samba is a backup/share mount (`/root/samba`, incl. `/root/samba/vera-cycle`
  and `/root/samba/Netruino cycle`). Only copy there when the user explicitly asks.
- Orchestrator host is the sandbox itself (`10.35.228.144`); it has no BMC.
