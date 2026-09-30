# Refactor verification

## Release 2026.10.01.2 — Run 2

**143 offline tests: 142 PASS, 1 explicit Linux-root cross-UID environment SKIP, 0 failures/errors.** Includes 28 new Run 2 tests and all 115 original tests. Bash syntax (three scripts), Python AST (nine production modules), version output, diff checks and Chrome desktop/128-node report checks passed. Nine selected new tests against untouched `b148a73` produced 17 expected assertion failures and zero errors as a negative control. No reviewer ZIP or live rack was used. See [finding-by-finding evidence and limits](../docs/RUN2_IMPLEMENTATION.md). All older release results below are historical.

## Release 2026.10.01

Current results: **115 offline tests run, 114 PASS, 1 SKIP** (Linux-root cross-UID unavailable on Windows). Both project shell scripts and the stop script passed individual syntax checks; production Python compiled; diff whitespace checks passed. Chrome/Playwright desktop and 128-node synthetic report checks passed with no JavaScript errors or overflow. See [the current implementation and acceptance record](../docs/IMPLEMENTATION_2026-10-01.md) for scope and limits. Earlier results below are historical.

Verified on 2026-09-29 in the local Windows workspace. No rack SSH, power actions, IPMI or apt installation was performed against real equipment.

## Results

- **52 offline unittest cases ran; 48 passed and 4 shell fixtures were skipped** because this Windows workspace has no Bash executable. Coverage includes pure parsers/policy, campaign fake transports, inventory selection, target blocking, fixed PRE comparisons, all six mode/channel combinations, response-loss reconciliation, recovery deadlines, delayed BMC SSH, graceful stop, crash report reconstruction, endpoint-lock contention, sensor duplicate/missing/read-error behavior, SEL error preservation, dmesg read/clear gap preservation, PCIe downgrade detection and concise loop evidence. Follow-up regressions cover incomplete sensor rows and PRE review behavior, discrete hexadecimal sensor statuses, documented Vera no-value exceptions, explicit `None` credentials, UTC+8 Run IDs, issue aggregation, failed dmesg clearing and command-dispatch failure paths.
- Pyflakes and Ruff rules `F,E9,I,B023,B007,B905,DTZ005,PLW1510` passed for the six production Python modules. This is a targeted correctness/import check, not a claim that every optional Ruff style rule passes. Platform-specific imports and the optional Paramiko import remain deferred with explanatory comments; endpoint locks remain shared across users.
- Bash syntax check passed for the hardware script and targeted stop script.
- Python compilation and `git diff --check` passed.
- Real Paramiko 4.0.0 was installed in the ignored local `.venv` to inspect transport behavior. Its unbounded exec-acknowledgement wait is covered by a deadline watchdog and a stalled-ack regression.
- Playwright against installed Chrome passed at **1440px** and **390px**: tabs, keyboard navigation, disclosure expansion, known/new filtering, empty search results, issue-to-phase navigation, no document overflow and no JavaScript page errors.
- The independent Impeccable frontend finish reviewer returned **ship**, with no material fixes. One nonblocking mobile issue-table label wrap remains. Design tokens and the sidecar were documented and checked against the finished source.

## Artifacts

- `test-results/demo/CYCLE_REVIEW_REPORT.html`: clearly labeled synthetic demonstration, reproducible with `python tests/make_demo.py`.
- `.impeccable/review/`: validated desktop/mobile overview, node and issue captures plus browser-check results (ignored generated artifacts).
- `IMPLEMENTATION_SPEC.md`: approved behavior.
- `README.md`: configuration, operation, limits and recovery.

## Not yet verified on hardware

Linux cross-user flock and directory permissions, actual BMC `/usr/bin/powerctrl.sh` / `stbypowerctrl.sh` behavior, ACPI soft-off/on timing, MFT/BF4 model identification, actual dmidecode/IPMI formats and package-repository availability require a controlled rack run. Locks coordinate one shared Linux orchestrator, not independent control machines. The checked-in inventory intentionally blocks missing hostnames. No claim of live-rack acceptance is made.

`review/offline_review.py` is historical pre-refactor analysis, not the current regression suite. The independent legacy `dryrun_sim.py` was not changed.


## 2026-09-30 implementation verification

- Offline unittest discovery: **81 tests run, 80 passed, 1 skipped**. The skipped test requires Linux root to drop to a different UID; this Windows host cannot execute that acceptance test. No rack endpoints were contacted.
- Real sensor fixtures, fake transport PRE/POST, all cycle modes, SEL channel selection and one-time clearing, loop-before/POST event deltas (including reused IDs), malformed/empty SEL handling, immutable PRE comparisons, duplicate sensor visibility, and endpoint-only PCIe verdicts covered.
- Shell fixture tests ran with bundled GNU Bash 5.2 (`sh.exe` in Git for Windows), not skipped. Both project configs and stop script passed syntax checking. BF4 tests cover one board serial across two PCI functions, two distinct card identities, missing serial evidence, BF3 rejection and exact expected count.
- Separate-process locks reject overlapping endpoints, allow different endpoints and allow reacquisition after release. A campaign-level regression confirms a busy target prints BLOCKED before any remote command. Linux cross-user file-opening behavior is fixed by avoiding O_CREAT on existing shared files; cross-UID acceptance remains to be run on Linux.
- Desktop Chrome: three views, filters, phase navigation, keyboard tab navigation and no horizontal document overflow. A synthetic **128-node** report passes search/selection/natural ordering and print coverage checks. No browser errors. This validates UI scale only, not simultaneous rack load.
- Python compile checks passed. HTML screenshots were visually inspected. The wizard and inventory files were preserved.
- Actual BF4 hardware acceptance remains necessary: lspci must expose the same VPD board serial on the functions belonging to one physical card. Missing identity is an explicit FAIL, never a guessed card quantity.

Reproduce browser checks after generating demo and demo128 fixtures:

```bash
python3 dev/tests/make_demo.py
python3 dev/tests/make_demo.py test-results/demo128 128
node dev/tests/check_report.cjs test-results/demo/CYCLE_REVIEW_REPORT.html test-results/demo128/CYCLE_REVIEW_REPORT.html
```
