# Refactor verification

Verified on 2026-09-29 in the local Windows workspace. No rack SSH, power actions, IPMI or apt installation was performed against real equipment.

## Results

- **39 offline unittest cases passed**: pure parsers/policy, campaign fake transports, inventory selection, target blocking, fixed PRE comparisons, all six mode/channel combinations, response-loss reconciliation, recovery deadlines, delayed BMC SSH, graceful stop, crash report reconstruction, endpoint-lock contention, sensor duplicate/missing/read-error behavior, SEL error preservation, dmesg read/clear gap preservation and shell hardware fixtures.
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
