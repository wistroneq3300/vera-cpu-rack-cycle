# VERA Cycle Run 2 — 2026.10.01.2

Base: `b148a73a6a69035779d92997b240a9dcbed1f0d3` (`v2026.10.01`). At the start of this work, remote main and the peeled tag still pointed to this commit; no later implementation superseded these findings. Branch `codex/run2-review` uses a separate `vera-cycle-run2` worktree. Remote main and the existing annotated tag are preserved. The release commit is the target of new tag `v2026.10.01.2`.

The FINAL USER DECISIONS in [the requirements](vera_cycle_codex_requirements.md) remain authoritative. No reviewer ZIP was supplied. These regressions were independently written from the review inputs and expected behavior, using production code with offline transports, PATH stubs and synthetic records.

## Finding disposition and evidence

All ten items are **fixed** in this release, subject to the validation limits below. Tests are under `dev/tests/`.

| ID | Implementation | Regression / preserved control |
| --- | --- | --- |
| R2-01 P1 | `cycle_engine.py`: separate file verification/execution-complete flags; consistent transport/exit/final RESULT gate; PRE blocks, incomplete POST stops only that node and cannot count as completed/valid. Independent evidence continues where safe. | `test_run2_execution.py`: NOT_ISSUED, timeout/RESPONSE_LOST, syntax, no final RESULT, inconsistent exit/result, trailing/duplicate RESULT; PRE block; full RESULT FAIL/exit 1 two-loop keep-going; two-node isolation. |
| R2-02 P1 | `cycle_dmesg.py`: failure-specific NVMe matching excludes normal shutdown-timeout configuration. | `test_nvme_normal_and_real_timeout_full_pipeline`: engine record→aggregation→console; initialization excluded, real I/O timeout and controller-down remain FAIL. |
| R2-03 P2 | `cycle_dmesg.py`: bounded native AER blocks retain BDF, status/mask, named error bits and full raw lines/span; device/subtype identity excludes severity/count. | `test_run2_parsers.py`: BadTLP→BadDLLP NEW, separate aggregate entries, console detail, multiline evidence; interleaved BDFs, adjacent same-BDF events, unrelated-message boundary, severity stability, integer timestamps. |
| R2-04 P2 | Both hardware scripts: unique CPU-ID accounting independent of SOCKET; explicit malformed/duplicate/unknown ONLINE and missing topology findings. | `test_cpu_row_accounting_matrix`: both projects; blank socket offline with absent/Unknown Thread Count, numeric socket offline, healthy, malformed, duplicate, invalid ONLINE. No fixed SKU; Thread Count optional. |
| R2-05 P2 | Both scripts: ordinary/Legacy Endpoint distinguished from RCiEP/RCEC; absent optional link unsupported, provided link evaluated. | `test_pcie_device_type_matrix`: both projects; ordinary valid/missing, Legacy missing, RCiEP absent/valid/downgraded/denied/advertised-but-missing, RCEC absent. |
| R2-06 P2 | `cycle_engine.py`: POST always compares to recovered boot or old boot for rejected/not-issued. Mismatch saves observed boot and unexpected-transition finding, stops node and does not adopt the unexpected boot. | `test_rejected_or_unissued_extra_boot_is_not_adopted`; `test_rejected_same_boot_and_lost_response_controls`. Original action failure preserved; same-boot rejection still POSTs; response loss reconciles without redispatch. |
| R2-07 P2 | `cycle_recovery.py`, `cycle_report.py`: node/loop merge, validated revisions/completion, completed-prefix selection, unioned findings/evidence and retained conflicting versions. Missing/corrupt sidecars cannot erase journal loops/FAIL. Counters and terminal state checked. | `test_run2_recovery.py`: missing loop, journal only, corrupt sidecar, newer partial versus complete FAIL, completed superset versus partial journal, idempotence, multi-node history, unsupported counter/zero loop, malformed flags. |
| R2-08 P3 | `cycle_storage.py`, `cycle_report.py`, `cycle_runtime.py`, `cycle_core.py`: shared output writer lock, PID/start-token checks inside rebuild lock, unique atomic temporary filenames. | Live CLI with same runtime root refuses and preserves journal bytes; terminated subprocess recovers; controlled rename-boundary race leaves runner successful and journal RUNNING; cross-process writer lock; PID-token reuse; foreign-controller refusal. |
| N1 | `cycle_core.py`: Unicode Cc plus U+FFFD validation precedes sensor health shortcuts. | `test_sensor_del_c1_and_padding`: DEL/C1/NUL/U+FFFD fail; tab padding accepted. |
| N2 | `cycle_dmesg.py`, `cycle_core.py`, `cycle_engine.py`: native EDAC count excluded from identity; separate `native_error_count`/`occurrence_count`; native count growth WORSENED. Console/HTML label native captured counts separately. | Parser and engine→aggregate→console tests: 1 CE→5 CE stable identity/WORSENED; one message remains one observation; different DIMM and CE/UE stay distinct. |

## Counter and recovery semantics

- `attempts`: attempted cycle actions, including definite action failure.
- `boot_confirmed`: expected recovery boot transition observed; can remain confirmed if subsequent hardware execution is incomplete.
- `post_complete` / `completed`: POST reaches the end with complete hardware execution. Independent collection alone is recorded separately and is not completed POST.
- `valid_cycle` / `valid_cycles`: recovered boot, stable POST identity, power-on evidence, verified file and complete hardware execution. Hardware health FAIL is independent.
- `script_verified`: remote file type/owner/mode/SHA passed; it does not prove execution.
- `hardware_execution_complete`: transport RETURNED, exactly one terminal RESULT, PASS/0 or FAIL/1 consistency, no findings contradicting PASS.

Recovery does not choose a sidecar by mtime. Engine records have monotonic per-record revisions. A completed superset may finish a partial prefix; contradictory terminal versions or a newer partial retain alternate versions and unioned findings/evidence, with an integrity failure. Missing/invalid sidecars preserve journal history. Invalid primary records abort without overwriting them. PRE is not redefined; alternate PRE findings are kept separately.

Integrity problems produce `REPORT_RECOVERY_INTEGRITY`, INCOMPLETE and campaign FAIL. This is a data-integrity failure, not a claim of a new physical fault. Existing hardware FAIL remains separately visible. Counter claims unsupported by surviving records are retained as `recovery_original_counters`, not presented as verified completed cycles.

## Verification — 2026-10-01, Asia/Taipei

Windows, bundled Python, Git Bash and Chrome/Playwright; no real rack commands or power operations.

```bash
python3 -m unittest discover -s dev/tests -v
# 143 tests: 142 PASS, 1 explicit environment SKIP, 0 failures/errors
# Original 115: 114 PASS, 1 SKIP; new Run 2: 28 PASS
for script in neutrino_config.sh naboo_config.sh stop_cycle.sh; do bash -n "$script" || exit; done
python3 neutrino_cycle.py --version
# 2026.10.01.2
python3 dev/tests/make_demo.py test-results/demo
python3 dev/tests/make_demo.py test-results/demo128 128
VERA_TEST_BROWSER=chrome node dev/tests/check_report.cjs \
  test-results/demo/CYCLE_REVIEW_REPORT.html \
  test-results/demo128/CYCLE_REVIEW_REPORT.html
```

- Ordinary unittest discovery; no skip wrapper or new exemption. The existing cross-UID test reports `Cross-UID test needs a Linux root test environment`. WSL/Linux was unavailable. The existing crash-rebuild fixture now represents a terminated owner token, since actually live owners are refused.
- 28 new tests include multiple transport subcases and 32 full hardware-script fixture executions across two projects.
- Negative control: nine selected new methods against untouched `b148a73` produced 17 expected assertion failures (including subtests), zero errors. This demonstrates those tests catch baseline defects; it is not baseline acceptance.
- Nine top-level Python modules passed AST syntax parsing. Three scripts passed Bash syntax. Git whitespace checks passed.
- Chrome desktop tabs, filters, keyboard, evidence navigation, console search/download availability and no overflow passed. 128-node synthetic search, selection and print coverage passed; no JavaScript errors. These are report checks, not hardware load testing.

## Retained behavior and limits

Full hardware FAIL keep-going, node isolation, immutable PRE, historical FAIL, graceful stop, SEL operations and original hardware expectations retain regression coverage. No SMART, firmware manifest, fixed CPU SKU, rack orchestration, arbitrary BDF whitelist, quantity changes or OEM decoder was added.

Linux-root cross-UID acceptance remains outstanding; it is not claimed passed. No real rack/kernel/firmware/topology acceptance or power-cycle run was performed. POSIX writer locking uses flock; this environment exercised the Windows interprocess path. These are controller-local locks, not distributed locks. A RUNNING owner on another controller is refused because local PID checks cannot establish its liveness; recover on the source controller after stopping before sharing the recovered bundle.

Native AER association uses device-prefixed headers and recognizable continuations, closes on a new same-device message and limits continuation gaps to 32 lines. Unbounded or ambiguous log association is not promised; full raw capture remains available. Ring overflow, external clearing and events after the final read remain the documented snapshot limits. Native counts describe captured messages, not lifetime counter deltas.
