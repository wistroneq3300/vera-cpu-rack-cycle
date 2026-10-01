# Release 2026.10.01 — review implementation

Historical release record. Run 2 found additional conditional defects; see [2026.10.01.2 corrections and regression evidence](RUN2_IMPLEMENTATION.md). The results below describe the original release, not exhaustive acceptance of every branch.

Implemented against `259a80fa7579ef459ab0922ae4b877f56391870b`, following the FINAL USER DECISIONS in [the supplied review](vera_cycle_codex_requirements.md). The final decisions override earlier proposals in that review and historical development documents.

## Delivered behavior

| Review | Implementation / acceptance evidence |
| --- | --- |
| F04 / F05 | One exclusive upload per node/campaign to `/var/tmp`; regular file, owner, mode and SHA gate before every execution. Missing/corrupt/unsafe file stops that node without re-upload or execution. Regression covers empty/error/mismatched SHA, upload/partial transfer failure, unsafe/missing file, reuse and the real Transport `wx` contract. |
| F02 / F01 | Explicit kernel event families, native CPER severities and section severity, separate adjacent/interleaved events, visible orphan/truncated events, device-preserving fingerprints. Corrected/recoverable WARN; fatal/uncorrected FAIL. Increased count/native severity or disposition is WORSENED. Production parser→classification→aggregation→console regressions ensure a new panic remains visible. |
| F03 | Durable raw capture at BEFORE_ACTION, POST entry and AFTER_CHECKS; end-of-POST `dmesg -c` including the final loop. Findings point to their actual raw file/line span/boot/phase. Boot-aware raw-event multisets remove overlapping observations. Stateful ring-buffer tests cover errors during hardware checks, between loops and read→clear, including distinct BDFs. |
| F06 | Name validation precedes health shortcuts. U+FFFD/control-character names fail, including numeric/discrete/CorUti rows. Exact known CorUti family retained. All three real 240-row sensor fixtures participate in unittest discovery. |
| F07 | Missing/unreadable endpoint LnkSta, denied capabilities and changed enumeration/link BDF sets fail; downgrade still fails. Evaluated/unsupported/unreadable status is explicit. No invented upstream topology or wiring whitelist. |
| F08 / F10 | Budget starts after START preparation. Zero exercised cycles cannot be COMPLETE. START has its own journal/evidence and cannot change reviewed PRE, timing or baseline fingerprints. Revalidate endpoint identities and PRE boot before start clearing. |
| F09 | SEL operations/channel/clearing policy unchanged. HTML correctly describes an empty delta as zero **new** events, not empty cumulative SEL. |
| F11 / F13 | Check recovered boot against POST entry and tail, and pin the expected boot between rounds. Unexpected transitions stop the affected node. Attempts, POST completions, confirmed boots and valid cycles are separate. Rejected commands do not count as valid cycles. |
| F12 | Legacy `dev/dryrun_sim.py` exits before credentials/network/process operations. Its historical source is retained for reference. |
| F14–F16 | PCI identity compares full BDF/numeric vendor-device ID, not description text. MST counts unique full BDFs and fails duplicates. PCI inventory duplicates fail. BF4 physical-card identity remains lspci VPD-only, with exact enumeration/VPD BDF set and duplicate checks. |
| CPU / memory | Populated/enabled processor, OS socket and all logical CPU online checks; compare SMBIOS thread count when present. No hard-coded core SKU. Installed memory capacity vs MemTotal, default lower ratio 0.90; CLI `--memory-min-ratio` / standalone `MEMORY_MIN_RATIO` configure it. |
| UX / isolation | Per-check summary and per-loop dmesg deltas; stage/exception console; WORSENED report filter/export. Existing wizard, selected channel, confirmation, locks, no ambiguous power retries, keep-going hardware FAIL and owner-only graceful stop preserved. Historical FAIL stays FAIL. |

Valid cycle counts describe execution evidence, not SIT acceptance. Hardware FAIL can coexist with a valid cycle. Collection failures fail health while independent checks continue; identity, boot and script trust failures stop the affected node.

## Explicitly outside this release

No NVMe SMART, golden firmware manifest, new GPU requirement, fixed CPU SKU, revised inventory/BF4 quantities, sensor OEM discrete decoder, functional workloads or four-node/rack power-domain orchestration. These require specifications or were excluded by the final decisions. No live rack operations were performed.

Finite dmesg snapshots cannot guarantee retention across ring-buffer overflow, unrelated external clearing, or events after the final read. The parser supports tested formats, not every vendor/kernel dialect. Administrative users and uploaded-file ownership are trusted; protection against concurrent hostile privileged modification is outside this model. `/var/tmp` must survive the platform's cycle; deletion fails closed instead of causing a second upload.

## Verification

Final local run on 2026-10-01 (Windows): **115 tests, 114 PASS, 1 SKIP**, no failures. The skip is the Linux-root cross-UID test. Python compilation, individual syntax checks of both project scripts and `stop_cycle.sh`, and `git diff --check` passed. Chrome/Playwright synthetic desktop and 128-node checks passed: tabs, filters, search, selection, evidence navigation, keyboard behavior, print coverage, no document overflow and no JavaScript errors. The desktop node report was visually inspected.

Offline unittest discovery includes the original suite, strict unknown-command rejection in its fake transport, production upload-contract checks, stateful event/evidence tests, and both hardware scripts with isolated PATH fixtures. Shell fixtures include unique healthy BDFs, disabled/offline CPUs, ratio boundaries, missing/denied links and inconsistent BF4 identities.

Windows cannot run the existing Linux-root cross-UID acceptance test; that skip is explicit. Actual SSH/SFTP, ARM hardware, firmware/BMC responses, cross-user Linux permissions and platform persistence still need controlled hardware acceptance. Browser fixtures are synthetic, including the 128-node display test; they do not establish rack concurrency capacity.

Reproduce:

```bash
python3 -m unittest discover -s dev/tests -v
for script in neutrino_config.sh naboo_config.sh stop_cycle.sh; do bash -n "$script" || exit; done
python3 -m compileall -q cycle_core.py cycle_dmesg.py cycle_engine.py cycle_report.py cycle_transport.py cycle_runtime.py neutrino_cycle.py
python3 neutrino_cycle.py --version
python3 dev/tests/make_demo.py
python3 dev/tests/make_demo.py test-results/demo128 128
node dev/tests/check_report.cjs test-results/demo/CYCLE_REVIEW_REPORT.html test-results/demo128/CYCLE_REVIEW_REPORT.html
git diff --check
```
