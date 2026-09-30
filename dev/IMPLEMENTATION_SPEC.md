> Historical decisions below are superseded where they conflict with the final user policy and [2026-10-01 implementation](../docs/IMPLEMENTATION_2026-10-01.md). The original review is retained in docs/vera_cycle_codex_requirements.md.

# Approved campaign behavior

This is the implementation contract from the operator discussion, not a list of new proposals.

- English console and reports. Select project, targets, cycle mode, channel and limits before PRE. Only inband/outband; no automatic fallback.
- Check selected targets concurrently. Take one immutable PRE per campaign, directly in `tray_node/pre_*`. Compare every POST to it.
- Show concise PRE results and issue reasons, then ask whether to start. Hardware failures remain failures even when accepted. Wrong/missing hostname, unreachable identity, duplicate endpoint and unusable baseline block a target. Explain exclusions and confirm remaining targets. Cancelled PRE is discarded.
- Auto-install missing standard OS packages with apt; record installation failures. MFT/mst is supplied with the OS and is never installed by this program.
- Preserve PRE dmesg; validate but do not save PRE SEL. Clear each successfully captured log once on campaign start. Capture/clear dmesg after each loop. SEL stays cumulative for the entire campaign; record per-loop before/after snapshot deltas for human event interpretation, via OS inband or LANPlus outband.
- Complete the requested run despite HW/FW failures. Stop only an unrecoverable/unsafe target, retain all evidence and continue other targets. Graceful stop finishes current POST. Incomplete execution cannot be reported as a complete campaign.
- Sensor faults are never overwritten by duplicate names. Critical/non-recoverable and unreadable values fail; non-critical warns. Immediately confirm missing sensors; persistent disappearance fails.
- SOCAMM installed count must equal 16. BF4 is mandatory and only explicit BF4 identity qualifies. PCIe downgrade fails. Keep expected quantities in the selected `<project>_config.sh`.
- Snapshot the local hardware script once, hash it and upload it to an isolated run path. No stale remote script fallback.
- Identity comes from named CSV hostname columns, not inferred names or MACs. Missing real names must be filled by the operator.
- Tray-qualified paths and labels, unique Run ID, endpoint locks across local users, targeted stop. Different endpoints can run concurrently. Locks cannot silently fail open.
- Classify POST issues by the original PRE node/code/component pairs; label PRE findings PRE-EXISTING. Known issues still fail. Merge recurrence with phase/loop references while preserving raw evidence.
- Generate JSON/text/Markdown plus one offline HTML review for the whole cycle. Overview, searchable node selection, issue recurrence, PRE, loop actions/recovery, inventory, firmware, dmesg, cumulative/delta SEL and evidence; expandable details. Wistron-inspired presentation, desktop-focused and keyboard accessible.
- No hardware commands are executed during development verification. dryrun_sim.py is a separate legacy utility and is outside this refactor.

Hardware acceptance still requires a controlled rack run: verify platform command paths, firmware responses, package repositories and BF4 identification against actual equipment.

## Pending sensor specification

Await the official sensor specification for each project. Until supplied, do not infer that PRE is missing a required sensor. Future work: map stable sensor identities and expected inventory from the specification, validate PRE against it, and compare POST against both the specification and original PRE. Report missing/extra sensors and status changes separately. Retain duplicate-name WARN findings and raw rows so firmware can be corrected; do not suppress identical duplicates.

## Physical BF4 identification

`BF4_EXPECTED` is an exact physical-card quantity, not a port/function quantity. Use lspci BF4 identity plus a shared VPD board serial. Ambiguous identity must fail explicitly rather than reporting two ports as two cards or dividing blindly. NIC inventory remains on MST until real lspci evidence supports replacing it.
