# Approved campaign behavior

This is the implementation contract from the operator discussion, not a list of new proposals.

- English console and reports. Select project, targets, cycle mode, channel and limits before PRE. Only inband/outband; no automatic fallback.
- Check selected targets concurrently. Take one immutable PRE per campaign, directly in `tray_node/pre_*`. Compare every POST to it.
- Show concise PRE results and issue reasons, then ask whether to start. Hardware failures remain failures even when accepted. Wrong/missing hostname, unreachable identity, duplicate endpoint and unusable baseline block a target. Explain exclusions and confirm remaining targets. Cancelled PRE is discarded.
- Auto-install missing standard OS packages with apt; record installation failures. MFT/mst is supplied with the OS and is never installed by this program.
- Preserve PRE dmesg and SEL before clearing once on campaign start. Capture/clear dmesg after each loop. SEL stays cumulative for the entire campaign; record deltas for human event interpretation.
- Complete the requested run despite HW/FW failures. Stop only an unrecoverable/unsafe target, retain all evidence and continue other targets. Graceful stop finishes current POST. Incomplete execution cannot be reported as a complete campaign.
- Sensor faults are never overwritten by duplicate names. Critical/non-recoverable and unreadable values fail; non-critical warns. Immediately confirm missing sensors; persistent disappearance fails.
- SOCAMM installed count must equal 16. BF4 is mandatory and only explicit BF4 identity qualifies. PCIe downgrade fails. Keep expected quantities in vera_rack.sh.
- Snapshot the local hardware script once, hash it and upload it to an isolated run path. No stale remote script fallback.
- Identity comes from named CSV hostname columns, not inferred names or MACs. Missing real names must be filled by the operator.
- Tray-qualified paths and labels, unique Run ID, endpoint locks across local users, targeted stop. Different endpoints can run concurrently. Locks cannot silently fail open.
- Automatically classify issues using a snapshotted Markdown policy. Known issues still fail. Merge recurrence with phase/loop references while preserving raw evidence.
- Generate JSON/text/Markdown plus one offline HTML review for the whole cycle. Overview, per-node tabs, issue recurrence, PRE, loop actions/recovery, inventory, firmware, dmesg, cumulative/delta SEL and evidence; expandable details. Wistron-inspired presentation, accessible and responsive.
- No hardware commands are executed during development verification. dryrun_sim.py is a separate legacy utility and is outside this refactor.

Hardware acceptance still requires a controlled rack run: verify platform command paths, firmware responses, package repositories and BF4 identification against actual equipment.
