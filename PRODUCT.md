# Vera CPU Rack Cycle

An internal Wistron validation tool for engineers running repeated reboot, DC power and auxiliary AC cycles on Vera CPU rack nodes. The orchestrator runs outside the rack. Operators select targets, inspect concise PRE failures, then decide whether to run. Failures must never disappear from the final review.

The HTML artifact is a standalone, offline engineering review of the entire campaign, not only hardware health. Engineers need to identify which node and loop first showed a problem, distinguish known from new issues, and open the exact evidence. Manual BMC event interpretation remains an operator responsibility.

Approved interface: English; Wistron-inspired green brand accents; node tabs; expandable PRE/loop details; readable summaries before raw logs; desktop lab use with mobile-readable layout. Avoid external assets, external analytics, invented pass results and decorative graphs without measured data.

Safety and completeness are separate from health. One failed check means FAIL. A known issue stays FAIL. Incomplete or blocked work must be explicit.
