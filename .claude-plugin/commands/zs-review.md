---
description: Show ZombieSlayer's end-of-task quarantine review for this session.
---

Read `.zombieslayer/session.jsonl` under the project root (falls back to
`$CLAUDE_PROJECT_DIR/.zombieslayer/session.jsonl`). Each line is a JSON
event from the ZombieSlayer hook — `quarantine`, `blocked_write`,
`review_action`, or `deferred_execution`.

Render a compact review:

1. Count quarantine events by risk category.
2. For each quarantined item, show source, score, top rule, and the
   suggested remediation (exclude / include / reprocess-clean).
3. List any blocked writes and the reason.
4. End with a one-line summary: `N quarantined, M blocked writes`.

If the log does not exist, say "No ZombieSlayer events recorded this
session." and stop — do not fabricate events.
