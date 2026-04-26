---
description: Show ZombieSlayer's end-of-task quarantine review for this session.
---

Read `.zombieslayer/session.jsonl` under the project root (falls back to
`$CLAUDE_PROJECT_DIR/.zombieslayer/session.jsonl`). Each line is a JSON
event from the ZombieSlayer hooks — `quarantine`, `blocked_write`,
`review_action`, `deferred_execution`, or `image_scan`.

Render a compact review:

1. Count quarantine events by risk category. Split text-layer entries
   from image-layer entries (`source_layer == "vision"` on the event).
2. For each quarantined item, show source, score, top rule, and the
   suggested remediation (exclude / include / reprocess-clean).
3. For each image-layer quarantine entry, also show the SHA-256, any
   sanitization actions recorded for that scan (from the most recent
   `image_scan` event with the same source), and a one-line summary of
   the rules that fired.
4. List any blocked writes and the reason.
5. End with a one-line summary:
   `N text quarantined, M image quarantined, K blocked writes`.

`REPROCESS_CLEAN` for an image entry means use the sanitized bytes
recorded in the matching `image_scan` event.

If the log does not exist, say "No ZombieSlayer events recorded this
session." and stop — do not fabricate events.
