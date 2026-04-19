# ZombieSlayer

Zombie prompt-injection safeguard for Claude-centered agents.

ZombieSlayer intercepts retrieval and web-fetch content before it reaches
the model, quarantines suspicious material, blocks contaminated writes to
memory/summaries/handoffs, and gives the user a compact end-of-task review
with **exclude / include / reprocess-clean** actions.

See [PRD.md](PRD.md) for the full product spec and [CLAUDE.md](CLAUDE.md)
for contributor guidance.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

## Quick start

```python
from zombieslayer import ContentItem, PersistenceTarget, SourceTrust, ZombieSlayer

zs = ZombieSlayer()

items = [
    ContentItem(text=page_text, source=url, trust=SourceTrust.UNTRUSTED)
    for url, page_text in fetched_pages
]
safe, quarantined = zs.scan_intake(items)

# Feed only `safe` results into the model context.
context = "\n\n".join(r.item.text for r in safe)

# Guard persistence writes.
decision = zs.check_write(
    summary_text,
    PersistenceTarget.SUMMARY,
    derived_from=[r.item.id for r in safe],
)
if not decision.allowed:
    print("blocked:", decision.reason)

# End-of-task review.
summary = zs.end_of_task()
for rec in summary.records:
    print(rec.result.item.source, rec.result.categories)
    # zs.review.exclude(rec.result.item.id)
    # zs.review.include(rec.result.item.id)
    # zs.review.reprocess_clean(rec.result.item.id)
```

## Features

- Rule-based detector (override, exfiltration, unsafe-action, persistence)
  plus structural anomaly signals (zero-width chars, imperative density,
  hidden HTML/CSS, fake role tags).
- Source-aware quarantine thresholds with `fast` and `strict` modes.
- Persistence guard with retro-scan of previously stored artifacts.
- Deferred execution for irreversible external actions derived from
  tainted sources (PRD §18).
- Plugin-style callback hooks: `on_quarantine`, `on_blocked_write`,
  `on_review`.
- Zero runtime dependencies.
