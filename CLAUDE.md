# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

ZombieSlayer — a developer-first plugin that protects Claude-centered agents
from "zombie" prompt injections: hidden instructions in retrieved or browsed
content that influence later reasoning or persist into memory/summaries.

See [PRD.md](PRD.md) for the full product spec. This file captures only what
is useful while editing code.

## Layout

- `src/zombieslayer/` — package source
  - `types.py` — dataclasses and enums (`ContentItem`, `ScanResult`, `RiskCategory`, `SourceTrust`, `ScanMode`, `PersistenceTarget`, `ReviewAction`)
  - `detector.py` — rule engine + structural anomaly signals (zero-width chars, imperative density)
  - `policy.py` — source-aware thresholds, aggregate scoring (`1 - Π(1 - s)`)
  - `quarantine.py` — in-memory store keyed by `ContentItem.id`
  - `scanner.py` — `IntakeScanner` for retrieval/web content
  - `persistence.py` — `PersistenceGuard` for memory/summary/handoff writes + retro-scan
  - `review.py` — end-of-task `exclude` / `include` / `reprocess_clean`
  - `plugin.py` — `ZombieSlayer` facade, callback hooks, deferred actions
- `tests/` — pytest suite

## Common commands

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

## Design rules

- **Detection lives in `detector.py` rules**; thresholds and trust-aware
  decisions live in `policy.py`. Keep these concerns separate — a new rule
  should not hardcode a trust level.
- **Aggregate score** combines findings via `1 - Π(1 - score_i)` so multiple
  weak signals compound. Don't sum or max.
- **Source-aware thresholds** go through `Policy.thresholds[(trust, mode)]`.
  When adding a new `SourceTrust` or `ScanMode`, update that table.
- **Quarantine store identity** is `ContentItem.id`. The store is swappable
  (e.g., for persistence across sessions) — don't assume in-memory.
- **Review actions** must only expose `approved_text()` for `INCLUDE` or
  `REPROCESS_CLEAN`; never for `EXCLUDE` or pending.
- **Deferred actions** (PRD §18) hold until all `derived_from` sources are
  approved in review. Don't short-circuit this gate.
- **No external dependencies** in the core package — keep it stdlib-only so
  integrators can vendor it cheaply.

## Extending detection

Add a `Rule` to `_RULES` in [detector.py](src/zombieslayer/detector.py). Give
it a conservative score; let policy thresholds do the aggression tuning.
Structural signals (multi-line, cross-pattern) go in `Detector._structural`.

## Testing conventions

- Every new rule gets a positive test in `tests/test_detector.py` and a
  benign-text test confirming it doesn't fire on legitimate content.
- Plugin-level behavior (intake → quarantine → review → deferred actions)
  goes in `tests/test_plugin.py`.
- Tests must not require network or external services.

## Out of scope for MVP (see PRD §7, §12)

Do not add: tool-output scanning, enterprise admin, multi-agent topology
views, non-Claude provider adapters, model-based classifiers. These are
Phase 4+.
