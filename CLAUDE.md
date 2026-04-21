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
  - `admin.py` — `AdminPolicy` (disabled rules, source allow/deny lists, threshold overrides)
  - `quarantine.py` — in-memory store keyed by `ContentItem.id`
  - `scanner.py` — `IntakeScanner` for retrieval/web/tool content
  - `persistence.py` — `PersistenceGuard` for memory/summary/handoff writes + retro-scan
  - `review.py` — end-of-task `exclude` / `include` / `reprocess_clean`
  - `remediation.py` — automatic recovery-action recommendations
  - `topology.py` — handoff-graph tracker for multi-agent / tainted-lineage views
  - `audit.py` — append-only JSONL audit log for compliance export
  - `plugin.py` — `ZombieSlayer` facade, callback hooks, deferred actions
- `.claude-plugin/` — Claude Code plugin manifest, hooks, commands
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

## Scope

The MVP (PRD §12) is done. The project is now building toward its end goal:
a **Claude Code plugin** that wraps the core engine. Post-MVP features from
PRD §12 are in scope — tool-output scanning, fine-grained admin policies,
multi-agent handoff topology, automatic remediation recommendations, and
audit exports are all welcome.

Still out of scope:
- **Non-Claude provider adapters** — conflicts with the Claude-plugin goal.
- **Model-based classifiers in the core engine** — the core must stay
  stdlib-only so integrators can vendor it cheaply (see "Design rules").
  A plugin layer may call Claude itself; the engine may not.

## Claude plugin layout

The Claude Code plugin lives under `.claude-plugin/`:
- `plugin.json` — plugin manifest
- `hooks/hooks.json` — PostToolUse hooks that scan WebFetch output
- `hooks/scan_tool_output.py` — hook script, invokes `ZombieSlayer`
- `commands/zs-review.md` — `/zs-review` slash command
