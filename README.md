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

## Claude Code plugin

ZombieSlayer ships a PostToolUse hook that scans every `WebFetch` and
`WebSearch` result in real time and blocks suspicious content before it
reaches the model. A `/zs-review` slash command shows the quarantine log
at the end of a session.

Once installed the hook fires on **every** `WebFetch` and `WebSearch`
across **every** Claude Code session — you do not need a browser-agent
project to benefit.

### Install (recommended)

From inside Claude Code:

```
/plugin marketplace add jerryjlwang/ZombieSlayer
/plugin install zombieslayer@zombieslayer-plugins
```

If the hook doesn't activate immediately, reload plugins:

```
/reload-plugins
```

That's it. Suspicious content is blocked and logged to
`.zombieslayer/session.jsonl` in the project you're working in. Run
`/zs-review` at any point to see the quarantine summary for the session.

To pause without uninstalling: `/plugin disable zombieslayer`.

### Per-project setup (alternative)

If you'd rather wire the hook into a single project instead of installing
it globally:

**1. Clone and install the package**

```bash
git clone https://github.com/jerryjlwang/ZombieSlayer /path/to/ZombieSlayer
pip install -e /path/to/ZombieSlayer
```

**2. Register the hook** in your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/ZombieSlayer/.claude-plugin/hooks/scan_tool_output.py"
          }
        ]
      }
    ]
  }
}
```

**3. Copy the slash command:**

```bash
mkdir -p .claude/commands
cp /path/to/ZombieSlayer/.claude-plugin/commands/zs-review.md .claude/commands/zs-review.md
```

The hook will now run only in this project.

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

## Vision layer (optional)

Image-borne prompt injections (legible text rendered into a JPEG, hidden
white-on-white text, EXIF/XMP metadata payloads, QR-encoded instructions,
LSB steganography, polyglot files, adversarial perturbations) bypass the
text engine entirely. The optional `zombieslayer_vision` sibling package
adds an image-scanning layer that:

- detects polyglot files and trims trailing-byte payloads,
- extracts EXIF / XMP / PNG-text fields and re-runs the core detector on
  them via a synthesized `ContentItem`,
- statistically flags LSB steganography and JPEG DCT-domain hiding,
- finds low-contrast and alpha-only hidden text,
- decodes QR codes and barcodes (when libzbar is available),
- runs Tesseract + Claude vision in `STRICT` mode and flags large
  divergence between the two,
- always returns sanitized bytes (metadata stripped, LSBs zeroed,
  recompressed, trailing bytes truncated) for `REPROCESS_CLEAN`.

```bash
pip install -e ".[vision]"   # also requires Tesseract + libzbar binaries
```

```python
from zombieslayer_vision import VisionScanner, make_image_item
from zombieslayer.types import SourceTrust

scanner = VisionScanner()
result = scanner.scan(make_image_item(image_bytes, "fetch://x", SourceTrust.UNTRUSTED))
if result.quarantined:
    print(result.score, [f.rule for f in result.findings])
clean_bytes = result.sanitized_bytes  # always populated
```

The Claude Code plugin's hooks include `Read`, MCP screenshot tools, and
`UserPromptSubmit` so any image entering a session is scanned before its
contents shape the model's reasoning. Set
`ZOMBIESLAYER_AUTO_SUBSTITUTE_SANITIZED=1` to pass sanitized bytes
through instead of denying.
