# ZombieSlayer Demo — Browser Research Agent

A minimal Claude Code agent that browses the web while ZombieSlayer
intercepts every WebFetch/WebSearch result for zombie prompt injections.

## Setup

```bash
# From the repo root, install the package once:
pip install -e ..

# Open Claude Code inside this directory:
claude
```

The PostToolUse hook is pre-configured in `.claude/settings.json`.
No extra setup needed.

## Usage

Ask the agent to research anything:

```
Research the latest developments in prompt injection attacks.
```

Claude will fetch pages normally. If any fetched content triggers
ZombieSlayer, the hook blocks the result and logs the event to
`.zombieslayer/session.jsonl`.

At the end of the session, run:

```
/zs-review
```

to see everything that was quarantined, with source, score, risk
category, and suggested action (exclude / include / reprocess-clean).

## What to test

Good pages to probe real detection:

- **Legitimate content** — Wikipedia articles, docs pages, arXiv papers.
  These should pass through cleanly (low false-positive check).
- **Prompt injection research** — pages discussing or demonstrating
  injection attacks. The detector should flag injected payloads, not
  the surrounding analysis prose.
- **Adversarial pages** — if you control a page, embed a zombie payload
  (e.g. an HTML comment or hidden div with `ignore previous instructions`)
  and verify it's caught.

## Logs

Quarantine events are appended to `.zombieslayer/session.jsonl`.
Each line is a JSON object with `event`, `source`, `score`, `categories`,
and `timestamp`. The file persists across sessions so you can diff runs.
