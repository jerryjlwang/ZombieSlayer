#!/usr/bin/env python3
"""PostToolUse hook: scan WebFetch/WebSearch output through ZombieSlayer.

Claude Code delivers the hook payload as JSON on stdin. If the tool's output
looks like a zombie prompt injection, we emit a `permissionDecision=deny`
with a reason so Claude sees the block and can route around it. Otherwise we
stay silent and let the tool result through.

Quarantine records are appended to `.zombieslayer/session.jsonl` under the
project root so `/zs-review` can surface them at end-of-task.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Allow the hook to run from a checkout without `pip install -e .`.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from zombieslayer import (  # noqa: E402
    AuditLog,
    ContentItem,
    SourceTrust,
    ZombieSlayer,
)


def _extract_text(tool_input: dict, tool_response) -> tuple[str, str]:
    """Return (source_label, text) from the hook payload."""
    source = (
        tool_input.get("url")
        or tool_input.get("query")
        or "unknown"
    )
    if isinstance(tool_response, str):
        return source, tool_response
    if isinstance(tool_response, dict):
        for key in ("content", "text", "result", "output"):
            val = tool_response.get(key)
            if isinstance(val, str):
                return source, val
        return source, json.dumps(tool_response)
    return source, str(tool_response)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # nothing to scan

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response")
    if tool_response is None:
        return 0

    source, text = _extract_text(tool_input, tool_response)
    trust = (
        SourceTrust.UNTRUSTED
        if tool_name in ("WebFetch", "WebSearch")
        else SourceTrust.TOOL_OUTPUT
    )

    session_dir = Path(
        os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    ) / ".zombieslayer"
    session_dir.mkdir(parents=True, exist_ok=True)
    zs = ZombieSlayer(audit=AuditLog(path=session_dir / "session.jsonl"))

    item = ContentItem(text=text, source=source, trust=trust)
    _, quarantined = zs.scan_intake([item])
    if not quarantined:
        return 0

    res = quarantined[0]
    rec = zs.store.get(res.item.id)
    tip = zs.recommend(rec) if rec else None
    reason = (
        f"ZombieSlayer quarantined {tool_name} output from {source}: "
        f"score={res.score:.2f}, categories="
        f"{[c.value for c in res.categories]}."
    )
    if tip:
        reason += f" Suggested action: {tip.action.value} ({tip.rationale})."

    hook_output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    json.dump(hook_output, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
