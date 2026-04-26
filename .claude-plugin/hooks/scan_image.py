#!/usr/bin/env python3
"""PostToolUse / UserPromptSubmit hook: scan image-bearing tool outputs.

Routes image bytes (or paths to image files) through the vision layer.
On a high-aggregate-score result the hook emits a `permissionDecision=
deny` payload mirroring `scan_tool_output.py`. When the operator opts
into `ZOMBIESLAYER_AUTO_SUBSTITUTE_SANITIZED=1`, we instead pass the
sanitized bytes back via `additionalContext`.

Hook payload extraction is intentionally tolerant — Claude Code's
exact field names for image attachments are still firming up. The
script tries every reasonable shape (path, base64 bytes, raw bytes)
and silently no-ops if none match.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from zombieslayer import AuditLog, SourceTrust  # noqa: E402

try:
    from zombieslayer_vision import VisionPolicy, VisionScanner, make_image_item
except ImportError:
    # Vision extra not installed — degrade silently.
    sys.exit(0)


_IMAGE_MAGICS = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"BM",
    b"RIFF",
)


def _looks_like_image(data: bytes) -> bool:
    head = data[:16]
    return any(head.startswith(m) for m in _IMAGE_MAGICS)


def _extract_images(payload: dict) -> list[tuple[str, bytes]]:
    """Return [(source_label, image_bytes), ...] for every image in payload."""
    images: list[tuple[str, bytes]] = []
    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response")

    # 1. Read tool: file_path on disk.
    file_path = tool_input.get("file_path") or tool_input.get("path")
    if file_path and isinstance(file_path, str):
        suffix = Path(file_path).suffix.lower()
        if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif"}:
            try:
                images.append((f"file://{file_path}", Path(file_path).read_bytes()))
            except Exception:
                pass

    # 2. tool_response carries image content (MCP screenshot-style tools).
    if isinstance(tool_response, dict):
        for key in ("image", "image_base64", "data", "bytes", "content"):
            val = tool_response.get(key)
            if isinstance(val, str) and len(val) > 32:
                # Try base64.
                try:
                    decoded = base64.b64decode(val, validate=False)
                except Exception:
                    decoded = None
                if decoded and _looks_like_image(decoded):
                    images.append((f"tool:{payload.get('tool_name','?')}:{key}", decoded))
            elif isinstance(val, bytes) and _looks_like_image(val):
                images.append((f"tool:{payload.get('tool_name','?')}:{key}", val))

    # 3. UserPromptSubmit: attachments array.
    for attachment in payload.get("attachments") or []:
        if not isinstance(attachment, dict):
            continue
        path = attachment.get("path")
        if path and isinstance(path, str):
            try:
                data = Path(path).read_bytes()
            except Exception:
                continue
            if _looks_like_image(data):
                images.append((f"attachment://{path}", data))
            continue
        b64 = attachment.get("base64") or attachment.get("data")
        if isinstance(b64, str):
            try:
                data = base64.b64decode(b64, validate=False)
            except Exception:
                continue
            if _looks_like_image(data):
                images.append(("attachment:base64", data))
    return images


def _trust_for_tool(tool_name: str, event: str) -> SourceTrust:
    if event == "UserPromptSubmit":
        return SourceTrust.USER
    if tool_name in ("WebFetch", "WebSearch"):
        return SourceTrust.UNTRUSTED
    if tool_name == "Read":
        return SourceTrust.DEVELOPER
    return SourceTrust.TOOL_OUTPUT


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    event = payload.get("hook_event_name") or "PostToolUse"
    tool_name = payload.get("tool_name", "")
    images = _extract_images(payload)
    if not images:
        return 0

    session_dir = Path(
        os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    ) / ".zombieslayer"
    session_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(path=session_dir / "session.jsonl")

    policy = VisionPolicy()
    # Default to FAST for tool output to keep cost predictable; STRICT
    # for user-attached images (highest-impact attack surface).
    from zombieslayer.types import ScanMode
    policy.core.mode = ScanMode.STRICT if event == "UserPromptSubmit" else ScanMode.FAST
    scanner = VisionScanner(policy=policy)

    auto_substitute = os.environ.get("ZOMBIESLAYER_AUTO_SUBSTITUTE_SANITIZED") == "1"

    blocked: list[dict] = []
    sanitized_outputs: list[dict] = []
    for source, data in images:
        item = make_image_item(data, source, _trust_for_tool(tool_name, event))
        result = scanner.scan(item)
        # Audit every scan (clean and quarantined) so the layer is
        # observable end-to-end.
        audit._emit({
            "event": "image_scan",
            "source": source,
            "score": result.score,
            "quarantined": result.quarantined,
            "sha256": item.sha256,
            "rules": sorted({f.rule for f in result.findings}),
            "sanitization_actions": [
                {"name": a.name, "detail": a.detail, "bytes_removed": a.bytes_removed}
                for a in result.sanitization_actions
            ],
            "source_layer": "vision",
        })
        if not result.quarantined:
            continue
        # Write to the same quarantine log shape the text hook uses.
        audit._emit({
            "event": "quarantine",
            "item_id": item.id,
            "source": source,
            "trust": item.trust.value,
            "score": result.score,
            "categories": sorted({f.category.value for f in result.findings}),
            "rules": sorted({f.rule for f in result.findings}),
            "source_layer": "vision",
        })
        if auto_substitute:
            sanitized_outputs.append({
                "source": source,
                "sanitized_bytes_b64": base64.b64encode(result.sanitized_bytes).decode("ascii"),
            })
        else:
            blocked.append({
                "source": source,
                "score": round(result.score, 3),
                "rules": sorted({f.rule for f in result.findings}),
            })

    if blocked:
        reason = (
            f"ZombieSlayer quarantined {len(blocked)} image(s): "
            + "; ".join(
                f"{b['source']} (score={b['score']}, rules={b['rules']})"
                for b in blocked
            )
        )
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }, sys.stdout)
        return 0

    if sanitized_outputs:
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": json.dumps({
                    "zombieslayer_sanitized_images": sanitized_outputs,
                }),
            }
        }, sys.stdout)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
