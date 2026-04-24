from __future__ import annotations

import fnmatch
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zombieslayer.types import ScanMode, SourceTrust


@dataclass(frozen=True)
class AllowDenyEntry:
    """Single allow/deny rule with optional wildcards, regex, and expiry.

    - `pattern`: matched against the item's `source` field.
    - `regex=True` treats the pattern as an anchored regex (`re.search`).
      Otherwise `fnmatch.fnmatchcase` is used (shell-style `*` / `?`).
    - `expires_at`: unix timestamp; `None` means never expires.
    - `version` / `note`: operator bookkeeping.
    """
    pattern: str
    regex: bool = False
    expires_at: float | None = None
    version: int = 1
    note: str = ""

    def matches(self, source: str, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        if self.expires_at is not None and t >= self.expires_at:
            return False
        if self.regex:
            try:
                return re.search(self.pattern, source) is not None
            except re.error:
                return False
        return fnmatch.fnmatchcase(source, self.pattern)

    @classmethod
    def from_value(cls, value: Any) -> AllowDenyEntry:
        """Accept either a bare string or a dict for backward compatibility."""
        if isinstance(value, str):
            return cls(pattern=value)
        if isinstance(value, dict):
            return cls(
                pattern=str(value["pattern"]),
                regex=bool(value.get("regex", False)),
                expires_at=(
                    float(value["expires_at"])
                    if value.get("expires_at") is not None else None
                ),
                version=int(value.get("version", 1)),
                note=str(value.get("note", "")),
            )
        raise TypeError(f"unsupported allow/deny entry: {type(value).__name__}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "regex": self.regex,
            "expires_at": self.expires_at,
            "version": self.version,
            "note": self.note,
        }


@dataclass
class AdminPolicy:
    """Fine-grained operator-level controls (PRD §12 post-MVP).

    Layers on top of `Detector` + `Policy` without changing their internals.
    Operators tune aggression without editing rule code:

    - `disabled_rules`: skip specific rule names (e.g. a noisy one in your corpus).
    - `rule_score_overrides`: re-weight a rule's contribution.
    - `source_allowlist` / `source_denylist`: wildcard- or regex-matched
      sources with optional expiry (issue #2 §3).
    - `threshold_overrides`: replace entries in the `(trust, mode)` threshold table.
    - `feedback`: operator-reported outcomes (e.g. regressions from INCLUDE
      decisions) used for soft rule-weight tuning (issue #2 §6).
    """

    disabled_rules: set[str] = field(default_factory=set)
    rule_score_overrides: dict[str, float] = field(default_factory=dict)
    source_allowlist: list[AllowDenyEntry] = field(default_factory=list)
    source_denylist: list[AllowDenyEntry] = field(default_factory=list)
    threshold_overrides: dict[tuple[SourceTrust, ScanMode], float] = field(
        default_factory=dict
    )
    feedback: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Accept the legacy set[str] / Iterable[str] shape so older callers
        # (and test fixtures) don't break when they pass exact-match sources.
        self.source_allowlist = self._coerce_entries(self.source_allowlist)
        self.source_denylist = self._coerce_entries(self.source_denylist)

    @staticmethod
    def _coerce_entries(value: Any) -> list[AllowDenyEntry]:
        if not value:
            return []
        if isinstance(value, (list, tuple, set, frozenset)):
            return [
                v if isinstance(v, AllowDenyEntry) else AllowDenyEntry.from_value(v)
                for v in value
            ]
        raise TypeError(
            f"source_allowlist/source_denylist must be iterable, got {type(value).__name__}"
        )

    # ---- helpers -------------------------------------------------------
    def is_allowlisted(self, source: str, now: float | None = None) -> bool:
        return any(e.matches(source, now) for e in self.source_allowlist)

    def is_denylisted(self, source: str, now: float | None = None) -> bool:
        return any(e.matches(source, now) for e in self.source_denylist)

    def prune_expired(self, now: float | None = None) -> int:
        """Drop expired allow/deny entries. Returns number removed."""
        t = time.time() if now is None else now
        before = len(self.source_allowlist) + len(self.source_denylist)
        self.source_allowlist = [
            e for e in self.source_allowlist
            if e.expires_at is None or e.expires_at > t
        ]
        self.source_denylist = [
            e for e in self.source_denylist
            if e.expires_at is None or e.expires_at > t
        ]
        after = len(self.source_allowlist) + len(self.source_denylist)
        return before - after

    def record_feedback(self, item_id: str, outcome: str) -> None:
        """Record operator outcome (e.g. 'regression', 'fine') for an item."""
        self.feedback[item_id] = outcome

    # ---- serialization -------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path) -> AdminPolicy:
        """Load from a JSON file. Format:

            {
              "disabled_rules": ["tool_invoke"],
              "rule_score_overrides": {"role_reassignment": 0.8},
              "source_allowlist": [
                "https://docs.internal/exact",
                {"pattern": "https://*.docs.internal/*"},
                {"pattern": "^https://cdn\\\\.example\\\\.com/", "regex": true,
                 "expires_at": 1893456000, "note": "temp bypass"}
              ],
              "source_denylist": ["https://known-bad.example"],
              "threshold_overrides": {"untrusted:strict": 0.3}
            }
        """
        data: dict[str, Any] = json.loads(Path(path).read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdminPolicy:
        thresholds: dict[tuple[SourceTrust, ScanMode], float] = {}
        for key, val in (data.get("threshold_overrides") or {}).items():
            trust_str, _, mode_str = key.partition(":")
            thresholds[(SourceTrust(trust_str), ScanMode(mode_str))] = float(val)

        allow_raw = data.get("source_allowlist") or []
        deny_raw = data.get("source_denylist") or []
        return cls(
            disabled_rules=set(data.get("disabled_rules") or ()),
            rule_score_overrides={
                k: float(v) for k, v in (data.get("rule_score_overrides") or {}).items()
            },
            source_allowlist=[AllowDenyEntry.from_value(v) for v in allow_raw],
            source_denylist=[AllowDenyEntry.from_value(v) for v in deny_raw],
            threshold_overrides=thresholds,
            feedback=dict(data.get("feedback") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "disabled_rules": sorted(self.disabled_rules),
            "rule_score_overrides": dict(self.rule_score_overrides),
            "source_allowlist": [e.to_dict() for e in self.source_allowlist],
            "source_denylist": [e.to_dict() for e in self.source_denylist],
            "threshold_overrides": {
                f"{k[0].value}:{k[1].value}": v
                for k, v in self.threshold_overrides.items()
            },
            "feedback": dict(self.feedback),
        }
