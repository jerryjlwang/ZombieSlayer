from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zombieslayer.types import ScanMode, SourceTrust


@dataclass
class AdminPolicy:
    """Fine-grained operator-level controls (PRD §12 post-MVP).

    Layers on top of `Detector` + `Policy` without changing their internals.
    Operators tune aggression without editing rule code:

    - `disabled_rules`: skip specific rule names (e.g. a noisy one in your corpus).
    - `rule_score_overrides`: re-weight a rule's contribution.
    - `source_allowlist`: exact-match sources that are never quarantined.
    - `source_denylist`: exact-match sources that are always quarantined.
    - `threshold_overrides`: replace entries in the `(trust, mode)` threshold table.
    """

    disabled_rules: set[str] = field(default_factory=set)
    rule_score_overrides: dict[str, float] = field(default_factory=dict)
    source_allowlist: set[str] = field(default_factory=set)
    source_denylist: set[str] = field(default_factory=set)
    threshold_overrides: dict[tuple[SourceTrust, ScanMode], float] = field(
        default_factory=dict
    )

    # ---- helpers -------------------------------------------------------
    def is_allowlisted(self, source: str) -> bool:
        return source in self.source_allowlist

    def is_denylisted(self, source: str) -> bool:
        return source in self.source_denylist

    # ---- serialization -------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path) -> AdminPolicy:
        """Load from a JSON file. Format:

            {
              "disabled_rules": ["tool_invoke"],
              "rule_score_overrides": {"role_reassignment": 0.8},
              "source_allowlist": ["https://docs.internal/*"],
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
        return cls(
            disabled_rules=set(data.get("disabled_rules") or ()),
            rule_score_overrides={
                k: float(v) for k, v in (data.get("rule_score_overrides") or {}).items()
            },
            source_allowlist=set(data.get("source_allowlist") or ()),
            source_denylist=set(data.get("source_denylist") or ()),
            threshold_overrides=thresholds,
        )
