from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import Any


class RiskCategory(str, enum.Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    DATA_EXFILTRATION = "data_exfiltration"
    UNSAFE_ACTION = "unsafe_action"
    PERSISTENCE = "persistence"
    STRUCTURAL_ANOMALY = "structural_anomaly"


class SourceTrust(str, enum.Enum):
    UNTRUSTED = "untrusted"        # web, random retrieval
    RETRIEVAL = "retrieval"        # indexed corpus, still external
    DEVELOPER = "developer"        # developer-configured
    USER = "user"                  # explicit user input


class ScanMode(str, enum.Enum):
    FAST = "fast"
    STRICT = "strict"


class PersistenceTarget(str, enum.Enum):
    MEMORY = "memory"
    SUMMARY = "summary"
    HANDOFF = "handoff"


class ReviewAction(str, enum.Enum):
    EXCLUDE = "exclude"
    INCLUDE = "include"
    REPROCESS_CLEAN = "reprocess_clean"


@dataclass
class ContentItem:
    """A single piece of content intercepted at intake."""
    text: str
    source: str                    # URL, document id, etc.
    trust: SourceTrust = SourceTrust.UNTRUSTED
    chunk_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    # Provenance: ContentItem.ids this artifact was derived from. Used by
    # `PersistenceGuard.retro_scan` to apply the *minimum* trust along the
    # derivation chain rather than the artifact's own (possibly inflated)
    # trust label.
    derived_from: tuple[str, ...] = ()


@dataclass
class Finding:
    """A single detector hit within a content item."""
    category: RiskCategory
    reason: str
    span: tuple[int, int]          # (start, end) char offsets
    rule: str
    score: float                   # 0.0 - 1.0


@dataclass
class ScanResult:
    item: ContentItem
    findings: list[Finding]
    score: float                   # aggregate suspiciousness
    quarantined: bool
    sanitized_text: str | None = None  # populated on reprocess-clean

    @property
    def categories(self) -> list[RiskCategory]:
        seen: list[RiskCategory] = []
        for f in self.findings:
            if f.category not in seen:
                seen.append(f.category)
        return seen


@dataclass
class QuarantineRecord:
    result: ScanResult
    action: ReviewAction | None = None   # user choice, once made


@dataclass
class ReviewSummary:
    records: list[QuarantineRecord]

    def by_category(self) -> dict[RiskCategory, int]:
        counts: dict[RiskCategory, int] = {}
        for rec in self.records:
            for c in rec.result.categories:
                counts[c] = counts.get(c, 0) + 1
        return counts

    def render(self) -> str:
        """Compact D-style review display (PRD §17)."""
        if not self.records:
            return "ZombieSlayer \u2014 nothing quarantined."

        _TIMES = "\u00d7"
        _CHECK = "\u2713"
        _ACTION_LABEL: dict[ReviewAction | None, str] = {
            None: "PENDING",
            ReviewAction.EXCLUDE: "EXCLUDED",
            ReviewAction.INCLUDE: "INCLUDED",
            ReviewAction.REPROCESS_CLEAN: "CLEANED",
        }

        n = len(self.records)
        lines: list[str] = []
        lines.append(f"ZombieSlayer \u2014 {n} quarantined item{'s' if n > 1 else ''}")

        cats = self.by_category()
        if cats:
            lines.append("  " + "  |  ".join(
                f"{cat.value.upper()} {_TIMES}{count}"
                for cat, count in sorted(cats.items(), key=lambda kv: -kv[1])
            ))

        lines.append("")

        for i, rec in enumerate(self.records, 1):
            label = _ACTION_LABEL[rec.action]
            source = rec.result.item.source or "(unknown source)"
            lines.append(f" {i}. [{label}] {source}  (score {rec.result.score:.2f})")

            if rec.result.findings:
                top = max(rec.result.findings, key=lambda f: f.score)
                lines.append(f"    {top.rule}: {top.reason}")
            else:
                lines.append("    (no individual findings; quarantined by aggregate signal)")

            cats_str = ", ".join(c.value.upper() for c in rec.result.categories)
            if cats_str:
                lines.append(f"    Categories: {cats_str}")

            if rec.action is None:
                lines.append("    Actions: exclude | include | reprocess-clean")
            elif rec.action == ReviewAction.REPROCESS_CLEAN and rec.result.sanitized_text:
                lines.append(f"    {_CHECK} Sanitized text available for rerun")

            lines.append("")

        return "\n".join(lines).rstrip()


@dataclass
class PersistenceDecision:
    allowed: bool
    target: PersistenceTarget
    reason: str
    findings: list[Finding] = field(default_factory=list)
    blocked_source_ids: tuple[str, ...] = ()
