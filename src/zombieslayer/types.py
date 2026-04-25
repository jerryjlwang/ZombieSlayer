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
    TOOL_OUTPUT = "tool_output"    # text returned by a tool/function call
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "source": self.source,
            "trust": self.trust.value,
            "chunk_ref": self.chunk_ref,
            "metadata": dict(self.metadata),
            "id": self.id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ContentItem":
        return cls(
            text=d["text"],
            source=d["source"],
            trust=SourceTrust(d.get("trust", SourceTrust.UNTRUSTED.value)),
            chunk_ref=d.get("chunk_ref"),
            metadata=dict(d.get("metadata") or {}),
            id=d.get("id") or uuid.uuid4().hex,
        )


@dataclass
class Finding:
    """A single detector hit within a content item."""
    category: RiskCategory
    reason: str
    span: tuple[int, int]          # (start, end) char offsets
    rule: str
    score: float                   # 0.0 - 1.0
    kind: str = "generic"          # short noun for context-preserving redaction
    # Signal family — used by ensemble voting in Policy.aggregate. One of
    # "rules", "structural", "intent", "behavioral". Default "rules" matches
    # the dominant case so legacy constructors keep working.
    family: str = "rules"
    # Optional structured metadata:
    #   "decoded_from": which decoder surfaced this finding (base64, url, ...)
    #   "metadata_key": if finding came from ContentItem.metadata, the key name
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "reason": self.reason,
            "span": list(self.span),
            "rule": self.rule,
            "score": self.score,
            "kind": self.kind,
            "family": self.family,
            "evidence": dict(self.evidence),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        span = d.get("span") or [0, 0]
        return cls(
            category=RiskCategory(d["category"]),
            reason=d["reason"],
            span=(int(span[0]), int(span[1])),
            rule=d["rule"],
            score=float(d["score"]),
            kind=d.get("kind", "generic"),
            family=d.get("family", "rules"),
            evidence=dict(d.get("evidence") or {}),
        )


@dataclass
class ScanResult:
    item: ContentItem
    findings: list[Finding]
    score: float                   # aggregate suspiciousness
    quarantined: bool
    sanitized_text: str | None = None  # populated on reprocess-clean
    sanitized_metadata: dict[str, Any] | None = None  # populated on reprocess-clean

    def to_dict(self) -> dict[str, Any]:
        return {
            "item": self.item.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
            "quarantined": self.quarantined,
            "sanitized_text": self.sanitized_text,
            "sanitized_metadata":
                dict(self.sanitized_metadata) if self.sanitized_metadata is not None else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanResult":
        return cls(
            item=ContentItem.from_dict(d["item"]),
            findings=[Finding.from_dict(f) for f in d.get("findings") or []],
            score=float(d["score"]),
            quarantined=bool(d["quarantined"]),
            sanitized_text=d.get("sanitized_text"),
            sanitized_metadata=dict(d["sanitized_metadata"])
                if d.get("sanitized_metadata") is not None else None,
        )

    @property
    def categories(self) -> list[RiskCategory]:
        seen: list[RiskCategory] = []
        for f in self.findings:
            if f.category not in seen:
                seen.append(f.category)
        return seen

    def explain(self, threshold: float | None = None) -> str:
        """Decision-tree style trace of why this item was (not) quarantined."""
        lines: list[str] = []
        src = self.item.source or "(unknown source)"
        lines.append(f"ScanResult — source={src} trust={self.item.trust.value}")
        if not self.findings:
            lines.append("  no findings fired")
        else:
            lines.append(f"  findings ({len(self.findings)}):")
            for f in sorted(self.findings, key=lambda x: -x.score):
                decoded = f.evidence.get("decoded_from")
                meta_key = f.evidence.get("metadata_key")
                extras: list[str] = []
                if decoded:
                    extras.append(f"decoded={decoded}")
                if meta_key:
                    extras.append(f"metadata_key={meta_key}")
                tail = f" [{', '.join(extras)}]" if extras else ""
                lines.append(
                    f"    - {f.rule} ({f.category.value}) score={f.score:.2f} "
                    f"span={f.span} kind={f.kind}{tail}"
                )
                lines.append(f"      {f.reason}")
        lines.append(f"  aggregate score = {self.score:.3f}")
        if threshold is not None:
            cmp = ">=" if self.score >= threshold else "<"
            lines.append(
                f"  policy threshold = {threshold:.3f}  "
                f"(score {cmp} threshold \u2192 "
                f"{'QUARANTINE' if self.quarantined else 'allow'})"
            )
        else:
            lines.append(f"  quarantined = {self.quarantined}")
        return "\n".join(lines)


@dataclass
class QuarantineRecord:
    result: ScanResult
    action: ReviewAction | None = None   # user choice, once made

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.to_dict(),
            "action": self.action.value if self.action is not None else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "QuarantineRecord":
        action_raw = d.get("action")
        return cls(
            result=ScanResult.from_dict(d["result"]),
            action=ReviewAction(action_raw) if action_raw is not None else None,
        )


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

            cats_str = ", ".join(c.value.upper() for c in rec.result.categories)
            if cats_str:
                lines.append(f"    Categories: {cats_str}")

            if rec.action is None:
                from zombieslayer.remediation import recommend
                tip = recommend(rec)
                lines.append("    Actions: exclude | include | reprocess-clean")
                lines.append(
                    f"    \u2192 Suggested: {tip.action.value} "
                    f"({tip.confidence:.0%}) \u2014 {tip.rationale}"
                )
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
