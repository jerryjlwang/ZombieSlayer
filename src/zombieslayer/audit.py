from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zombieslayer.types import (
    PersistenceDecision,
    ReviewAction,
    ScanResult,
)


@dataclass
class AuditLog:
    """Append-only JSONL audit log for compliance export (PRD §12 post-MVP).

    Every security-relevant decision — quarantine, blocked write, review action,
    deferred-action execution — is serialized as one line. Enterprises can ship
    the file to their SIEM without any additional transformation.
    """

    path: Path | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = Path(self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---- record helpers -----------------------------------------------
    def record_quarantine(self, result: ScanResult) -> None:
        self._emit({
            "event": "quarantine",
            "item_id": result.item.id,
            "source": result.item.source,
            "trust": result.item.trust.value,
            "score": result.score,
            "categories": [c.value for c in result.categories],
            "rules": sorted({f.rule for f in result.findings}),
        })

    def record_blocked_write(self, decision: PersistenceDecision) -> None:
        self._emit({
            "event": "blocked_write",
            "target": decision.target.value,
            "reason": decision.reason,
            "rules": sorted({f.rule for f in decision.findings}),
        })

    def record_review_action(self, item_id: str, action: ReviewAction) -> None:
        self._emit({
            "event": "review_action",
            "item_id": item_id,
            "action": action.value,
        })

    def record_deferred_execution(
        self, name: str, derived_from: tuple[str, ...]
    ) -> None:
        self._emit({
            "event": "deferred_execution",
            "action_name": name,
            "derived_from": list(derived_from),
        })

    def record_behavior_alert(self, alert: Any) -> None:
        """Record a BehaviorMonitor alert (issue #2 §5)."""
        self._emit({
            "event": "behavior_alert",
            "source": getattr(alert, "source", ""),
            "kind": getattr(alert, "kind", ""),
            "detail": getattr(alert, "detail", ""),
            "severity": getattr(alert, "severity", 0.0),
        })

    def record_regression(self, item_id: str) -> None:
        """Record an operator-reported regression (issue #2 §6)."""
        self._emit({
            "event": "regression",
            "item_id": item_id,
        })

    def record_replay(self, source: str, matched_sources: list[str]) -> None:
        """Record a cross-source replay finding (issue #2 §4)."""
        self._emit({
            "event": "replay_match",
            "source": source,
            "matched_sources": list(matched_sources),
        })

    def record_retro_scan_startup(self, scanned: int, newly_quarantined: int) -> None:
        """Record an automatic retro-scan run at plugin boot (issue #6 §9)."""
        self._emit({
            "event": "retro_scan_startup",
            "scanned": scanned,
            "newly_quarantined": newly_quarantined,
        })

    def record_memory_poisoning(
        self, target: str, source_id: str, ratio: float
    ) -> None:
        """Record a write blocked because it quotes quarantined content (issue #6 §9)."""
        self._emit({
            "event": "memory_poisoning",
            "target": target,
            "source_id": source_id,
            "match_ratio": ratio,
        })

    def record_persistence_write(
        self, target: str, artifact_id: str, text_hash: str
    ) -> None:
        """Record a successful persistence write (issue #6 §9 — rollback timeline)."""
        self._emit({
            "event": "persistence_write",
            "target": target,
            "artifact_id": artifact_id,
            "text_hash": text_hash,
        })

    def record_rollback_proposed(
        self, reason: str, since: float, artifact_ids: list[str]
    ) -> None:
        """Record an operator-initiated rollback proposal (issue #6 §9)."""
        self._emit({
            "event": "rollback_proposed",
            "reason": reason,
            "since": since,
            "artifact_ids": list(artifact_ids),
        })

    def record_rollback_executed(self, artifact_ids: list[str]) -> None:
        """Record host confirmation that a rollback was applied (issue #6 §9)."""
        self._emit({
            "event": "rollback_executed",
            "artifact_ids": list(artifact_ids),
        })

    # ---- output --------------------------------------------------------
    def _emit(self, payload: dict[str, Any]) -> None:
        payload = {"ts": time.time(), **payload}
        self.events.append(payload)
        if self.path is not None:
            with self.path.open("a") as fh:
                fh.write(json.dumps(payload) + "\n")

    def export(self) -> str:
        """Return the log as a JSONL string (same shape as the on-disk file)."""
        return "\n".join(json.dumps(e) for e in self.events)
