from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from zombieslayer.admin import AdminPolicy
from zombieslayer.audit import AuditLog
from zombieslayer.detector import Detector
from zombieslayer.persistence import PersistenceGuard
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.remediation import Recommendation, recommend
from zombieslayer.review import ReviewFlow
from zombieslayer.scanner import IntakeScanner
from zombieslayer.topology import HandoffGraph
from zombieslayer.types import (
    ContentItem,
    PersistenceDecision,
    PersistenceTarget,
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
    ScanMode,
    ScanResult,
    SourceTrust,
)


OnQuarantine = Callable[[ScanResult], None]
OnBlockedWrite = Callable[[PersistenceDecision], None]
OnReview = Callable[[ReviewSummary], None]


@dataclass
class DeferredAction:
    """An external action whose execution is paused until end-of-task review.

    Per PRD §18: irreversible external actions derived from tainted content
    are deferred rather than interrupting live flow.
    """
    name: str
    payload: dict[str, Any]
    derived_from: tuple[str, ...]
    executed: bool = False


@dataclass
class ZombieSlayer:
    """Plugin facade with sane defaults and callback hooks."""

    mode: ScanMode = ScanMode.STRICT
    detector: Detector = field(default_factory=Detector)
    policy: Policy | None = None
    store: QuarantineStore = field(default_factory=QuarantineStore)
    admin: AdminPolicy = field(default_factory=AdminPolicy)
    audit: AuditLog = field(default_factory=AuditLog)
    topology: HandoffGraph = field(default_factory=HandoffGraph)

    on_quarantine: OnQuarantine | None = None
    on_blocked_write: OnBlockedWrite | None = None
    on_review: OnReview | None = None

    _deferred: list[DeferredAction] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.policy is None:
            self.policy = Policy(mode=self.mode)
        else:
            self.policy.mode = self.mode

        # Apply admin overrides to detector + policy.
        if self.admin.disabled_rules:
            self.detector.disabled_rules |= self.admin.disabled_rules
        if self.admin.rule_score_overrides:
            self.detector.score_overrides.update(self.admin.rule_score_overrides)
        if self.admin.threshold_overrides:
            self.policy.thresholds.update(self.admin.threshold_overrides)

        self.scanner = IntakeScanner(self.detector, self.policy, self.store, self.admin)
        self.guard = PersistenceGuard(self.detector, self.policy, self.store)
        self.review = ReviewFlow(self.detector, self.store)

    # ---- intake --------------------------------------------------------
    def scan_intake(
        self, items: Iterable[ContentItem]
    ) -> tuple[list[ScanResult], list[ScanResult]]:
        safe, quarantined = self.scanner.scan_batch(items)
        for r in quarantined:
            self.audit.record_quarantine(r)
            self.topology.add_node(r.item.id, r.item.source)
            self.topology.mark_tainted(r.item.id)
            if self.on_quarantine:
                self.on_quarantine(r)
        for r in safe:
            self.topology.add_node(r.item.id, r.item.source)
        return safe, quarantined

    def scan_tool_output(
        self, tool_name: str, output: str, trust: SourceTrust = SourceTrust.TOOL_OUTPUT
    ) -> ScanResult:
        """Scan a tool/function-call output as untrusted intake (PRD §12)."""
        result = self.scanner.scan_tool_output(tool_name, output, trust)
        self.topology.add_node(result.item.id, result.item.source)
        if result.quarantined:
            self.topology.mark_tainted(result.item.id)
            self.audit.record_quarantine(result)
            if self.on_quarantine:
                self.on_quarantine(result)
        return result

    # ---- persistence ---------------------------------------------------
    def check_write(
        self,
        text: str,
        target: PersistenceTarget,
        derived_from: Iterable[str] = (),
        artifact_id: str | None = None,
    ) -> PersistenceDecision:
        derived_from = tuple(derived_from)
        decision = self.guard.check_write(text, target, derived_from)

        # Record topology regardless of decision — the attempt itself is a node.
        if artifact_id is None:
            artifact_id = f"{target.value}:{len(self.topology.labels)}"
        self.topology.add_node(artifact_id, artifact_id)
        for src in derived_from:
            self.topology.add_edge(src, artifact_id)

        if not decision.allowed:
            self.topology.mark_tainted(artifact_id)
            self.audit.record_blocked_write(decision)
            if self.on_blocked_write:
                self.on_blocked_write(decision)
        return decision

    def retro_scan(self, artifacts: Iterable[ContentItem]) -> list[ScanResult]:
        results = self.guard.retro_scan(artifacts)
        for r in results:
            if r.quarantined:
                self.topology.add_node(r.item.id, r.item.source)
                self.topology.mark_tainted(r.item.id)
                self.audit.record_quarantine(r)
                if self.on_quarantine:
                    self.on_quarantine(r)
        return results

    # ---- deferred actions (PRD §18) -----------------------------------
    def defer_action(
        self, name: str, payload: dict[str, Any], derived_from: Iterable[str]
    ) -> DeferredAction:
        action = DeferredAction(
            name=name, payload=dict(payload), derived_from=tuple(derived_from)
        )
        self._deferred.append(action)
        return action

    def pending_actions(self) -> list[DeferredAction]:
        return [a for a in self._deferred if not a.executed]

    def execute_approved_actions(
        self, executor: Callable[[DeferredAction], Any]
    ) -> list[tuple[DeferredAction, Any]]:
        """Run deferred actions whose source items were approved in review."""
        ran: list[tuple[DeferredAction, Any]] = []
        for action in self._deferred:
            if action.executed:
                continue
            if all(self._source_approved(sid) for sid in action.derived_from):
                result = executor(action)
                action.executed = True
                self.audit.record_deferred_execution(action.name, action.derived_from)
                ran.append((action, result))
        return ran

    def _source_approved(self, item_id: str) -> bool:
        rec = self.store.get(item_id)
        if rec is None:
            return True  # never quarantined => fine
        return self.review.approved_text(rec) is not None

    # ---- review --------------------------------------------------------
    def end_of_task(self) -> ReviewSummary:
        summary = self.review.summary()
        if self.on_review:
            self.on_review(summary)
        return summary

    def recommend(self, rec: QuarantineRecord) -> Recommendation:
        """Auto-remediation suggestion for a quarantined record (PRD §12)."""
        return recommend(rec)

    def apply_review_action(self, item_id: str, action: ReviewAction) -> QuarantineRecord:
        """Unified entry point that also records to the audit log."""
        if action == ReviewAction.EXCLUDE:
            rec = self.review.exclude(item_id)
        elif action == ReviewAction.INCLUDE:
            rec = self.review.include(item_id)
        else:
            rec = self.review.reprocess_clean(item_id)
        self.audit.record_review_action(item_id, action)
        return rec
