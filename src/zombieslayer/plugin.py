from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from zombieslayer.admin import AdminPolicy
from zombieslayer.audit import AuditLog
from zombieslayer.behavior import BehaviorAlert, BehaviorMonitor
from zombieslayer.detector import Detector
from zombieslayer.persistence import PersistenceGuard
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.remediation import Recommendation, recommend
from zombieslayer.replay import ReplayTracker
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
OnBehaviorAlert = Callable[[BehaviorAlert], None]


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


@dataclass(frozen=True)
class RollbackEntry:
    target: str
    artifact_id: str
    text_hash: str
    ts: float


@dataclass
class RollbackPlan:
    """An advisory rollback proposal (issue #6 §9).

    The plugin surfaces what *would* be rolled back; the host application
    actually undoes the writes. Entries are reverse-chronological so callers
    can apply them safely.
    """
    reason: str
    since: float
    entries: list[RollbackEntry]

    @property
    def artifact_ids(self) -> list[str]:
        return [e.artifact_id for e in self.entries]


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
    replay: ReplayTracker | None = field(default_factory=ReplayTracker)
    behavior: BehaviorMonitor | None = field(default_factory=BehaviorMonitor)

    on_quarantine: OnQuarantine | None = None
    on_blocked_write: OnBlockedWrite | None = None
    on_review: OnReview | None = None
    on_behavior_alert: OnBehaviorAlert | None = None

    auto_retro_scan: bool = False

    _deferred: list[DeferredAction] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.policy is None:
            self.policy = Policy(mode=self.mode)
        else:
            self.policy.mode = self.mode

        if self.admin.disabled_rules:
            self.detector.disabled_rules |= self.admin.disabled_rules
        if self.admin.rule_score_overrides:
            self.detector.score_overrides.update(self.admin.rule_score_overrides)
        if self.admin.threshold_overrides:
            self.policy.thresholds.update(self.admin.threshold_overrides)

        self.scanner = IntakeScanner(
            self.detector, self.policy, self.store, self.admin,
            replay=self.replay, behavior=self.behavior,
        )
        self.guard = PersistenceGuard(self.detector, self.policy, self.store)
        self.review = ReviewFlow(self.detector, self.store)

        if self.auto_retro_scan:
            self._startup_retro_scan()

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
        self._flush_behavior_alerts()
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
        self._flush_behavior_alerts()
        return result

    def _flush_behavior_alerts(self) -> None:
        alerts = self.scanner.drain_alerts()
        for alert in alerts:
            self.audit.record_behavior_alert(alert)
            if self.on_behavior_alert:
                self.on_behavior_alert(alert)

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

        if artifact_id is None:
            artifact_id = f"{target.value}:{len(self.topology.labels)}"
        self.topology.add_node(artifact_id, artifact_id)
        for src in derived_from:
            self.topology.add_edge(src, artifact_id)

        if not decision.allowed:
            self.topology.mark_tainted(artifact_id)
            self.audit.record_blocked_write(decision)
            poisoned = self.guard.last_poisoning_match
            if poisoned is not None:
                source_id, ratio = poisoned
                self.audit.record_memory_poisoning(target.value, source_id, ratio)
            if self.on_blocked_write:
                self.on_blocked_write(decision)
        else:
            text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self.audit.record_persistence_write(target.value, artifact_id, text_hash)
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

    def replay_artifacts(self, items: Iterable[ContentItem]) -> list[ScanResult]:
        """Convenience alias for `retro_scan` (issue #6 §9).

        Use when the host has artifacts (memory entries, summaries) that
        weren't routed through the store but should be re-evaluated against
        current rules.
        """
        return self.retro_scan(items)

    # ---- rollback (issue #6 §9) ---------------------------------------
    def propose_rollback(
        self, reason: str, since: float | None = None
    ) -> RollbackPlan:
        """Build an advisory rollback plan covering writes after `since`.

        The plugin does **not** undo memory writes itself — the host owns
        that surface. Callers iterate `plan.entries` (newest first) and
        unwind them in their own persistence layer, then call
        `confirm_rollback(plan)` so the audit log records execution.

        Args:
            reason: Operator-facing description of why a rollback is needed.
            since: Unix timestamp; entries with `ts >= since` are included.
                Defaults to the timestamp of the first quarantined item still
                in the store, falling back to 0 (full timeline).
        """
        if since is None:
            quarantine_events = [
                e for e in self.audit.events if e.get("event") == "quarantine"
            ]
            since = quarantine_events[0]["ts"] if quarantine_events else 0.0

        entries: list[RollbackEntry] = []
        for evt in self.audit.events:
            if evt.get("event") != "persistence_write":
                continue
            if evt.get("ts", 0.0) < since:
                continue
            entries.append(RollbackEntry(
                target=evt["target"],
                artifact_id=evt["artifact_id"],
                text_hash=evt["text_hash"],
                ts=evt["ts"],
            ))
        entries.sort(key=lambda e: e.ts, reverse=True)

        plan = RollbackPlan(reason=reason, since=since, entries=entries)
        self.audit.record_rollback_proposed(reason, since, plan.artifact_ids)
        return plan

    def confirm_rollback(self, plan: RollbackPlan) -> None:
        """Record host confirmation that the plan was applied externally."""
        self.audit.record_rollback_executed(plan.artifact_ids)

    def _startup_retro_scan(self) -> list[ScanResult]:
        """Auto retro-scan all items the durable store knows about (issue #6 §9).

        Pulls each `ContentItem` out of existing quarantine records and
        re-runs detection. New quarantines from rule changes since the
        record was written propagate via taint as usual; an audit entry
        records the boot scan.
        """
        items = [rec.result.item for rec in self.store.all()]
        if not items:
            self.audit.record_retro_scan_startup(scanned=0, newly_quarantined=0)
            return []
        before = {rec.result.item.id for rec in self.store.all()}
        results = self.retro_scan(items)
        after = {rec.result.item.id for rec in self.store.all()}
        newly = len(after - before)
        self.audit.record_retro_scan_startup(scanned=len(items), newly_quarantined=newly)
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

    # ---- operator feedback loop (issue #2 §6) --------------------------
    def mark_regression(self, item_id: str, delta: float = 0.05) -> None:
        """Operator reports that an INCLUDE decision caused a regression.

        Soft-learning: lower the per-(trust, mode) threshold for the affected
        trust tier so future content with similar scores is quarantined. Also
        nudges the dominant rule's score up by `delta` so its weight reflects
        the observed impact (never above 1.0, never auto-disabled).
        """
        rec = self.store.get(item_id)
        if rec is None:
            return
        self.admin.record_feedback(item_id, "regression")
        self.audit.record_regression(item_id)

        trust = rec.result.item.trust
        mode = self.policy.mode  # type: ignore[union-attr]
        cur_thr = self.policy.thresholds.get((trust, mode), 0.5)  # type: ignore[union-attr]
        new_thr = max(0.05, cur_thr - delta)
        self.policy.thresholds[(trust, mode)] = new_thr  # type: ignore[union-attr]
        self.admin.threshold_overrides[(trust, mode)] = new_thr

        if rec.result.findings:
            dominant = max(rec.result.findings, key=lambda f: f.score).rule
            current = self.detector.score_overrides.get(dominant)
            if current is None:
                for r in self.detector.rules:
                    if r.name == dominant:
                        current = r.score
                        break
            if current is not None:
                new_score = min(1.0, current + delta)
                self.detector.score_overrides[dominant] = new_score
                self.admin.rule_score_overrides[dominant] = new_score
