from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from zombieslayer.detector import Detector
from zombieslayer.persistence import PersistenceGuard
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.review import ReviewFlow
from zombieslayer.scanner import IntakeScanner
from zombieslayer.types import (
    ContentItem,
    PersistenceDecision,
    PersistenceTarget,
    ReviewSummary,
    ScanMode,
    ScanResult,
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
    """Plugin facade with sane defaults and callback hooks.

    Typical integration:

        zs = ZombieSlayer()
        safe, quarantined = zs.scan_intake(items)
        # feed `safe` text to the agent
        decision = zs.check_write(text, PersistenceTarget.MEMORY)
        ...
        summary = zs.end_of_task()
    """
    mode: ScanMode = ScanMode.STRICT
    detector: Detector = field(default_factory=Detector)
    policy: Policy | None = None
    store: QuarantineStore = field(default_factory=QuarantineStore)

    on_quarantine: OnQuarantine | None = None
    on_blocked_write: OnBlockedWrite | None = None
    on_review: OnReview | None = None

    _deferred: list[DeferredAction] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.policy is None:
            self.policy = Policy(mode=self.mode)
        else:
            self.policy.mode = self.mode
        self.scanner = IntakeScanner(self.detector, self.policy, self.store)
        self.guard = PersistenceGuard(self.detector, self.policy, self.store)
        self.review = ReviewFlow(self.detector, self.store)

    # ---- intake --------------------------------------------------------
    def scan_intake(
        self, items: Iterable[ContentItem]
    ) -> tuple[list[ScanResult], list[ScanResult]]:
        safe, quarantined = self.scanner.scan_batch(items)
        if self.on_quarantine:
            for r in quarantined:
                self.on_quarantine(r)
        return safe, quarantined

    # ---- persistence ---------------------------------------------------
    def check_write(
        self,
        text: str,
        target: PersistenceTarget,
        derived_from: Iterable[str] = (),
    ) -> PersistenceDecision:
        decision = self.guard.check_write(text, target, derived_from)
        if not decision.allowed and self.on_blocked_write:
            self.on_blocked_write(decision)
        return decision

    def retro_scan(self, artifacts: Iterable[ContentItem]) -> list[ScanResult]:
        results = self.guard.retro_scan(artifacts)
        if self.on_quarantine:
            for r in results:
                if r.quarantined:
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
        """Run deferred actions whose source items were approved in review.

        If `executor` raises, the action is left as not-executed and the
        exception propagates so the caller can decide whether to retry.
        Note: an executor with partial side effects may run twice on retry —
        executors should be idempotent.
        """
        ran: list[tuple[DeferredAction, Any]] = []
        for action in self._deferred:
            if action.executed:
                continue
            if all(self._source_approved(sid) for sid in action.derived_from):
                result = executor(action)
                action.executed = True
                ran.append((action, result))
        return ran

    # ---- session boundary ---------------------------------------------
    def reset(self) -> None:
        """Clear quarantine state and pending deferred actions.

        Call between independent tasks when reusing a single ZombieSlayer
        instance, otherwise quarantined items from earlier tasks accumulate
        in later end-of-task reviews.
        """
        self.store.clear()
        self._deferred.clear()

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
