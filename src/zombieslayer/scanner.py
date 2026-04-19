from __future__ import annotations

from collections.abc import Iterable

from zombieslayer.detector import Detector
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.types import ContentItem, ScanResult


class IntakeScanner:
    """Scans retrieval chunks and web-fetch content before model-context inclusion.

    Usage:
        scanner = IntakeScanner(detector, policy, store)
        safe, quarantined = scanner.scan_batch(items)
        # pass `safe` to the model; present `quarantined` at end-of-task
    """

    def __init__(
        self,
        detector: Detector,
        policy: Policy,
        store: QuarantineStore,
    ) -> None:
        self.detector = detector
        self.policy = policy
        self.store = store

    def scan_item(self, item: ContentItem) -> ScanResult:
        findings = self.detector.scan(item)
        quarantine, score = self.policy.should_quarantine(item.trust, findings)
        result = ScanResult(
            item=item,
            findings=findings,
            score=score,
            quarantined=quarantine,
        )
        if quarantine:
            self.store.add(result)
        return result

    def scan_batch(
        self, items: Iterable[ContentItem]
    ) -> tuple[list[ScanResult], list[ScanResult]]:
        safe: list[ScanResult] = []
        quarantined: list[ScanResult] = []
        for item in items:
            res = self.scan_item(item)
            (quarantined if res.quarantined else safe).append(res)
        return safe, quarantined
