from __future__ import annotations

from collections.abc import Iterable

from zombieslayer.admin import AdminPolicy
from zombieslayer.detector import Detector
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.types import (
    ContentItem,
    Finding,
    RiskCategory,
    ScanResult,
    SourceTrust,
)


class IntakeScanner:
    """Scans retrieval chunks, web-fetch content, and tool output before inclusion.

    Usage:
        scanner = IntakeScanner(detector, policy, store)
        safe, quarantined = scanner.scan_batch(items)
    """

    def __init__(
        self,
        detector: Detector,
        policy: Policy,
        store: QuarantineStore,
        admin: AdminPolicy | None = None,
    ) -> None:
        self.detector = detector
        self.policy = policy
        self.store = store
        self.admin = admin or AdminPolicy()

    def scan_item(self, item: ContentItem) -> ScanResult:
        # Allowlist short-circuits scanning entirely.
        if self.admin.is_allowlisted(item.source):
            return ScanResult(item=item, findings=[], score=0.0, quarantined=False)

        findings = self.detector.scan(item)

        if self.admin.is_denylisted(item.source):
            findings = findings + [Finding(
                category=RiskCategory.STRUCTURAL_ANOMALY,
                reason="source appears on operator denylist",
                span=(0, min(len(item.text), 1)),
                rule="admin_denylist",
                score=1.0,
            )]
            result = ScanResult(item=item, findings=findings, score=1.0, quarantined=True)
            self.store.add(result)
            return result

        threshold = self.admin.threshold_overrides.get(
            (item.trust, self.policy.mode), self.policy.threshold(item.trust)
        )
        score = self.policy.aggregate(findings)
        quarantine = score >= threshold
        result = ScanResult(
            item=item, findings=findings, score=score, quarantined=quarantine,
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

    def scan_tool_output(
        self, tool_name: str, output: str, trust: SourceTrust = SourceTrust.TOOL_OUTPUT
    ) -> ScanResult:
        """Scan a tool's textual output (PRD §12 post-MVP).

        Tool output is a major attack surface: an MCP server, a shell command,
        or a fetched API response can all carry hidden directives. Wrapping
        the output as a `ContentItem` lets it flow through the same intake
        pipeline as retrieval/web content.
        """
        item = ContentItem(
            text=output, source=f"tool:{tool_name}", trust=trust
        )
        return self.scan_item(item)
