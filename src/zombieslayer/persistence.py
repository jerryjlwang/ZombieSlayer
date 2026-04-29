from __future__ import annotations

from collections.abc import Iterable

from zombieslayer.detector import Detector
from zombieslayer.policy import Policy
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.types import (
    ContentItem,
    PersistenceDecision,
    PersistenceTarget,
    ScanResult,
    SourceTrust,
)


class PersistenceGuard:
    """Blocks suspicious writes into memory/summaries/handoffs and retro-scans storage.

    Any write containing content derived from quarantined sources, or newly
    matching detection rules, is blocked. On a blocked write, the guard
    retro-scans previously stored artifacts to surface contamination.
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

    def check_write(
        self,
        text: str,
        target: PersistenceTarget,
        derived_from: Iterable[str] = (),
    ) -> PersistenceDecision:
        """Decide whether a write into `target` is safe.

        `derived_from` are ContentItem.ids the write was derived from; if any
        are already quarantined, the write is blocked regardless of its text.
        """
        tainted_ids: list[str] = []
        tainted_findings: list = []
        for item_id in derived_from:
            rec = self.store.get(item_id)
            if rec is not None:
                tainted_ids.append(item_id)
                tainted_findings.extend(rec.result.findings)
        if tainted_ids:
            ids_str = ", ".join(tainted_ids)
            return PersistenceDecision(
                allowed=False,
                target=target,
                reason=f"derived from quarantined source(s) {ids_str}",
                findings=tainted_findings,
                blocked_source_ids=tuple(tainted_ids),
            )

        # Treat the write itself as untrusted content: suspicious instruction
        # text in a memory write is exactly the persistence-attack signature.
        probe = ContentItem(text=text, source=f"write:{target.value}", trust=SourceTrust.UNTRUSTED)
        findings = self.detector.scan(probe)
        quarantine, score = self.policy.should_quarantine(SourceTrust.UNTRUSTED, findings)
        if quarantine:
            return PersistenceDecision(
                allowed=False,
                target=target,
                reason=f"write matches suspicious patterns (score={score:.2f})",
                findings=findings,
            )
        return PersistenceDecision(allowed=True, target=target, reason="clean", findings=findings)

    def retro_scan(self, artifacts: Iterable[ContentItem]) -> list[ScanResult]:
        """Re-scan already-stored artifacts for contamination.

        Newly suspicious items are added to the quarantine store so they show
        up in the end-of-task review alongside intake-time quarantine.
        """
        results: list[ScanResult] = []
        for item in artifacts:
            findings = self.detector.scan(item)
            # Use the *minimum* trust along the derivation chain so that an
            # artifact tagged USER but derived from UNTRUSTED content gets the
            # stricter UNTRUSTED threshold.
            effective_trust = self._effective_trust(item)
            quarantine, score = self.policy.should_quarantine(effective_trust, findings)
            result = ScanResult(
                item=item, findings=findings, score=score, quarantined=quarantine
            )
            if quarantine and self.store.get(item.id) is None:
                self.store.add(result)
            results.append(result)
        return results

    _TRUST_RANK = {
        SourceTrust.UNTRUSTED: 0,
        SourceTrust.RETRIEVAL: 1,
        SourceTrust.DEVELOPER: 2,
        SourceTrust.USER: 3,
    }

    def _effective_trust(self, item: ContentItem) -> SourceTrust:
        min_trust = item.trust
        min_rank = self._TRUST_RANK[item.trust]
        for src_id in item.derived_from:
            rec = self.store.get(src_id)
            if rec is None:
                continue
            src_rank = self._TRUST_RANK[rec.result.item.trust]
            if src_rank < min_rank:
                min_rank = src_rank
                min_trust = rec.result.item.trust
        return min_trust
