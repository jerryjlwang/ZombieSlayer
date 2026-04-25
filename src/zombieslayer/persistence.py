from __future__ import annotations

import difflib
import re
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


_WS_RE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WS_RE.sub(" ", text.lower()).strip()


class PersistenceGuard:
    """Blocks suspicious writes into memory/summaries/handoffs and retro-scans storage.

    Any write containing content derived from quarantined sources, or newly
    matching detection rules, is blocked. On a blocked write, the guard
    retro-scans previously stored artifacts to surface contamination.

    With `poisoning_check=True` (default), the guard additionally compares
    the write text against quarantined snippets via fuzzy substring matching
    — catches paraphrased / quoted poisoning when the host forgets to
    declare `derived_from` (issue #6 §9).
    """

    def __init__(
        self,
        detector: Detector,
        policy: Policy,
        store: QuarantineStore,
        poisoning_check: bool = True,
        poisoning_min_chars: int = 40,
        poisoning_ratio: float = 0.6,
    ) -> None:
        self.detector = detector
        self.policy = policy
        self.store = store
        self.poisoning_check = poisoning_check
        self.poisoning_min_chars = poisoning_min_chars
        self.poisoning_ratio = poisoning_ratio
        self.last_poisoning_match: tuple[str, float] | None = None

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
        self.last_poisoning_match = None
        for item_id in derived_from:
            rec = self.store.get(item_id)
            if rec is not None:
                return PersistenceDecision(
                    allowed=False,
                    target=target,
                    reason=f"derived from quarantined source {item_id}",
                    findings=rec.result.findings,
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

        if self.poisoning_check:
            poisoned = self._poisoning_match(text)
            if poisoned is not None:
                source_id, ratio = poisoned
                self.last_poisoning_match = poisoned
                return PersistenceDecision(
                    allowed=False,
                    target=target,
                    reason=(
                        f"poisoned: write quotes quarantined source {source_id} "
                        f"(similarity {ratio:.0%})"
                    ),
                    findings=findings,
                )

        return PersistenceDecision(allowed=True, target=target, reason="clean", findings=findings)

    def _poisoning_match(self, text: str) -> tuple[str, float] | None:
        """Return (source_item_id, ratio) if the write text echoes a quarantined snippet.

        Two checks run in order:
          1. Shared substring of at least `poisoning_min_chars` after
             whitespace normalization — catches verbatim quotes.
          2. `difflib.SequenceMatcher.quick_ratio` ≥ `poisoning_ratio` —
             catches near-paraphrases of short snippets.
        """
        norm_write = _normalize(text)
        if not norm_write:
            return None
        for record in self.store.all():
            if record.action is not None:
                continue  # operator already adjudicated this item
            quarantined_text = record.result.item.text
            norm_q = _normalize(quarantined_text)
            if not norm_q:
                continue

            match = difflib.SequenceMatcher(None, norm_write, norm_q).find_longest_match(
                0, len(norm_write), 0, len(norm_q)
            )
            if match.size >= self.poisoning_min_chars:
                ratio = match.size / max(len(norm_q), 1)
                return (record.result.item.id, min(1.0, ratio))

            if len(norm_q) <= self.poisoning_min_chars * 2:
                ratio = difflib.SequenceMatcher(None, norm_write, norm_q).quick_ratio()
                if ratio >= self.poisoning_ratio:
                    return (record.result.item.id, ratio)

        return None

    def retro_scan(self, artifacts: Iterable[ContentItem]) -> list[ScanResult]:
        """Re-scan already-stored artifacts for contamination.

        Newly suspicious items are added to the quarantine store so they show
        up in the end-of-task review alongside intake-time quarantine.
        """
        results: list[ScanResult] = []
        for item in artifacts:
            findings = self.detector.scan(item)
            quarantine, score = self.policy.should_quarantine(item.trust, findings)
            result = ScanResult(
                item=item, findings=findings, score=score, quarantined=quarantine
            )
            if quarantine and self.store.get(item.id) is None:
                self.store.add(result)
            results.append(result)
        return results
