from __future__ import annotations

from zombieslayer.detector import Detector
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.types import (
    ContentItem,
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
    ScanResult,
)


class ReviewFlow:
    """End-of-task review: exclude / include / reprocess-clean."""

    def __init__(self, detector: Detector, store: QuarantineStore) -> None:
        self.detector = detector
        self.store = store

    def summary(self) -> ReviewSummary:
        return self.store.summary()

    def exclude(self, item_id: str) -> QuarantineRecord:
        return self.store.set_action(item_id, ReviewAction.EXCLUDE)

    def include(self, item_id: str) -> QuarantineRecord:
        """User explicitly approves a quarantined item for rerun as-is."""
        return self.store.set_action(item_id, ReviewAction.INCLUDE)

    def reprocess_clean(self, item_id: str) -> QuarantineRecord:
        """Strip suspicious spans while preserving surrounding content.

        Spans are collapsed to `[redacted:<rule>]` markers so downstream
        synthesis still sees that *something* was removed, without carrying
        the instruction payload.
        """
        rec = self.store.get(item_id)
        if rec is None:
            raise KeyError(item_id)

        text = rec.result.item.text
        # Merge overlapping spans, walk in reverse so offsets stay valid.
        spans = sorted(
            ((f.span, f.rule) for f in rec.result.findings),
            key=lambda s: s[0][0],
        )
        merged: list[tuple[tuple[int, int], str]] = []
        for (start, end), rule in spans:
            if merged and start <= merged[-1][0][1]:
                (ps, pe), prule = merged[-1]
                merged[-1] = ((ps, max(pe, end)), f"{prule}+{rule}")
            else:
                merged.append(((start, end), rule))

        out = text
        for (start, end), rule in reversed(merged):
            out = out[:start] + f"[redacted:{rule}]" + out[end:]

        # Re-scan the cleaned text; if it still trips the detector, we keep
        # the record quarantined but stash the attempt for the user.
        probe = ContentItem(
            text=out,
            source=rec.result.item.source,
            trust=rec.result.item.trust,
            chunk_ref=rec.result.item.chunk_ref,
        )
        residual = self.detector.scan(probe)

        rec.result.sanitized_text = out
        rec.action = ReviewAction.REPROCESS_CLEAN
        if residual:
            # Surface residual findings so the developer/user sees that the
            # clean was partial.
            rec.result.findings = rec.result.findings + [
                f for f in residual if f.rule not in {m[1] for m in merged}
            ]
        return rec

    def approved_text(self, rec: QuarantineRecord) -> str | None:
        """Return text safe to feed back into a rerun, if any."""
        if rec.action == ReviewAction.INCLUDE:
            return rec.result.item.text
        if rec.action == ReviewAction.REPROCESS_CLEAN:
            return rec.result.sanitized_text
        return None

    def approved_results(self) -> list[tuple[QuarantineRecord, str]]:
        out: list[tuple[QuarantineRecord, str]] = []
        for rec in self.store.all():
            text = self.approved_text(rec)
            if text is not None:
                out.append((rec, text))
        return out
