from __future__ import annotations

from typing import Any

from zombieslayer.detector import Detector
from zombieslayer.quarantine import QuarantineStore
from zombieslayer.types import (
    ContentItem,
    Finding,
    QuarantineRecord,
    ReviewAction,
    ReviewSummary,
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

        Spans are collapsed to `[redacted:<category>:<kind>]` markers so
        downstream synthesis sees what kind of content was removed, without
        carrying the instruction payload. Metadata is sanitized recursively
        (issue #2 §6).
        """
        rec = self.store.get(item_id)
        if rec is None:
            raise KeyError(item_id)

        text = rec.result.item.text

        # Split text-range findings (those with span (s, e) where e > s) from
        # metadata findings (span (0, 0) or no real span).
        text_findings = [
            f for f in rec.result.findings
            if f.span[1] > f.span[0] and not f.evidence.get("metadata_key")
        ]

        spans = sorted(
            ((f.span, _redaction_label(f)) for f in text_findings),
            key=lambda s: s[0][0],
        )
        merged: list[tuple[tuple[int, int], str]] = []
        for (start, end), label in spans:
            if merged and start <= merged[-1][0][1]:
                (ps, pe), plabel = merged[-1]
                merged[-1] = ((ps, max(pe, end)), _combine_labels(plabel, label))
            else:
                merged.append(((start, end), label))

        out = text
        for (start, end), label in reversed(merged):
            out = out[:start] + f"[redacted:{label}]" + out[end:]

        # Recursively sanitize metadata strings (issue #2 §6).
        sanitized_meta = self._sanitize_metadata(rec.result.item.metadata)

        # Re-scan the cleaned text; if it still trips the detector, we keep
        # the record quarantined but stash the attempt for the user.
        probe = ContentItem(
            text=out,
            source=rec.result.item.source,
            trust=rec.result.item.trust,
            chunk_ref=rec.result.item.chunk_ref,
            metadata={},  # already sanitized
        )
        residual = self.detector.scan(probe)

        rec.result.sanitized_text = out
        rec.result.sanitized_metadata = sanitized_meta
        rec.action = ReviewAction.REPROCESS_CLEAN
        if residual:
            known = {m[1] for m in merged}
            rec.result.findings = rec.result.findings + [
                f for f in residual if f.rule not in known
            ]
        return rec

    def _sanitize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        if not metadata:
            return dict(metadata)
        out: dict[str, Any] = {}
        for key, value in metadata.items():
            if isinstance(value, str) and value.strip():
                probe = ContentItem(text=value, source=f"metadata:{key}")
                hits = self.detector.scan(probe)
                text_hits = [
                    f for f in hits
                    if f.span[1] > f.span[0] and not f.evidence.get("metadata_key")
                ]
                if text_hits:
                    out[key] = _redact_ranges(value, text_hits)
                else:
                    out[key] = value
            else:
                out[key] = value
        return out

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


def _redaction_label(finding: Finding) -> str:
    cat = finding.category.value
    kind = finding.kind or "generic"
    return f"{cat}:{kind}"


def _combine_labels(a: str, b: str) -> str:
    if a == b:
        return a
    # If categories match, keep category + combine kinds.
    a_cat, _, a_kind = a.partition(":")
    b_cat, _, b_kind = b.partition(":")
    if a_cat == b_cat:
        kinds = sorted({a_kind, b_kind})
        return f"{a_cat}:{'+'.join(kinds)}"
    return f"{a}+{b}"


def _redact_ranges(text: str, findings: list[Finding]) -> str:
    merged: list[tuple[tuple[int, int], str]] = []
    for f in sorted(findings, key=lambda x: x.span[0]):
        start, end = f.span
        label = _redaction_label(f)
        if merged and start <= merged[-1][0][1]:
            (ps, pe), plabel = merged[-1]
            merged[-1] = ((ps, max(pe, end)), _combine_labels(plabel, label))
        else:
            merged.append(((start, end), label))
    out = text
    for (start, end), label in reversed(merged):
        out = out[:start] + f"[redacted:{label}]" + out[end:]
    return out
