from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass, field

from zombieslayer.types import ContentItem, Finding, RiskCategory


# Normalization for shingling: lowercase, collapse whitespace, drop punctuation
# so that trivial formatting variations still collide.
_NORMALIZE = re.compile(r"[^a-z0-9]+")


def _shingles(text: str, n: int = 5) -> set[str]:
    """Normalized n-gram shingles hashed to short hex digests."""
    tokens = [t for t in _NORMALIZE.split(text.lower()) if t]
    if len(tokens) < n:
        if not tokens:
            return set()
        window = " ".join(tokens)
        return {hashlib.sha1(window.encode()).hexdigest()[:16]}
    out: set[str] = set()
    for i in range(len(tokens) - n + 1):
        window = " ".join(tokens[i : i + n])
        out.add(hashlib.sha1(window.encode()).hexdigest()[:16])
    return out


@dataclass
class _Record:
    source: str
    shingles: set[str]


@dataclass
class ReplayTracker:
    """Detect suspect content replayed across distinct sources (issue #2 §4).

    Maintains a rolling LRU of recently scanned items. When a new item shares
    a meaningful fraction of n-gram shingles with one or more *different*
    sources in the window, emit a `cross_source_replay` finding.

    Kept intentionally simple and stdlib-only: sha1-shingled 5-grams with a
    Jaccard-similarity threshold.
    """

    window: int = 256
    similarity: float = 0.35
    min_shingles: int = 5
    _buffer: deque[_Record] = field(default_factory=deque)

    def observe(self, item: ContentItem) -> list[Finding]:
        shingles = _shingles(item.text)
        findings = self._check(item, shingles)
        self._buffer.append(_Record(source=item.source, shingles=shingles))
        while len(self._buffer) > self.window:
            self._buffer.popleft()
        return findings

    def _check(self, item: ContentItem, shingles: set[str]) -> list[Finding]:
        if len(shingles) < self.min_shingles:
            return []
        matches: list[tuple[str, float]] = []
        for rec in self._buffer:
            if rec.source == item.source or not rec.shingles:
                continue
            inter = len(shingles & rec.shingles)
            if inter == 0:
                continue
            union = len(shingles | rec.shingles)
            sim = inter / union if union else 0.0
            if sim >= self.similarity:
                matches.append((rec.source, sim))
        if not matches:
            return []
        # Compounding score: more distinct matching sources => higher.
        distinct_sources = len({m[0] for m in matches})
        top_sim = max(m[1] for m in matches)
        score = min(0.5 + 0.1 * distinct_sources + 0.2 * top_sim, 0.9)
        sample = ", ".join(sorted({m[0] for m in matches})[:3])
        return [Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=(
                f"content signature repeats across {distinct_sources} other "
                f"source(s) in window (top similarity {top_sim:.2f}): {sample}"
            ),
            span=(0, min(len(item.text), 1)),
            rule="cross_source_replay",
            score=score,
            kind="replay",
            evidence={
                "matched_sources": sorted({m[0] for m in matches}),
                "top_similarity": top_sim,
            },
        )]

    def clear(self) -> None:
        self._buffer.clear()
