from __future__ import annotations

from dataclasses import dataclass, field

from zombieslayer.types import Finding, ScanMode, SourceTrust


# Default family weights for the ensemble. Empty mapping = legacy product
# aggregation across all findings (backward compatible).
_DEFAULT_FAMILY_WEIGHTS: dict[str, float] = {
    "rules": 0.5,
    "structural": 0.2,
    "intent": 0.2,
    "behavioral": 0.1,
}


@dataclass
class EnsembleConfig:
    """Operator-tunable ensemble voting configuration (issue #6 §8).

    When `weights` is non-empty, `Policy.aggregate` groups findings by
    `Finding.family`, aggregates within each family via the existing
    `1 - Π(1 - s)` rule, and combines across families as a weighted sum
    (clamped to [0, 1]). Weights for absent families are treated as 0.

    Backward compat: with `weights={}` (the default), aggregation degenerates
    to the legacy "all findings as one bucket" behavior.
    """

    weights: dict[str, float] = field(default_factory=dict)

    @classmethod
    def with_defaults(cls) -> "EnsembleConfig":
        """Construct with the recommended starter weights."""
        return cls(weights=dict(_DEFAULT_FAMILY_WEIGHTS))

    def is_enabled(self) -> bool:
        return any(w > 0 for w in self.weights.values())


@dataclass
class Policy:
    """Source-aware thresholds and mode selection.

    The aggregate score is computed as `1 - Π(1 - f.score)` across findings,
    so multiple weaker signals compound. Quarantine fires when the aggregate
    exceeds the per-(trust, mode) threshold.

    When `ensemble.is_enabled()` is true, aggregation switches to weighted
    voting across signal families (issue #6 §8) — see `EnsembleConfig`.
    """

    thresholds: dict[tuple[SourceTrust, ScanMode], float] = field(
        default_factory=lambda: {
            (SourceTrust.UNTRUSTED, ScanMode.STRICT): 0.35,
            (SourceTrust.UNTRUSTED, ScanMode.FAST): 0.55,
            (SourceTrust.RETRIEVAL, ScanMode.STRICT): 0.45,
            (SourceTrust.RETRIEVAL, ScanMode.FAST): 0.65,
            (SourceTrust.TOOL_OUTPUT, ScanMode.STRICT): 0.40,
            (SourceTrust.TOOL_OUTPUT, ScanMode.FAST): 0.60,
            (SourceTrust.DEVELOPER, ScanMode.STRICT): 0.7,
            (SourceTrust.DEVELOPER, ScanMode.FAST): 0.85,
            (SourceTrust.USER, ScanMode.STRICT): 0.8,
            (SourceTrust.USER, ScanMode.FAST): 0.9,
        }
    )
    mode: ScanMode = ScanMode.STRICT
    ensemble: EnsembleConfig = field(default_factory=EnsembleConfig)

    def aggregate(self, findings: list[Finding]) -> float:
        if not self.ensemble.is_enabled():
            return self._product(findings)
        # Weighted-family vote.
        by_family: dict[str, list[Finding]] = {}
        for f in findings:
            by_family.setdefault(f.family or "rules", []).append(f)
        total = 0.0
        for family, fs in by_family.items():
            weight = self.ensemble.weights.get(family, 0.0)
            if weight <= 0:
                continue
            total += weight * self._product(fs)
        return max(0.0, min(1.0, total))

    @staticmethod
    def _product(findings: list[Finding]) -> float:
        prod = 1.0
        for f in findings:
            prod *= 1.0 - max(0.0, min(1.0, f.score))
        return 1.0 - prod

    def threshold(self, trust: SourceTrust) -> float:
        return self.thresholds.get((trust, self.mode), 0.5)

    def should_quarantine(self, trust: SourceTrust, findings: list[Finding]) -> tuple[bool, float]:
        score = self.aggregate(findings)
        return score >= self.threshold(trust), score
