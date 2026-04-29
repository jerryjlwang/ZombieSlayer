from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from zombieslayer.types import Finding, ScanMode, SourceTrust


@dataclass
class Policy:
    """Source-aware thresholds and mode selection.

    The aggregate score is computed as `1 - Π(1 - f.score)` across findings,
    so multiple weaker signals compound. Quarantine fires when the aggregate
    exceeds the per-(trust, mode) threshold.
    """

    thresholds: dict[tuple[SourceTrust, ScanMode], float] = field(
        default_factory=lambda: {
            (SourceTrust.UNTRUSTED, ScanMode.STRICT): 0.35,
            (SourceTrust.UNTRUSTED, ScanMode.FAST): 0.55,
            (SourceTrust.RETRIEVAL, ScanMode.STRICT): 0.45,
            (SourceTrust.RETRIEVAL, ScanMode.FAST): 0.65,
            (SourceTrust.DEVELOPER, ScanMode.STRICT): 0.7,
            (SourceTrust.DEVELOPER, ScanMode.FAST): 0.85,
            (SourceTrust.USER, ScanMode.STRICT): 0.8,
            (SourceTrust.USER, ScanMode.FAST): 0.9,
        }
    )
    mode: ScanMode = ScanMode.STRICT

    def aggregate(self, findings: list[Finding]) -> float:
        prod = 1.0
        for f in findings:
            prod *= 1.0 - max(0.0, min(1.0, f.score))
        return 1.0 - prod

    def threshold(self, trust: SourceTrust) -> float:
        key = (trust, self.mode)
        if key not in self.thresholds:
            warnings.warn(
                f"no threshold configured for ({trust.value}, {self.mode.value}); "
                "falling back to 0.5. Update Policy.thresholds when adding a new "
                "SourceTrust or ScanMode.",
                RuntimeWarning,
                stacklevel=2,
            )
            return 0.5
        return self.thresholds[key]

    def should_quarantine(self, trust: SourceTrust, findings: list[Finding]) -> tuple[bool, float]:
        score = self.aggregate(findings)
        return score >= self.threshold(trust), score
