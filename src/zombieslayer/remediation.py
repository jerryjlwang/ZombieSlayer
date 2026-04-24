from __future__ import annotations

from dataclasses import dataclass

from zombieslayer.types import (
    QuarantineRecord,
    ReviewAction,
    RiskCategory,
    SourceTrust,
)


@dataclass
class Recommendation:
    action: ReviewAction
    rationale: str
    confidence: float  # 0.0 - 1.0


# Severity weights per category (issue #2 §6). Persistence/exfiltration sit
# highest because those attacks are what the project explicitly exists to
# defend against (PRD §1).
_CATEGORY_SEVERITY: dict[RiskCategory, float] = {
    RiskCategory.PERSISTENCE: 1.00,
    RiskCategory.DATA_EXFILTRATION: 0.95,
    RiskCategory.INSTRUCTION_OVERRIDE: 0.80,
    RiskCategory.UNSAFE_ACTION: 0.75,
    RiskCategory.STRUCTURAL_ANOMALY: 0.55,
}


# Trust weights: higher-trust sources get more benefit of the doubt. A USER
# item that still tripped quarantine should lean *include* more than an
# UNTRUSTED scrape that hit the same rules.
_TRUST_WEIGHT: dict[SourceTrust, float] = {
    SourceTrust.UNTRUSTED: 0.0,
    SourceTrust.RETRIEVAL: 0.1,
    SourceTrust.TOOL_OUTPUT: 0.15,
    SourceTrust.DEVELOPER: 0.5,
    SourceTrust.USER: 0.6,
}


def _severity(categories: set[RiskCategory]) -> float:
    if not categories:
        return 0.0
    return max(_CATEGORY_SEVERITY.get(c, 0.5) for c in categories)


def recommend(rec: QuarantineRecord) -> Recommendation:
    """Suggest an automatic remediation for a quarantined record.

    Severity-weighted blend (issue #2 §6):
        signal = max(category severity) * (1 - trust_weight)
        coverage = redaction span fraction
    High signal + high coverage => EXCLUDE.
    High signal + low coverage => REPROCESS_CLEAN.
    Low signal, any coverage   => INCLUDE (only if findings absent).
    """
    categories = set(rec.result.categories)
    findings = rec.result.findings
    score = rec.result.score
    item = rec.result.item

    if not findings:
        return Recommendation(
            ReviewAction.INCLUDE,
            "no active findings — safe to include",
            0.9,
        )

    text_len = max(len(item.text), 1)
    covered = sum(
        end - start for (start, end) in (f.span for f in findings) if end > start
    )
    coverage = min(covered / text_len, 1.0)

    severity = _severity(categories)
    trust_w = _TRUST_WEIGHT.get(item.trust, 0.0)
    signal = severity * (1.0 - trust_w)

    # Persistence remains the nuclear-option category: if both signal and
    # raw score are elevated, exclude regardless of coverage.
    if RiskCategory.PERSISTENCE in categories and score >= 0.7:
        return Recommendation(
            ReviewAction.EXCLUDE,
            "persistence-class attack; excluding to prevent contamination",
            min(0.9, 0.7 + 0.2 * signal),
        )

    if RiskCategory.DATA_EXFILTRATION in categories and score >= 0.8:
        return Recommendation(
            ReviewAction.EXCLUDE,
            "data-exfiltration payload; source is likely hostile overall",
            min(0.88, 0.7 + 0.2 * signal),
        )

    if coverage >= 0.5 and signal >= 0.5:
        return Recommendation(
            ReviewAction.EXCLUDE,
            (
                f"suspicious content covers {coverage:.0%} of the item "
                f"(severity {severity:.2f}, trust={item.trust.value}); "
                "little to salvage"
            ),
            min(0.85, 0.55 + 0.3 * signal),
        )

    return Recommendation(
        ReviewAction.REPROCESS_CLEAN,
        (
            f"localized injection ({coverage:.0%} of text, severity {severity:.2f}); "
            "clean and rerun"
        ),
        min(0.8, 0.4 + 0.3 * signal + 0.1 * (1 - coverage)),
    )
