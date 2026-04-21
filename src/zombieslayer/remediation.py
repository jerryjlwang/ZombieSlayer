from __future__ import annotations

from dataclasses import dataclass

from zombieslayer.types import (
    QuarantineRecord,
    ReviewAction,
    RiskCategory,
)


@dataclass
class Recommendation:
    action: ReviewAction
    rationale: str
    confidence: float  # 0.0 - 1.0


def recommend(rec: QuarantineRecord) -> Recommendation:
    """Suggest an automatic remediation for a quarantined record (PRD §12 post-MVP).

    Heuristic: the more severe and localized the finding, the more we prefer
    reprocess-clean; uniformly hostile content should be excluded.
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
    covered = sum(end - start for (start, end) in (f.span for f in findings))
    coverage = min(covered / text_len, 1.0)

    # Persistence attacks are the PRD's highest-severity class; exclude them.
    if RiskCategory.PERSISTENCE in categories and score >= 0.7:
        return Recommendation(
            ReviewAction.EXCLUDE,
            "persistence-class attack; excluding to prevent contamination",
            0.9,
        )

    # Exfiltration payloads are almost always worth excluding.
    if RiskCategory.DATA_EXFILTRATION in categories and score >= 0.8:
        return Recommendation(
            ReviewAction.EXCLUDE,
            "data-exfiltration payload; source is likely hostile overall",
            0.85,
        )

    # Broadly hostile pages (hostile spans cover most of the text) → exclude.
    if coverage >= 0.5:
        return Recommendation(
            ReviewAction.EXCLUDE,
            f"suspicious content covers {coverage:.0%} of the item; little to salvage",
            0.75,
        )

    # Localized injections in otherwise-useful content → reprocess-clean.
    return Recommendation(
        ReviewAction.REPROCESS_CLEAN,
        f"localized injection ({coverage:.0%} of text); clean and rerun",
        0.7,
    )
