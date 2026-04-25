"""Issue #6 §8 — ensemble voting across signal families."""

from __future__ import annotations

from zombieslayer.policy import EnsembleConfig, Policy
from zombieslayer.types import Finding, RiskCategory


def _f(score: float, family: str = "rules", rule: str = "test") -> Finding:
    return Finding(
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        reason="t",
        span=(0, 0),
        rule=rule,
        score=score,
        family=family,
    )


def test_legacy_aggregation_when_ensemble_disabled():
    p = Policy()  # ensemble.weights empty by default → product aggregation
    findings = [_f(0.4, "rules", "a"), _f(0.5, "structural", "b")]
    # 1 - (1-0.4)(1-0.5) = 1 - 0.30 = 0.70
    assert abs(p.aggregate(findings) - 0.70) < 1e-9


def test_weighted_family_vote_combines_per_family_products():
    p = Policy(ensemble=EnsembleConfig(weights={"rules": 0.5, "structural": 0.5}))
    findings = [
        _f(0.4, "rules", "a"),
        _f(0.4, "rules", "b"),
        _f(0.5, "structural", "c"),
    ]
    # rules family: 1 - (0.6)(0.6) = 0.64
    # structural family: 0.5
    # weighted: 0.5*0.64 + 0.5*0.5 = 0.57
    assert abs(p.aggregate(findings) - 0.57) < 1e-6


def test_weight_zero_silences_family():
    p = Policy(ensemble=EnsembleConfig(weights={"rules": 1.0, "intent": 0.0}))
    findings = [_f(0.3, "rules", "a"), _f(0.95, "intent", "i")]
    # only rules family contributes; intent's 0.95 is silenced
    assert abs(p.aggregate(findings) - 0.3) < 1e-9


def test_intent_dominant_can_quarantine_alone():
    p = Policy(ensemble=EnsembleConfig.with_defaults())
    findings = [_f(0.95, "intent", "intent_verifier")]
    # default intent weight = 0.2; aggregate = 0.2 * 0.95 = 0.19
    # Below the UNTRUSTED/STRICT threshold (0.35) — design choice: intent
    # alone shouldn't trip; it's an ensemble member, not a sole oracle.
    score = p.aggregate(findings)
    assert abs(score - 0.19) < 1e-9


def test_clamp_to_unit_interval():
    p = Policy(ensemble=EnsembleConfig(weights={"rules": 5.0}))  # absurd weight
    findings = [_f(0.9, "rules", "a")]
    assert p.aggregate(findings) == 1.0


def test_unknown_family_falls_through_to_zero_weight():
    p = Policy(ensemble=EnsembleConfig(weights={"rules": 1.0}))
    findings = [_f(0.99, "mystery", "x")]
    assert p.aggregate(findings) == 0.0


def test_default_ensemble_preserves_quarantine_for_combined_signals():
    """Rules + structural combined should still quarantine UNTRUSTED/STRICT."""
    from zombieslayer.types import ScanMode, SourceTrust

    p = Policy(mode=ScanMode.STRICT, ensemble=EnsembleConfig.with_defaults())
    findings = [
        _f(0.9, "rules", "override"),
        _f(0.7, "structural", "hidden"),
    ]
    # rules family: 0.9; structural family: 0.7
    # weighted: 0.5*0.9 + 0.2*0.7 = 0.45 + 0.14 = 0.59
    quarantine, score = p.should_quarantine(SourceTrust.UNTRUSTED, findings)
    assert score == 0.59
    assert quarantine  # 0.59 >= 0.35


def test_ensemble_findings_default_to_rules_family():
    f = Finding(
        category=RiskCategory.INSTRUCTION_OVERRIDE,
        reason="t",
        span=(0, 0),
        rule="t",
        score=0.5,
    )
    assert f.family == "rules"
