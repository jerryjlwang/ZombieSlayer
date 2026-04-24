"""Precision/recall floor for the attack bench corpus (issue #2 §10).

Fails if the detector regresses below a minimum recall on known attacks or
drops below a minimum precision on benign content. Meant as a guardrail, not
a research benchmark — thresholds are tuned to where the engine stands today.
"""

from __future__ import annotations

from zombieslayer import ContentItem, ZombieSlayer

from .corpus import BENIGN, HOSTILE


def _run() -> tuple[dict[str, bool], dict[str, bool]]:
    zs = ZombieSlayer()
    hostile_items = [
        ContentItem(text=text, source=f"hostile://{name}", trust=trust)
        for name, text, trust in HOSTILE
    ]
    benign_items = [
        ContentItem(text=text, source=f"benign://{name}", trust=trust)
        for name, text, trust in BENIGN
    ]
    _, qh = zs.scan_intake(hostile_items)
    sb, _ = zs.scan_intake(benign_items)

    hostile_quarantined = {r.item.source.split("//", 1)[1]: True for r in qh}
    hostile_all = {name: hostile_quarantined.get(name, False) for name, *_ in HOSTILE}
    benign_ok = {r.item.source.split("//", 1)[1]: True for r in sb}
    benign_all = {name: benign_ok.get(name, False) for name, *_ in BENIGN}
    return hostile_all, benign_all


def test_recall_floor():
    hostile, _benign = _run()
    recall = sum(1 for v in hostile.values() if v) / len(hostile)
    missed = [k for k, v in hostile.items() if not v]
    # Baseline measured while writing this test — raise over time, never lower.
    assert recall >= 0.85, f"recall dropped to {recall:.2f}; missed={missed}"


def test_benign_precision_floor():
    _hostile, benign = _run()
    precision = sum(1 for v in benign.values() if v) / len(benign)
    false_positives = [k for k, v in benign.items() if not v]
    assert precision >= 0.85, (
        f"benign precision dropped to {precision:.2f}; "
        f"false positives={false_positives}"
    )


def test_print_bench_summary(capsys):
    hostile, benign = _run()
    recall = sum(1 for v in hostile.values() if v) / len(hostile)
    precision = sum(1 for v in benign.values() if v) / len(benign)
    print(f"\nZombieSlayer bench: recall={recall:.2%}, benign-precision={precision:.2%}")
    print("  hostile misses:", [k for k, v in hostile.items() if not v])
    print("  benign false positives:", [k for k, v in benign.items() if not v])
    out = capsys.readouterr().out
    assert "bench" in out
