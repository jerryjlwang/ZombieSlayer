"""Issue #6 §8 — adversarial regression coverage.

Asserts specific seed × transform combos that the detector currently handles.
The full harness lives in scripts/adversarial_selftest.py and surfaces
weaker gaps as informational output. This test is the load-bearing subset:
if any of these stops detecting, something regressed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "scripts"))

from adversarial_selftest import (  # noqa: E402
    SEEDS,
    TRANSFORMS,
    evaluate,
)


def _outcome_for(seed_idx: int, transform: str):
    transforms = [(name, fn) for name, fn in TRANSFORMS if name == transform]
    return evaluate([SEEDS[seed_idx]], transforms)[0]


# (seed_idx, transform_name) — must all be quarantined.
_REGRESSION_GUARDS = [
    # All seeds are caught in plain form.
    *[(i, "plain") for i in range(len(SEEDS))],
    # Base64 wrapping decodes & re-fires.
    (0, "base64"),
    (1, "base64"),
    (5, "base64"),
    # Percent-encoding (full byte encode) decodes & re-fires.
    (0, "percent_encoded"),
    (1, "percent_encoded"),
    # Zero-width insertion is caught by the structural rule.
    (0, "zero_width"),
    (1, "zero_width"),
    # Casing shuffle — re.IGNORECASE rules survive.
    (0, "casing_shuffle"),
    (1, "casing_shuffle"),
    # HTML entities decode at whole-text granularity.
    (0, "html_entities"),
    (1, "html_entities"),
    # Unicode escape sequences also decode.
    (0, "unicode_escapes"),
    (1, "unicode_escapes"),
    # Leetspeak normalization fires for ignore/disregard families.
    (0, "leetspeak"),
    (1, "leetspeak"),
]


@pytest.mark.parametrize("seed_idx,transform", _REGRESSION_GUARDS)
def test_seed_quarantined_under_transform(seed_idx: int, transform: str):
    outcome = _outcome_for(seed_idx, transform)
    assert outcome.quarantined, (
        f"seed[{seed_idx}] under {transform} no longer quarantines — "
        f"score={outcome.score:.3f} threshold={outcome.threshold:.3f}"
    )


def test_harness_main_reports_no_regressions():
    """Calling the harness as a script must exit 0 — i.e., all plain-form
    seeds are still caught. Variant misses are tolerated."""
    from adversarial_selftest import main

    # main() writes a report file; redirect to tmp.
    import os
    cwd = os.getcwd()
    try:
        os.chdir(_REPO)
        sys.argv = ["adversarial_selftest", "--quick", "--report", "/tmp/_adv_test.md"]
        rc = main()
    finally:
        os.chdir(cwd)
    assert rc == 0
