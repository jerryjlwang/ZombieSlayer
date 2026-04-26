"""Stage 8 — adversarial divergence check.

Run the Claude vision API again on a transformed copy of the input
(random crop, JPEG-quality recompression, slight downsample). If the
two extractions disagree significantly, the image's behaviour depends
on small pixel-level details — the signature of an adversarial
perturbation crafted for one specific decoder.
"""
from __future__ import annotations

import io
import random

from zombieslayer.types import Finding, RiskCategory

from zombieslayer_vision.extractor import VisionClient, VisionUnavailableError, _token_overlap


def divergence_check(
    data: bytes,
    baseline_text: str,
    vision_client: VisionClient | None = None,
    seed: int = 17,
) -> list[Finding]:
    """Return a divergence finding when the transformed extraction diverges.

    No-op if the vision client is unavailable or baseline_text is empty —
    we have nothing to compare against in that case.
    """
    if not baseline_text:
        return []
    transformed = _transform(data, seed)
    if transformed is None:
        return []
    client = vision_client or VisionClient()
    try:
        rerun = client.extract_text(transformed)
    except VisionUnavailableError:
        return []
    except Exception:
        return []

    overlap = _token_overlap(baseline_text, rerun)
    if overlap >= 0.6:
        return []
    score = max(0.55, min(0.85, 0.85 - overlap))
    return [Finding(
        category=RiskCategory.STRUCTURAL_ANOMALY,
        reason=(
            f"vision-extraction diverges across input transforms "
            f"(token overlap {overlap:.2f}) — possible adversarial "
            f"perturbation"
        ),
        span=(0, 0),
        rule="adversarial_divergence",
        score=score,
        kind="hidden",
        family="structural",
        evidence={
            "source_layer": "vision",
            "agreement": round(overlap, 3),
        },
    )]


def _transform(data: bytes, seed: int) -> bytes | None:
    """Apply random crop + recompression + downsample. None on failure."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            if im.mode != "RGB":
                im = im.convert("RGB")
            w, h = im.size
            rng = random.Random(seed)
            crop_w = max(8, int(w * 0.95))
            crop_h = max(8, int(h * 0.95))
            x = rng.randint(0, w - crop_w) if w > crop_w else 0
            y = rng.randint(0, h - crop_h) if h > crop_h else 0
            cropped = im.crop((x, y, x + crop_w, y + crop_h))
            new_size = (max(8, int(crop_w * 0.9)), max(8, int(crop_h * 0.9)))
            resized = cropped.resize(new_size, Image.LANCZOS)
            buf = io.BytesIO()
            resized.save(buf, "JPEG", quality=80)
            return buf.getvalue()
    except Exception:
        return None
