"""Stage 5 — hidden-text scan.

Two complementary cases:

1. **Low-contrast region**: per-channel histogram analysis identifies
   pixel ranges that occupy a tiny fraction of the dynamic range. Those
   regions are isolated, contrast-stretched, and OCR'd. Catches
   white-on-white and 1-pixel-font tricks.

2. **Alpha-only text**: when the alpha channel carries variation while
   the RGB layer is uniform, the alpha plane is treated as a
   single-channel image and OCR'd separately. Catches the "transparent
   text overlay" trick.

Returns `(findings, extracted_text)`. Extracted text is funnelled into
the synthesized `ContentItem` and re-scanned by the core `Detector`.
"""
from __future__ import annotations

import io

from zombieslayer.types import Finding, RiskCategory


def scan(data: bytes, run_ocr: bool = True) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    text_parts: list[str] = []

    try:
        from PIL import Image
    except ImportError:
        return findings, ""

    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            mode = im.mode
            if mode in ("RGBA", "LA"):
                rgb = im.convert("RGB")
                alpha = im.getchannel("A")
            elif mode == "P" and "transparency" in im.info:
                rgba = im.convert("RGBA")
                rgb = rgba.convert("RGB")
                alpha = rgba.getchannel("A")
            else:
                rgb = im.convert("RGB")
                alpha = None
            rgb.load()
    except Exception:
        return findings, ""

    # --- Alpha-only text: alpha varies but RGB is near-uniform. ----------
    if alpha is not None:
        a_extrema = alpha.getextrema()
        if a_extrema and (a_extrema[1] - a_extrema[0]) > 32:
            r_extrema = rgb.getchannel("R").getextrema()
            g_extrema = rgb.getchannel("G").getextrema()
            b_extrema = rgb.getchannel("B").getextrema()
            rgb_range = max(
                r_extrema[1] - r_extrema[0],
                g_extrema[1] - g_extrema[0],
                b_extrema[1] - b_extrema[0],
            )
            if rgb_range < 16:
                findings.append(Finding(
                    category=RiskCategory.STRUCTURAL_ANOMALY,
                    reason="image carries information only in the alpha channel",
                    span=(0, 0),
                    rule="alpha_only_content",
                    score=0.55,
                    kind="hidden",
                    family="structural",
                    evidence={"source_layer": "vision"},
                ))
                if run_ocr:
                    text = _ocr(alpha)
                    if text:
                        text_parts.append(text)

    # --- Low-contrast text: stretch and OCR. -----------------------------
    extrema = rgb.getextrema()
    full_range = max(hi - lo for lo, hi in extrema)
    if 1 < full_range < 32:
        # Stretch the dynamic range to maximize OCR's chances.
        try:
            from PIL import ImageOps
            stretched = ImageOps.autocontrast(rgb, cutoff=0)
        except Exception:
            stretched = rgb
        findings.append(Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=(
                f"image has near-uniform color range ({full_range}/255) — "
                f"possible hidden text"
            ),
            span=(0, 0),
            rule="low_contrast_region",
            score=0.55,
            kind="hidden",
            family="structural",
            evidence={"source_layer": "vision", "range": full_range},
        ))
        if run_ocr:
            text = _ocr(stretched)
            if text:
                text_parts.append(text)

    return findings, "\n".join(text_parts).strip()


def _ocr(image) -> str:
    """Best-effort OCR. Returns "" if Tesseract is unavailable."""
    try:
        import pytesseract
    except ImportError:
        return ""
    try:
        return pytesseract.image_to_string(image).strip()
    except Exception:
        return ""
