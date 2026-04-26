"""Stage 2 / 4 — steganography detection.

Two cheap, complementary signals:

* `lsb_chi_square`: chi-square of the LSB plane distribution. Random LSBs
  (the signature of LSB stego) sit very close to a 50/50 split; natural
  images deviate. We invert the test — a *low* chi-square is suspicious.
* `jpeg_dct_diff`: re-encode JPEGs at quality 75 and measure pixel
  divergence from the original. F5/JSteg-style frequency-domain hiding
  inflates this value.

Both functions return `list[Finding]` — sanitization (LSB zeroing,
recompression) lives in `sanitizer.py`.
"""
from __future__ import annotations

import io

from zombieslayer.types import Finding, RiskCategory

from zombieslayer_vision.types import ImageFormat


def lsb_chi_square(data: bytes) -> list[Finding]:
    try:
        from PIL import Image
    except ImportError:
        return []
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            if im.mode not in ("RGB", "RGBA", "L"):
                im = im.convert("RGB")
            pixels = im.tobytes()
    except Exception:
        return []

    if len(pixels) < 1024:
        return []

    # Sample a stride to bound cost on large images.
    stride = max(1, len(pixels) // 65536)
    sample = pixels[::stride]
    n = len(sample)
    ones = sum(1 for b in sample if b & 1)
    zeros = n - ones
    expected = n / 2
    chi = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected

    # Empirical thresholds. Natural photos have chi >> 5; LSB-stego sits
    # in [0, ~3]. We flag anything below 2.0 as suspicious.
    if chi >= 2.0:
        return []
    score = max(0.55, min(0.9, 0.9 - chi * 0.15))
    return [Finding(
        category=RiskCategory.STRUCTURAL_ANOMALY,
        reason=(
            f"LSB chi-square test {chi:.2f} indicates possible least-significant-bit "
            f"steganography (expected >2.0 for natural images)"
        ),
        span=(0, 0),
        rule="lsb_steganography_suspected",
        score=score,
        kind="hidden",
        family="structural",
        evidence={
            "source_layer": "vision",
            "chi_square": round(chi, 4),
            "samples": n,
        },
    )]


def jpeg_dct_diff(data: bytes, fmt: ImageFormat) -> list[Finding]:
    if fmt is not ImageFormat.JPEG:
        return []
    try:
        from PIL import Image
    except ImportError:
        return []
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            if im.mode != "RGB":
                im = im.convert("RGB")
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=75)
            buf.seek(0)
            with Image.open(buf) as recompressed:
                recompressed.load()
                a = im.tobytes()
                b = recompressed.tobytes()
    except Exception:
        return []

    n = min(len(a), len(b))
    if n == 0:
        return []
    # Mean absolute difference per byte.
    total = 0
    stride = max(1, n // 65536)
    samples = 0
    for i in range(0, n, stride):
        total += abs(a[i] - b[i])
        samples += 1
    mean_diff = total / samples
    # Natural recompression at q75 typically gives mean diff < 5 on q≥85
    # source images. A larger diff hints at high-frequency hidden data.
    if mean_diff < 8.0:
        return []
    score = min(0.7, 0.3 + mean_diff / 100.0)
    return [Finding(
        category=RiskCategory.STRUCTURAL_ANOMALY,
        reason=(
            f"JPEG DCT recompression diff {mean_diff:.1f} suggests possible "
            f"frequency-domain steganography"
        ),
        span=(0, 0),
        rule="jpeg_dct_anomaly",
        score=score,
        kind="hidden",
        family="structural",
        evidence={
            "source_layer": "vision",
            "mean_diff": round(mean_diff, 3),
        },
    )]
