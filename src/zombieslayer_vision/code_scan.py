"""Stage 6 — decode QR codes and 1D barcodes embedded in the image.

Wraps `pyzbar` (which in turn wraps libzbar). When libzbar is not
available, this stage degrades to a no-op rather than failing the scan.

Returns `(findings, decoded_payloads)`. Decoded payloads feed the
synthesized text item so the core `Detector`'s URL-side-channel and
override rules apply automatically.
"""
from __future__ import annotations

import io

from zombieslayer.types import Finding, RiskCategory


def scan(data: bytes) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    payloads: list[str] = []

    try:
        from pyzbar import pyzbar
    except Exception:
        return findings, payloads

    try:
        from PIL import Image
    except ImportError:
        return findings, payloads

    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            results = pyzbar.decode(im)
    except Exception:
        return findings, payloads

    for r in results:
        try:
            payload = r.data.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        if not payload:
            continue
        payloads.append(payload)
        findings.append(Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=(
                f"image contains a {r.type} payload "
                f"({len(payload)} chars) — content fed into core text scan"
            ),
            span=(0, 0),
            rule="image_code_payload",
            score=0.4,
            kind="hidden",
            family="structural",
            evidence={
                "source_layer": "vision",
                "code_type": r.type,
                "payload_length": len(payload),
            },
        ))
    return findings, payloads
