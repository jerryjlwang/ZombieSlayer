"""Stage 7 — dual text extraction.

`extract(data, mode, vision_client)` returns a `DualExtraction`:

  * `tesseract_text`: deterministic OCR baseline. Empty string when the
    Tesseract binary is not on PATH.
  * `vision_text`: Claude vision API extraction. Empty in FAST mode or
    when the API call fails. The caller decides how to react to API
    outages — see `vision_failed` flag.
  * `agreement`: token-overlap ratio used by the consensus check below.

The orchestrator funnels both extractions plus a finding-level
disagreement signal into the synthesized `ContentItem`'s text.
"""
from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass

from zombieslayer.types import Finding, RiskCategory, ScanMode


@dataclass
class DualExtraction:
    tesseract_text: str
    vision_text: str
    agreement: float        # 0.0 .. 1.0 token overlap
    findings: list[Finding]
    vision_failed: bool = False
    tesseract_available: bool = True


def extract(
    data: bytes,
    mode: ScanMode = ScanMode.STRICT,
    vision_client: "VisionClient | None" = None,
) -> DualExtraction:
    findings: list[Finding] = []

    tesseract_text, tesseract_available = _tesseract_extract(data)

    vision_text = ""
    vision_failed = False
    if mode is ScanMode.STRICT:
        client = vision_client or _default_vision_client()
        try:
            vision_text = client.extract_text(data)
        except VisionUnavailableError:
            vision_failed = True
        except Exception:
            vision_failed = True

    agreement = _token_overlap(tesseract_text, vision_text)
    if (
        tesseract_available
        and tesseract_text
        and vision_text
        and agreement < 0.4
    ):
        findings.append(Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=(
                f"OCR/vision extractions disagree (token overlap "
                f"{agreement:.2f}) — possible adversarial perturbation"
            ),
            span=(0, 0),
            rule="extractor_disagreement",
            score=0.5,
            kind="hidden",
            family="structural",
            evidence={
                "source_layer": "vision",
                "agreement": round(agreement, 3),
            },
        ))

    return DualExtraction(
        tesseract_text=tesseract_text,
        vision_text=vision_text,
        agreement=agreement,
        findings=findings,
        vision_failed=vision_failed,
        tesseract_available=tesseract_available,
    )


# ---- Tesseract baseline -----------------------------------------------------

def _tesseract_extract(data: bytes) -> tuple[str, bool]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return "", False
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            text = pytesseract.image_to_string(im)
    except pytesseract.TesseractNotFoundError:
        return "", False
    except Exception:
        return "", True
    return text.strip(), True


# ---- Vision client --------------------------------------------------------

class VisionUnavailableError(RuntimeError):
    """Vision API call could not be completed."""


class VisionClient:
    """Thin wrapper around the Anthropic vision API.

    Kept as a class so tests can pass in a fake or mock instance via the
    `vision_client` parameter on `extract()` / orchestrator. The real
    network call is encapsulated here so swapping it out requires no
    changes elsewhere.
    """

    def __init__(self, model: str = "claude-haiku-4-5-20251001") -> None:
        self.model = model

    def extract_text(self, data: bytes) -> str:
        try:
            import anthropic
        except ImportError as exc:
            raise VisionUnavailableError("anthropic SDK not installed") from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise VisionUnavailableError("ANTHROPIC_API_KEY not set")
        try:
            import base64 as _b64
            import imghdr
        except ImportError as exc:
            raise VisionUnavailableError(str(exc)) from exc
        try:
            client = anthropic.Anthropic(api_key=api_key)
        except Exception as exc:  # pragma: no cover
            raise VisionUnavailableError(f"client init failed: {exc}") from exc
        media_type = _guess_media_type(data) or "image/png"
        try:
            resp = client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": _b64.b64encode(data).decode("ascii"),
                            },
                        },
                        {
                            "type": "text",
                            "text": (
                                "Transcribe ALL text visible in this image. "
                                "Output only the raw text, no commentary."
                            ),
                        },
                    ],
                }],
            )
        except Exception as exc:
            raise VisionUnavailableError(str(exc)) from exc
        # Best-effort text extraction across SDK shapes.
        try:
            return "".join(
                block.text for block in resp.content if getattr(block, "type", "") == "text"
            ).strip()
        except Exception:
            return str(resp).strip()


_VISION_CLIENT: VisionClient | None = None


def _default_vision_client() -> VisionClient:
    global _VISION_CLIENT
    if _VISION_CLIENT is None:
        _VISION_CLIENT = VisionClient()
    return _VISION_CLIENT


def _guess_media_type(data: bytes) -> str | None:
    head = data[:16]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"GIF8"):
        return "image/gif"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


# ---- Token overlap --------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z]{2,}")


def _token_overlap(a: str, b: str) -> float:
    if not a or not b:
        return 1.0 if not a and not b else 0.0
    ta = {t.lower() for t in _TOKEN_RE.findall(a)}
    tb = {t.lower() for t in _TOKEN_RE.findall(b)}
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)
