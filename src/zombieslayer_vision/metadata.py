"""Stage 1 — extract every text-bearing metadata field from an image.

Returns a `dict[str, str]`. Empty values are dropped. The orchestrator wraps
this into a `ContentItem.metadata` mapping which the core `Detector` then
scans through its existing `_scan_metadata` path.

EXIF (via piexif), Pillow's `Image.info` (PNG `tEXt`/`zTXt`/`iTXt`, JPEG
markers, GIF comment, etc.), and a bare-bones XMP packet sniff are all
funnelled through one interface so callers do not need to care which
metadata flavour produced a given string.
"""
from __future__ import annotations

import io
import re
from typing import Any


def extract(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    out.update(_extract_pillow(data))
    out.update(_extract_exif(data))
    out.update(_extract_xmp(data))
    return {k: v for k, v in out.items() if isinstance(v, str) and v.strip()}


def _extract_pillow(data: bytes) -> dict[str, str]:
    try:
        from PIL import Image
    except ImportError:
        return {}
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            info: dict[str, Any] = dict(im.info or {})
    except Exception:
        return {}
    out: dict[str, str] = {}
    for k, v in info.items():
        if isinstance(v, bytes):
            try:
                v = v.decode("utf-8", errors="ignore")
            except Exception:
                continue
        if isinstance(v, str) and v.strip():
            out[f"pillow:{k}"] = v
    return out


def _extract_exif(data: bytes) -> dict[str, str]:
    try:
        import piexif
    except ImportError:
        return {}
    try:
        exif_dict = piexif.load(data)
    except Exception:
        return {}
    out: dict[str, str] = {}
    for ifd_name, ifd_data in exif_dict.items():
        if not isinstance(ifd_data, dict):
            continue
        for tag_id, value in ifd_data.items():
            try:
                tag_name = piexif.TAGS[ifd_name][tag_id]["name"]
            except (KeyError, TypeError):
                tag_name = f"tag_{tag_id}"
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="ignore")
                except Exception:
                    continue
            if isinstance(value, str) and value.strip():
                out[f"exif:{ifd_name}:{tag_name}"] = value
    return out


_XMP_RE = re.compile(rb"<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>", re.S)
_XMP_TEXT_RE = re.compile(rb">([^<>]{3,})<", re.S)


def _extract_xmp(data: bytes) -> dict[str, str]:
    """Best-effort XMP packet text extraction without an XML parser dep."""
    out: dict[str, str] = {}
    m = _XMP_RE.search(data)
    if not m:
        return out
    body = m.group(1)
    seen: set[str] = set()
    for i, snippet in enumerate(_XMP_TEXT_RE.findall(body)):
        try:
            text = snippet.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        if text and text not in seen:
            seen.add(text)
            out[f"xmp:text_{i}"] = text
    return out
