"""Sanitizer — always-on cleanup of an image's bytes.

Operations (PRD §"Sanitization"):
  * strip all metadata
  * zero least-significant bits of every pixel channel
  * recompress (JPEG q85 / PNG lossless)
  * truncate trailing-byte payloads at the image-format end marker
  * (in STRICT mode) slight downsample as adversarial mitigation

Returns `(sanitized_bytes, [SanitizationAction])`. The action list goes
straight into the audit log so reviewers can see what was modified.
"""
from __future__ import annotations

import io

from zombieslayer_vision.format_detect import find_eof_offset
from zombieslayer_vision.types import ImageFormat, SanitizationAction


def sanitize(
    data: bytes,
    fmt: ImageFormat,
    strict: bool = False,
) -> tuple[bytes, list[SanitizationAction]]:
    actions: list[SanitizationAction] = []

    # 1. Truncate any trailing bytes after the format's EOF marker.
    end = find_eof_offset(data, fmt)
    if end is not None and end < len(data):
        removed = len(data) - end
        data = data[:end]
        actions.append(SanitizationAction(
            name="truncate_trailing_bytes",
            detail=f"removed {removed} bytes after {fmt.value.upper()} EOF marker",
            bytes_removed=removed,
        ))

    # 2. Pillow-based: re-decode, zero LSBs, drop metadata, recompress.
    try:
        from PIL import Image
    except ImportError:
        return data, actions

    try:
        im = Image.open(io.BytesIO(data))
        im.load()
    except Exception:
        return data, actions

    original_size_bytes = len(data)
    metadata_count = len(im.info or {})

    # Zero LSBs across all channels (lossless on RGB / RGBA / L / P).
    if im.mode not in ("RGB", "RGBA", "L"):
        im = im.convert("RGBA" if "A" in im.mode else "RGB")

    width, height = im.size
    pixels = bytearray(im.tobytes())
    for i in range(len(pixels)):
        pixels[i] &= 0xFE
    cleaned = Image.frombytes(im.mode, (width, height), bytes(pixels))
    actions.append(SanitizationAction(
        name="zero_lsbs",
        detail=f"zeroed LSBs across {len(im.getbands())} channel(s)",
    ))

    # Optional downsample for STRICT-mode adversarial mitigation.
    if strict and (width > 64 and height > 64):
        new_size = (max(1, int(width * 0.95)), max(1, int(height * 0.95)))
        cleaned = cleaned.resize(new_size, Image.LANCZOS)
        actions.append(SanitizationAction(
            name="downsample",
            detail=f"resized {width}x{height} -> {new_size[0]}x{new_size[1]}",
        ))

    # Recompress with metadata stripped.
    out = io.BytesIO()
    if fmt is ImageFormat.JPEG:
        if cleaned.mode != "RGB":
            cleaned = cleaned.convert("RGB")
        cleaned.save(out, "JPEG", quality=85, optimize=True)
    elif fmt is ImageFormat.PNG:
        cleaned.save(out, "PNG", optimize=True)
    elif fmt is ImageFormat.GIF:
        cleaned.save(out, "GIF")
    elif fmt is ImageFormat.WEBP:
        cleaned.save(out, "WEBP", quality=85)
    elif fmt is ImageFormat.BMP:
        cleaned.save(out, "BMP")
    elif fmt is ImageFormat.TIFF:
        cleaned.save(out, "TIFF")
    else:
        cleaned.save(out, "PNG")

    if metadata_count:
        actions.append(SanitizationAction(
            name="strip_metadata",
            detail=f"dropped {metadata_count} metadata field(s)",
        ))

    sanitized = out.getvalue()
    actions.append(SanitizationAction(
        name="recompress",
        detail=f"re-encoded {fmt.value} ({original_size_bytes} -> {len(sanitized)} bytes)",
    ))
    return sanitized, actions
