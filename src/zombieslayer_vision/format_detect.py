"""Stage 0 — image-format detection and polyglot sniff.

Pure function over bytes:

    detect(data) -> (ImageFormat, list[Finding])

Findings emitted here cover:
  * `polyglot_trailing_bytes` — extra payload appended after the image's
    end-of-file marker. Specifically detects ZIP central directories,
    HTML/script tags, PE/ELF headers, and any large unexplained tail.
  * `unsupported_format` — magic bytes don't match a supported format.
"""
from __future__ import annotations

from typing import Any

from zombieslayer.types import Finding, RiskCategory

from zombieslayer_vision.types import ImageFormat


# Magic bytes for the formats we can parse.
_MAGIC: tuple[tuple[bytes, ImageFormat], ...] = (
    (b"\x89PNG\r\n\x1a\n", ImageFormat.PNG),
    (b"\xff\xd8\xff", ImageFormat.JPEG),
    (b"GIF87a", ImageFormat.GIF),
    (b"GIF89a", ImageFormat.GIF),
    (b"BM", ImageFormat.BMP),
    (b"II*\x00", ImageFormat.TIFF),
    (b"MM\x00*", ImageFormat.TIFF),
)


# Unsupported but recognizable formats — flagged as `unsupported_format`.
_UNSUPPORTED: tuple[tuple[bytes, str], ...] = (
    (b"ftypheic", "HEIC"),
    (b"ftypheix", "HEIC"),
    (b"ftyphevc", "HEIC"),
    (b"ftypmif1", "HEIF"),
    (b"ftypavif", "AVIF"),
    (b"ftypavis", "AVIF sequence"),
)


# Suspicious payload signatures that should not appear after image EOF.
_TRAILING_SIGS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "ZIP local file header"),
    (b"PK\x05\x06", "ZIP end-of-central-directory"),
    (b"<script", "HTML <script> tag"),
    (b"<html", "HTML document"),
    (b"<?php", "PHP open tag"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ\x90\x00", "PE/MZ executable"),
    (b"#!/usr/bin", "shell script"),
)


def detect(data: bytes) -> tuple[ImageFormat, list[Finding]]:
    findings: list[Finding] = []
    fmt = _sniff_magic(data)
    if fmt is ImageFormat.UNKNOWN:
        # Try to name an unsupported-but-known format for a better message.
        for sig, label in _UNSUPPORTED:
            if sig in data[:64]:
                findings.append(Finding(
                    category=RiskCategory.STRUCTURAL_ANOMALY,
                    reason=f"{label} format is not supported by the vision scanner",
                    span=(0, 0),
                    rule="unsupported_format",
                    score=0.65,
                    kind="hidden",
                    family="structural",
                    evidence={"source_layer": "vision", "format": label},
                ))
                return fmt, findings
        findings.append(Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason="image format could not be identified from magic bytes",
            span=(0, 0),
            rule="unsupported_format",
            score=0.7,
            kind="hidden",
            family="structural",
            evidence={"source_layer": "vision"},
        ))
        return fmt, findings

    # Trailing-byte sniff: locate the format's EOF marker and inspect what
    # comes after.
    end_offset = _find_eof_offset(data, fmt)
    if end_offset is not None and end_offset < len(data):
        trailing = data[end_offset:]
        # Tolerate a tiny amount of padding (e.g. spec-compliant XMP packets).
        if len(trailing) > 8:
            label = _classify_trailing(trailing)
            findings.append(Finding(
                category=RiskCategory.STRUCTURAL_ANOMALY,
                reason=(
                    f"polyglot file: {len(trailing)} bytes appended after "
                    f"{fmt.value.upper()} end-of-image marker"
                    + (f" ({label})" if label else "")
                ),
                span=(0, 0),
                rule="polyglot_trailing_bytes",
                score=0.85 if label else 0.55,
                kind="hidden",
                family="structural",
                evidence={
                    "source_layer": "vision",
                    "format": fmt.value,
                    "trailing_bytes": len(trailing),
                    "classification": label or "unknown",
                },
            ))
    return fmt, findings


def _sniff_magic(data: bytes) -> ImageFormat:
    head = data[:16]
    for sig, fmt in _MAGIC:
        if head.startswith(sig):
            return fmt
    # WebP: RIFF....WEBP
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ImageFormat.WEBP
    return ImageFormat.UNKNOWN


def find_eof_offset(data: bytes, fmt: ImageFormat) -> int | None:
    """Public alias used by the sanitizer to know where to truncate."""
    return _find_eof_offset(data, fmt)


def _find_eof_offset(data: bytes, fmt: ImageFormat) -> int | None:
    if fmt is ImageFormat.JPEG:
        # JPEG ends at the first 0xFFD9 marker after the SOI.
        idx = data.rfind(b"\xff\xd9")
        return idx + 2 if idx >= 0 else None
    if fmt is ImageFormat.PNG:
        # PNG IEND chunk: 0x49454e44, then 4-byte CRC. Locate IEND, add 8
        # (length(0) was 4 bytes before IEND, but rfind on IEND + 8 is safer).
        idx = data.rfind(b"IEND")
        if idx < 0:
            return None
        # IEND chunk layout: 4-byte length (== 0) + b"IEND" + 4-byte CRC
        return idx + 8
    if fmt is ImageFormat.GIF:
        # GIF terminator is 0x3B (";").
        idx = data.rfind(b"\x3b")
        return idx + 1 if idx >= 0 else None
    if fmt is ImageFormat.BMP:
        # BMP file size lives at offset 2..6 (little-endian uint32).
        if len(data) >= 6:
            size = int.from_bytes(data[2:6], "little")
            if 0 < size <= len(data):
                return size
        return None
    # WEBP / TIFF: leave EOF detection to Pillow's recompression for now.
    return None


def _classify_trailing(trailing: bytes) -> str | None:
    head = trailing[:64].lower()
    for sig, label in _TRAILING_SIGS:
        if sig.lower() in head:
            return label
    if any(b > 127 for b in trailing[:32]) and len(trailing) > 4096:
        return "large binary tail"
    return None


def to_evidence(fmt: ImageFormat) -> dict[str, Any]:
    return {"source_layer": "vision", "format": fmt.value}
