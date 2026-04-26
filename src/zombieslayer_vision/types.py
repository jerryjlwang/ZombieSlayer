"""Data types for the vision layer.

Mirrors `zombieslayer.types.ContentItem` / `ScanResult` for binary content,
but lives in a sibling package so the core stays stdlib-only.
"""
from __future__ import annotations

import enum
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any

from zombieslayer.types import ContentItem, Finding, ScanResult, SourceTrust


class ImageFormat(str, enum.Enum):
    PNG = "png"
    JPEG = "jpeg"
    GIF = "gif"
    BMP = "bmp"
    TIFF = "tiff"
    WEBP = "webp"
    UNKNOWN = "unknown"


@dataclass
class ImageItem:
    """A single image intercepted at intake — the binary analogue of ContentItem."""

    data: bytes
    source: str
    trust: SourceTrust = SourceTrust.UNTRUSTED
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def size_bytes(self) -> int:
        return len(self.data)


@dataclass
class SanitizationAction:
    """One action taken by the sanitizer on an image. Audit-friendly."""

    name: str
    detail: str = ""
    bytes_removed: int = 0


@dataclass
class ImageScanResult:
    """Result of scanning one image. Parallels ScanResult."""

    item: ImageItem
    findings: list[Finding]
    score: float
    quarantined: bool
    sanitized_bytes: bytes
    sanitization_actions: list[SanitizationAction] = field(default_factory=list)
    extracted_text: str = ""
    synthesized_item: ContentItem | None = None
    cache_hit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item.id,
            "source": self.item.source,
            "trust": self.item.trust.value,
            "sha256": self.item.sha256,
            "size_bytes": self.item.size_bytes,
            "score": self.score,
            "quarantined": self.quarantined,
            "findings": [f.to_dict() for f in self.findings],
            "sanitization_actions": [
                {"name": a.name, "detail": a.detail, "bytes_removed": a.bytes_removed}
                for a in self.sanitization_actions
            ],
            "extracted_text_snippet": self.extracted_text[:200],
            "cache_hit": self.cache_hit,
        }

    def core_result(self) -> ScanResult | None:
        """Return the ScanResult of the synthesized text item, if any."""
        if self.synthesized_item is None:
            return None
        return ScanResult(
            item=self.synthesized_item,
            findings=self.findings,
            score=self.score,
            quarantined=self.quarantined,
        )
