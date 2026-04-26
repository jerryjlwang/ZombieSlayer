"""Result cache keyed by SHA-256 of the original image bytes.

Backend is swappable, mirroring `QuarantineStore`. The default in-memory
backend is fine for a single session; integrators can plug in a durable
store by subclassing `ImageResultCache`.
"""
from __future__ import annotations

from typing import Protocol

from zombieslayer_vision.types import ImageScanResult


class ImageResultCache(Protocol):
    def get(self, sha256: str) -> ImageScanResult | None: ...
    def put(self, sha256: str, result: ImageScanResult) -> None: ...


class InMemoryImageResultCache:
    def __init__(self) -> None:
        self._data: dict[str, ImageScanResult] = {}

    def get(self, sha256: str) -> ImageScanResult | None:
        return self._data.get(sha256)

    def put(self, sha256: str, result: ImageScanResult) -> None:
        self._data[sha256] = result

    def __len__(self) -> int:
        return len(self._data)
