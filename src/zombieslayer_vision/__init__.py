"""ZombieSlayer Vision — image-borne prompt-injection defenses.

Sibling package to `zombieslayer`. The core text engine is unmodified
and remains stdlib-only; this package adds an image-scanning layer that
funnels image-derived text through the existing core `Detector`.

Optional install: `pip install zombieslayer[vision]`.
"""
from zombieslayer_vision.cache import ImageResultCache, InMemoryImageResultCache
from zombieslayer_vision.extractor import VisionClient, VisionUnavailableError
from zombieslayer_vision.policy import VisionPolicy
from zombieslayer_vision.scanner import VisionScanner, make_image_item
from zombieslayer_vision.types import (
    ImageFormat,
    ImageItem,
    ImageScanResult,
    SanitizationAction,
)

__all__ = [
    "ImageFormat",
    "ImageItem",
    "ImageResultCache",
    "ImageScanResult",
    "InMemoryImageResultCache",
    "SanitizationAction",
    "VisionClient",
    "VisionPolicy",
    "VisionScanner",
    "VisionUnavailableError",
    "make_image_item",
]
