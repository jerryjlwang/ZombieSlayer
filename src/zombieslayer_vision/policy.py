"""Vision-layer policy extension.

Wraps the core `Policy` and adds vision-specific knobs that don't make
sense at the text layer:

  * `max_bytes`, `max_dimension`: per-image hard limits.
  * `per_stage_timeout_seconds`: SIGALRM-style timeout for each stage.
  * `per_image_budget_seconds`: total budget for one image's pipeline.
  * `early_exit_score`: if any single finding crosses this, the
    remaining stages are skipped.
  * `vision_api_unavailable_action`: "quarantine" or "allow".
  * `disabled_vision_rules`: per-rule disable list (mirrors
    `AdminPolicy.disabled_rules`).
  * `auto_substitute_sanitized`: when true, hooks pass the sanitized
    bytes through instead of denying. Off by default — transparency wins.

All knobs have safe defaults; in particular FAST mode degrades to the
text-layer behaviour we already had.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from zombieslayer.policy import Policy
from zombieslayer.types import ScanMode, SourceTrust


@dataclass
class VisionPolicy:
    core: Policy = field(default_factory=Policy)

    # Hard limits.
    max_bytes: int = 16 * 1024 * 1024          # 16 MiB
    max_dimension: int = 8192                  # max width or height
    per_stage_timeout_seconds: float = 8.0
    per_image_budget_seconds: float = 30.0

    # Early-exit: skip remaining stages if any finding score >= this.
    early_exit_score: float = 0.95

    # Vision-API outage behaviour.
    vision_api_unavailable_action: str = "quarantine"  # "quarantine" | "allow"

    # Per-rule disable list (mirrors core AdminPolicy.disabled_rules).
    disabled_vision_rules: set[str] = field(default_factory=set)

    # Hook behaviour.
    auto_substitute_sanitized: bool = False

    # Per-batch limit (applied by the orchestrator's scan_batch helper).
    max_images_per_batch: int = 64

    def threshold(self, trust: SourceTrust) -> float:
        return self.core.threshold(trust)

    @property
    def mode(self) -> ScanMode:
        return self.core.mode
