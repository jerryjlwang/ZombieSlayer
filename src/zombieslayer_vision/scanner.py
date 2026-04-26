"""VisionScanner — orchestrator for the image-scanning pipeline.

Public surface is one shallow method:

    scanner.scan(item) -> ImageScanResult

Internally it walks stages 0–8 (see PRD), enforces budgets, applies the
cache, computes aggregate score via the core `Policy.aggregate`, and
synthesizes the `ContentItem` that flows into the existing text-layer
machinery.

Sanitization runs **unconditionally** on every image. Sanitized bytes
are returned as part of the result and are the payload used when a
reviewer selects `REPROCESS_CLEAN`.
"""
from __future__ import annotations

import io
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from zombieslayer.detector import Detector
from zombieslayer.types import ContentItem, Finding, RiskCategory, ScanMode

from zombieslayer_vision import (
    adversarial,
    code_scan,
    extractor,
    format_detect,
    hidden_text,
    metadata as metadata_mod,
    sanitizer,
    stego,
)
from zombieslayer_vision.cache import ImageResultCache, InMemoryImageResultCache
from zombieslayer_vision.policy import VisionPolicy
from zombieslayer_vision.types import (
    ImageFormat,
    ImageItem,
    ImageScanResult,
    SanitizationAction,
)


@dataclass
class VisionScanner:
    detector: Detector = field(default_factory=Detector)
    policy: VisionPolicy = field(default_factory=VisionPolicy)
    cache: ImageResultCache = field(default_factory=InMemoryImageResultCache)
    vision_client: extractor.VisionClient | None = None

    def scan(self, item: ImageItem) -> ImageScanResult:
        # Cache check.
        cached = self.cache.get(item.sha256)
        if cached is not None:
            cached.cache_hit = True
            return cached

        budget_start = time.monotonic()
        findings: list[Finding] = []
        actions: list[SanitizationAction] = []

        # ---- Pre-flight: size / dimension limits. -----------------------
        if item.size_bytes > self.policy.max_bytes:
            findings.append(self._oversized_finding(item))
            return self._finalize(item, findings, actions, item.data, "")

        # ---- Stage 0: format + polyglot. --------------------------------
        fmt, fmt_findings = format_detect.detect(item.data)
        findings.extend(fmt_findings)

        # Dimension check (Pillow needed; skip for unparseable formats).
        try:
            from PIL import Image
            with Image.open(io.BytesIO(item.data)) as im:
                im.load()
                if max(im.size) > self.policy.max_dimension:
                    findings.append(Finding(
                        category=RiskCategory.STRUCTURAL_ANOMALY,
                        reason=(
                            f"image dimension {im.size} exceeds "
                            f"max {self.policy.max_dimension}"
                        ),
                        span=(0, 0),
                        rule="oversized_dimensions",
                        score=0.7,
                        kind="hidden",
                        family="structural",
                        evidence={"source_layer": "vision", "size": list(im.size)},
                    ))
                if im.is_animated if hasattr(im, "is_animated") else False:
                    findings.append(Finding(
                        category=RiskCategory.STRUCTURAL_ANOMALY,
                        reason=(
                            "animated image: only first and last frames are "
                            "scanned in MVP"
                        ),
                        span=(0, 0),
                        rule="animated_partial_scan",
                        score=0.15,
                        kind="hidden",
                        family="structural",
                        evidence={"source_layer": "vision"},
                    ))
        except Exception as exc:
            findings.append(Finding(
                category=RiskCategory.STRUCTURAL_ANOMALY,
                reason=f"image parser error: {type(exc).__name__}",
                span=(0, 0),
                rule="parse_failure",
                score=0.7,
                kind="hidden",
                family="structural",
                evidence={"source_layer": "vision"},
            ))

        # If the format is unsupported / parse failed, sanitization will
        # still try its best (may no-op) and we exit early.
        if fmt is ImageFormat.UNKNOWN:
            sanitized, actions = sanitizer.sanitize(item.data, fmt)
            return self._finalize(item, findings, actions, sanitized, "")

        if self._should_early_exit(findings):
            sanitized, actions = sanitizer.sanitize(item.data, fmt)
            return self._finalize(item, findings, actions, sanitized, "")

        # ---- Stage 1: metadata extraction. -----------------------------
        meta_strings = self._with_budget(
            budget_start, lambda: metadata_mod.extract(item.data), "metadata"
        )
        if isinstance(meta_strings, _Timeout):
            findings.append(meta_strings.finding("metadata"))
            meta_strings = {}

        # ---- Stage 2 + 4: stego signals. -------------------------------
        stage_findings = self._with_budget(
            budget_start, lambda: stego.lsb_chi_square(item.data), "lsb_stego"
        )
        if isinstance(stage_findings, _Timeout):
            findings.append(stage_findings.finding("lsb_stego"))
        else:
            findings.extend(stage_findings)

        stage_findings = self._with_budget(
            budget_start, lambda: stego.jpeg_dct_diff(item.data, fmt), "dct_stego"
        )
        if isinstance(stage_findings, _Timeout):
            findings.append(stage_findings.finding("dct_stego"))
        else:
            findings.extend(stage_findings)

        # ---- Stage 5: hidden-text scan. --------------------------------
        result = self._with_budget(
            budget_start, lambda: hidden_text.scan(item.data), "hidden_text"
        )
        hidden_text_str = ""
        if isinstance(result, _Timeout):
            findings.append(result.finding("hidden_text"))
        else:
            ht_findings, hidden_text_str = result
            findings.extend(ht_findings)

        # ---- Stage 6: QR / barcodes. -----------------------------------
        result = self._with_budget(
            budget_start, lambda: code_scan.scan(item.data), "code_scan"
        )
        code_payloads: list[str] = []
        if isinstance(result, _Timeout):
            findings.append(result.finding("code_scan"))
        else:
            cs_findings, code_payloads = result
            findings.extend(cs_findings)

        # ---- Stage 7: dual extraction. ---------------------------------
        dual = self._with_budget(
            budget_start,
            lambda: extractor.extract(
                item.data, mode=self.policy.mode, vision_client=self.vision_client,
            ),
            "extract",
        )
        baseline_text = ""
        if isinstance(dual, _Timeout):
            findings.append(dual.finding("extract"))
        else:
            findings.extend(dual.findings)
            baseline_text = dual.vision_text or dual.tesseract_text
            if (
                self.policy.mode is ScanMode.STRICT
                and dual.vision_failed
            ):
                findings.append(self._vision_outage_finding())

        # ---- Stage 8: adversarial divergence. --------------------------
        if (
            self.policy.mode is ScanMode.STRICT
            and not isinstance(dual, _Timeout)
            and not dual.vision_failed
            and dual.vision_text
            and not self._should_early_exit(findings)
        ):
            adv_findings = self._with_budget(
                budget_start,
                lambda: adversarial.divergence_check(
                    item.data,
                    dual.vision_text,
                    vision_client=self.vision_client,
                ),
                "adversarial",
            )
            if isinstance(adv_findings, _Timeout):
                findings.append(adv_findings.finding("adversarial"))
            else:
                findings.extend(adv_findings)

        # ---- Build extracted-text union for synthesized item. ----------
        extracted_parts: list[str] = []
        if not isinstance(dual, _Timeout):
            if dual.tesseract_text:
                extracted_parts.append(dual.tesseract_text)
            if dual.vision_text:
                extracted_parts.append(dual.vision_text)
        if hidden_text_str:
            extracted_parts.append(hidden_text_str)
        for p in code_payloads:
            extracted_parts.append(p)
        # Metadata strings flow into ContentItem.metadata (so
        # Detector._scan_metadata fires) — not into the visible text.

        extracted_text = "\n".join(extracted_parts).strip()

        # ---- Sanitize unconditionally. ---------------------------------
        sanitized, sanitize_actions = sanitizer.sanitize(
            item.data, fmt, strict=self.policy.mode is ScanMode.STRICT,
        )
        actions.extend(sanitize_actions)

        return self._finalize(
            item, findings, actions, sanitized, extracted_text,
            metadata=meta_strings if isinstance(meta_strings, dict) else {},
        )

    # -- helpers ---------------------------------------------------------

    def scan_batch(self, items: Iterable[ImageItem]) -> list[ImageScanResult]:
        items = list(items)
        if len(items) > self.policy.max_images_per_batch:
            items = items[: self.policy.max_images_per_batch]
        return [self.scan(it) for it in items]

    def _finalize(
        self,
        item: ImageItem,
        findings: list[Finding],
        actions: list[SanitizationAction],
        sanitized: bytes,
        extracted_text: str,
        metadata: dict[str, str] | None = None,
    ) -> ImageScanResult:
        # Filter disabled vision rules.
        if self.policy.disabled_vision_rules:
            findings = [
                f for f in findings
                if f.rule not in self.policy.disabled_vision_rules
            ]

        # Build the synthesized ContentItem so the core Detector's text
        # rules apply to extracted text (and metadata). The synthesized
        # item's source encodes lineage; derived_from puts the image's
        # id into the deferred-action gate.
        synthesized = ContentItem(
            text=extracted_text,
            source=f"image:sha256:{item.sha256}",
            trust=item.trust,
            metadata={
                "vision:source": item.source,
                "vision:image_id": item.id,
                **{k: v for k, v in (metadata or {}).items()},
            },
        )

        # Run the core detector over the synthesized item; merge findings.
        if extracted_text or metadata:
            text_findings = self.detector.scan(synthesized)
            for f in text_findings:
                # Mark them as image-derived so audits can split layers.
                if "source_layer" not in f.evidence:
                    f.evidence["source_layer"] = "image_text"
            findings.extend(text_findings)

        score = self.policy.core.aggregate(findings)
        threshold = self.policy.threshold(item.trust)
        quarantined = score >= threshold

        result = ImageScanResult(
            item=item,
            findings=findings,
            score=score,
            quarantined=quarantined,
            sanitized_bytes=sanitized,
            sanitization_actions=actions,
            extracted_text=extracted_text,
            synthesized_item=synthesized,
        )
        self.cache.put(item.sha256, result)
        return result

    def _should_early_exit(self, findings: list[Finding]) -> bool:
        return any(f.score >= self.policy.early_exit_score for f in findings)

    def _with_budget(self, started: float, fn, stage: str):
        if time.monotonic() - started > self.policy.per_image_budget_seconds:
            return _Timeout(stage, "per-image budget exceeded")
        stage_started = time.monotonic()
        try:
            value = fn()
        except Exception as exc:
            return _Timeout(stage, f"{type(exc).__name__}: {exc}")
        if (time.monotonic() - stage_started) > self.policy.per_stage_timeout_seconds:
            # The stage already returned, but it ran over budget. Surface a
            # low-score informational finding so operators can spot the
            # slow stage in the audit log.
            return _Timeout(stage, "stage timeout (returned, but slow)", value=value)
        return value

    def _oversized_finding(self, item: ImageItem) -> Finding:
        return Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=(
                f"image size {item.size_bytes} bytes exceeds policy max "
                f"{self.policy.max_bytes}"
            ),
            span=(0, 0),
            rule="oversized_image",
            score=0.7,
            kind="hidden",
            family="structural",
            evidence={"source_layer": "vision"},
        )

    def _vision_outage_finding(self) -> Finding:
        action = self.policy.vision_api_unavailable_action
        if action == "allow":
            score = 0.0
        else:
            score = 0.7  # quarantine — fail closed.
        return Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=(
                f"Claude vision API unavailable in STRICT mode "
                f"(policy={action})"
            ),
            span=(0, 0),
            rule="vision_api_unavailable",
            score=score,
            kind="hidden",
            family="structural",
            evidence={"source_layer": "vision"},
        )


@dataclass
class _Timeout:
    """Sentinel returned by `_with_budget` when a stage misbehaves."""
    stage: str
    detail: str
    value: object | None = None

    def finding(self, stage: str) -> Finding:
        rule = "scan_budget_exceeded" if "budget" in self.detail else "stage_timeout"
        return Finding(
            category=RiskCategory.STRUCTURAL_ANOMALY,
            reason=f"vision stage {stage}: {self.detail}",
            span=(0, 0),
            rule=rule,
            score=0.6 if rule == "scan_budget_exceeded" else 0.2,
            kind="hidden",
            family="structural",
            evidence={"source_layer": "vision", "stage": stage},
        )


def make_image_item(
    data: bytes,
    source: str,
    trust=None,
) -> ImageItem:
    """Convenience constructor used by hooks and tests."""
    from zombieslayer.types import SourceTrust
    return ImageItem(
        data=data,
        source=source,
        trust=trust or SourceTrust.UNTRUSTED,
        id=uuid.uuid4().hex,
    )
