from __future__ import annotations

import re
from dataclasses import dataclass

from zombieslayer.types import ContentItem, Finding, RiskCategory


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    category: RiskCategory
    score: float
    reason: str


# Pattern library. Patterns are intentionally conservative-first; source-aware
# thresholds in policy.py decide whether to quarantine.
_RULES: tuple[Rule, ...] = (
    Rule(
        "override_ignore",
        re.compile(r"\bignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|directions|prompts?|rules)\b", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.9,
        "asks the model to ignore prior instructions",
    ),
    Rule(
        "override_disregard",
        re.compile(r"\bdisregard (?:the |all |any )?(?:system|developer|previous|prior) (?:prompt|instructions?)\b", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.9,
        "asks the model to disregard system/developer prompt",
    ),
    Rule(
        "override_new_instructions",
        re.compile(r"\b(?:new|updated|revised) instructions?\s*[:\-]", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.5,
        "introduces 'new instructions' directive",
    ),
    Rule(
        "role_reassignment",
        re.compile(r"\byou are now\b|\bact as\b|\bpretend to be\b|\bfrom now on,? you\b", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.55,
        "attempts to reassign agent role",
    ),
    Rule(
        "system_prompt_reveal",
        re.compile(r"\b(?:reveal|print|show|output|repeat) (?:your |the )?(?:system|initial|hidden) (?:prompt|instructions?)\b", re.I),
        RiskCategory.DATA_EXFILTRATION, 0.9,
        "requests disclosure of system/hidden prompt",
    ),
    Rule(
        "secret_exfil",
        re.compile(r"\b(?:send|email|post|upload|exfiltrate|leak) (?:.{0,40}?)(?:secret|api[_ ]?key|token|password|credentials?)\b", re.I),
        RiskCategory.DATA_EXFILTRATION, 0.95,
        "requests exfiltration of secrets/credentials",
    ),
    Rule(
        "url_side_channel",
        re.compile(r"\b(?:fetch|GET|curl|navigate to|visit)\s+https?://\S+\?[^\s]*(?:data|secret|token|key|prompt)=", re.I),
        RiskCategory.DATA_EXFILTRATION, 0.9,
        "URL appears to be a side-channel exfiltration endpoint",
    ),
    Rule(
        "tool_invoke",
        re.compile(r"\b(?:call|invoke|use) (?:the )?tool\b|\bfunction_call\s*:", re.I),
        RiskCategory.UNSAFE_ACTION, 0.4,
        "embedded tool-invocation directive",
    ),
    Rule(
        "persist_memory",
        re.compile(r"\b(?:remember|memorize|store|save)\s+(?:this|the following|that)\b|\b(?:add|write) (?:to|into) (?:your )?memory\b", re.I),
        RiskCategory.PERSISTENCE, 0.8,
        "asks the agent to persist content into memory",
    ),
    Rule(
        "persist_future",
        re.compile(r"\b(?:in (?:all )?future (?:runs|sessions|conversations))|\bfor (?:all|every) subsequent (?:task|run|session)\b", re.I),
        RiskCategory.PERSISTENCE, 0.85,
        "targets future runs/sessions",
    ),
    Rule(
        "hidden_html_comment",
        re.compile(r"<!--.*?(?:ignore|system|instruction|prompt|you are).*?-->", re.I | re.S),
        RiskCategory.STRUCTURAL_ANOMALY, 0.7,
        "model-directed text hidden in HTML comment",
    ),
    Rule(
        "hidden_style",
        re.compile(r"style\s*=\s*\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)", re.I),
        RiskCategory.STRUCTURAL_ANOMALY, 0.6,
        "content hidden via CSS",
    ),
    Rule(
        "fake_system_tag",
        re.compile(r"<\s*(?:system|assistant|developer)\s*>|\[(?:SYSTEM|ASSISTANT|DEVELOPER)\]", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.75,
        "fake role/system tag in external content",
    ),
)


# Characters used to smuggle instructions through invisibly.
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


class Detector:
    """Rule-based detector augmented with structural anomaly signals.

    Returns findings; aggregation and quarantine decisions live in `Policy`.
    """

    def __init__(self, rules: tuple[Rule, ...] = _RULES) -> None:
        self.rules = rules

    def scan(self, item: ContentItem) -> list[Finding]:
        findings: list[Finding] = []
        text = item.text

        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                findings.append(Finding(
                    category=rule.category,
                    reason=rule.reason,
                    span=(m.start(), m.end()),
                    rule=rule.name,
                    score=rule.score,
                ))

        findings.extend(self._structural(text))
        return findings

    def _structural(self, text: str) -> list[Finding]:
        out: list[Finding] = []

        # Zero-width / bidi smuggling
        zw_hits = list(_ZERO_WIDTH.finditer(text))
        if zw_hits:
            out.append(Finding(
                category=RiskCategory.STRUCTURAL_ANOMALY,
                reason=f"contains {len(zw_hits)} zero-width/bidi control characters",
                span=(zw_hits[0].start(), zw_hits[-1].end()),
                rule="zero_width_chars",
                score=min(0.5 + 0.05 * len(zw_hits), 0.9),
            ))

        # Instruction density: many imperative lines clustered into short text
        # is suspicious for content sourced from a web page or document chunk.
        imperative = re.findall(
            r"(?mi)^\s*(?:please\s+)?(?:do|do not|don't|ignore|follow|send|reveal|print|remember|forget|output|execute|run|call)\b",
            text,
        )
        words = max(len(text.split()), 1)
        density = len(imperative) / words
        if len(imperative) >= 3 and density > 0.08:
            out.append(Finding(
                category=RiskCategory.STRUCTURAL_ANOMALY,
                reason=f"high imperative-instruction density ({len(imperative)} hits, {density:.0%})",
                span=(0, min(len(text), 200)),
                rule="imperative_density",
                score=min(0.4 + density, 0.85),
            ))

        return out
