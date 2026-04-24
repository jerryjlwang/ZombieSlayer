from __future__ import annotations

import re
import statistics
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
        re.compile(
            r"style\s*=\s*\"[^\"]*(?:"
            r"display\s*:\s*none"
            r"|visibility\s*:\s*hidden"
            r"|font-size\s*:\s*0"
            r"|opacity\s*:\s*0(?!\.)"
            r"|clip-path\s*:\s*(?:inset\(\s*100%|circle\(\s*0)"
            r"|(?:left|top|right|bottom)\s*:\s*-\d{3,}(?:px|em|rem|vh|vw)"
            r")",
            re.I,
        ),
        RiskCategory.STRUCTURAL_ANOMALY, 0.6,
        "content hidden via CSS",
    ),
    Rule(
        "hidden_color_match",
        re.compile(
            r"style\s*=\s*\"[^\"]*(?:"
            r"color\s*:\s*(?:#fff(?:fff)?|white)\b[^\"]*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)\b"
            r"|background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)\b[^\"]*color\s*:\s*(?:#fff(?:fff)?|white)\b"
            r"|color\s*:\s*(?:#0{3}(?:0{3})?|black)\b[^\"]*background(?:-color)?\s*:\s*(?:#0{3}(?:0{3})?|black)\b"
            r"|background(?:-color)?\s*:\s*(?:#0{3}(?:0{3})?|black)\b[^\"]*color\s*:\s*(?:#0{3}(?:0{3})?|black)\b"
            r")",
            re.I,
        ),
        RiskCategory.STRUCTURAL_ANOMALY, 0.6,
        "text color matches background (invisible text)",
    ),
    Rule(
        "fake_system_tag",
        re.compile(r"<\s*(?:system|assistant|developer)\s*>|\[(?:SYSTEM|ASSISTANT|DEVELOPER)\]", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.75,
        "fake role/system tag in external content",
    ),
    Rule(
        "chatml_role_token",
        re.compile(r"<\|im_start\|>\s*(?:system|user|assistant|developer)\b|<\|im_end\|>", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.75,
        "ChatML role delimiter in external content",
    ),
    Rule(
        "llama_inst_token",
        re.compile(r"\[INST\].{0,500}?\[/INST\]|<<SYS>>.{0,500}?<</SYS>>", re.I | re.S),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.75,
        "Llama-style instruction/system delimiter pair",
    ),
    Rule(
        "fake_transcript_json",
        re.compile(
            r'"role"\s*:\s*"(?:system|assistant|developer)"\s*,?.{0,200}?"content"\s*:',
            re.I | re.S,
        ),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.7,
        "JSON transcript payload with role/content fields",
    ),
    Rule(
        "fake_transcript_yaml",
        re.compile(
            r"^\s*-?\s*role\s*:\s*(?:system|assistant|developer)\b.{0,200}?^\s*content\s*:",
            re.I | re.M | re.S,
        ),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.65,
        "YAML transcript payload with role/content fields",
    ),
    Rule(
        "code_fence_role_tag",
        re.compile(
            r"(?:^|\n)\s*(?:```|~~~)[ \t]*"
            r"(?:system|assistant|developer|instructions?|agent|tool|function)\b",
            re.I | re.M,
        ),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.75,
        "code fence language tag impersonates agent role",
    ),
)


# Characters used to smuggle instructions through invisibly.
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


# Sentence-level register signals. Used by `_denoising` to score each sentence
# against the document baseline; a localized cluster that diverges sharply is
# our stdlib stand-in for reconstruction error (PRD §14.3).
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'\(\[])")
_IMPERATIVE_START = re.compile(
    r"^\s*(?:please\s+|now\s+|first[, ]+)?"
    r"(?:ignore|forget|disregard|override|bypass|"
    r"send|email|post|upload|exfiltrate|leak|transmit|"
    r"reveal|print|show|output|repeat|dump|"
    r"remember|memorize|store|save|persist|"
    r"execute|run|call|invoke|fetch|"
    r"act|pretend|behave|respond|answer)\b",
    re.I,
)
_SECOND_PERSON = re.compile(r"\byou(?:r|'re|'ve|'ll|rself)?\b", re.I)
_MODAL_COMMAND = re.compile(
    r"\byou (?:must|should|need to|have to|are (?:required|expected|instructed) to)\b",
    re.I,
)
_OVERRIDE_REF = re.compile(
    r"\b(?:previous|prior|above|earlier|system|developer|hidden|initial) "
    r"(?:instructions?|prompt|rules?|directions?|message)\b",
    re.I,
)


class Detector:
    """Rule-based detector augmented with structural anomaly signals.

    Returns findings; aggregation and quarantine decisions live in `Policy`.
    """

    def __init__(
        self,
        rules: tuple[Rule, ...] = _RULES,
        disabled_rules: set[str] | None = None,
        score_overrides: dict[str, float] | None = None,
    ) -> None:
        self.rules = rules
        self.disabled_rules: set[str] = set(disabled_rules or ())
        self.score_overrides: dict[str, float] = dict(score_overrides or {})

    def scan(self, item: ContentItem) -> list[Finding]:
        findings: list[Finding] = []
        text = item.text

        for rule in self.rules:
            if rule.name in self.disabled_rules:
                continue
            score = self.score_overrides.get(rule.name, rule.score)
            for m in rule.pattern.finditer(text):
                findings.append(Finding(
                    category=rule.category,
                    reason=rule.reason,
                    span=(m.start(), m.end()),
                    rule=rule.name,
                    score=score,
                ))

        findings.extend(self._structural(text))
        findings.extend(self._denoising(text))
        if self.disabled_rules:
            findings = [f for f in findings if f.rule not in self.disabled_rules]
        if self.score_overrides:
            findings = [
                Finding(
                    category=f.category,
                    reason=f.reason,
                    span=f.span,
                    rule=f.rule,
                    score=self.score_overrides.get(f.rule, f.score),
                )
                for f in findings
            ]
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
        imp_hits = list(re.finditer(
            r"(?mi)^\s*(?:please\s+)?(?:do|do not|don't|ignore|follow|send|reveal|print|remember|forget|output|execute|run|call)\b",
            text,
        ))
        words = max(len(text.split()), 1)
        density = len(imp_hits) / words
        if len(imp_hits) >= 3 and density > 0.08:
            out.append(Finding(
                category=RiskCategory.STRUCTURAL_ANOMALY,
                reason=f"high imperative-instruction density ({len(imp_hits)} hits, {density:.0%})",
                span=(imp_hits[0].start(), imp_hits[-1].end()),
                rule="imperative_density",
                score=min(0.4 + density, 0.85),
            ))

        return out

    def _denoising(self, text: str) -> list[Finding]:
        """Flag instruction-register clusters that diverge from the document baseline.

        Stdlib approximation of PRD §14.3's denoising/reconstruction heuristic:
        score each sentence for instruction-payload characteristics, then flag
        contiguous spans that score well above the document's median sentence
        score when the document is otherwise clean. This catches injections
        buried inside benign web/retrieval content without firing on uniformly
        instructional material (docs, how-tos) where `imperative_density` or
        rule hits would fire instead.
        """
        sentences = self._split_sentences(text)
        if len(sentences) < 3:
            return []

        scores = [self._sentence_score(s) for _, _, s in sentences]
        baseline = statistics.median(scores)

        # Only fire when the *document* reads as mostly non-instructional.
        # Uniformly imperative content (how-tos) will have a high baseline and
        # is handled by `imperative_density` / rule hits, not by this signal.
        if baseline >= 0.25:
            return []

        threshold = max(0.45, baseline * 3.0 + 0.15)
        anomalous = [i for i, s in enumerate(scores) if s >= threshold]
        if not anomalous:
            return []

        out: list[Finding] = []
        cluster_start = anomalous[0]
        prev = anomalous[0]
        for idx in anomalous[1:] + [None]:
            if idx is None or idx != prev + 1:
                start_char = sentences[cluster_start][0]
                end_char = sentences[prev][1]
                size = prev - cluster_start + 1
                out.append(Finding(
                    category=RiskCategory.STRUCTURAL_ANOMALY,
                    reason=(
                        f"instruction-register cluster ({size} sentence"
                        f"{'s' if size > 1 else ''}) diverges from document baseline"
                    ),
                    span=(start_char, end_char),
                    rule="semantic_anomaly_cluster",
                    score=min(0.4 + 0.15 * size, 0.82),
                ))
                if idx is not None:
                    cluster_start = idx
            if idx is not None:
                prev = idx

        return out

    def _split_sentences(self, text: str) -> list[tuple[int, int, str]]:
        """Return (start, end, sentence_text) triples preserving offsets."""
        if not text.strip():
            return []
        spans: list[tuple[int, int, str]] = []
        cursor = 0
        for match in _SENTENCE_SPLIT.finditer(text):
            end = match.start()
            chunk = text[cursor:end]
            if chunk.strip():
                spans.append((cursor, end, chunk))
            cursor = match.end()
        tail = text[cursor:]
        if tail.strip():
            spans.append((cursor, len(text), tail))
        return spans

    def _sentence_score(self, sentence: str) -> float:
        """Score a single sentence 0.0–1.0 on instruction-payload features."""
        score = 0.0
        if _IMPERATIVE_START.search(sentence):
            score += 0.35
        if _MODAL_COMMAND.search(sentence):
            score += 0.30
        if _OVERRIDE_REF.search(sentence):
            score += 0.30
        words = max(len(sentence.split()), 1)
        second_person_hits = len(_SECOND_PERSON.findall(sentence))
        if second_person_hits:
            score += min(0.25, 0.10 + 0.05 * second_person_hits)
        # Short, punchy sentences are more command-like than long prose.
        if words <= 18 and (_IMPERATIVE_START.search(sentence) or _MODAL_COMMAND.search(sentence)):
            score += 0.10
        return min(score, 1.0)
