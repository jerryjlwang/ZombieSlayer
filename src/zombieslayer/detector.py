from __future__ import annotations

import base64
import codecs
import html as html_mod
import re
import statistics
import unicodedata
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from zombieslayer.types import ContentItem, Finding, RiskCategory


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    category: RiskCategory
    score: float
    reason: str
    kind: str = "generic"  # short noun used by context-preserving redaction


# Pattern library. Patterns are intentionally conservative-first; source-aware
# thresholds in policy.py decide whether to quarantine.
_RULES: tuple[Rule, ...] = (
    Rule(
        "override_ignore",
        re.compile(r"\bignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|directions|prompts?|rules)\b", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.9,
        "asks the model to ignore prior instructions",
        kind="command",
    ),
    Rule(
        "override_disregard",
        re.compile(r"\bdisregard (?:the |all |any )?(?:system|developer|previous|prior) (?:prompt|instructions?)\b", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.9,
        "asks the model to disregard system/developer prompt",
        kind="command",
    ),
    Rule(
        "override_new_instructions",
        re.compile(r"\b(?:new|updated|revised) instructions?\s*[:\-]", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.5,
        "introduces 'new instructions' directive",
        kind="command",
    ),
    Rule(
        "role_reassignment",
        re.compile(r"\byou are now\b|\bact as\b|\bpretend to be\b|\bfrom now on,? you\b", re.I),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.55,
        "attempts to reassign agent role",
        kind="role",
    ),
    Rule(
        "system_prompt_reveal",
        re.compile(r"\b(?:reveal|print|show|output|repeat) (?:your |the )?(?:system|initial|hidden) (?:prompt|instructions?)\b", re.I),
        RiskCategory.DATA_EXFILTRATION, 0.9,
        "requests disclosure of system/hidden prompt",
        kind="command",
    ),
    Rule(
        "secret_exfil",
        re.compile(r"\b(?:send|email|post|upload|exfiltrate|leak) (?:.{0,40}?)(?:secret|api[_ ]?key|token|password|credentials?)\b", re.I),
        RiskCategory.DATA_EXFILTRATION, 0.95,
        "requests exfiltration of secrets/credentials",
        kind="secret",
    ),
    Rule(
        "url_side_channel",
        re.compile(r"\b(?:fetch|GET|curl|navigate to|visit)\s+https?://\S+\?[^\s]*(?:data|secret|token|key|prompt)=", re.I),
        RiskCategory.DATA_EXFILTRATION, 0.9,
        "URL appears to be a side-channel exfiltration endpoint",
        kind="url",
    ),
    Rule(
        "tool_invoke",
        re.compile(r"\b(?:call|invoke|use) (?:the )?tool\b|\bfunction_call\s*:", re.I),
        RiskCategory.UNSAFE_ACTION, 0.4,
        "embedded tool-invocation directive",
        kind="command",
    ),
    Rule(
        "persist_memory",
        re.compile(r"\b(?:remember|memorize|store|save)\s+(?:this|the following|that)\b|\b(?:add|write) (?:to|into) (?:your )?memory\b", re.I),
        RiskCategory.PERSISTENCE, 0.8,
        "asks the agent to persist content into memory",
        kind="command",
    ),
    Rule(
        "persist_future",
        re.compile(r"\b(?:in (?:all )?future (?:runs|sessions|conversations))|\bfor (?:all|every) subsequent (?:task|run|session)\b", re.I),
        RiskCategory.PERSISTENCE, 0.85,
        "targets future runs/sessions",
        kind="command",
    ),
    Rule(
        "hidden_html_comment",
        re.compile(r"<!--.*?(?:ignore|system|instruction|prompt|you are).*?-->", re.I | re.S),
        RiskCategory.STRUCTURAL_ANOMALY, 0.7,
        "model-directed text hidden in HTML comment",
        kind="hidden",
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
        kind="hidden",
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
        kind="role",
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
        kind="role",
    ),
    # --- Obfuscation / evasion additions (issue #2 §1) ---
    Rule(
        "whitespace_split_override",
        re.compile(
            r"\bi\W*g\W*n\W*o\W*r\W*e\W+(?:a\W*l\W*l\W+|a\W*n\W*y\W+|t\W*h\W*e\W+)?"
            r"(?:p\W*r\W*e\W*v\W*i\W*o\W*u\W*s|p\W*r\W*i\W*o\W*r|a\W*b\W*o\W*v\W*e)\W+"
            r"(?:i\W*n\W*s\W*t\W*r\W*u\W*c\W*t\W*i\W*o\W*n\W*s?|p\W*r\W*o\W*m\W*p\W*t\W*s?)\b",
            re.I,
        ),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.8,
        "ignore-previous directive split by whitespace/punctuation",
        kind="command",
    ),
    # --- Supply-chain signatures (issue #2 §2) ---
    Rule(
        "supply_chain_signature",
        re.compile(
            r"\b(?:prompt\s+injection\s+(?:template|payload)|"
            r"system\s+override\s+v\d+|"
            r"jailbreak\s+(?:prompt|payload)|"
            r"DAN\s+mode)\b",
            re.I,
        ),
        RiskCategory.INSTRUCTION_OVERRIDE, 0.85,
        "matches known injection/jailbreak template signature",
        kind="command",
    ),
    # --- Markdown / JSON comment hiding (issue #2 §2) ---
    Rule(
        "json_comment_hiding",
        re.compile(
            r"(?ms)\{[^{}]*?(?://[^\n]*(?:ignore|system|instruction|prompt|you\s+are)"
            r"|/\*[^*]*?(?:ignore|system|instruction|prompt|you\s+are)[^*]*?\*/)[^{}]*?\}",
        ),
        RiskCategory.STRUCTURAL_ANOMALY, 0.6,
        "model-directed text hidden in JSON comment",
        kind="hidden",
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


# ---- Decoder / normalizer helpers (issue #2 §1) ---------------------------

# Base64-ish chunk: conservative length to avoid random word matches.
_BASE64_CHUNK = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
# Percent-encoded URL sequences.
_PERCENT_ENCODED = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
# HTML entity clusters (decimal, hex, or named).
_HTML_ENTITY = re.compile(r"(?:&#\d+;|&#x[0-9a-fA-F]+;|&[a-zA-Z]{2,};){3,}")
# \uXXXX escape clusters.
_UNICODE_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}|(?:\\x[0-9a-fA-F]{2}){3,}")
# ROT13-looking text: at least ~30 chars of letters to avoid noise.
_ROT13_CANDIDATE = re.compile(r"[A-Za-z][A-Za-z ,.'\-]{30,}")

# Leetspeak substitutions applied before running override rules a second time.
_LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                           "7": "t", "@": "a", "$": "s", "!": "i"})

# Code-point ranges for non-Latin scripts commonly used in homograph attacks.
_CYRILLIC_LOOKALIKES = set("аеорсухАВЕКМНОРСТХаеорсухУВЕКМ")  # selective
_GREEK_LOOKALIKES = set("αβγεικνορτυωΑΒΕΗΙΚΜΝΟΡΤΥΧΖ")


def _is_printable_ratio(s: str, min_ratio: float = 0.85) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() and (c.isascii() or c.isalpha()))
    return printable / len(s) >= min_ratio


class Detector:
    """Rule-based detector augmented with structural anomaly signals.

    Returns findings; aggregation and quarantine decisions live in `Policy`.

    Extensions (issue #2):
      - Pre-decode stage: findings on decoded obfuscation are mapped back to the
        original span so redaction stays correct.
      - Leetspeak / homograph / whitespace-split patterns.
      - Metadata scan (ContentItem.metadata string values).
      - Pluggable `intent_verifier` hook — returns a 0..1 suspicion score for a
        passage; reserved for plugin-layer callers (e.g. Claude API). Core
        stays stdlib-only.
    """

    def __init__(
        self,
        rules: tuple[Rule, ...] = _RULES,
        disabled_rules: set[str] | None = None,
        score_overrides: dict[str, float] | None = None,
        intent_verifier: Callable[[str], float] | None = None,
    ) -> None:
        self.rules = rules
        self.disabled_rules: set[str] = set(disabled_rules or ())
        self.score_overrides: dict[str, float] = dict(score_overrides or {})
        self.intent_verifier = intent_verifier

    def scan(self, item: ContentItem) -> list[Finding]:
        findings: list[Finding] = []
        text = item.text

        base = self._run_rules(text)
        findings.extend(base)
        findings.extend(self._structural(text))
        findings.extend(self._denoising(text))
        findings.extend(self._decoded_findings(text))
        already_fired = {f.rule for f in base}
        findings.extend(self._normalized_findings(text, already_fired))
        findings.extend(self._homograph(text))
        findings.extend(self._scan_metadata(item.metadata))
        findings.extend(self._intent(text))

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
                    kind=f.kind,
                    evidence=f.evidence,
                )
                for f in findings
            ]
        return findings

    # ---- core rule loop ------------------------------------------------
    def _run_rules(
        self,
        text: str,
        span_mapper: Callable[[int, int], tuple[int, int]] | None = None,
        decoded_from: str | None = None,
    ) -> list[Finding]:
        """Run `self.rules` over `text`, remapping spans if requested."""
        out: list[Finding] = []
        for rule in self.rules:
            if rule.name in self.disabled_rules:
                continue
            score = self.score_overrides.get(rule.name, rule.score)
            for m in rule.pattern.finditer(text):
                start, end = m.start(), m.end()
                if span_mapper is not None:
                    start, end = span_mapper(start, end)
                evidence: dict[str, Any] = {}
                if decoded_from:
                    evidence["decoded_from"] = decoded_from
                out.append(Finding(
                    category=rule.category,
                    reason=rule.reason if not decoded_from
                        else f"{rule.reason} (decoded from {decoded_from})",
                    span=(start, end),
                    rule=rule.name,
                    score=score,
                    kind=rule.kind,
                    evidence=evidence,
                ))
        return out

    # ---- structural anomalies (unchanged) ------------------------------
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
                kind="hidden",
            ))

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
                kind="command",
            ))

        return out

    # ---- denoising (unchanged) -----------------------------------------
    def _denoising(self, text: str) -> list[Finding]:
        sentences = self._split_sentences(text)
        if len(sentences) < 3:
            return []

        scores = [self._sentence_score(s) for _, _, s in sentences]
        baseline = statistics.median(scores)

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
                    kind="command",
                ))
                if idx is not None:
                    cluster_start = idx
            if idx is not None:
                prev = idx

        return out

    def _split_sentences(self, text: str) -> list[tuple[int, int, str]]:
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
        if words <= 18 and (_IMPERATIVE_START.search(sentence) or _MODAL_COMMAND.search(sentence)):
            score += 0.10
        return min(score, 1.0)

    # ---- decoded findings (issue #2 §1) --------------------------------
    def _decoded_findings(self, text: str) -> list[Finding]:
        """Try decoding suspicious substrings; re-run rules on the decoded text.

        Findings are reported with the *original* span (the encoded region) so
        redaction removes the opaque blob instead of the plaintext we produced.
        """
        out: list[Finding] = []

        def run(decoded: str, orig_start: int, orig_end: int, name: str) -> None:
            mapper = lambda s, e: (orig_start, orig_end)  # noqa: E731
            out.extend(self._run_rules(decoded, span_mapper=mapper, decoded_from=name))

        # Base64
        for m in _BASE64_CHUNK.finditer(text):
            blob = m.group(0)
            try:
                decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
            except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
                continue
            if _is_printable_ratio(decoded):
                run(decoded, m.start(), m.end(), "base64")

        # Percent-encoding
        for m in _PERCENT_ENCODED.finditer(text):
            try:
                decoded = urllib.parse.unquote(m.group(0))
            except Exception:
                continue
            if decoded != m.group(0):
                run(decoded, m.start(), m.end(), "url_percent")

        # HTML entities — decode at whole-text granularity so entity runs
        # separated by spaces still reconstruct a contiguous phrase.
        if _HTML_ENTITY.search(text):
            decoded = html_mod.unescape(text)
            if decoded != text:
                out.extend(self._run_rules(
                    decoded,
                    span_mapper=lambda s, e: (0, min(len(text), 1)),
                    decoded_from="html_entity",
                ))

        # Unicode escape sequences — same approach.
        if _UNICODE_ESCAPES.search(text):
            try:
                decoded = codecs.decode(text, "unicode_escape")
            except (UnicodeDecodeError, ValueError):
                decoded = None
            if decoded and decoded != text:
                out.extend(self._run_rules(
                    decoded,
                    span_mapper=lambda s, e: (0, min(len(text), 1)),
                    decoded_from="unicode_escape",
                ))

        # ROT13 — only accept if the decoded text fires rules.
        for m in _ROT13_CANDIDATE.finditer(text):
            candidate = m.group(0)
            try:
                decoded = codecs.decode(candidate, "rot_13")
            except Exception:
                continue
            # Only surface rule hits from ROT13; imperative-start counts are
            # too noisy otherwise.
            hits = self._run_rules(
                decoded,
                span_mapper=lambda s, e, st=m.start(), en=m.end(): (st, en),
                decoded_from="rot13",
            )
            if hits:
                out.extend(hits)

        return out

    # ---- leetspeak normalization (issue #2 §1) -------------------------
    def _normalized_findings(
        self, text: str, already_fired: set[str] | None = None
    ) -> list[Finding]:
        """Apply leet-substitution then re-run override rules.

        Only override/role/persistence/exfil rules are re-run — density-style
        signals are noisy on normalized text. Rules that already fired on the
        plain text are skipped so we don't double-count.
        """
        already = already_fired or set()
        # Short-circuit if the text has no digits/leet glyphs at all.
        if not any(c in text for c in "0134578@$!"):
            return []
        normalized = text.translate(_LEET_MAP).lower()
        if normalized == text.lower():
            return []
        out: list[Finding] = []
        leet_rules = {
            "override_ignore", "override_disregard", "override_new_instructions",
            "role_reassignment", "system_prompt_reveal", "secret_exfil",
            "persist_memory", "persist_future",
        }
        # We can't reliably map normalized spans to original spans, so mark the
        # whole text as the span and label it leetspeak-derived.
        for rule in self.rules:
            if rule.name not in leet_rules or rule.name in self.disabled_rules:
                continue
            if rule.name in already:
                continue  # plain text already fired this rule; skip the leet dupe
            score = self.score_overrides.get(rule.name, rule.score)
            for _ in rule.pattern.finditer(normalized):
                # Use (0, 0) span so leet findings contribute to the aggregate
                # score but do not cause whole-text redaction. The non-leet
                # rule (if it fires on the original) handles redaction.
                out.append(Finding(
                    category=rule.category,
                    reason=f"{rule.reason} (via leetspeak substitution)",
                    span=(0, 0),
                    rule=f"{rule.name}_leet",
                    score=max(0.0, score - 0.05),
                    kind=rule.kind,
                    evidence={"decoded_from": "leetspeak"},
                ))
                break
        return out

    # ---- homograph / mixed-script detection (issue #2 §1) --------------
    def _homograph(self, text: str) -> list[Finding]:
        """Flag words mixing Latin with Cyrillic/Greek lookalike characters."""
        out: list[Finding] = []
        for m in re.finditer(r"[^\s\W\d_]{3,}", text, flags=re.UNICODE):
            word = m.group(0)
            has_latin = False
            has_other_script = False
            for ch in word:
                if "LATIN" in unicodedata.name(ch, ""):
                    has_latin = True
                elif ch in _CYRILLIC_LOOKALIKES or ch in _GREEK_LOOKALIKES:
                    has_other_script = True
                elif "CYRILLIC" in unicodedata.name(ch, "") or "GREEK" in unicodedata.name(ch, ""):
                    has_other_script = True
            if has_latin and has_other_script:
                out.append(Finding(
                    category=RiskCategory.STRUCTURAL_ANOMALY,
                    reason=f"mixed-script (homograph) word: {word!r}",
                    span=(m.start(), m.end()),
                    rule="homograph_mixed_script",
                    score=0.55,
                    kind="hidden",
                    evidence={"word": word},
                ))
        return out

    # ---- metadata scan (issue #2 §2) -----------------------------------
    def _scan_metadata(self, metadata: dict[str, Any]) -> list[Finding]:
        """Scan string values in ContentItem.metadata for instruction payloads."""
        if not metadata:
            return []
        out: list[Finding] = []
        for key, value in metadata.items():
            if not isinstance(value, str) or not value.strip():
                continue
            sub = self._run_rules(value)
            for f in sub:
                out.append(Finding(
                    category=f.category,
                    reason=f"{f.reason} (in metadata:{key})",
                    span=(0, 0),  # metadata findings have no offset in main text
                    rule=f"metadata_{f.rule}",
                    score=f.score,
                    kind=f.kind,
                    evidence={"metadata_key": key, "matched": f.rule},
                ))
        return out

    # ---- pluggable intent verifier (issue #2 §8) -----------------------
    def _intent(self, text: str) -> list[Finding]:
        """Call the optional intent verifier (plugin-layer hook).

        Core never ships with an implementation — integrators wire Claude or
        another classifier here. Kept off by default so the core stays
        stdlib-only.
        """
        if self.intent_verifier is None:
            return []
        try:
            score = float(self.intent_verifier(text))
        except Exception:
            return []
        if score <= 0.0:
            return []
        return [Finding(
            category=RiskCategory.INSTRUCTION_OVERRIDE,
            reason=f"intent verifier flagged passage (score={score:.2f})",
            span=(0, len(text)),
            rule="intent_verifier",
            score=min(max(score, 0.0), 1.0),
            kind="command",
            evidence={"source": "intent_verifier"},
        )]


def available_decoders() -> Iterable[str]:
    """Names of decoders that the detector's pre-decode stage tries."""
    return ("base64", "url_percent", "html_entity", "unicode_escape", "rot13")
