"""Zero-cost structural detection over message content.

These detectors are deterministic and allocation-light: they run on every
message, offline, with no model and no network. They catch the class of
injection that is *structurally* anomalous rather than semantically suspicious
-- hidden Unicode carriers, chat-template delimiters smuggled into tool output,
and instruction-shaped text buried in comments.

The split of responsibilities matters and is deliberate: **detectors observe,
policy decides.** Every rule here only reports a finding and a severity. Whether
a finding is fatal depends on where the tainted content is flowing, which is
the provenance engine's job, not this module's.

Detection targets map to OWASP MCP Top 10 (2026):
  MCP03 Tool Poisoning, MCP10 Context Injection & Over-Sharing.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from airlock.audit.log import Decision, Finding
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.base import Verdict

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Cap per message. Detection must not become a denial-of-service vector -- an
#: attacker who can make the gateway spend unbounded time on one payload has
#: found the cheapest attack of all.
MAX_SCAN_CHARS = 256_000

#: Excerpt cap. Findings are evidence, not a second copy of the payload; the
#: audit log must not silently become a plaintext archive of agent traffic.
MAX_EXCERPT = 120

# Unicode tag characters (U+E0000..U+E007F) and variation selector
# *supplements* (U+E0100..U+E01EF) render as nothing, are deprecated for
# ordinary text, and are a known carrier for instructions that a human reviewer
# cannot see. There is no legitimate reason for them to appear in a tool result.
_TAG_RANGE = range(0xE0000, 0xE0080)
_VS_SUPPLEMENT_RANGE = range(0xE0100, 0xE01F0)

# BMP variation selectors (U+FE00..U+FE0F) are a different animal: they are the
# standard way to request emoji presentation ("❤️" vs "❤"). Flagging them as a
# critical hidden-text carrier would block ordinary emoji, so they are recorded
# at info severity -- present in the audit trail, never a blocking signal.
_VS_BMP_RANGE = range(0xFE00, 0xFE10)

# Format characters that are invisible in most renderers and are routinely used
# to smuggle instructions past human review: zero-width space/joiner, word
# joiner, invisible separator, BOM-as-ZWNBSP, soft hyphen.
_ZERO_WIDTH = {
    0x00AD,  # soft hyphen
    0x200B,  # zero width space
    0x200C,  # zero width non-joiner
    0x200D,  # zero width joiner
    0x2060,  # word joiner
    0x2063,  # invisible separator
    0xFEFF,  # zero width no-break space / BOM
}

# U+200C/U+200D are the only zero-width characters with a large legitimate
# corpus: they join emoji sequences ("family", profession pictograms) and shape
# Indic/Arabic script. Flagging them unconditionally would make the detector
# useless on any real user-facing content, and a rule that cries wolf on
# emoji is a rule operators turn off.
#
# So ZWJ/ZWNJ only count as findings when they are *not* doing that job. An
# attacker smuggling text through the joiner still lands in ordinary words, so
# the emoji-flanked exemption does not create a bypass -- it only exempts the
# case where the joiner is surrounded by pictographs, which carry no letters to
# hide inside them.
_ZWJ_LIKE = frozenset({0x200C, 0x200D})

#: Code point ranges treated as pictographic/emoji for the ZWJ exemption.
_EMOJI_RANGES = (
    range(0x1F000, 0x1FB00),  # emoji and pictograph extensions
    range(0x2600, 0x27C0),  # misc symbols, dingbats
    range(0x2B00, 0x2C00),  # arrows and geometric shapes used in emoji
    range(0x1F1E6, 0x1F200),  # regional indicators (flags)
    range(0xFE00, 0xFE10),  # variation selectors, appear in emoji runs
)


def _is_emoji(code: int) -> bool:
    return any(code in span for span in _EMOJI_RANGES)


# Bidirectional control characters. "Trojan Source" (CVE-2021-42574) showed how
# these make displayed order disagree with logical order.
_BIDI = {
    0x200E,  # left-to-right mark
    0x200F,  # right-to-left mark
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,  # LRE RLE PDF LRO RLO
    0x2066,
    0x2067,
    0x2068,
    0x2069,  # LRI RLI FSI PDI
}

# Chat-template special tokens. These are unambiguous: they have no role in
# human-facing text, and their presence in a tool result means content is
# masquerading as a control channel.
_TEMPLATE_TOKENS = re.compile(
    r"<\|(?:im_start|im_end|endoftext|system|user|assistant|tool|start_header_id|"
    r"end_header_id|eot_id|begin_of_text|end_of_text|python_tag)\|>"
    r"|\[/?INST\]"
    r"|<<SYS>>|<</SYS>>",
    re.IGNORECASE,
)

# Instruction-shaped text inside a comment. Deliberately narrow: this is the
# lowest-confidence rule in the set and is reported at "low" severity so the
# evaluation can show its false-positive cost honestly rather than hiding it.
_COMMENTED_INSTRUCTION = re.compile(
    r"<!--(?=[^>]{0,600}(?:ignore|disregard|override|system prompt|instruction|"
    r"you must|do not tell|exfiltrat|send (?:it|them|the)))[^>]{0,600}-->",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class RuleHit:
    rule: str
    severity: Severity
    owasp: str | None
    detail: str
    path: str
    excerpt: str

    def to_finding(self) -> Finding:
        return Finding(
            rule=self.rule,
            severity=self.severity,
            detail=f"{self.detail} at {self.path}",
            owasp=self.owasp,
        )


def iter_strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Walk arbitrary JSON, yielding every string and its location.

    A path-qualified walk (rather than reaching for known MCP field names) means
    new protocol shapes are covered the day they appear, which is the same
    forward-compatibility argument that justifies untyped envelopes.
    """
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_strings(item, f"{path}[{index}]")


def _excerpt(text: str, index: int, width: int = 24) -> str:
    """Render a window around an offset with control characters escaped."""
    start = max(0, index - width)
    end = min(len(text), index + width)
    window = text[start:end]
    escaped = "".join(
        ch if ch.isprintable() and ch not in "\r\n\t" else f"\\u{ord(ch):04x}" for ch in window
    )
    if len(escaped) > MAX_EXCERPT:
        escaped = escaped[:MAX_EXCERPT] + "..."
    return escaped


def scan_text(text: str, path: str) -> list[RuleHit]:
    """Apply every structural rule to one string."""
    if not text:
        return []
    hits: list[RuleHit] = []

    # Single pass over code points for all character-class rules.
    seen: dict[str, int] = {}
    tag_count = vs_count = zero_width_count = bidi_count = vs_bmp_count = 0
    text_length = len(text)
    for offset, char in enumerate(text):
        code = ord(char)
        if code in _TAG_RANGE:
            tag_count += 1
            seen.setdefault("unicode-tag", offset)
        elif code in _VS_SUPPLEMENT_RANGE:
            vs_count += 1
            seen.setdefault("unicode-tag", offset)
        elif code in _VS_BMP_RANGE:
            vs_bmp_count += 1
            seen.setdefault("emoji-presentation", offset)
        elif code in _ZERO_WIDTH:
            if code in _ZWJ_LIKE and 0 < offset < text_length - 1:
                before = ord(text[offset - 1])
                after = ord(text[offset + 1])
                if _is_emoji(before) and _is_emoji(after):
                    continue  # legitimate pictograph sequence
            zero_width_count += 1
            seen.setdefault("zero-width", offset)
        elif code in _BIDI:
            bidi_count += 1
            seen.setdefault("bidi-control", offset)

    if tag_count or vs_count:
        hits.append(
            RuleHit(
                rule="unicode-tag",
                severity="critical",
                owasp="MCP03",
                detail=(
                    f"{tag_count} tag character(s) and {vs_count} variation selector(s) "
                    "carry invisible text"
                ),
                path=path,
                excerpt=_excerpt(text, seen["unicode-tag"]),
            )
        )
    if bidi_count:
        hits.append(
            RuleHit(
                rule="bidi-control",
                severity="high",
                owasp="MCP03",
                detail=f"{bidi_count} bidirectional control character(s) present",
                path=path,
                excerpt=_excerpt(text, seen["bidi-control"]),
            )
        )
    if zero_width_count:
        hits.append(
            RuleHit(
                rule="zero-width",
                severity="medium",
                owasp="MCP03",
                detail=f"{zero_width_count} zero-width/format character(s) present",
                path=path,
                excerpt=_excerpt(text, seen["zero-width"]),
            )
        )

    if vs_bmp_count:
        hits.append(
            RuleHit(
                rule="emoji-presentation",
                severity="info",
                owasp=None,
                detail=f"{vs_bmp_count} BMP variation selector(s) requesting emoji presentation",
                path=path,
                excerpt=_excerpt(text, seen["emoji-presentation"]),
            )
        )

    for match in _TEMPLATE_TOKENS.finditer(text):
        hits.append(
            RuleHit(
                rule="template-token",
                severity="high",
                owasp="MCP03",
                detail=f"chat-template token {match.group(0)!r} embedded in content",
                path=path,
                excerpt=_excerpt(text, match.start()),
            )
        )

    for match in _COMMENTED_INSTRUCTION.finditer(text):
        hits.append(
            RuleHit(
                rule="commented-instruction",
                severity="low",
                owasp="MCP10",
                detail="instruction-shaped text inside an HTML comment",
                path=path,
                excerpt=_excerpt(text, match.start()),
            )
        )

    return hits


class StructuralInspector:
    """Detector that runs structural rules over request params and results."""

    name = "structural"

    def __init__(self, *, block_at: Severity | None = "critical") -> None:
        # Default: block only on the one class with no legitimate use. Every
        # other severity flags, leaving the decision to policy. Blocking on
        # medium-severity heuristics by default is how security tools acquire
        # the false-positive rate that gets them uninstalled.
        self.block_at = block_at

    def _inspect(self, value: Any) -> tuple[list[Finding], Severity]:
        findings: list[Finding] = []
        worst: Severity = "info"
        budget = MAX_SCAN_CHARS
        for path, text in iter_strings(value):
            if budget <= 0:
                break
            budget -= len(text)
            for hit in scan_text(text, path):
                findings.append(hit.to_finding())
                if SEVERITY_RANK[hit.severity] > SEVERITY_RANK[worst]:
                    worst = hit.severity
        return findings, worst

    def inspect_request(self, message: Message, ctx: SessionContext) -> Verdict:
        # Only arguments carry attacker-influenced content on this leg. The
        # tool name is metadata the policy engine handles separately.
        if message.method != "tools/call":
            return Verdict.allow()
        findings, worst = self._inspect(message.params.get("arguments"))
        return self._decision(findings, worst)

    def inspect_response(self, message: Message, ctx: SessionContext) -> Verdict:
        if not message.is_error:
            findings, worst = self._inspect(message.result)
            return self._decision(findings, worst)
        return Verdict.allow()

    def _decision(self, findings: Sequence[Finding], worst: Severity) -> Verdict:
        if not findings:
            return Verdict.allow()
        action: Decision = "block" if self._is_blocking(worst) else "flag"
        return Verdict.of(action, *findings)

    def _is_blocking(self, severity: Severity) -> bool:
        if self.block_at is None:
            return False
        return SEVERITY_RANK[severity] >= SEVERITY_RANK[self.block_at]
