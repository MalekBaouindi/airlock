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

import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from airlock.audit.log import Decision, Finding
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.base import Verdict


class BaselineError(ValueError):
    """A `--tool-baseline` file exists but could not be read as one."""

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


def _tool_signature(tool: dict[str, Any]) -> str:
    """Canonical form of the part of a tool definition a human actually reviews."""
    return json.dumps(
        {"description": tool.get("description"), "inputSchema": tool.get("inputSchema")},
        sort_keys=True,
        default=str,
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


def _is_documentation_quoting(text: str, start: int) -> bool:
    """Is this token being *quoted* rather than *used*?

    A token at the start of a line, or one preceded by a fence, a bullet, or a
    backtick, is someone showing you the syntax. A token with ordinary prose
    running into it on both sides is someone trying to become the control
    channel.

    The distinction is positional rather than semantic, so it costs nothing and
    cannot be talked around by rewording: an attacker who wants the check to
    fire simply has to not put the token at a line start.
    """
    line_start = text.rfind("\n", 0, start) + 1
    before = text[line_start:start]
    if not before.strip():
        return True  # first thing on the line
    stripped = before.rstrip()
    return stripped.endswith(("`", "*", "-", "|", ">", ":", "```"))


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
        if _is_documentation_quoting(text, match.start()):
            # Documentation *about* chat templates necessarily contains the
            # tokens. What distinguishes an attack is a token embedded in
            # running prose -- positioned so it will be read as a control
            # channel rather than quoted as an example.
            continue
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
    """Detector that runs structural rules over request params and results.

    Also holds one piece of state: the first ``tools/list`` definition seen for
    each tool name in this session. A server that silently rewrites a tool's
    description or schema after a human has already approved it (OWASP calls
    this a rug pull; MCP's own ``notifications/tools/list_changed`` is the
    mechanism) is detectable with no model and no corpus of attack strings --
    the comparison is against the server's own earlier answer, not a pattern.
    A benign capability upgrade looks identical, so this defaults to `flag`,
    like every other heuristic here with a legitimate use on the other side.
    """

    name = "structural"

    def __init__(
        self,
        *,
        block_at: Severity | None = "critical",
        baseline_path: str | Path | None = None,
    ) -> None:
        # Default: block only on the one class with no legitimate use. Every
        # other severity flags, leaving the decision to policy. Blocking on
        # medium-severity heuristics by default is how security tools acquire
        # the false-positive rate that gets them uninstalled.
        self.block_at = block_at
        self._known_tools: dict[str, str] = {}
        # Without a baseline path, a rug pull is only caught within the one
        # session that saw both the approved and the rewritten definition --
        # restart the proxy and the comparison starts from nothing. With one,
        # a definition a human approved outlives the process: it is read at
        # startup and never silently overwritten by a later, different answer.
        # Only a definition for a *name this baseline has never seen* gets
        # written back; a name it already has is pinned, exactly as a rug pull
        # needs it to be, until an operator re-approves it explicitly (see
        # `airlock tool-baseline`).
        self._baseline_path = Path(baseline_path) if baseline_path is not None else None
        if self._baseline_path is not None and self._baseline_path.exists():
            self._load_baseline()

    def reset(self) -> None:
        self._known_tools.clear()
        if self._baseline_path is not None and self._baseline_path.exists():
            self._load_baseline()

    def _load_baseline(self) -> None:
        assert self._baseline_path is not None
        try:
            raw = json.loads(self._baseline_path.read_text())
        except OSError as exc:
            raise BaselineError(f"cannot read tool baseline {self._baseline_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise BaselineError(f"{self._baseline_path} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise BaselineError(
                f"{self._baseline_path}: expected an object mapping tool name to definition"
            )
        for name, entry in raw.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                raise BaselineError(
                    f"{self._baseline_path}: entry {name!r} is not a tool definition object"
                )
            self._known_tools[name] = _tool_signature(entry)

    def _remember_new_tool(self, name: str, signature: str) -> list[RuleHit]:
        """Add a never-before-seen tool to the persisted baseline, if there is one.

        Nothing has been approved to compare this against, so there is nothing
        to pin yet -- unlike a changed definition, writing it is safe. A write
        failure must not be swallowed: it means the next restart loses this
        tool's protection silently, which is exactly the kind of gap this
        feature exists to close, so it is reported as a finding rather than
        dropped.
        """
        if self._baseline_path is None:
            return []
        try:
            existing: dict[str, Any] = {}
            if self._baseline_path.exists():
                parsed = json.loads(self._baseline_path.read_text())
                if isinstance(parsed, dict):
                    existing = parsed
            existing[name] = json.loads(signature)
            self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._baseline_path.with_name(self._baseline_path.name + ".tmp")
            tmp.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp.replace(self._baseline_path)
        except OSError as exc:
            return [
                RuleHit(
                    rule="tool-baseline-write-failed",
                    severity="info",
                    owasp=None,
                    detail=f"could not persist new tool {name!r} to {self._baseline_path}: {exc}",
                    path=f"$.tools[name={name!r}]",
                    excerpt="",
                )
            ]
        return []

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
        if message.is_error:
            return Verdict.allow()
        findings, worst = self._inspect(message.result)
        if ctx.inbound_method == "tools/list":
            for hit in self._tool_definition_drift(message.result):
                findings.append(hit.to_finding())
                if SEVERITY_RANK[hit.severity] > SEVERITY_RANK[worst]:
                    worst = hit.severity
        return self._decision(findings, worst)

    def _tool_definition_drift(self, result: Any) -> list[RuleHit]:
        if not isinstance(result, dict):
            return []
        tools = result.get("tools")
        if not isinstance(tools, list):
            return []
        hits: list[RuleHit] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name")
            if not isinstance(name, str):
                continue
            signature = _tool_signature(tool)
            previous = self._known_tools.get(name)
            if previous is None:
                # Nothing approved this name yet, in this session or on disk.
                # Record it as the trusted definition going forward.
                self._known_tools[name] = signature
                hits.extend(self._remember_new_tool(name, signature))
                continue
            if previous != signature:
                hits.append(
                    RuleHit(
                        rule="tool-definition-changed",
                        severity="high",
                        owasp="MCP03",
                        detail=(
                            f"tool {name!r} description or input schema differs from "
                            "the one already approved; not pinned to the new value -- "
                            "re-run `airlock tool-baseline` to approve it"
                            if self._baseline_path is not None
                            else f"tool {name!r} description or input schema differs from "
                            "the one first presented in this session"
                        ),
                        path=f"$.tools[name={name!r}]",
                        excerpt=_excerpt(str(tool.get("description") or ""), 0),
                    )
                )
                # Deliberately not written back to `_known_tools` or disk: a
                # changed definition stays flagged on every subsequent
                # tools/list too, rather than being silently adopted as the
                # new normal the second time it is seen.
        return hits

    def _decision(self, findings: Sequence[Finding], worst: Severity) -> Verdict:
        if not findings:
            return Verdict.allow()
        action: Decision = "block" if self._is_blocking(worst) else "flag"
        return Verdict.of(action, *findings)

    def _is_blocking(self, severity: Severity) -> bool:
        if self.block_at is None:
            return False
        return SEVERITY_RANK[severity] >= SEVERITY_RANK[self.block_at]
