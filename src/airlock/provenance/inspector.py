"""The provenance inspector: sources, sinks, and the decision between them.

This is the layer that the evaluation credits with six of the open misses, and
the reason it is worth building separately from the structural detector is
that it needs state the other does not have. An attack that drips a secret one
character per request, or reads a value in one turn and posts it three turns
later, is invisible to any analyzer that sees one message in isolation.

Three rules, each corresponding to a shape the corpus actually contains:

``egress-tainted-value``
    A fragment of known secret material appears in an outbound payload.

``egress-sharded``
    Individually unremarkable fragments accumulate, in order, into a known
    atom. No single request is worth stopping.

``egress-untrusted-destination`` / ``egress-memory-indirection``
    The *destination* was chosen by untrusted content, and is external. Nothing
    leaked yet; the agent is being aimed.

That last pair is where the interesting false-positive boundary sits, and it is
deliberately drawn with a real trust anchor rather than a heuristic. A host
under a reserved suffix (``.internal``, ``.local``) or a private address cannot
be registered by an outside attacker, so a config file pointing metrics at
``metrics.internal`` is a legitimate configuration and is allowed through --
while the runbook that redirects an auth endpoint to a partner CDN is not. The
corpus contains both, and they are otherwise the same transcript shape.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from airlock.audit.log import Finding
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.base import Verdict
from airlock.provenance.model import (
    SENSITIVE_PATH,
    EgressMatch,
    TaintStore,
    hosts_in,
    strings_in,
)

#: Argument names whose value is sent to somebody else. A call carrying one of
#: these is a sink regardless of what the tool is called.
EGRESS_ARGUMENTS = frozenset(
    {
        "body",
        "data",
        "payload",
        "content",
        "text",
        "message",
        "comment",
        "notes",
        "headers",
        "authorization",
        "to",
        "cc",
        "bcc",
        "recipients",
        "attendees",
        "subject",
        "description",
        "title",
        "webhook",
        "channel",
        "query",
    }
)

#: Argument names that name a destination.
DESTINATION_ARGUMENTS = ("url", "endpoint", "to", "webhook", "uri", "destination")

#: Tools that transmit by construction. A tool with no outbound-looking
#: argument is not assumed to be a sink; guessing from the name alone is how a
#: gateway starts blocking `read_file`.
EGRESS_TOOLS = re.compile(
    r"(?i)^(http|https|curl|post|send|mail|email|slack|webhook|publish|upload|"
    r"notify|create_(?:calendar_)?event|post_?message|share)"
)

#: Memory tools, and where they store. ``memory_write(key=..., value=...)`` is
#: the only shape the corpus uses, but ``memory.set`` is common enough in the
#: wild to be worth accepting.
_MEMORY_WRITE = re.compile(r"(?i)memory[._]?(?:write|set|store|put)")

_OWASP = "MCP10"


def _destination_of(arguments: dict[str, Any]) -> str:
    for key in DESTINATION_ARGUMENTS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _host_of(destination: str) -> str:
    hosts = hosts_in(destination)
    return next(iter(hosts), "")


class ProvenanceInspector:
    """Tracks taint across a session and blocks it at outbound sinks."""

    name = "provenance"

    def __init__(
        self, *, block_at: Literal["info", "low", "medium", "high", "critical"] = "critical"
    ) -> None:
        self._block_at = block_at
        self._store = TaintStore()
        #: The request currently awaiting a response, so a result knows what it
        #: is a result *of* and which request it answers.
        self._inflight: dict[str, tuple[str, bool]] = {}

    @property
    def store(self) -> TaintStore:
        return self._store

    def reset(self) -> None:
        self._store = TaintStore()
        self._inflight.clear()

    # -- request leg --------------------------------------------------------

    def inspect_request(self, message: Message, ctx: SessionContext) -> Verdict:
        if message.method != "tools/call":
            return Verdict.allow()
        params = message.params if isinstance(message.params, dict) else {}
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return Verdict.allow()
        key = str(message.id)

        if _MEMORY_WRITE.search(name):
            self._store.note_memory_write(
                str(arguments.get("key", "")), str(arguments.get("value", ""))
            )
            return Verdict.allow()

        self._inflight[key] = (name, is_sensitive_request(name, arguments))
        return self._check_sink(name, arguments)

    # -- response leg -------------------------------------------------------

    def inspect_response(self, message: Message, ctx: SessionContext) -> Verdict:
        if ctx.inbound_method != "tools/call":
            return Verdict.allow()
        tool, sensitive = self._inflight.pop(str(message.id), ("", False))
        if not tool:
            return Verdict.allow()
        if message.is_error:
            return self._record_denial(tool, message)
        return self._record_result(tool, message, sensitive)

    # -- sources ------------------------------------------------------------

    def _record_result(self, tool: str, message: Message, sensitive: bool) -> Verdict:
        result = message.result if isinstance(message.result, dict) else {}
        text = "\n".join(strings_in(result))
        if not text:
            return Verdict.allow()
        # Sensitivity is a property of the *request*: what was asked for. A
        # redacted or empty result is still a result about a secret, and the
        # atoms have to exist for the fragment rule to have anything to match.
        self._store.note_read(f"{tool}()", text, sensitive=sensitive)
        self._note_pointers(text)
        return Verdict.allow()

    def _record_denial(self, tool: str, message: Message) -> Verdict:
        error = message.error if isinstance(message.error, dict) else {}
        text = str(error.get("message", ""))
        if not text:
            return Verdict.allow()
        self._store.note_denial(f"{tool}() denial", text)
        return Verdict.allow()

    def _note_pointers(self, text: str) -> None:
        """Untrusted content that names a memory key makes that key suspect."""
        for key in self._store.memory:
            if key in text:
                self._store.note_pointer(key)

    # -- sinks --------------------------------------------------------------

    def _check_sink(self, tool: str, arguments: dict[str, Any]) -> Verdict:
        payload = "\n".join(str(arguments[key]) for key in EGRESS_ARGUMENTS if key in arguments)
        destination = _destination_of(arguments)
        is_sink = bool(payload) and (bool(EGRESS_TOOLS.search(tool)) or destination != "")
        if not is_sink:
            return Verdict.allow()

        matches: list[EgressMatch] = []
        if payload:
            # Record before matching: a fragment is only interesting as part of
            # the stream it is being appended to.
            self._store.record_outbound(payload)
            matches.extend(self._store.match_fragments(payload))
            for source in self._store.secret_sources():
                rebuilt = self._store.match_reconstruction(source)
                if rebuilt is not None:
                    matches.append(rebuilt)
        host = _host_of(destination)
        if host:
            leak = self._store.match_destination(host)
            if leak is not None:
                matches.append(leak)

        if not matches:
            return Verdict.allow()
        verdict = self._verdict(matches, tool)
        # Roll back a refused *complete* leak, but keep fragments.
        #
        # A blocked request did not leave the process, so keeping its whole
        # secret resident would make every later sink in the session match --
        # the gateway would block all egress for the rest of the conversation,
        # which is the false positive that gets a proxy switched back off.
        #
        # Fragments are the exception. They are the drip, and the attacker
        # resumes after a block, so the recorded characters are what let the
        # resumed request be recognised instead of granted a clean slate.
        if verdict.action == "block" and any(
            m.rule in ("egress-tainted-value", "egress-sharded") for m in matches
        ):
            self._store.rollback_outbound(payload)
        return verdict

    def _verdict(self, matches: list[EgressMatch], tool: str) -> Verdict:
        seen: set[str] = set()
        findings: list[Finding] = []
        for match in matches:
            if match.rule in seen:
                continue
            seen.add(match.rule)
            findings.append(
                Finding(
                    rule=match.rule,
                    severity="critical",
                    detail=match.detail,
                    owasp=_OWASP,
                )
            )
        return Verdict.of("block" if self._block_at == "critical" else "flag", *findings)


def is_sensitive_request(name: str, arguments: dict[str, Any]) -> bool:
    """Does this call ask for a secret store?"""
    if not re.search(r"(?i)(read|get|fetch|cat|open|stat|ls|list|download)", name):
        return False
    return any(
        isinstance(value, str) and SENSITIVE_PATH.search(value) for value in arguments.values()
    )


__all__ = ["ProvenanceInspector", "is_sensitive_request"]
