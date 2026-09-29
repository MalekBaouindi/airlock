"""Per-connection session state for the relay.

A response envelope in JSON-RPC carries only an ``id``; it does not say which
method produced it. Since the entire threat model here is about *tool results*
specifically -- the runtime channel OWASP names as the unguarded trust gap --
the relay has to reconstruct that correlation itself. Without it the gateway
cannot tell a ``tools/call`` result apart from a ``tools/list`` result, and
would either inspect nothing or inspect the wrong things.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from dataclasses import dataclass, field

from airlock.gateway.jsonrpc import Id, Message


@dataclass
class SessionContext:
    """Mutable state for one host<->upstream connection."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)
    methods_seen: Counter[str] = field(default_factory=Counter)

    #: request id -> method, so responses can be attributed. Populated on the
    #: request leg and consumed on the response leg.
    _pending: dict[Id, str] = field(default_factory=dict)

    #: request id -> tool name, for `tools/call` only. Kept beside `_pending`
    #: rather than derived from it because the pending map holds methods: a
    #: detector asking "which tool produced this result?" wants the tool, and
    #: the only way to answer is to have recorded it.
    _pending_tools: dict[Id, str] = field(default_factory=dict)

    #: The method that produced the response currently being inspected. Set by
    #: :meth:`note_response` *before* detectors run, and readable without
    #: consuming -- an inspector that needs the correlation cannot be the same
    #: call that destroys it, or every detector after the first would see None.
    inbound_method: str | None = None

    #: Same, for the tool name. Whether a payload came from `web_fetch` or from
    #: `read_file` is not decoration: content fetched from a third party and
    #: content read off the local disk are not equally untrusted, and a judge
    #: told only that "some tool returned text" has to guess.
    inbound_tool: str | None = None

    def note_request(self, message: Message) -> None:
        """Record an outgoing request so its response can be attributed later."""
        method = message.method
        if method is None:
            return
        self.methods_seen[method] += 1
        if message.is_request:
            self._pending[message.id] = method
            tool = message.tool_name
            if tool is not None:
                self._pending_tools[message.id] = tool

    def settle(self, request_id: Id) -> None:
        """Mark a request as answered by the gateway itself.

        A blocked request never reaches the upstream, so no response will ever
        arrive for it -- but the relay has already answered the host with a
        synthetic error. Leaving it pending means the abandoned-request sweep
        treats it as unanswered and sends a *second* error for the same id, so
        the host sees one request produce two responses. JSON-RPC has no way to
        express that, and a client that trusts the first error is now reading a
        reply it never asked for.
        """
        self._pending.pop(request_id, None)
        self._pending_tools.pop(request_id, None)

    def note_response(self, message: Message) -> str | None:
        """Expose a response's originating method to detectors.

        Non-destructive. Pair it with :meth:`method_for_response` to consume the
        correlation once the message has been processed.
        """
        if not message.is_response:
            return None
        self.inbound_method = self._pending.get(message.id)
        self.inbound_tool = self._pending_tools.get(message.id)
        return self.inbound_method

    def method_for_response(self, message: Message) -> str | None:
        """Return the method that produced this response, then forget it."""
        if not message.is_response:
            return None
        return self._pending.pop(message.id, None)

    def peek_method_for_response(self, message: Message) -> str | None:
        """Like :meth:`method_for_response` but leaves the correlation intact."""
        if not message.is_response:
            return None
        return self._pending.get(message.id)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def drain_pending(self) -> list[Id]:
        """Return and forget every request still awaiting a response.

        Used when the upstream dies: a request that will never be answered has
        to be failed explicitly, or the host waits on a reply that cannot come.
        """
        outstanding = list(self._pending)
        self._pending.clear()
        self._pending_tools.clear()
        return outstanding
