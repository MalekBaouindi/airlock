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

    def note_request(self, message: Message) -> None:
        """Record an outgoing request so its response can be attributed later."""
        method = message.method
        if method is None:
            return
        self.methods_seen[method] += 1
        if message.is_request:
            self._pending[message.id] = method

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
        return outstanding
