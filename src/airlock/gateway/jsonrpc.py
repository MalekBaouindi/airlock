"""Raw JSON-RPC 2.0 envelopes.

The relay operates on untyped envelopes rather than typed MCP models, on
purpose. A gateway that only understands the methods listed in today's MCP
specification will silently drop or crash on the ones added tomorrow, and the
entire point of interposition is that it observes *everything* crossing the
boundary. Forwarding unknown methods is a security property here, not a
shortcut: an attacker who can make the gateway drop a message it does not
recognise has found an evasion primitive.

Reference: JSON-RPC 2.0 <https://www.jsonrpc.org/specification>
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

# JSON-RPC 2.0 reserves -32768..-32000 for the protocol. Codes outside that
# range (and below -32000 in practice) are implementation-defined; we use the
# conventional -32000 block so clients surface the reason rather than treating
# it as a transport failure.
CODE_PARSE_ERROR: Final = -32700
CODE_INVALID_REQUEST: Final = -32600
CODE_METHOD_NOT_FOUND: Final = -32601
CODE_INTERNAL_ERROR: Final = -32603

#: Emitted in place of a response the policy engine refused to let through.
#: Distinct from transport errors so that eval harnesses can count blocks
#: without pattern-matching on human-readable strings.
CODE_BLOCKED: Final = -32010

Id = int | str | None


class ProtocolError(ValueError):
    """A line could not be interpreted as a JSON-RPC envelope."""


@dataclass(frozen=True, slots=True)
class Message:
    """An untyped JSON-RPC envelope.

    Wrapping the raw mapping rather than deserialising into typed models keeps
    the relay forward-compatible: unknown fields survive a round trip
    untouched.
    """

    raw: dict[str, Any]

    # -- construction ------------------------------------------------------

    @classmethod
    def parse(cls, line: bytes | str) -> Message:
        text = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line
        text = text.strip()
        if not text:
            raise ProtocolError("empty line")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid JSON: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise ProtocolError(f"envelope must be an object, got {type(parsed).__name__}")
        if "jsonrpc" not in parsed:
            raise ProtocolError("missing 'jsonrpc' member")
        return cls(parsed)

    def to_bytes(self) -> bytes:
        """Serialise as a newline-delimited frame, as MCP stdio requires."""
        return (
            json.dumps(self.raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        )

    # -- shape -------------------------------------------------------------

    @property
    def id(self) -> Id:
        value = self.raw.get("id")
        if value is None or isinstance(value, (int, str)):
            return value
        # A malformed id is the peer's problem to notice, not a reason to crash
        # the relay; coercing keeps an unparseable envelope on the wire where
        # the other end can report it properly.
        return str(value)

    @property
    def method(self) -> str | None:
        value = self.raw.get("method")
        return value if isinstance(value, str) else None

    @property
    def params(self) -> dict[str, Any]:
        value = self.raw.get("params")
        return value if isinstance(value, dict) else {}

    @property
    def is_response(self) -> bool:
        """A response carries an id and neither method nor a bare result on a request."""
        return "method" not in self.raw and ("result" in self.raw or "error" in self.raw)

    @property
    def is_request(self) -> bool:
        return self.method is not None and "id" in self.raw

    @property
    def is_notification(self) -> bool:
        return self.method is not None and "id" not in self.raw

    @property
    def is_error(self) -> bool:
        return "error" in self.raw

    @property
    def result(self) -> Any:
        return self.raw.get("result")

    @property
    def error(self) -> dict[str, Any] | None:
        value = self.raw.get("error")
        return value if isinstance(value, dict) else None

    @property
    def tool_name(self) -> str | None:
        """Tool targeted by a ``tools/call`` request, if this is one."""
        if self.method != "tools/call":
            return None
        name = self.params.get("name")
        return name if isinstance(name, str) else None

    def __repr__(self) -> str:
        shape = (
            "request"
            if self.is_request
            else "notification"
            if self.is_notification
            else "response"
            if self.is_response
            else "unknown"
        )
        return f"<Message {shape} id={self.id!r} method={self.method!r}>"


def error_response(
    request_id: Id,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> Message:
    """Build a JSON-RPC error envelope addressed to ``request_id``."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return Message({"jsonrpc": "2.0", "id": request_id, "error": error})
