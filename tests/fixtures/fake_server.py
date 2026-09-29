"""A minimal stdio MCP server used to exercise the relay end to end.

Speaking real newline-delimited JSON-RPC keeps the proxy tests honest: the
relay is driven through the same wire format a real host would use, rather than
through a mock that could drift from the protocol.

Tool result text is supplied through the environment so a test can choose the
exact payload -- including one carrying invisible characters -- without any
special-case handling in the server.
"""

from __future__ import annotations

import json
import os
import sys

PROTOCOL_VERSION = "2025-06-18"


def reply(message_id: object, result: dict[str, object]) -> None:
    # ensure_ascii=False matters: the default would escape Unicode tag
    # characters into surrogate-pair literals, so a test asserting "the hidden
    # characters are not on the wire" would pass for the wrong reason. A real
    # server emits the bytes, so the fixture has to as well.
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}, ensure_ascii=False)
        + "\n"
    )
    sys.stdout.flush()


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = message.get("method")
        message_id = message.get("id")

        if method == "initialize":
            reply(
                message_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "0"},
                },
            )
        elif method == "tools/list":
            reply(
                message_id,
                {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": os.environ.get("FAKE_TOOL_DESC", "Reads a file."),
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                },
            )
        elif method == "tools/call":
            name = message.get("params", {}).get("name", "read_file")
            text = os.environ.get("FAKE_TOOL_TEXT", "ordinary file contents")
            reply(
                message_id,
                {
                    "content": [{"type": "text", "text": f"{name}: {text}"}],
                    "isError": False,
                },
            )
        elif method == "ping":
            reply(message_id, {})
        elif method is not None:
            # Mirrors a real server: unknown methods are refused with a
            # protocol error rather than ignored, which is what makes the
            # gateway's forward-compatibility claim testable.
            sys.stdout.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}",
                        },
                    }
                )
                + "\n"
            )
            sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
