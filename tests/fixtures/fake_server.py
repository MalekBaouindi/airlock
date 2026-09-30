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


def reply_error(message_id: object, message: str, code: int = -32601) -> None:
    sys.stdout.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}
        )
        + "\n"
    )
    sys.stdout.flush()


EXTRA_TOOL = {
    "name": "sync_artifact",
    "description": "Pushes an artifact somewhere.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "artifact": {"type": "string"},
            "target": {"type": "string"},
            "options": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "retries": {"type": "integer"},
                },
            },
        },
    },
}

READ_FILE = {
    "name": "read_file",
    "description": "Reads a file.",
    "inputSchema": {"type": "object", "properties": {}},
}

PING_TOOL = {
    "name": "ping_host",
    "description": "Checks a host.",
    "inputSchema": {
        "type": "object",
        "properties": {"host": {"type": "string"}},
    },
}


def _tools_page(message):
    """Answer tools/list, honouring the paging and failure modes under test.

    FAKE_TOOLS_EXTRA=1     adds a tool with a destination field named `target`, which
                           is in no list Airlock ships, plus a nested `options.url`.
    FAKE_TOOLS_PAGES=1     splits the tool list across two pages.
    FAKE_TOOLS_CURSOR=<c> always returns the same cursor, to exercise loop detection.
    FAKE_TOOLS_NO_LIST=1   refuses tools/list the way some servers do.
    """
    if os.environ.get("FAKE_TOOLS_NO_LIST") == "1":
        reply_error(message.get("id"), "Method not found", -32601)
        return {}
    tools = [dict(READ_FILE, description=os.environ.get("FAKE_TOOL_DESC", READ_FILE["description"]))]
    if os.environ.get("FAKE_TOOLS_EXTRA") == "1":
        tools.append(EXTRA_TOOL)
    if os.environ.get("FAKE_TOOLS_EXTRA") == "2":
        tools.append(PING_TOOL)
    if os.environ.get("FAKE_TOOLS_DEEP") == "1":
        node: dict = {"type": "string"}
        for _ in range(400):
            node = {"type": "object", "properties": {"n": node}}
        tools.append(
            {
                "name": "deep_tool",
                "description": "Nests far past anything a report should walk.",
                "inputSchema": {"type": "object", "properties": {"root": node}},
            }
        )
    forced = os.environ.get("FAKE_TOOLS_CURSOR")
    if forced:
        page = {"tools": tools, "nextCursor": forced}
        return page
    if os.environ.get("FAKE_TOOLS_PAGES") == "1":
        # The first page is not the whole surface. Stopping there would under-report,
        # which is the exact failure this command exists to remove.
        if message.get("params", {}).get("cursor") != "page-2":
            return {"tools": tools[:1], "nextCursor": "page-2"}
        return {"tools": tools[1:]}
    return {"tools": tools}


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
                    "protocolVersion": os.environ.get("FAKE_PROTOCOL", PROTOCOL_VERSION),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "0"},
                },
            )
        elif method == "tools/list":
            reply(message_id, _tools_page(message))
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
