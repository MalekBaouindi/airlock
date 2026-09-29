from __future__ import annotations

import json

import pytest

from airlock.gateway.jsonrpc import (
    CODE_BLOCKED,
    Message,
    ProtocolError,
    error_response,
)


def test_parses_a_request() -> None:
    msg = Message.parse(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    assert msg.is_request
    assert not msg.is_response
    assert msg.id == 1
    assert msg.method == "tools/list"


def test_parses_a_notification() -> None:
    msg = Message.parse('{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert msg.is_notification
    assert msg.id is None


def test_parses_a_result() -> None:
    msg = Message.parse('{"jsonrpc":"2.0","id":3,"result":{"ok":true}}')
    assert msg.is_response
    assert msg.result == {"ok": True}
    assert not msg.is_error


def test_parses_an_error() -> None:
    msg = Message.parse('{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"x"}}')
    assert msg.is_error
    assert msg.error == {"code": -32000, "message": "x"}


def test_tool_name_only_on_tools_call() -> None:
    call = Message.parse(
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}'
    )
    assert call.tool_name == "read_file"
    assert call.params["arguments"]["path"] == "/etc/passwd"

    other = Message.parse('{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    assert other.tool_name is None


def test_round_trip_preserves_unknown_fields() -> None:
    """Forward-compatibility: an envelope field the gateway has never heard of
    must survive the relay untouched, or the gateway becomes an evasion vector."""
    raw = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "some/future/method",
        "params": {"futureField": {"nested": [1, 2, 3]}},
        "meta": {"traceId": "abc"},
    }
    recovered = json.loads(Message(raw).to_bytes())
    assert recovered == raw


def test_rejects_malformed_input() -> None:
    for bad in [b"", b"   ", b"not json", b"[1,2,3]", b'{"id":1}', b"null"]:
        with pytest.raises(ProtocolError):
            Message.parse(bad)


def test_error_response_shape() -> None:
    msg = error_response(7, CODE_BLOCKED, "Blocked by airlock policy", {"reason": "x"})
    assert msg.id == 7
    assert msg.is_error
    assert msg.error is not None
    assert msg.error["code"] == CODE_BLOCKED
    assert msg.error["data"] == {"reason": "x"}


def test_error_response_omits_absent_data() -> None:
    msg = error_response(7, -1, "no data")
    assert msg.error is not None
    assert "data" not in msg.error
