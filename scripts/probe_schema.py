"""Hostile input probe for the schema parser in airlock.discover.

`discover` parses JSON that an arbitrary MCP server supplied, which makes it the
newest untrusted-input parser in the project. Everything here is something a
server could legitimately -- or maliciously -- put on the wire, checked to see
whether it produces a verdict or a traceback.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from airlock.discover import DiscoveryError, _tools_from


def deep(depth: int) -> dict:
    node: dict = {"type": "string"}
    for _ in range(depth):
        node = {"type": "object", "properties": {"n": node}}
    return {"type": "object", "properties": {"root": node}}


CASES: dict[str, object] = {
    "no_schema_at_all": {"name": "t"},
    "schema_is_null": {"name": "t", "inputSchema": None},
    "schema_is_a_list": {"name": "t", "inputSchema": [1, 2, 3]},
    "schema_is_a_string": {"name": "t", "inputSchema": "object"},
    "properties_is_null": {"name": "t", "inputSchema": {"type": "object", "properties": None}},
    "properties_is_a_list": {
        "name": "t",
        "inputSchema": {"type": "object", "properties": ["a", "b"]},
    },
    "property_value_is_a_string": {
        "name": "t",
        "inputSchema": {"type": "object", "properties": {"a": "string"}},
    },
    "property_value_is_null": {
        "name": "t",
        "inputSchema": {"type": "object", "properties": {"a": None}},
    },
    "no_name": {"inputSchema": {"type": "object", "properties": {}}},
    "name_is_a_dict": {"name": {"x": 1}, "inputSchema": {"type": "object", "properties": {}}},
    "deeply_nested_50": {"name": "t", "inputSchema": deep(50)},
    "deeply_nested_500": {"name": "t", "inputSchema": deep(500)},
    "deeply_nested_2000": {"name": "t", "inputSchema": deep(2000)},
    "deeply_nested_10000": {"name": "t", "inputSchema": deep(10000)},
    "type_is_a_list": {
        "name": "t",
        "inputSchema": {"type": ["string", "null"], "properties": {"a": {}}},
    },
    "thousands_of_properties": {
        "name": "t",
        "inputSchema": {
            "type": "object",
            "properties": {f"p{i}": {"type": "string"} for i in range(5000)},
        },
    },
    "unicode_and_control_names": {
        "name": "\u00e9\u4e2d\U0001f600",
        "inputSchema": {
            "type": "object",
            "properties": {"tärget": {"type": "string"}, "url": {"type": "string"}},
        },
    },
    "entry_is_not_an_object": "not even a dict",
    "one_bad_entry_among_good": "SENTINEL",
    "unnamed_tool": {"inputSchema": {"type": "object", "properties": {"url": {}}}},
    "tools_is_not_a_list": "nope",
    "tools_is_empty": {"tools": []},
}


def main() -> int:
    crashes = 0
    for label, payload in CASES.items():
        if payload == "SENTINEL":
            result = {"tools": ["junk", {"name": "good", "inputSchema": None}, 42]}
        else:
            result = payload if label == "tools_is_not_a_list" else {"tools": [payload]}
        try:
            tools, notes = _tools_from(result)
            shown = sum(len(t.properties) for t in tools)
            note = f" | {len(notes)} note(s)" if notes else ""
            print(f"ok       {label:28} {len(tools)} tool(s), {shown} argument(s){note}")
        except DiscoveryError as exc:
            print(f"refused  {label:28} {exc}")
        except RecursionError:
            crashes += 1
            print(f"CRASH    {label:28} RecursionError -- traceback, not a diagnosis")
        except TimeoutError:
            crashes += 1
            print(f"CRASH    {label:28} TimeoutError")
        except Exception as exc:
            crashes += 1
            print(f"CRASH    {label:28} {type(exc).__name__}: {exc}")
    print(f"\n{crashes} crash(es)")
    return 1 if crashes else 0


if __name__ == "__main__":
    raise SystemExit(main())
