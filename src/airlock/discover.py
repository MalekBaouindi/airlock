"""Ask a server what its tools actually accept, instead of guessing.

The policy layer can only govern a ``(tool, argument)`` surface somebody named.
The offline checker finds those names from the corpus, which means the corpus
decided the vocabulary, which means a server free to call an argument ``target``
gets a field Airlock never examines. That is the same shape of failure as the
provenance bug where the verdict depended on the hash seed: a field nobody looked
at is not a field that was found to be safe.

So this module does the one thing the corpus cannot, which is go and ask. It runs
the server, completes the MCP handshake, reads ``tools/list`` and reports the real
property names per tool.

Two limits are worth stating before the code rather than after it, because a
discovery tool that oversells itself is worse than no discovery tool:

**A schema cannot tell you what a field carries.** ``target`` may hold a webhook
URL, a shard number, or a colour. Nothing in ``inputSchema`` settles it. So this
module reports *every* property of *every* tool and marks the ones whose names
follow MCP convention, and a human still decides. The conventional marking is a
reading aid, not a verdict.

**This is not enforcement.** Running it is an operator decision, against a server
the operator chose, before writing a policy. The proxy stays a pure relay and
still decides only what the policy file says. A server that never implements
``tools/list`` is a server whose surface this cannot see, and the report says so
rather than guessing from tool names.
"""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import time
from collections.abc import Iterator, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from airlock import __version__

#: The protocol revision this client asks for. Servers are expected to answer with
#: a version they support; a mismatch is reported rather than papered over, since a
#: silent downgrade is how a client ends up reading a schema that is not there.
PROTOCOL_VERSION = "2025-06-18"

CLIENT_NAME = "airlock-discover"

DEFAULT_TIMEOUT = 30.0


class DiscoveryError(RuntimeError):
    """The server could not be asked, or would not answer coherently."""


#: Names that carry a destination somewhere else in the ecosystem often enough to
#: be worth flagging in a report. Deliberately broader than the policy checker's
#: ``RECIPIENT_ARGUMENTS``: that list is what gets *enforced* and so has to be
#: conservative, while this list only decides what to *show* a human, where a false
#: positive costs one glance.
_DESTINATION_NAME = re.compile(
    r"""(
        url | uri | href | link
        | host | hostname | domain | addr(ess)?
        | endpoint | target | dest(ination)?
        | webhook | callback
        | to | cc | bcc | recipient(s)?
        | attendee(s)?
        | bucket | path | file | folder
        | server | instance | org | account | project | repo
    )""",
    re.VERBOSE,
)


def looks_destination_shaped(name: str) -> bool:
    """Whether ``name`` follows convention for a field that points somewhere."""
    return bool(_DESTINATION_NAME.search(name.lower()))


@dataclass(frozen=True, slots=True)
class ToolSurface:
    """One tool as the server describes it."""

    name: str
    description: str
    #: (property name, declared type) in schema order, nested objects flattened to
    #: ``parent.child`` because that is where the interesting arguments live and a
    #: flat list hides them.
    properties: tuple[tuple[str, str], ...] = ()

    @property
    def destination_shaped(self) -> tuple[str, ...]:
        """Properties whose names follow destination convention."""
        return tuple(name for name, _ in self.properties if looks_destination_shaped(name))


@dataclass(frozen=True, slots=True)
class Discovery:
    """Everything one ``tools/list`` walk found, plus what it could not find."""

    server_name: str
    server_version: str
    protocol_version: str
    tools: tuple[ToolSurface, ...]
    notes: tuple[str, ...] = ()

    @property
    def surfaces(self) -> tuple[tuple[str, str], ...]:
        """Every (tool, property) pair, for checking against a policy."""
        return tuple(
            (tool.name, prop) for tool in self.tools for prop, _ in tool.properties
        )


# -- the wire ------------------------------------------------------------------


@dataclass(slots=True)
class _Server:
    """A spawned MCP server, with the process cleaned up whatever happens."""

    argv: Sequence[str]
    timeout: float
    _process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    _buffer: bytearray = field(default_factory=bytearray, repr=False)
    _lines: int = field(default=0, repr=False)

    def __enter__(self) -> _Server:
        try:
            self._process = subprocess.Popen(
                list(self.argv),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,  # the server's diagnostics belong on our stderr
            )
        except FileNotFoundError as exc:
            raise DiscoveryError(f"cannot run {self.argv[0]!r}: {exc}") from exc
        except OSError as exc:
            raise DiscoveryError(f"cannot start {self.argv[0]!r}: {exc}") from exc
        return self

    def __exit__(self, *_exc: object) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        if process.stdin is not None:
            # A server that has already gone away has closed its end; the process
            # table is what still needs cleaning up, not the stream.
            with suppress(OSError):
                process.stdin.close()
        try:
            process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            # A server that will not exit on a closed stdin gets killed. Leaving it
            # running would outlive the command that was inspecting it.
            process.kill()
            process.wait(timeout=self.timeout)

    def send(self, payload: dict[str, Any]) -> None:
        assert self._process is not None and self._process.stdin is not None
        self._process.stdin.write(json.dumps(payload).encode() + b"\n")
        self._process.stdin.flush()

    def read_line(self) -> bytes:
        """One line, or a diagnosis. Bounded by ``timeout`` for the whole call.

        Reads the raw descriptor and keeps its own line buffer instead of calling
        ``select`` on the ``BufferedReader`` and then ``readline()``. The two do not
        compose: ``select`` answers for the file descriptor, so it cannot see a line
        that is already sitting in Python's buffer, and a reader built that way can
        wait out a full timeout on a response it is holding in memory. Checking the
        buffer first removes the possibility rather than relying on timing.

        The deadline is also carried across reads instead of restarting per read, so
        a server dribbling a line out one byte at a time gets one timeout in total
        rather than an unbounded hold on the command.
        """
        assert self._process is not None and self._process.stdout is not None
        fd = self._process.stdout.fileno()
        deadline = time.monotonic() + self.timeout
        while True:
            if b"\n" in self._buffer:
                line, _, rest = self._buffer.partition(b"\n")
                self._buffer = bytearray(rest)
                self._lines += 1
                return bytes(line) + b"\n"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiscoveryError(self._timeout_report())
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                raise DiscoveryError(
                    f"{self.argv[0]} closed its output after {self._lines} line(s) and "
                    f"{self._state()}. A server that exits rather than answering, or that "
                    f"expects a transport other than stdio, cannot be asked what its "
                    f"tools accept."
                )
            self._buffer.extend(chunk)

    def _state(self) -> str:
        """The child's liveness, phrased so it distinguishes the two situations."""
        process = self._process
        assert process is not None
        code = process.poll()
        if code is None:
            return f"is still running (pid {process.pid})"
        return f"exited with status {code}"

    def _timeout_report(self) -> str:
        """Say enough about a silent server that the next one is explainable.

        A timeout on its own is the least actionable message a command can print: it
        does not distinguish a server that is thinking, a server that is waiting for
        something else entirely, and a child that died before it wrote anything. So
        the report carries the child's liveness and how much arrived.
        """
        received = f", received {self._lines} line(s)"
        if not self._lines:
            received += " -- it never answered the handshake"
        return (
            f"{self.argv[0]} did not answer within {self.timeout:g}s and "
            f"{self._state()}{received}. A server that will not talk cannot be asked what its tools "
            f"accept, and the honest report is that the surface was not seen."
        )


def _ask(server: _Server, request_id: int, method: str, params: dict[str, Any]) -> Any:
    """Send one request and return its result, tolerating interleaved traffic.

    A server is allowed to send requests and notifications of its own, so the
    reader skips anything that is not the response it is waiting for rather than
    assuming its own traffic is the only traffic.
    """
    server.send(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
    )
    for _ in range(64):
        line = server.read_line()
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            # stdout is the wire. A server that prints a banner or a log line there
            # is not merely untidy, it has broken the protocol, and saying so beats
            # handing an operator a JSON traceback about line 1 column 1.
            raise DiscoveryError(
                f"the server wrote something to stdout that is not JSON: "
                f"{line[:120]!r}. stdout is the transport, so this server cannot be "
                f"asked over stdio -- its diagnostics belong on stderr."
            ) from exc
        if raw.get("id") != request_id or "method" in raw:
            continue
        if "error" in raw:
            error = raw["error"]
            raise DiscoveryError(
                f"{method} failed: {error.get('message', error)!r} "
                f"(code {error.get('code', '?')})"
            )
        return raw.get("result")
    raise DiscoveryError(f"{method} was never answered")


def _flatten(
    properties: dict[str, Any], prefix: str = ""
) -> Iterator[tuple[str, str]]:
    """Yield (dotted name, type) for a schema's properties, descending one level.

    Nested objects matter here: a policy that names ``tool.url`` does nothing about
    ``tool.options.url``, and a server that puts the webhook inside ``options`` is
    ordinary.
    """
    for name, schema in properties.items():
        path = f"{prefix}{name}"
        if not isinstance(schema, dict):
            yield path, "unknown"
            continue
        declared = schema.get("type")
        kind = declared if isinstance(declared, str) else "object?" if "properties" in schema else "?"
        yield path, kind
        if isinstance(schema.get("properties"), dict):
            yield from _flatten(schema["properties"], prefix=f"{path}.")


def _tools_from(result: Any) -> tuple[ToolSurface, ...]:
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        raise DiscoveryError("tools/list did not return a 'tools' array")
    tools: list[ToolSurface] = []
    for entry in result["tools"]:
        if not isinstance(entry, dict):
            continue
        schema = entry.get("inputSchema")
        properties = schema.get("properties") if isinstance(schema, dict) else None
        tools.append(
            ToolSurface(
                name=str(entry.get("name", "<unnamed>")),
                description=str(entry.get("description", "")).strip(),
                properties=tuple(_flatten(properties)) if isinstance(properties, dict) else (),
            )
        )
    return tuple(tools)


def fetch(argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> Discovery:
    """Spawn ``argv``, complete the handshake and return its tool surface."""
    if not argv:
        raise DiscoveryError("no server command given")
    notes: list[str] = []
    with _Server(argv=argv, timeout=timeout) as server:
        result = _ask(
            server,
            1,
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": __version__},
            },
        )
        if not isinstance(result, dict):
            raise DiscoveryError("initialize did not return an object")
        info = result.get("serverInfo")
        server_name = str(info.get("name", "unknown")) if isinstance(info, dict) else "unknown"
        server_version = (
            str(info.get("version", "unknown")) if isinstance(info, dict) else "unknown"
        )
        negotiated = str(result.get("protocolVersion", "unknown"))
        if negotiated != PROTOCOL_VERSION:
            notes.append(
                f"server negotiated protocol {negotiated}, this client asked for "
                f"{PROTOCOL_VERSION}. The tool list below may not match what the "
                f"server would serve its own clients."
            )
        server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        # tools/list is paginated. Stopping at the first page would under-report the
        # surface, and under-reporting here is the exact failure this tool exists to
        # remove, so it follows the cursor and says so when it stops.
        tools: list[ToolSurface] = []
        cursor: str | None = None
        for _ in range(100):
            params = {"cursor": cursor} if cursor else {}
            page = _ask(server, 2 + len(tools), "tools/list", params)
            if not isinstance(page, dict):
                raise DiscoveryError("tools/list did not return an object")
            tools.extend(_tools_from(page))
            nxt = page.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                break
            if nxt == cursor:
                notes.append(f"tools/list repeated cursor {nxt!r}; stopped to avoid a loop")
                break
            cursor = nxt
        else:
            notes.append("tools/list did not finish paginating; the surface may be partial")

    if not tools:
        notes.append("the server advertises no tools")
    return Discovery(
        server_name=server_name,
        server_version=server_version,
        protocol_version=negotiated,
        tools=tuple(tools),
        notes=tuple(notes),
    )


# -- reporting -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Gap:
    """A destination-shaped field the policy file does not govern."""

    tool: str
    argument: str
    #: Whether the name follows MCP convention, or whether it merely looked ordinary
    #: and is being shown for a human to judge. Both are reported; only one is a
    #: convention-based flag.
    conventional: bool

    @property
    def label(self) -> str:
        return f"{self.tool}.{self.argument}"


def gaps_against(discovery: Discovery, policy: Any, *, only_conventional: bool = False) -> list[Gap]:
    """Report (tool, argument) pairs a policy does not govern.

    ``only_conventional`` narrows the report to names that follow destination
    convention. Left off, the report includes every argument the policy does not
    mention, because the whole point is to show a human something they had not
    considered and a schema cannot tell us which of those matter.
    """
    covered = {(tool, argument) for tool, arguments in policy.surfaces.items() for argument in arguments}
    gaps: list[Gap] = []
    for tool in discovery.tools:
        for argument, _ in tool.properties:
            if (tool.name, argument) in covered:
                continue
            conventional = looks_destination_shaped(argument)
            if only_conventional and not conventional:
                continue
            gaps.append(Gap(tool.name, argument, conventional))
    return gaps


def report(discovery: Discovery, gaps: Sequence[Gap] | None) -> str:
    """Render the discovery and its gaps as plain text.

    ``gaps`` of ``None`` means coverage was not checked at all, which is a
    different statement from "checked and found none" and must not be printed as
    though the policy had cleared every argument.
    """
    lines = [
        f"{discovery.server_name} {discovery.server_version} "
        f"(protocol {discovery.protocol_version})",
        "",
    ]
    for tool in discovery.tools:
        lines.append(f"  {tool.name}")
        if tool.description:
            lines.append(f"    {tool.description.splitlines()[0]}")
        for argument, kind in tool.properties:
            mark = "~" if looks_destination_shaped(argument) else " "
            lines.append(f"   {mark} {argument}: {kind}")
        lines.append("")
    if not discovery.tools:
        lines.append("  (no tools advertised)")
        lines.append("")

    lines.append(
        f"{len(discovery.surfaces)} argument(s) across {len(discovery.tools)} tool(s); "
        f"~ marks a name that follows destination convention."
    )
    lines.append("")
    lines.append("A schema does not say what a field carries. '~' is convention, not")
    lines.append("evidence, and a field with an ordinary name can still point somewhere.")
    lines.append("")

    if gaps is None:
        lines.append("No policy file, so coverage was not checked.")
    elif gaps:
        lines.append(f"{len(gaps)} argument(s) this policy does not govern:")
        for gap in gaps:
            mark = "~" if gap.conventional else " "
            lines.append(f"   {mark} {gap.label}")
    else:
        lines.append("Every argument this server advertises is named in the policy.")

    for note in discovery.notes:
        lines.append("")
        lines.append(f"note: {note}")
    return "\n".join(lines)
