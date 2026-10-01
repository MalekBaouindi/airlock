from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from airlock.cli import main
from airlock.discover import (
    Discovery,
    DiscoveryError,
    ToolSurface,
    _Server,
    fetch,
    gaps_against,
    looks_destination_shaped,
    report,
)
from airlock.inspect.policy import RECIPIENT_ARGUMENTS, Policy, Surface

FAKE = str(Path(__file__).resolve().parent / "fixtures" / "fake_server.py")
SERVER = [sys.executable, FAKE]


def discover(monkeypatch: pytest.MonkeyPatch, **env: str) -> Discovery:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return fetch(SERVER, timeout=15.0)


class TestTheBlindSpot:
    def test_it_finds_a_destination_field_the_enforced_list_never_could(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The point is not that 'target' is unknown to every list here -- the report
        # regex flags it. The point is that it is absent from RECIPIENT_ARGUMENTS,
        # the list that gets *enforced*, so the corpus could never surface it and a
        # policy written from the corpus cannot govern it. Only asking can.
        assert "target" not in RECIPIENT_ARGUMENTS
        assert looks_destination_shaped("target")
        found = discover(monkeypatch, FAKE_TOOLS_EXTRA="1")
        assert "sync_artifact.target" in {
            f"{tool.name}.{name}" for tool in found.tools for name, _ in tool.properties
        }

    def test_it_descends_into_nested_objects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A policy naming tool.url says nothing about tool.options.url, and a server
        # that puts the webhook inside options is ordinary.
        found = discover(monkeypatch, FAKE_TOOLS_EXTRA="1")
        surface = next(t for t in found.tools if t.name == "sync_artifact")
        names = {name for name, _ in surface.properties}
        assert "options.url" in names
        assert "options.retries" in names

    def test_it_reports_a_server_that_never_answers_tools_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with pytest.raises(DiscoveryError, match=r"closed its output|failed"):
            discover(monkeypatch, FAKE_TOOLS_NO_LIST="1")


class TestPagination:
    def test_it_follows_the_cursor_to_the_end(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Stopping at page one would under-report the surface, which is the same
        # failure as not asking at all.
        found = discover(monkeypatch, FAKE_TOOLS_EXTRA="1", FAKE_TOOLS_PAGES="1")
        assert [t.name for t in found.tools] == ["read_file", "sync_artifact"]

    def test_a_repeating_cursor_does_not_loop_forever(self, monkeypatch: pytest.MonkeyPatch) -> None:
        found = discover(monkeypatch, FAKE_TOOLS_CURSOR="stuck")
        assert found.tools
        assert any("repeated cursor" in note for note in found.notes)


class TestCoverage:
    def _discovery(self) -> Discovery:
        return Discovery(
            server_name="s",
            server_version="0",
            protocol_version="2025-06-18",
            tools=(
                ToolSurface(
                    "send_email",
                    "",
                    (("to", "string"), ("body", "string"), ("subject", "string")),
                ),
            ),
        )

    def test_it_flags_conventional_and_ordinary_names_separately(self) -> None:
        policy = Policy(surfaces={"send_email": {"to": Surface(allow=(), anywhere=False)}})
        gaps = gaps_against(self._discovery(), policy)
        labelled = {gap.label: gap.conventional for gap in gaps}
        # 'to' is governed, so absent; 'body' and 'subject' are not governed and are
        # not conventional, so they are listed for a human without being called gaps.
        assert labelled == {"send_email.body": False, "send_email.subject": False}

    def test_conventional_only_narrows_the_report(self) -> None:
        discovery = Discovery(
            server_name="s",
            server_version="0",
            protocol_version="2025-06-18",
            tools=(ToolSurface("t", "", (("target", "string"), ("retries", "integer"))),),
        )
        policy = Policy()
        assert {g.label for g in gaps_against(discovery, policy)} == {"t.target", "t.retries"}
        assert {g.label for g in gaps_against(discovery, policy, only_conventional=True)} == {
            "t.target"
        }


class TestHonesty:
    def test_unchecked_coverage_is_not_reported_as_full_coverage(self) -> None:
        # "No policy, so coverage was not checked" and "the policy covers everything"
        # are different sentences, and conflating them is the failure this tool is
        # most likely to introduce.
        discovery = Discovery("s", "0", "p", (ToolSurface("t", "", (("target", "string"),)),))
        assert "No policy file" in report(discovery, None)
        assert "does not govern" not in report(discovery, None)

    def test_it_says_a_schema_cannot_say_what_a_field_carries(self) -> None:
        discovery = Discovery("s", "0", "p", (ToolSurface("t", "", (("target", "string"),)),))
        text = report(discovery, gaps_against(discovery, Policy()))
        assert "does not say what a field carries" in text
        assert "convention, not" in text

    def test_a_protocol_mismatch_is_surfaced_not_papered_over(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FAKE_PROTOCOL", "1999-01-01")
        found = discover(monkeypatch)
        assert any("negotiated protocol 1999-01-01" in note for note in found.notes)


class TestProcessHygiene:
    def test_a_server_that_will_not_exit_is_killed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Leaving it running would mean the command that was inspecting it outlives
        # its own inspection.
        before = subprocess.run(["pgrep", "-f", "hang_server"], capture_output=True)
        assert before.returncode != 0 or not before.stdout

    def test_it_reports_a_server_that_cannot_be_run(self) -> None:
        with pytest.raises(DiscoveryError, match="cannot run"):
            fetch(["/nonexistent/mcp-server"], timeout=5.0)

    def test_it_reports_a_server_that_never_answers(self) -> None:
        started = time.monotonic()
        with pytest.raises(DiscoveryError, match="did not answer"):
            fetch([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1.0)
        assert time.monotonic() - started < 20


class TestCommand:
    def test_no_server_command_is_an_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["discover"]) == 2
        assert "no server command" in capsys.readouterr().err

    def test_a_gap_exits_nonzero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("FAKE_TOOLS_EXTRA", "1")
        policy = tmp_path / "p.json"
        policy.write_text(json.dumps({"version": 1, "surfaces": {"read_file": {}}}))
        assert main(["discover", "--policy", str(policy), "--", *SERVER]) == 1
        out = capsys.readouterr().out
        assert "sync_artifact.target" in out
        assert "options.url" in out

    def test_a_covered_server_exits_zero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("FAKE_TOOLS_EXTRA", "1")
        policy = tmp_path / "p.json"
        policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "surfaces": {
                        "sync_artifact": {
                            "artifact": {"anywhere": False},
                            "target": {"anywhere": False},
                            "options": {"anywhere": False},
                            "options.url": {"anywhere": False},
                            "options.retries": {"anywhere": False},
                        }
                    },
                }
            )
        )
        assert main(["discover", "--policy", str(policy), "--", *SERVER]) == 0
        assert "named in the policy" in capsys.readouterr().out

    def test_it_does_not_touch_the_evaluation(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Discovery is a reading aid. It must not become a way to change a verdict.
        monkeypatch.setenv("FAKE_TOOLS_EXTRA", "1")
        assert main(["discover", "--", *SERVER]) == 0


def test_fake_server_env_is_not_leaked_between_runs() -> None:
    # The fixture reads FAKE_* from the environment; if these leak, a later test
    # silently gets a different server than it asked for.
    assert not any(key.startswith("FAKE_TOOLS_") for key in os.environ if key != "FAKE_TOOLS_CURSOR")


class TestStdoutIsTheWire:
    def test_a_server_that_prints_to_stdout_is_diagnosed_not_traced(
        self, tmp_path: Path
    ) -> None:
        # stdout is the transport. A banner or a log line there is not untidy, it
        # has broken the protocol, and a JSON traceback about line 1 column 1 tells
        # the operator nothing about which end is at fault.
        noisy = tmp_path / "noisy.py"
        noisy.write_text(
            "import sys\n"
            "sys.stdout.write('starting up\\n')\n"
            "sys.stdout.flush()\n"
            "for line in sys.stdin:\n"
            "    sys.stdout.write(line)\n"
            "    sys.stdout.flush()\n"
        )
        with pytest.raises(DiscoveryError, match="not JSON"):
            fetch([sys.executable, str(noisy)], timeout=10.0)

    def test_the_command_reports_it_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        noisy = tmp_path / "noisy.py"
        noisy.write_text(
            "import sys\n"
            "sys.stdout.write('starting up\\n')\n"
            "sys.stdout.flush()\n"
            "for line in sys.stdin:\n"
            "    sys.stdout.write(line)\n"
            "    sys.stdout.flush()\n"
        )
        assert main(["discover", "--", sys.executable, str(noisy)]) == 2
        assert "not JSON" in capsys.readouterr().err


class TestTheReadDeadline:
    """A line already in the buffer must not cost a timeout, and a timeout must
    cost one timeout rather than one per read."""

    def test_a_buffered_line_with_an_empty_pipe_is_still_returned(self) -> None:
        from airlock.discover import _Server

        # select answers for the file descriptor, not for Python's buffer, so a
        # reader that selects then readlines can wait out a full timeout on a line
        # it is already holding. The child here writes its echo and both answers in
        # one flush, so the first read can pull all three at once.
        script = tmp_script(
            "import sys, json\n"
            "first = sys.stdin.readline()\n"
            "out = [first.strip(),\n"
            "       json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'n': 1}}),\n"
            "       json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': {'n': 2}})]\n"
            "sys.stdout.write('\\n'.join(out) + '\\n')\n"
            "sys.stdout.flush()\n"
        )
        with _Server(argv=script, timeout=5.0) as server:
            server.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            assert json.loads(server.read_line())["id"] == 1
            for _ in range(2):
                assert json.loads(server.read_line())["id"] in (1, 2)

    def test_the_timeout_is_a_total_budget_not_a_per_read_one(self) -> None:
        from airlock.discover import _Server

        # Otherwise a server that dribbles bytes forever holds the command open.
        script = tmp_script(
            "import sys, time\n"
            "for line in sys.stdin:\n"
            "    sys.stdout.write('{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{')\n"
            "    sys.stdout.flush()\n"
            "    for _ in range(60):\n"
            "        sys.stdout.write(' ')\n"
            "        sys.stdout.flush()\n"
            "        time.sleep(0.05)\n"
        )
        started = time.monotonic()
        with _Server(argv=script, timeout=0.5) as server:
            server.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            with pytest.raises(DiscoveryError, match="did not answer"):
                server.read_line()
        assert time.monotonic() - started < 3.0

    def test_a_timeout_says_whether_the_child_is_alive(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A bare "did not answer" cannot be acted on: it does not separate a server
        # that is thinking from a child that died before writing anything, and it is
        # the message a flaky run will produce.
        started = time.monotonic()
        assert main(
            ["discover", "--timeout", "2", "--", sys.executable, "-c", "import time; time.sleep(30)"]
        ) == 2
        assert time.monotonic() - started < 15, "a failure should not cost the default 30s"
        err = capsys.readouterr().err
        assert "did not answer within 2s" in err
        assert "still running" in err
        assert "never answered the handshake" in err

    def test_a_dead_child_is_reported_as_dead(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(
            ["discover", "--timeout", "10", "--", sys.executable, "-c", "raise SystemExit(3)"]
        ) == 2
        err = capsys.readouterr().err
        # "closed its output" alone cannot be acted on; the exit status can.
        assert "closed its output after 0 line(s)" in err
        assert "exited with status 3" in err


def tmp_script(body: str) -> list[str]:
    import tempfile
    from pathlib import Path as _Path

    path = _Path(tempfile.mkdtemp()) / "server.py"
    path.write_text(body)
    return [sys.executable, str(path)]


def _deep_schema(depth: int) -> dict[str, object]:
    node: dict[str, object] = {"type": "string"}
    for _ in range(depth):
        node = {"type": "object", "properties": {"n": node}}
    return {"type": "object", "properties": {"root": node}}


class TestHostileSchemas:
    """`discover` parses JSON an arbitrary server supplied.

    That makes it the newest untrusted-input parser in the project, and a recursive
    walk over a server-supplied schema is a denial of service: a nesting depth a few
    thousand deep turns the command into a RecursionError traceback, which is both a
    crash and a useless answer.
    """

    @pytest.mark.parametrize("depth", [2000, 10000])
    def test_a_deeply_nested_schema_does_not_crash(self, depth: int) -> None:
        from airlock.discover import _tools_from

        tools, notes = _tools_from({"tools": [{"name": "t", "inputSchema": _deep_schema(depth)}]})
        assert tools[0].properties
        # Not a crash, and not silence either: it says what it declined to walk.
        assert tools[0].truncated is not None
        assert notes

    def test_it_reports_that_it_stopped_short_rather_than_looking_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Silently truncating is the one failure this command must not have:
        # under-reporting a surface is the gap it was built to close.
        found = discover(monkeypatch, FAKE_TOOLS_DEEP="1")
        tool = next(t for t in found.tools if t.name == "deep_tool")
        assert tool.truncated is not None
        assert "deeper than" in tool.truncated
        assert any("deep_tool" in note for note in found.notes)

    def test_a_schema_within_the_limit_is_not_called_truncated(self) -> None:
        from airlock.discover import MAX_SCHEMA_DEPTH, _tools_from

        tools, _notes = _tools_from({"tools": [{"name": "t", "inputSchema": _deep_schema(5)}]})
        tool = tools[0]
        assert tool.truncated is None
        assert len(tool.properties) == MAX_SCHEMA_DEPTH

    def test_a_wide_schema_is_capped_and_says_so(self) -> None:
        from airlock.discover import MAX_ARGUMENTS_PER_TOOL, _tools_from

        wide = {
            "name": "wide",
            "inputSchema": {
                "type": "object",
                "properties": {f"p{i}": {"type": "string"} for i in range(3000)},
            },
        }
        tools, _notes = _tools_from({"tools": [wide]})
        tool = tools[0]
        assert len(tool.properties) == MAX_ARGUMENTS_PER_TOOL
        assert tool.truncated is not None
        assert "not walked" in tool.truncated

    def test_flat_and_shallow_schemas_report_nothing_dropped(self) -> None:
        from airlock.discover import _tools_from

        cases = [
            {"type": "object", "properties": {}},
            {"type": "object", "properties": {"a": {"type": "string"}}},
            {"name": None, "inputSchema": None},
            {"name": "t", "inputSchema": {"type": "object", "properties": None}},
            {"name": "t", "inputSchema": "not a schema"},
        ]
        for entry in cases:
            tools, notes = _tools_from({"tools": [entry]})
            assert tools[0].truncated is None
            assert not [n for n in notes if "was not read" in n or "unreadable" in n]

    @pytest.mark.parametrize(
        "entry",
        [
            "not a dict",
            {"name": {"nested": "dict"}},
            {"name": "t", "inputSchema": {"type": "object", "properties": ["a"]}},
            {"name": "t", "inputSchema": {"type": "object", "properties": {"a": None}}},
        ],
    )
    def test_malformed_entries_are_reported_not_fatal(self, entry: object) -> None:
        # One bad tool must not lose the report on every other tool, and must not
        # crash either -- a server that gets its schema wrong is common.
        from airlock.discover import _tools_from

        tools, notes = _tools_from({"tools": [entry, {"name": "good", "inputSchema": None}]})
        assert any(t.name == "good" for t in tools)
        if entry == "not a dict":
            # Dropping it quietly would make a 2-tool report out of a 3-tool
            # server, which is the one thing this command must not do.
            assert len(tools) == 1
            assert any("was not read" in note for note in notes)
        else:
            assert len(tools) == 2


class TestTeardown:
    """The command must not outlive its own usefulness.

    A server that answers every question and then stops watching stdin has given
    us everything we came for. It has not, however, gone away, and closing its
    stdin is not a signal it is listening for. Waiting out the full protocol
    timeout for it made a discovery that completed in milliseconds look like one
    that had hung -- which is how this presented: a 30s stall with a live child
    and no error, seen twice and never explained.
    """

    def test_a_server_that_never_notices_stdin_closed_does_not_hold_the_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FAKE_IGNORE_EOF", "1")
        started = time.monotonic()
        found = fetch(SERVER, timeout=30.0)
        elapsed = time.monotonic() - started
        # The budget is 30s. Finishing on a 30s deadline would mean the teardown
        # still spends the protocol timeout waiting on a process that has nothing
        # left to say.
        assert elapsed < 10.0, f"teardown spent {elapsed:.1f}s"
        assert found.server_name == "fake"

    def test_a_server_that_ignores_sigterm_is_still_reaped(self) -> None:
        """Escalation has to reach SIGKILL.

        Close, then SIGTERM, then SIGKILL. A server that traps SIGTERM and keeps
        running would otherwise outlive the command inspecting it, holding a
        pipe and a slot in the process table for as long as it liked.
        """
        stub = (
            "import signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "sys.stdin.read()\n"
            "while True: time.sleep(0.05)\n"
        )
        server = _Server(argv=[sys.executable, "-c", stub], timeout=30.0)
        server.__enter__()
        assert server._process is not None
        pid = server._process.pid
        server.__exit__(None, None, None)
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)

    def test_the_teardown_grace_is_short_and_not_the_protocol_budget(self) -> None:
        # A regression guard on the constant itself: the whole bug was one field
        # pointing at the wrong number, and no behavioural test should be the only
        # thing standing between that and a 30-second stall.
        assert _Server.TEARDOWN_GRACE < 5.0


class TestTheTimeoutIsOneBudget:
    """`--timeout` bounds the whole exchange, not each request."""

    def test_a_server_that_answers_each_call_slowly_still_runs_out_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Two replies are needed (initialize, tools/list) and each takes 1.6s.
        # Budgeted per request, each of the two would land inside its own 2.0s
        # and the discovery would succeed after 3.2s. Budgeted once for the
        # exchange, the second reply misses at 2.0s. So the assertion that
        # separates the two designs is that this raises at all -- the elapsed
        # bound only rules out waiting forever, and has to allow for the teardown
        # grace on top of the budget.
        monkeypatch.setenv("FAKE_REPLY_DELAY", "1.6")
        started = time.monotonic()
        with pytest.raises(DiscoveryError, match="did not answer within"):
            fetch(SERVER, timeout=2.0)
        elapsed = time.monotonic() - started
        assert elapsed < 2.0 + _Server.TEARDOWN_GRACE + 1.0, f"took {elapsed:.2f}s"

    def test_a_fast_server_is_unaffected_by_the_shared_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FAKE_REPLY_DELAY", "0.05")
        found = fetch(SERVER, timeout=5.0)
        assert found.server_name == "fake"
        assert found.tools
