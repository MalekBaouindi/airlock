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
