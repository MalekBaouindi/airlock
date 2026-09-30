"""CLI contract tests.

The command line is the entire adoption surface, so the things a user actually
types have to be tested -- especially the exit codes, because that is what a
supervisor or CI step reacts to.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from airlock.audit.log import AuditLog, Finding, verify_chain
from airlock.cli import main


@pytest.fixture
def log_with_session(tmp_path: Path) -> Path:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(
        session_id="s1",
        direction="host->upstream",
        kind="request",
        decision="allow",
        method="tools/call",
        tool="read_file",
    )
    log.append(
        session_id="s1",
        direction="upstream->host",
        kind="response",
        decision="block",
        method="tools/call",
        findings=[
            Finding("unicode-tag", "critical", "hidden text", owasp="MCP03"),
        ],
    )
    return log.path


class TestTopLevel:
    def test_bare_invocation_prints_usage(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([]) == 0
        assert "usage:" in capsys.readouterr().out

    def test_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--help"]) == 0
        assert "airlock proxy" in capsys.readouterr().out

    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--version"]) == 0
        assert capsys.readouterr().out.strip()

    def test_unknown_command_is_a_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["frobnicate"]) == 2
        assert "unknown command" in capsys.readouterr().err


class TestProxyArgumentHandling:
    def test_missing_separator_is_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A missing '--' must fail loudly rather than silently guessing which
        arguments belong to the upstream server."""
        assert main(["proxy", "python3", "server.py"]) == 2
        assert "missing '--'" in capsys.readouterr().err

    def test_empty_upstream_is_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["proxy", "--"]) == 2
        assert "no upstream command" in capsys.readouterr().err

    def test_upstream_flags_are_not_parsed_as_ours(self, tmp_path: Path) -> None:
        """`--audit` after the separator belongs to the server, not to us.

        Driven through the real installed entry point in a subprocess, because
        this is a claim about argv handling on a live stdio transport.
        """
        import subprocess
        import sys

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "airlock.cli",
                "proxy",
                "--audit",
                str(tmp_path / "ours.jsonl"),
                "--",
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1:], file=sys.stderr)",
                "--audit",
                "/theirs.jsonl",
            ],
            input=b"",
            capture_output=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr.decode()
        # The upstream received its own flag, and we kept our own audit path.
        assert b"--audit /theirs.jsonl" in completed.stderr
        assert (tmp_path / "ours.jsonl").exists()


class TestVerify:
    def test_intact_chain_exits_zero(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["verify", str(log_with_session)]) == 0
        assert "chain intact" in capsys.readouterr().out

    def test_tampered_chain_exits_nonzero(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lines = log_with_session.read_text().splitlines()
        record = json.loads(lines[1])
        record["decision"] = "allow"
        lines[1] = json.dumps(record)
        log_with_session.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(log_with_session)]) == 1
        assert "TAMPERED" in capsys.readouterr().err

    def test_missing_file_exits_nonzero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["verify", str(tmp_path / "nope.jsonl")]) == 1
        assert "no such audit log" in capsys.readouterr().err

    def test_intact_chain_prints_the_head_to_compare_outside(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # "Intact" on its own is not a claim the chain can support, so the command
        # has to hand back the number an operator can actually check against
        # something outside the file.
        assert main(["verify", str(log_with_session)]) == 0
        out = capsys.readouterr().out
        assert f"head: {verify_chain(log_with_session).head}" in out
        assert "removed from the end" in out

    def test_a_torn_final_record_exits_two_not_one(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # 1 means something was edited. 2 means the log stopped early. The
        # responses are different -- look for an edit, or look for a full disk --
        # and a monitor can act on the difference.
        log_with_session.write_text(
            log_with_session.read_text() + '{"seq": 99, "ts": 1, "sessi'
        )
        assert main(["verify", str(log_with_session)]) == 2
        err = capsys.readouterr().err
        assert "TRUNCATED" in err
        assert "partial write" in err
        assert "TAMPERED" not in err


class TestReplay:
    def test_renders_all_records(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["replay", str(log_with_session)]) == 0
        out = capsys.readouterr().out
        assert "2 record(s)" in out
        assert "unicode-tag" in out

    def test_decision_filter(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["replay", str(log_with_session), "--decisions", "block"]) == 0
        out = capsys.readouterr().out
        assert "1 record(s)" in out

    @pytest.mark.parametrize("columns", [60, 100, 200])
    def test_rule_name_survives_any_terminal_width(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str], columns: int
    ) -> None:
        """The reason for a block must never be truncated or dropped.

        An incident review on a narrow terminal is exactly when this column
        matters, so the layout drops other columns before it gives up this one.
        """
        import os

        os.environ["COLUMNS"] = str(columns)
        try:
            assert main(["replay", str(log_with_session)]) == 0
        finally:
            del os.environ["COLUMNS"]
        out = capsys.readouterr().out
        assert "unicode-tag" in out
        assert "…" not in out.split("findings")[-1]

    def test_missing_file_exits_nonzero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["replay", str(tmp_path / "nope.jsonl")]) == 1


class TestChainIntegrityAfterCLIUse:
    def test_verify_agrees_with_library(self, log_with_session: Path) -> None:
        assert verify_chain(log_with_session).ok
        assert main(["verify", str(log_with_session)]) == 0
