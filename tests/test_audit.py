from __future__ import annotations

import itertools
import json
from pathlib import Path

from airlock.audit.log import AuditLog, Finding, digest_payload, verify_chain


def write(tmp_path: Path, n: int = 5) -> Path:
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(n):
        log.append(
            session_id="s1",
            direction="host->upstream",
            kind="request",
            decision="allow",
            method="tools/call",
            payload={"i": i},
        )
    return log.path


def test_records_are_chained(tmp_path: Path) -> None:
    path = write(tmp_path)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 5
    assert records[0]["prev_hash"] == "0" * 64
    for previous, current in itertools.pairwise(records):
        assert current["prev_hash"] == previous["hash"]


def test_chain_verifies(tmp_path: Path) -> None:
    result = verify_chain(write(tmp_path))
    assert result.ok
    assert result.records == 5


def test_log_is_appended_across_sessions(tmp_path: Path) -> None:
    first = AuditLog(tmp_path / "a.jsonl")
    first.append(session_id="s1", direction="internal", kind="session-open", decision="allow")
    second = AuditLog(tmp_path / "a.jsonl")
    second.append(session_id="s2", direction="internal", kind="session-open", decision="allow")

    result = verify_chain(first.path)
    assert result.ok
    assert result.records == 2


def test_detects_edited_record(tmp_path: Path) -> None:
    path = write(tmp_path)
    lines = path.read_text().splitlines()
    record = json.loads(lines[2])
    record["decision"] = "allow" if record["decision"] != "allow" else "block"
    lines[2] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at == 2


def test_detects_deleted_record(tmp_path: Path) -> None:
    path = write(tmp_path)
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.ok
    assert result.records == 2


def test_detects_reordered_records(tmp_path: Path) -> None:
    path = write(tmp_path)
    lines = path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at is not None


def test_capture_modes(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "d.jsonl", capture="digest")
    record = log.append(
        session_id="s",
        direction="upstream->host",
        kind="response",
        decision="flag",
        payload={"secret": "hunter2"},
    )
    assert record.payload is None
    assert record.payload_digest == digest_payload({"secret": "hunter2"})

    full = AuditLog(tmp_path / "f.jsonl", capture="full")
    stored = full.append(
        session_id="s",
        direction="upstream->host",
        kind="response",
        decision="flag",
        payload={"secret": "hunter2"},
    )
    assert stored.payload == {"secret": "hunter2"}

    none = AuditLog(tmp_path / "n.jsonl", capture="none")
    silent = none.append(
        session_id="s",
        direction="upstream->host",
        kind="response",
        decision="flag",
        payload={"secret": "hunter2"},
    )
    assert silent.payload is None
    assert silent.payload_digest is None


def test_audit_file_is_not_world_readable(tmp_path: Path) -> None:
    path = write(tmp_path)
    assert path.stat().st_mode & 0o077 == 0


def test_findings_survive_verification(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "f.jsonl")
    log.append(
        session_id="s",
        direction="upstream->host",
        kind="response",
        decision="block",
        findings=[Finding("unicode-tag", "critical", "invisible text", "MCP03")],
    )
    assert verify_chain(log.path).ok
    record = json.loads(log.path.read_text().splitlines()[0])
    assert record["findings"][0]["owasp"] == "MCP03"


def test_empty_log_verifies(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "empty.jsonl")
    assert verify_chain(log.path).ok
