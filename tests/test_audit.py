from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from airlock.audit.log import (
    AuditLog,
    Finding,
    digest_payload,
    iter_records,
    verify_chain,
)


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


class TestWhatTheChainCannotSee:
    """A hash chain detects interior tampering and nothing about the tail.

    Every record commits to the one before it, so removing a record from the end
    leaves the survivors exactly as consistent as they were. The chain verifies,
    and the leak is gone from the evidence. This is the limit of the primitive, not
    a bug in it, and these tests exist so the README cannot quietly imply
    otherwise.
    """

    def test_deleting_the_last_record_is_invisible_from_inside(self, tmp_path: Path) -> None:
        path = write(tmp_path)
        head = verify_chain(path).head

        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:-1]) + "\n")
        result = verify_chain(path)

        assert result.ok, "this is the point: internally consistent"
        assert result.records == 4
        assert result.head != head, "but the end of the chain moved, and that is visible"

    def test_the_head_is_the_number_to_compare_outside(self, tmp_path: Path) -> None:
        # Two logs can both be internally perfect and be different logs. The head
        # is what tells them apart, so it has to be reported rather than inferred.
        # Both are cut from the same file, so the only difference is the record
        # count -- two logs built independently differ by timestamp and would prove
        # nothing.
        base = write(tmp_path / "base", n=6).read_text().splitlines()
        full = tmp_path / "full.jsonl"
        full.write_text("\n".join(base) + "\n")
        short = tmp_path / "short.jsonl"
        short.write_text("\n".join(base[:-1]) + "\n")

        assert verify_chain(full).ok and verify_chain(short).ok
        assert verify_chain(full).head != verify_chain(short).head

    def test_a_lost_record_shows_up_in_the_head_either_way_it_is_lost(self, tmp_path: Path) -> None:
        # One record missing, two causes. A torn write never finished the sixth
        # record; a cut lost it after the fact. Both leave the same five verified
        # and the same head, which is why the head is the number to compare and the
        # count alone is not: one is a clean-looking log and the other is flagged.
        base = write(tmp_path / "base", n=6).read_text().splitlines()

        torn = tmp_path / "torn.jsonl"
        torn.write_text("\n".join(base[:5]) + "\n" + '{"seq": 6, "ts": 1, "sessi')
        cut = tmp_path / "cut.jsonl"
        cut.write_text("\n".join(base[:5]) + "\n")

        assert verify_chain(torn).truncated
        assert verify_chain(cut).ok and not verify_chain(cut).truncated
        assert verify_chain(torn).head == verify_chain(cut).head
        assert verify_chain(torn).records == verify_chain(cut).records == 5


class TestTornWrites:
    def test_a_half_written_final_record_is_reported_as_truncated(self, tmp_path: Path) -> None:
        # A process killed mid-write, or a disk that ran out of room, leaves a
        # partial line. Before this it raised JSONDecodeError out of the CLI, so
        # the operator got a traceback and no diagnosis.
        path = write(tmp_path)
        path.write_text(path.read_text() + '{"seq": 5, "ts": 1, "sessi')

        result = verify_chain(path)
        assert result.ok and result.truncated
        assert result.records == 5
        assert result.reason is not None and "partial write" in result.reason

    def test_truncation_is_not_reported_as_tampering(self, tmp_path: Path) -> None:
        # The honest diagnosis is data loss. An operator told their log was
        # tampered with goes looking for a person instead of a filesystem.
        path = write(tmp_path)
        path.write_text(path.read_text() + '{"seq": 5, "ts')
        result = verify_chain(path)
        assert result.truncated
        assert not (result.ok and not result.truncated)

    def test_interior_corruption_is_not_dismissed_as_a_torn_write(self, tmp_path: Path) -> None:
        # A line that ended cleanly and still does not parse is corruption or an
        # edit, not a torn write. Being charitable about it would hide the case
        # an incident review is actually looking for.
        path = write(tmp_path)
        lines = path.read_text().splitlines()
        lines[2] = '{"seq": 2, "ts": 1, "sessi'
        path.write_text("\n".join(lines) + "\n")

        result = verify_chain(path)
        assert not result.ok
        assert not result.truncated
        assert result.reason is not None and "unparseable" in result.reason

    def test_replay_stops_at_a_torn_tail_instead_of_raising(self, tmp_path: Path) -> None:
        path = write(tmp_path, n=3)
        path.write_text(path.read_text() + '{"seq": 3, "ts": 1, "sessi')
        assert len(list(iter_records(path))) == 3

    def test_replay_still_raises_on_interior_corruption(self, tmp_path: Path) -> None:
        # Skipping a bad record in the middle during an incident review would hide
        # precisely the edit someone is looking for.
        path = write(tmp_path)
        lines = path.read_text().splitlines()
        lines[1] = "{not json"
        path.write_text("\n".join(lines) + "\n")
        with pytest.raises(json.JSONDecodeError):
            list(iter_records(path))
