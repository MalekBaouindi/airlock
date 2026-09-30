"""Append-only, hash-chained audit trail.

Every interposed message produces exactly one record. Records are chained:
each one commits to the digest of its predecessor, so removing, reordering or
editing any record invalidates every record after it. An audit log that an
attacker (or a confused agent) can rewrite is not evidence, and the whole
value of a gateway is that it can answer "what actually crossed this boundary"
after the fact.

Payload capture defaults to digest-only. A security tool whose own logs become
a plaintext archive of everything the agent read is a liability, so retaining
full payloads is opt-in and explicit.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

CaptureMode = Literal["none", "digest", "full"]
Decision = Literal["allow", "block", "flag", "modify"]
Direction = Literal["host->upstream", "upstream->host", "internal"]

GENESIS: Final = "0" * 64


@dataclass(frozen=True, slots=True)
class Finding:
    """A single detector's observation about one message."""

    rule: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    detail: str
    #: OWASP MCP Top 10 identifier, when the finding maps onto one. Kept as
    #: data rather than prose so reports can group by standard.
    owasp: str | None = None

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        if data["owasp"] is None:
            del data["owasp"]
        return data


@dataclass(slots=True)
class AuditRecord:
    seq: int
    ts: float
    session_id: str
    direction: Direction
    kind: str
    decision: Decision
    method: str | None = None
    tool: str | None = None
    request_id: str | None = None
    findings: list[Finding] = field(default_factory=list)
    payload_digest: str | None = None
    payload: Any = None
    prev_hash: str = GENESIS
    hash: str = ""

    def _unsigned(self) -> dict[str, Any]:
        body = {
            "seq": self.seq,
            "ts": round(self.ts, 6),
            "session_id": self.session_id,
            "direction": self.direction,
            "kind": self.kind,
            "decision": self.decision,
            "method": self.method,
            "tool": self.tool,
            "request_id": self.request_id,
            "findings": [f.to_json() for f in self.findings],
            "payload_digest": self.payload_digest,
            "prev_hash": self.prev_hash,
        }
        if self.payload is not None:
            body["payload"] = self.payload
        return body

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self._unsigned(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_json(self) -> dict[str, Any]:
        body = self._unsigned()
        body["hash"] = self.hash
        return body


def digest_payload(payload: Any) -> str:
    """Stable content digest of an arbitrary JSON value."""
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=repr
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class AuditLog:
    """Hash-chained JSONL writer."""

    def __init__(self, path: Path, capture: CaptureMode = "digest") -> None:
        self.path = Path(path)
        self.capture = capture
        self._seq = 0
        self._prev = GENESIS
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists() and self.path.stat().st_size > 0
        if existed:
            self._restore_chain()
        else:
            # Tool traffic may contain credentials and user data; do not make
            # it world-readable just because the umask was permissive.
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            os.close(fd)

    def _restore_chain(self) -> None:
        """Continue an existing chain rather than restarting it."""
        last_hash = GENESIS
        count = 0
        with self.path.open("rb") as handle:
            for line in handle:
                if line.strip():
                    count += 1
                    last_hash = json.loads(line)["hash"]
        self._seq = count
        self._prev = last_hash

    def append(
        self,
        *,
        session_id: str,
        direction: Direction,
        kind: str,
        decision: Decision,
        method: str | None = None,
        tool: str | None = None,
        request_id: str | None = None,
        findings: list[Finding] | None = None,
        payload: Any = None,
    ) -> AuditRecord:
        record = AuditRecord(
            seq=self._seq,
            ts=time.time(),
            session_id=session_id,
            direction=direction,
            kind=kind,
            decision=decision,
            method=method,
            tool=tool,
            request_id=None if request_id is None else str(request_id),
            findings=findings or [],
            prev_hash=self._prev,
        )
        if payload is not None and self.capture != "none":
            record.payload_digest = digest_payload(payload)
        if payload is not None and self.capture == "full":
            record.payload = payload
        record.hash = record.compute_hash()

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(record.to_json(), separators=(",", ":"), ensure_ascii=False) + "\n"
            )
            handle.flush()

        self._seq += 1
        self._prev = record.hash
        return record


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    records: int
    broken_at: int | None = None
    reason: str | None = None
    #: The hash of the last record that verified. This is the chain's identity,
    #: and it is the only part a *truncated* log still gets right, so it is what
    #: an operator compares against anything outside the file.
    head: str = GENESIS
    #: The file ends in a partial record: a torn write, not an edit. Distinguished
    #: from tampering because the honest diagnosis is data loss, and telling an
    #: operator their log was tampered with when the disk ran out of space sends
    #: them looking for an attacker instead of a disk.
    truncated: bool = False


def verify_chain(path: Path) -> ChainVerification:
    """Recompute the chain and report the first record that does not fit.

    Detects the three tampering modes that matter: an edited record (hash
    mismatch), a deleted record (sequence or link mismatch), and a reordered
    pair (link mismatch).

    It cannot detect a *clean* truncation, and that limit is worth being precise
    about, because the naive reading of a hash chain is that it can. Every record
    commits to the one before it, so a record removed from the end leaves the
    records that remain as consistent as they ever were -- the chain verifies and
    a leak is gone from the evidence. Deleting from the middle cannot work,
    because the next record names the one that went missing.

    This is why :attr:`ChainVerification.head` exists. Tail deletion is
    undetectable by anything inside the file, so the end of the chain has to be
    compared against something that is not the file: a line count from the log
    pipeline, a SIEM copy, the ticket where the incident was filed. A verifier
    that can only answer "is this internally consistent" should hand back the
    number you would compare, not a bare yes.

    A torn final line is the one form of tail loss that *is* visible: a complete
    write includes its newline, so a record that does not parse and has no
    terminator is a write that was cut short.
    """
    prev = GENESIS
    count = 0
    with Path(path).open("rb") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                if not line.endswith(b"\n"):
                    return ChainVerification(
                        True,
                        count,
                        reason=f"final record is a partial write ({exc.msg})",
                        head=prev,
                        truncated=True,
                    )
                # A line that ended cleanly and still does not parse is not a torn
                # write. It is corruption or an edit in the middle of the file, and
                # it is not this function's job to be charitable about which.
                return ChainVerification(
                    False, count, None, f"unparseable record: {exc.msg}", head=prev
                )
            findings = [Finding(**f) for f in raw.get("findings", [])]
            record = AuditRecord(
                seq=raw["seq"],
                ts=raw["ts"],
                session_id=raw["session_id"],
                direction=raw["direction"],
                kind=raw["kind"],
                decision=raw["decision"],
                method=raw.get("method"),
                tool=raw.get("tool"),
                request_id=raw.get("request_id"),
                findings=findings,
                payload_digest=raw.get("payload_digest"),
                payload=raw.get("payload"),
                prev_hash=raw.get("prev_hash", GENESIS),
                hash=raw.get("hash", ""),
            )
            if record.prev_hash != prev:
                return ChainVerification(
                    False, count, record.seq, f"broken link at record {record.seq}", head=prev
                )
            if record.compute_hash() != record.hash:
                return ChainVerification(
                    False,
                    count,
                    record.seq,
                    f"content hash mismatch at record {record.seq}",
                    head=prev,
                )
            prev = record.hash
            count += 1
    return ChainVerification(True, count, head=prev)


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield raw audit records for replay and report generation.

    A torn final line stops the iteration rather than raising. Replay is a reader
    and the record is already gone, so raising would turn a partial log into an
    unreadable one. Interior corruption still raises: that is not a torn write, and
    quietly skipping it during an incident review would hide exactly the kind of
    edit an operator is looking for.
    """
    with Path(path).open("rb") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                if not line.endswith(b"\n"):
                    return
                raise
