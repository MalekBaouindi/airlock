"""stdio interposition relay.

Architecture: the proxy is an MCP *server* to the host and an MCP *client* to
the upstream server, but it does not use either role's typed API. It sits on the
raw newline-delimited JSON-RPC wire in both directions. Two consequences, both
intentional:

1. **Zero cooperation from upstream.** Any stdio MCP server is interceptable as
   is, because the proxy owns the subprocess's pipes. Requiring servers to opt
   in would make the gateway useless exactly where it is needed.

2. **Forward-compatibility as a security property.** Because envelopes are
   untyped, a method the gateway has never heard of is forwarded unchanged
   rather than dropped. An attacker who can make the gateway discard traffic it
   does not understand has found an evasion primitive, so "unknown" must never
   mean "ignore".

Failure posture is explicit and tested:

* Unparseable line  -> forwarded byte-for-byte, logged as a finding. Dropping
  it would break the agent; silently accepting it would hide an attack.
* Detector crash    -> treated as a block (fail closed). A detector that dies
  must not take the policy with it.
* Upstream exit     -> its exit code propagates.
* Host EOF          -> upstream is terminated and reaped.

The process's stdout is the wire. Every diagnostic goes to stderr.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, BinaryIO

from airlock.audit.log import AuditLog, Finding
from airlock.gateway.jsonrpc import (
    CODE_BLOCKED,
    CODE_INTERNAL_ERROR,
    Message,
    ProtocolError,
    error_response,
)
from airlock.gateway.session import SessionContext

if TYPE_CHECKING:  # avoids a gateway <-> inspect import cycle
    from airlock.inspect.base import InspectorPipeline


def _log(message: str) -> None:
    print(f"[airlock] {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True, slots=True)
class UpstreamSpec:
    """How to launch the server we are interposing on."""

    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] | None = None
    cwd: str | None = None

    @classmethod
    def from_argv(cls, argv: Sequence[str]) -> UpstreamSpec:
        if not argv:
            raise ValueError("upstream command is empty")
        return cls(command=argv[0], args=tuple(argv[1:]))

    def resolved_env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self.env:
            env.update(self.env)
        return env


async def _readline(stream: Any) -> bytes:
    """Read one line from either an asyncio stream or a blocking file object."""
    if isinstance(stream, asyncio.StreamReader):
        return await stream.readline()
    return await asyncio.to_thread(stream.readline)


async def _write(stream: Any, data: bytes) -> None:
    """Write a frame to either an asyncio stream or a blocking file object."""
    if isinstance(stream, asyncio.StreamWriter):
        stream.write(data)
        await stream.drain()
    else:
        await asyncio.to_thread(_write_blocking, stream, data)


def _write_blocking(stream: BinaryIO, data: bytes) -> None:
    stream.write(data)
    stream.flush()


class _SerialisedWriter:
    """Serialises writes to one stream.

    Both pumps can need to write to the host: the response leg forwards
    upstream results, and the request leg injects a synthetic error when it
    blocks a call. Interleaving those without a lock would corrupt the wire.
    """

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._lock = asyncio.Lock()

    async def send(self, data: bytes) -> None:
        async with self._lock:
            await _write(self._stream, data)


@dataclass
class ProxyStats:
    forwarded: int = 0
    blocked: int = 0
    flagged: int = 0
    modified: int = 0
    unparseable: int = 0
    detector_errors: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "forwarded": self.forwarded,
            "blocked": self.blocked,
            "flagged": self.flagged,
            "modified": self.modified,
            "unparseable": self.unparseable,
            "detector_errors": self.detector_errors,
        }


class StdioProxy:
    """Interposes on one stdio MCP connection."""

    #: Upper bound on waiting for an upstream to finish responding after the
    #: host half-closes. Generous enough for a slow local tool, short enough
    #: that a wedged server cannot pin the agent open indefinitely.
    DRAIN_TIMEOUT: float = 5.0

    def __init__(
        self,
        upstream: UpstreamSpec,
        pipeline: InspectorPipeline,
        audit: AuditLog,
        *,
        host_reader: Any | None = None,
        host_writer: Any | None = None,
        on_exit: Callable[[], None] | None = None,
    ) -> None:
        self.upstream = upstream
        self.pipeline = pipeline
        self.audit = audit
        self.stats = ProxyStats()
        self._host_reader = host_reader if host_reader is not None else sys.stdin.buffer
        self._host_writer = _SerialisedWriter(
            host_writer if host_writer is not None else sys.stdout.buffer
        )
        self._process: asyncio.subprocess.Process | None = None
        self._on_exit = on_exit

    # -- lifecycle ---------------------------------------------------------

    async def run(self) -> int:
        _log(f"interposing on: {self.upstream.command} {' '.join(self.upstream.args)}")
        self._process = await asyncio.create_subprocess_exec(
            self.upstream.command,
            *self.upstream.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            # The upstream's own diagnostics must stay visible to whoever
            # launched it, and must never reach our stdout, which is the wire.
            stderr=None,
            cwd=self.upstream.cwd,
            env=self.upstream.resolved_env(),
        )
        assert self._process.stdout is not None
        assert self._process.stdin is not None

        ctx = SessionContext()
        self.audit.append(
            session_id=ctx.session_id,
            direction="internal",
            kind="session-open",
            decision="allow",
            payload={"upstream": self.upstream.command, "args": list(self.upstream.args)},
        )

        host_to_up = asyncio.create_task(self._pump_host_to_upstream(self._process.stdin, ctx))
        up_to_host = asyncio.create_task(self._pump_upstream_to_host(self._process.stdout, ctx))

        try:
            done, _ = await asyncio.wait(
                {host_to_up, up_to_host}, return_when=asyncio.FIRST_COMPLETED
            )
            if host_to_up in done and not up_to_host.done():
                # The host closed its input. That is a half-close, not a
                # cancellation: requests already dispatched still owe responses,
                # and an agent routinely closes stdin and then reads the results
                # it was promised. Tear the upstream down only after the wire
                # has drained, otherwise the relay discards work it accepted.
                await self._drain(up_to_host)
                done = done | {up_to_host}
        finally:
            for task in (host_to_up, up_to_host):
                if not task.done():
                    task.cancel()
            await self._terminate()

        exit_code = 0
        if self._process.returncode is not None and self._process.returncode != 0:
            exit_code = self._process.returncode
        for task in done:
            exc = task.exception()
            if exc is not None:
                _log(f"pump failed: {exc!r}")
                exit_code = exit_code or 1

        await self._fail_pending(ctx)

        self.audit.append(
            session_id=ctx.session_id,
            direction="internal",
            kind="session-close",
            decision="allow",
            payload=self.stats.as_dict(),
        )
        if self._on_exit is not None:
            self._on_exit()
        _log(f"session closed: {self.stats.as_dict()}")
        return exit_code

    async def _fail_pending(self, ctx: SessionContext) -> None:
        """Answer requests the upstream never answered.

        When a server dies mid-call, the honest reply is an error. Staying
        silent leaves the host blocked on a response that cannot arrive, which
        turns a server fault into an agent hang -- the worst possible way for a
        security proxy to fail.
        """
        outstanding = ctx.drain_pending()
        if not outstanding:
            return
        returncode = self._process.returncode if self._process else None
        for request_id in outstanding:
            self.audit.append(
                session_id=ctx.session_id,
                direction="internal",
                kind="request-abandoned",
                decision="block",
                request_id=str(request_id) if request_id is not None else None,
                findings=[
                    Finding(
                        "upstream-terminated",
                        "critical",
                        f"upstream exited with code {returncode} before responding",
                    )
                ],
            )
            await self._host_writer.send(
                error_response(
                    request_id,
                    CODE_INTERNAL_ERROR,
                    f"Upstream MCP server exited (code {returncode}) before responding",
                    {"reason": "upstream-terminated"},
                ).to_bytes()
            )

    async def _drain(self, response_pump: asyncio.Task[None]) -> None:
        """Finish in-flight responses after the host half-closes its input.

        Closes the upstream's stdin so a well-behaved server sees EOF and
        exits, then waits for the response pump. Bounded, because a server that
        neither exits nor answers must not hang the agent forever.
        """
        assert self._process is not None
        if self._process.stdin is not None:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError, RuntimeError):
                self._process.stdin.close()
        try:
            await asyncio.wait_for(asyncio.shield(response_pump), timeout=self.DRAIN_TIMEOUT)
        except (TimeoutError, asyncio.CancelledError):
            _log("upstream did not finish responding within the drain window")
            if not response_pump.done():
                response_pump.cancel()

    async def _terminate(self) -> None:
        assert self._process is not None
        if self._process.returncode is not None:
            return
        try:
            self._process.terminate()
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
        except (TimeoutError, ProcessLookupError):
            with contextlib.suppress(ProcessLookupError):
                self._process.kill()

    # -- pumps -------------------------------------------------------------

    async def _pump_host_to_upstream(self, upstream_stdin: Any, ctx: SessionContext) -> None:
        while True:
            try:
                line = await _readline(self._host_reader)
            except (asyncio.CancelledError, RuntimeError):
                return
            if not line:
                return
            await self._handle_request_leg(line, upstream_stdin, ctx)

    async def _pump_upstream_to_host(self, upstream_stdout: Any, ctx: SessionContext) -> None:
        while True:
            try:
                line = await _readline(upstream_stdout)
            except asyncio.CancelledError:
                return
            if not line:
                return
            await self._handle_response_leg(line, ctx)

    # -- inspection --------------------------------------------------------

    async def _handle_request_leg(
        self, line: bytes, upstream_stdin: Any, ctx: SessionContext
    ) -> None:
        try:
            message = Message.parse(line)
        except ProtocolError as exc:
            self.stats.unparseable += 1
            self.audit.append(
                session_id=ctx.session_id,
                direction="host->upstream",
                kind="unparseable",
                decision="flag",
                findings=[Finding("malformed-frame", "medium", str(exc))],
                payload=line.decode("utf-8", errors="replace")[:4096],
            )
            # Forward verbatim: transparency beats tidiness. A frame we cannot
            # read is evidence, not permission to drop the agent's traffic.
            await _write(upstream_stdin, line)
            return

        ctx.note_request(message)
        result = self._run_detectors("request", message, ctx)

        if result.action == "block":
            self.stats.blocked += 1
            self.audit.append(
                session_id=ctx.session_id,
                direction="host->upstream",
                kind="request",
                decision="block",
                method=message.method,
                tool=message.tool_name,
                request_id=str(message.id) if message.id is not None else None,
                findings=list(result.findings),
                payload=message.raw,
            )
            await self._host_writer.send(self._blocked(message, result).to_bytes())
            # Answered by us, so no upstream response is coming. See
            # `SessionContext.settle` for why leaving this pending produces a
            # duplicate error for the host.
            ctx.settle(message.id)
            return

        self._record("host->upstream", "request", message, result, ctx)
        await _write(upstream_stdin, line)

    async def _handle_response_leg(self, line: bytes, ctx: SessionContext) -> None:
        try:
            message = Message.parse(line)
        except ProtocolError as exc:
            self.stats.unparseable += 1
            self.audit.append(
                session_id=ctx.session_id,
                direction="upstream->host",
                kind="unparseable",
                decision="flag",
                findings=[Finding("malformed-frame", "medium", str(exc))],
                payload=line.decode("utf-8", errors="replace")[:4096],
            )
            await self._host_writer.send(line)
            return

        # Expose the correlation to detectors first, then consume it. A stateful
        # inspector (provenance) needs to know which call produced this result,
        # and popping on the first read would starve every reader after it.
        ctx.note_response(message)
        method = ctx.method_for_response(message)
        result = self._run_detectors("response", message, ctx, method=method)

        if result.action == "block":
            self.stats.blocked += 1
            self.audit.append(
                session_id=ctx.session_id,
                direction="upstream->host",
                kind="response",
                decision="block",
                method=method,
                request_id=str(message.id) if message.id is not None else None,
                findings=list(result.findings),
                payload=message.raw,
            )
            await self._host_writer.send(self._blocked(message, result).to_bytes())
            return

        if result.action == "modify" and result.replacement is not None:
            self.stats.modified += 1
            self._record("upstream->host", "response", message, result, ctx, method=method)
            await self._host_writer.send(Message(result.replacement).to_bytes())
            return

        self._record("upstream->host", "response", message, result, ctx, method=method)
        await self._host_writer.send(line)

    def _run_detectors(
        self,
        leg: str,
        message: Message,
        ctx: SessionContext,
        *,
        method: str | None = None,
    ) -> Any:
        """Run the pipeline, converting a detector crash into a block."""
        try:
            if leg == "request":
                return self.pipeline.run_request(message, ctx)
            return self.pipeline.run_response(message, ctx)
        except Exception as exc:
            self.stats.detector_errors += 1
            _log(f"detector error (failing closed): {exc!r}")
            self.audit.append(
                session_id=ctx.session_id,
                direction="host->upstream" if leg == "request" else "upstream->host",
                kind=leg,
                decision="block",
                method=message.method or method,
                findings=[Finding("detector-error", "critical", f"detector raised: {exc!r}")],
            )
            return _BlockedVerdict()

    def _record(
        self,
        direction: Any,
        kind: str,
        message: Message,
        result: Any,
        ctx: SessionContext,
        *,
        method: str | None = None,
    ) -> None:
        decision = result.action
        if decision == "allow":
            self.stats.forwarded += 1
        elif decision == "flag":
            self.stats.flagged += 1
        elif decision == "modify":
            self.stats.modified += 1

        self.audit.append(
            session_id=ctx.session_id,
            direction=direction,
            kind=kind,
            decision=decision,
            method=message.method or method,
            tool=message.tool_name,
            request_id=str(message.id) if message.id is not None else None,
            findings=list(result.findings),
            payload=message.raw if decision != "allow" else None,
        )

    @staticmethod
    def _blocked(message: Message, result: Any = None) -> Message:
        # Rule names (never payload content) so the host's error is actionable
        # on its own. The agent needs to know *why* it was refused in order to
        # route around it legitimately rather than retry blindly.
        data: dict[str, Any] = {"reason": "inspection", "see": "airlock audit log"}
        findings = getattr(result, "findings", ())
        if findings:
            data["rules"] = sorted({f.rule for f in findings})
        return error_response(
            message.id,
            CODE_BLOCKED,
            "Blocked by airlock policy",
            data,
        )


@dataclass(frozen=True, slots=True)
class _BlockedVerdict:
    action: str = "block"
    findings: tuple[Finding, ...] = ()
    replacement: dict[str, Any] | None = None
