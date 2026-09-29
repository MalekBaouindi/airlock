"""Inspector interface and verdict combination.

Detectors are independent and composable. Each one sees a message and returns a
:class:`Verdict`; the pipeline folds them into a single decision. Keeping
detectors ignorant of each other matters for the evaluation side of this
project: the ablation table ("which layer earns its place?") is only
meaningful if each layer can be run alone.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from airlock.audit.log import Decision, Finding
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext

#: Ordered by increasing severity. A pipeline takes the most severe verdict it
#: receives, so a single blocking detector cannot be talked out of it by
#: permissive ones.
ACTION_RANK: dict[Decision, int] = {"allow": 0, "flag": 1, "modify": 2, "block": 3}


@dataclass(frozen=True, slots=True)
class Verdict:
    """One inspector's conclusion about one message."""

    action: Decision = "allow"
    findings: tuple[Finding, ...] = ()
    #: Populated only for ``action="modify"``. The relay substitutes this for
    #: the original envelope.
    replacement: dict[str, Any] | None = None

    @classmethod
    def allow(cls) -> Verdict:
        return cls()

    @classmethod
    def of(
        cls,
        action: Decision,
        *findings: Finding,
        replacement: dict[str, Any] | None = None,
    ) -> Verdict:
        if action == "modify" and replacement is None:
            raise ValueError("a 'modify' verdict must carry a replacement envelope")
        return cls(action=action, findings=tuple(findings), replacement=replacement)


ALLOW = Verdict()


@runtime_checkable
class Inspector(Protocol):
    """A detector that observes messages crossing the boundary."""

    name: str

    def inspect_request(self, message: Message, ctx: SessionContext) -> Verdict:
        """Called on the host->upstream leg, before forwarding."""
        ...

    def inspect_response(self, message: Message, ctx: SessionContext) -> Verdict:
        """Called on the upstream->host leg, before delivery."""
        ...


@dataclass(frozen=True, slots=True)
class PipelineResult:
    action: Decision
    findings: tuple[Finding, ...]
    replacement: dict[str, Any] | None = None
    #: Which inspectors contributed a non-allow verdict. Reported so the
    #: ablation can attribute detections to a layer.
    contributors: tuple[str, ...] = ()


@dataclass
class InspectorPipeline:
    """Runs inspectors in order and folds their verdicts into one decision."""

    inspectors: Sequence[Inspector] = field(default_factory=tuple)

    def run_request(self, message: Message, ctx: SessionContext) -> PipelineResult:
        return self._fold(
            (insp.name, insp.inspect_request(message, ctx)) for insp in self.inspectors
        )

    def run_response(self, message: Message, ctx: SessionContext) -> PipelineResult:
        return self._fold(
            (insp.name, insp.inspect_response(message, ctx)) for insp in self.inspectors
        )

    @staticmethod
    def _fold(verdicts: Any) -> PipelineResult:
        action: Decision = "allow"
        findings: list[Finding] = []
        replacement: dict[str, Any] | None = None
        contributors: list[str] = []

        for name, verdict in verdicts:
            findings.extend(verdict.findings)
            if verdict.action != "allow":
                contributors.append(name)
            if ACTION_RANK[verdict.action] > ACTION_RANK[action]:
                action = verdict.action
                replacement = verdict.replacement
            elif verdict.action == action == "modify" and replacement is None:
                replacement = verdict.replacement

        return PipelineResult(
            action=action,
            findings=tuple(findings),
            replacement=replacement,
            contributors=tuple(contributors),
        )
