"""The evaluation harness.

Runs every corpus case through a live gateway pipeline and compares each
step's actual verdict to the corpus's expected one.

The comparison is deliberately three-valued rather than binary, because
collapsing it to pass/fail would misrepresent the state of the system:

* **match** — the layer responsible for this step produced the expected verdict.
* **gap** — the step expects a non-allow verdict that a layer which does not
  exist yet was supposed to produce. This is coverage debt, not a broken
  detector, and counting it as either success or failure would lie.
* **false positive** — an ``allow`` step was flagged or blocked. Always a
  failure, with no excuse, because a gateway that cannot pass ordinary traffic
  is not deployable no matter what it catches.

The headline numbers follow from that split. Attack success rate counts an
attack as succeeding whenever the harmful step was *not* stopped, including the
steps attributed to unbuilt layers -- which is why the current numbers look
bad, and why they should.
"""

from __future__ import annotations

import json
import random
import statistics
import time
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.base import Inspector, InspectorPipeline, Resettable

Verdict = Literal["allow", "flag", "modify", "block"]

#: Severity weights for the weighted attack-success headline number. Counting
#: every case equally flatters a detector that catches the easy ones and misses
#: the high-impact ones, so the impact of a miss is priced in.
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 8.0,
    "high": 4.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.0,
}

#: Actions that stop an attack from taking effect. `flag` is not one of them:
#: the message still reaches the model, which is the entire point of the
#: runtime-channel threat model.
MITIGATING: frozenset[str] = frozenset({"block", "modify"})


@dataclass(frozen=True, slots=True)
class StepExpectation:
    verdict: Verdict
    reason: str
    #: Which layer was supposed to produce `verdict`. Absent for `allow` steps,
    #: since passing ordinary traffic requires no layer in particular.
    layer: str | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> StepExpectation:
        return cls(
            verdict=data["verdict"],
            reason=data.get("reason", ""),
            layer=data.get("layer"),
        )


@dataclass(frozen=True, slots=True)
class StepResult:
    case_id: str
    family: str
    #: Stated by the corpus, never inferred from the verdict.
    kind: str
    index: int
    direction: str
    expected: StepExpectation
    actual: Verdict
    rules: tuple[str, ...] = ()
    #: The same rule names in the order the pipeline emitted them, which `rules`
    #: deliberately discards. A verdict cannot depend on this -- the action is a
    #: rank maximum over inspectors, and the inspectors are a tuple -- but the
    #: audit log records findings in this order, so a tool that fingerprints
    #: decisions has a use for it.
    rule_order: tuple[str, ...] = ()
    outcome: Literal["match", "gap", "mismatch", "false-positive"] = "match"
    #: Wall-clock inspection time for this step, in nanoseconds.
    nanos: int = 0
    #: Case-level impact if this step is missed, used for the weighted headline.
    severity: str = "medium"

    @property
    def is_mitigated(self) -> bool:
        return self.actual in MITIGATING

    @property
    def is_attack_surviving(self) -> bool:
        """An expected-harm step that still got through."""
        return self.expected.verdict in MITIGATING and not self.is_mitigated


@dataclass(frozen=True, slots=True)
class Case:
    id: str
    kind: str
    family: str
    variant: str
    severity: str
    description: str
    citation: str
    claim: str
    split: str
    trace: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class FamilyStats:
    """One row of the per-family table, and the JSON object that mirrors it.

    Two definitions of "gap" lived side by side for most of the project's life:
    one in the renderer, one inlined in the `--json` payload, which assumed
    `structural` was the only layer that could ever own a step. On a full run they
    disagreed about 7 of 12 families, and the JSON was wrong in the flattering
    direction -- it reported gaps where there were none, and `stopped: 0` beside
    families the table had caught two steps of. Both read this now, so a dashboard
    and a human reading the same run cannot be told two different stories.

    `owned` means "this build has the layer that was supposed to produce this
    verdict". `gaps` are the harmful steps with no owner: counted as successful
    attacks, never as detector bugs. Detection is graded apart from the
    block/modify scale, because flagging everything scores 100% there.
    """

    family: str
    kind: str
    steps: int
    harmful: int
    owned: int
    stopped: int
    flagged_only: int
    gaps: int
    detection: int
    detected: int

    @property
    def recall(self) -> float:
        """Stopped over owned. Zero when nothing is owned, not a division."""
        return self.stopped / self.owned if self.owned else 0.0

    def as_json(self) -> dict[str, int]:
        return {
            "steps": self.steps,
            "harmful": self.harmful,
            "owned": self.owned,
            "stopped": self.stopped,
            "flag_only": self.flagged_only,
            "gaps": self.gaps,
            "detection": self.detection,
            "detected": self.detected,
        }


@dataclass(slots=True)
class Report:
    results: list[StepResult] = field(default_factory=list)
    #: Names of the detector layers that were actually running. A step whose
    #: accountable layer is missing from this set is a gap, not a regression --
    #: but only because the set is derived from the pipeline rather than
    #: hardcoded, so adding a layer cannot silently downgrade its failures.
    layers: tuple[str, ...] = ("structural",)

    def owns(self, layer: str | None) -> bool:
        """Is a layer responsible for this step present in this build?"""
        return layer is None or layer in self.layers

    # -- filtering ---------------------------------------------------------

    def family_stats(self) -> dict[str, FamilyStats]:
        """Per-family counts, graded identically for every consumer.

        Shared by the rendered table and the `--json` payload, so the two cannot
        drift apart again the moment a third layer is added.
        """
        stats: dict[str, FamilyStats] = {}
        for family, results in self.by_family().items():
            harmful = [r for r in results if r.expected.verdict in MITIGATING]
            detection = [r for r in results if r.expected.verdict == "flag"]
            owned = [r for r in harmful if self.owns(r.expected.layer)]
            stats[family] = FamilyStats(
                family=family,
                kind=results[0].kind,
                steps=len(results),
                harmful=len(harmful),
                owned=len(owned),
                stopped=sum(r.actual in MITIGATING for r in owned),
                flagged_only=sum(r.actual == "flag" for r in owned),
                gaps=len(harmful) - len(owned),
                detection=len(detection),
                detected=sum(r.actual in MITIGATING for r in detection),
            )
        return stats

    def by_family(self) -> dict[str, list[StepResult]]:
        grouped: dict[str, list[StepResult]] = defaultdict(list)
        for result in self.results:
            grouped[result.family].append(result)
        return dict(grouped)

    def attack_steps(self) -> list[StepResult]:
        """Steps where harm was expected: the ones the corpus asks to be stopped."""
        return [r for r in self.results if r.expected.verdict in MITIGATING]

    def benign_steps(self) -> list[StepResult]:
        """Every step the corpus expects to pass untouched."""
        return [r for r in self.results if r.expected.verdict == "allow"]

    # -- headline numbers --------------------------------------------------

    def attack_success_rate(self) -> float:
        """Fraction of harmful steps that were *not* stopped. Lower is better."""
        steps = self.attack_steps()
        return sum(r.is_attack_surviving for r in steps) / len(steps) if steps else 0.0

    def weighted_attack_success_rate(self) -> float:
        """ASR weighted by the impact of each miss."""
        steps = self.attack_steps()
        if not steps:
            return 0.0
        total = sum(SEVERITY_WEIGHT.get(r.severity, 1.0) for r in steps)
        survived = sum(SEVERITY_WEIGHT.get(r.severity, 1.0) for r in steps if r.is_attack_surviving)
        return survived / total if total else 0.0

    def detection_rate(self) -> float:
        """Fraction of harmful steps that produced any non-allow verdict.

        Reported next to ASR, not instead of it, because flagging everything
        scores 100% here and 0% protection in practice.
        """
        steps = self.attack_steps()
        caught = sum(r.actual != "allow" for r in steps)
        return caught / len(steps) if steps else 0.0

    def false_positive_rate(self) -> float:
        """Fraction of expected-allow steps that were not allowed."""
        steps = self.benign_steps()
        offenders = sum(r.actual != "allow" for r in steps)
        return offenders / len(steps) if steps else 0.0

    def gap_rate(self) -> float:
        """Share of harmful steps attributed to a layer that does not exist yet."""
        steps = self.attack_steps()
        gaps = sum(not self.owns(r.expected.layer) for r in steps)
        return gaps / len(steps) if steps else 0.0

    # -- failure accounting ------------------------------------------------

    def regressions(self) -> list[StepResult]:
        """Steps a layer in this build is accountable for that went wrong.

        False positives are excluded: they are their own category, and folding
        them in here would make a report claim two regressions when only one is.
        """
        return [r for r in self.results if r.outcome == "mismatch" and self.owns(r.expected.layer)]

    def false_positives(self) -> list[StepResult]:
        return [r for r in self.results if r.outcome == "false-positive"]

    def is_clean(self) -> bool:
        """Whether the build under test is honest about what it claims."""
        return not self.regressions() and not self.false_positives()

    def latency(self) -> dict[str, float]:
        """Per-step inspection time in nanoseconds.

        A structural scan is genuinely sub-microsecond, so reporting whole
        microseconds would render most steps as a flat 0us and hide the shape
        of the distribution entirely.
        """
        times = [float(r.nanos) for r in self.results]
        if not times:
            return {"p50": 0.0, "p95": 0.0, "max": 0.0, "mean": 0.0}
        ordered = sorted(times)
        return {
            "p50": statistics.median(ordered),
            "p95": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
            "max": max(ordered),
            "mean": statistics.fmean(ordered),
        }

    def bootstrap_ci(
        self, statistic: Any, *, samples: int = 2000, confidence: float = 0.95, seed: int = 0
    ) -> tuple[float, float]:
        """Percentile bootstrap over cases, not steps.

        Resampling steps would treat the 25 single-character requests of one
        sharded-egress case as 25 independent observations and report a
        confidence interval several times too narrow. Cases are the unit of
        independence, so they are the unit of resampling.
        """
        rng = random.Random(seed)
        per_case: dict[str, list[StepResult]] = defaultdict(list)
        for result in self.results:
            per_case[result.case_id].append(result)
        cases = list(per_case.values())
        if len(cases) < 2:
            return (float("nan"), float("nan"))

        values: list[float] = []
        for _ in range(samples):
            draw = [rng.choice(cases) for _ in cases]
            resampled = Report(results=[r for group in draw for r in group])
            values.append(float(statistic(resampled)))
        values.sort()
        alpha = (1.0 - confidence) / 2.0
        low = values[int(alpha * len(values))]
        high = values[min(len(values) - 1, int((1.0 - alpha) * len(values)))]
        return (low, high)


# -- corpus loading ---------------------------------------------------------


def load_corpus(root: Path) -> list[Case]:
    """Read every case from a corpus directory."""
    cases: list[Case] = []
    for path in sorted(Path(root).rglob("*.jsonl")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON: {exc.msg}") from exc
            cases.append(
                Case(
                    id=data["id"],
                    kind=data.get("kind", "benign" if data["family"] == "benign" else "attack"),
                    family=data["family"],
                    variant=data.get("variant", ""),
                    severity=data.get("severity", "medium"),
                    description=data.get("description", ""),
                    citation=data.get("source", {}).get("citation", ""),
                    claim=data.get("source", {}).get("claim", ""),
                    split=data.get("split", "test"),
                    trace=tuple(data["trace"]),
                )
            )
    return cases


def validate_corpus(cases: Sequence[Case]) -> list[str]:
    """Structural checks that must hold for the corpus to mean anything."""
    problems: list[str] = []
    seen: dict[str, Case] = {}
    for case in cases:
        if case.id in seen:
            problems.append(f"{case.id}: duplicate case id")
        seen[case.id] = case
        if not case.trace:
            problems.append(f"{case.id}: empty trace")
        if case.kind not in ("attack", "benign"):
            problems.append(f"{case.id}: bad kind {case.kind!r}")
        for index, step in enumerate(case.trace):
            if "expect" not in step or "message" not in step:
                problems.append(f"{case.id} step {index}: missing 'message' or 'expect'")
                continue
            verdict = step["expect"].get("verdict")
            if verdict not in ("allow", "flag", "modify", "block"):
                problems.append(f"{case.id} step {index}: bad verdict {verdict!r}")
            if verdict != "allow" and not step["expect"].get("layer"):
                problems.append(
                    f"{case.id} step {index}: non-allow step has no responsible layer, "
                    "so a miss cannot be attributed"
                )
            if step.get("direction") not in ("host->upstream", "upstream->host"):
                problems.append(f"{case.id} step {index}: bad direction")
        if case.kind == "attack" and not case.citation:
            problems.append(f"{case.id}: attack case has no source citation")
    return problems


# -- replay -----------------------------------------------------------------


def classify(
    expected: StepExpectation,
    actual: Verdict,
    layers: Sequence[str] = ("structural",),
) -> str:
    """Assign the outcome for one step.

    The distinction that carries the whole evaluation: a step no layer in this
    build is accountable for is a *gap* -- still counted as a successful attack,
    but not filed as a failure of code that is working as specified. Everything
    else must match.
    """
    if expected.verdict == "allow":
        return "match" if actual == "allow" else "false-positive"
    if actual == expected.verdict:
        return "match"
    if expected.layer is not None and expected.layer not in layers:
        return "gap"
    return "mismatch"


def replay_case(
    case: Case,
    pipeline: InspectorPipeline,
    layers: Sequence[str] = ("structural",),
) -> list[StepResult]:
    """Drive one transcript through the pipeline, step by step.

    State is per-case and fresh: a session context that leaked between cases
    would let one case's taint make the next case's verdict look better or
    worse than it is. That applies to the inspectors too -- a provenance layer
    accumulates state by design, so it is reset here rather than shared.
    """
    ctx = SessionContext()
    for inspector in pipeline.inspectors:
        if isinstance(inspector, Resettable):
            inspector.reset()
    results: list[StepResult] = []
    for index, step in enumerate(case.trace):
        expected = StepExpectation.from_json(step["expect"])
        message = Message(step["message"])

        started = time.perf_counter_ns()
        if step["direction"] == "host->upstream":
            ctx.note_request(message)
            verdict = pipeline.run_request(message, ctx)
        else:
            # Mirror the relay: expose the correlation to detectors, then
            # consume it. Replay has to see what the relay sees, or the
            # evaluation would grade a pipeline the gateway never runs.
            ctx.note_response(message)
            ctx.method_for_response(message)
            verdict = pipeline.run_response(message, ctx)
        nanos = time.perf_counter_ns() - started

        actual: Verdict = verdict.action
        results.append(
            StepResult(
                case_id=case.id,
                kind=case.kind,
                family=case.family,
                index=index,
                direction=step["direction"],
                expected=expected,
                actual=actual,
                rules=tuple(sorted({f.rule for f in verdict.findings})),
                rule_order=tuple(f.rule for f in verdict.findings),
                outcome=classify(expected, actual, layers),  # type: ignore[arg-type]
                nanos=nanos,
                severity=case.severity,
            )
        )
    return results


def replay(
    cases: Sequence[Case],
    inspectors: Sequence[Inspector],
    *,
    split: str | None = None,
) -> Report:
    """Run every case through a pipeline built from `inspectors`.

    The set of running layer names is recorded on the report and used to decide
    what counts as a gap, so it is read off the pipeline instead of being
    restated here. Otherwise adding a detector would leave its own failures
    classified as "not built yet" and passing silently.
    """
    pipeline = InspectorPipeline(tuple(inspectors))
    layers = tuple(insp.name for insp in pipeline.inspectors)
    report = Report(layers=layers)
    for case in cases:
        if split is not None and case.split != split:
            continue
        report.results.extend(replay_case(case, pipeline, layers))
    return report


def iter_failures(report: Report) -> Iterator[StepResult]:
    for result in report.results:
        if result.outcome in ("false-positive", "mismatch"):
            yield result
