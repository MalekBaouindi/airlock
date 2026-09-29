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
from airlock.inspect.base import Inspector, InspectorPipeline

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


@dataclass(slots=True)
class Report:
    results: list[StepResult] = field(default_factory=list)

    # -- filtering ---------------------------------------------------------

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
        gaps = sum(r.expected.layer is not None and r.expected.layer != "structural" for r in steps)
        return gaps / len(steps) if steps else 0.0

    # -- failure accounting ------------------------------------------------

    def regressions(self) -> list[StepResult]:
        """Structural-layer steps that did not behave as specified."""
        return [
            r for r in self.results if r.expected.layer == "structural" and r.outcome != "match"
        ]

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


def classify(expected: StepExpectation, actual: Verdict) -> str:
    """Assign the three-valued outcome for one step."""
    if expected.verdict == "allow":
        return "match" if actual == "allow" else "false-positive"
    if actual == expected.verdict:
        return "match"
    if expected.layer is not None and expected.layer != "structural":
        return "gap"
    return "mismatch"


def replay_case(case: Case, pipeline: InspectorPipeline) -> list[StepResult]:
    """Drive one transcript through the pipeline, step by step.

    State is per-case and fresh: a session context that leaked between cases
    would let one case's taint make the next case's verdict look better or
    worse than it is.
    """
    ctx = SessionContext()
    results: list[StepResult] = []
    for index, step in enumerate(case.trace):
        expected = StepExpectation.from_json(step["expect"])
        message = Message(step["message"])

        started = time.perf_counter_ns()
        if step["direction"] == "host->upstream":
            ctx.note_request(message)
            verdict = pipeline.run_request(message, ctx)
        else:
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
                outcome=classify(expected, actual),  # type: ignore[arg-type]
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
    """Run every case through a pipeline built from `inspectors`."""
    pipeline = InspectorPipeline(tuple(inspectors))
    report = Report()
    for case in cases:
        if split is not None and case.split != split:
            continue
        report.results.extend(replay_case(case, pipeline))
    return report


def iter_failures(report: Report) -> Iterator[StepResult]:
    for result in report.results:
        if result.outcome in ("false-positive", "mismatch"):
            yield result
