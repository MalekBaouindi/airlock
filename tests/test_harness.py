"""Harness tests.

The most important property of this module is not that it computes a number --
it is that the number is *load-bearing*. A gate that cannot fail is worse than
no gate, because it reports safety it has not verified. These tests therefore
deliberately break the detector and assert that the report notices.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from airlock.audit.log import Finding
from airlock.eval.harness import (
    Case,
    Report,
    StepExpectation,
    StepResult,
    classify,
    load_corpus,
    replay,
    replay_case,
    validate_corpus,
)
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.base import ALLOW, InspectorPipeline, Verdict
from airlock.inspect.structural import StructuralInspector

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
TAG = chr(0xE0000 | 0x41)


@pytest.fixture(scope="module")
def cases() -> list[Case]:
    loaded = load_corpus(CORPUS)
    assert loaded, "corpus is empty; run 'make corpus'"
    return loaded


@pytest.fixture(scope="module")
def report(cases: list[Case]) -> Report:
    return replay(cases, [StructuralInspector()])


# -- corpus integrity -------------------------------------------------------


class TestCorpus:
    def test_corpus_loads(self, cases: list[Case]) -> None:
        assert len(cases) >= 20

    def test_corpus_is_well_formed(self, cases: list[Case]) -> None:
        assert validate_corpus(cases) == []

    def test_ids_are_unique(self, cases: list[Case]) -> None:
        ids = [c.id for c in cases]
        assert len(ids) == len(set(ids))

    def test_every_attack_case_cites_a_source(self, cases: list[Case]) -> None:
        for case in cases:
            if case.family != "benign":
                assert case.citation, f"{case.id} has no citation"

    def test_benign_corpus_exists(self, cases: list[Case]) -> None:
        """Without a false-positive corpus the FPR is fictional."""
        benign = [c for c in cases if c.family == "benign"]
        assert len(benign) >= 5

    def test_every_family_has_harm_and_allow_steps(self, cases: list[Case]) -> None:
        """A family with no expected-allow steps would make per-family
        false-positive cost invisible."""
        for case in cases:
            if case.family == "benign":
                continue
            verdicts = {s["expect"]["verdict"] for s in case.trace}
            assert "allow" in verdicts, f"{case.id} has no passing steps"

    def test_splits_are_disjoint(self, cases: list[Case]) -> None:
        dev = {c.id for c in cases if c.split == "dev"}
        test = {c.id for c in cases if c.split == "test"}
        assert not (dev & test)

    def test_every_case_states_its_kind(self, cases: list[Case]) -> None:
        """Kind is a property of the corpus author, not something the evaluator
        deduces from verdicts."""
        for case in cases:
            assert case.kind in ("attack", "benign"), case.id
        assert {c.kind for c in cases if c.family == "benign"} == {"benign"}
        assert all(c.kind == "attack" for c in cases if c.family != "benign"), (
            "non-benign families must be attacks"
        )

    def test_both_splits_contain_owned_steps(self, cases: list[Case]) -> None:
        """A split with no steps the shipped layer is responsible for cannot
        score it, so `airlock eval --split test` would report a meaningless
        0% rather than a low score."""
        for split in ("dev", "test"):
            owned = [
                s
                for c in cases
                if c.split == split
                for s in c.trace
                if s["expect"].get("layer") == "structural"
            ]
            assert owned, f"{split} split has no structural steps to evaluate"

    def test_validator_catches_missing_layer(self) -> None:
        case = Case(
            id="x",
            kind="attack",
            family="f",
            variant="v",
            severity="high",
            description="",
            citation="c",
            claim="",
            split="test",
            trace=(
                {
                    "direction": "upstream->host",
                    "message": {"jsonrpc": "2.0", "id": 1, "result": {}},
                    "expect": {"verdict": "block", "reason": "harm"},
                },
            ),
        )
        problems = validate_corpus([case])
        assert any("no responsible layer" in p for p in problems)

    def test_validator_catches_duplicate_id(self) -> None:
        step = {
            "direction": "upstream->host",
            "message": {"jsonrpc": "2.0", "id": 1, "result": {}},
            "expect": {"verdict": "allow", "reason": ""},
        }
        args = ("dup", "benign", "f", "v", "low", "", "cite", "", "test", (step,))
        problems = validate_corpus([Case(*args), Case(*args)])  # type: ignore[arg-type]
        assert any("duplicate" in p for p in problems)


# -- classification ---------------------------------------------------------


class TestClassify:
    def test_exact_match(self) -> None:
        assert classify(StepExpectation("block", "", "structural"), "block") == "match"

    def test_allow_is_a_match(self) -> None:
        assert classify(StepExpectation("allow", "", None), "allow") == "match"

    @pytest.mark.parametrize("actual", ["flag", "block", "modify"])
    def test_non_allow_on_allow_step_is_a_false_positive(self, actual: str) -> None:
        """No excuse applies here: ordinary traffic must pass untouched."""
        assert classify(StepExpectation("allow", "", None), actual) == "false-positive"  # type: ignore[arg-type]

    def test_unbuilt_layer_miss_is_a_gap_not_a_bug(self) -> None:
        assert classify(StepExpectation("block", "", "provenance"), "allow") == "gap"

    def test_own_layer_miss_is_a_mismatch(self) -> None:
        """A regression in a layer this build actually ships is not 'gap debt'."""
        assert classify(StepExpectation("block", "", "structural"), "allow") == "mismatch"


# -- metrics ----------------------------------------------------------------


def _step(**kw: object) -> StepResult:
    """Build a StepResult with the outcome the harness would actually assign.

    Deriving it via `classify` matters: a hand-written `outcome` would let a
    test assert on a state the real pipeline never produces.
    """
    base: dict[str, object] = dict(
        case_id="c",
        kind="attack",
        family="f",
        index=0,
        direction="upstream->host",
        expected=StepExpectation("allow", "", None),
        actual="allow",
    )
    base.update(kw)
    expected = base["expected"]
    actual = base["actual"]
    assert isinstance(expected, StepExpectation)
    assert isinstance(actual, str)
    base["outcome"] = classify(expected, actual)  # type: ignore[arg-type]
    return StepResult(**base)  # type: ignore[arg-type]


class TestMetrics:
    def test_asr_counts_only_expected_harm(self) -> None:
        report = Report(
            results=[
                _step(expected=StepExpectation("block", "", "provenance"), actual="allow"),
                _step(expected=StepExpectation("block", "", "provenance"), actual="block"),
                _step(expected=StepExpectation("allow", "", None), actual="allow"),
            ]
        )
        assert report.attack_success_rate() == 0.5

    def test_flag_does_not_count_as_mitigation(self) -> None:
        """Flagging leaves the message in front of the model, so for the
        runtime-channel threat model it is not a stop."""
        report = Report(
            results=[_step(expected=StepExpectation("block", "", "structural"), actual="flag")]
        )
        assert report.attack_success_rate() == 1.0
        assert report.detection_rate() == 1.0

    def test_detection_and_asr_are_independent(self) -> None:
        report = Report(
            results=[_step(expected=StepExpectation("block", "", "structural"), actual="flag")]
        )
        assert report.detection_rate() == 1.0
        assert report.attack_success_rate() == 1.0

    def test_fpr_measures_only_allow_steps(self) -> None:
        report = Report(
            results=[
                _step(expected=StepExpectation("allow", "", None), actual="flag"),
                _step(expected=StepExpectation("allow", "", None), actual="allow"),
                _step(expected=StepExpectation("block", "", "structural"), actual="block"),
            ]
        )
        assert report.false_positive_rate() == 0.5

    def test_weighted_asr_prices_severity(self) -> None:
        """A miss on a critical case must cost more than a miss on a low one."""
        heavy = Report(
            results=[
                _step(
                    expected=StepExpectation("block", "", "p"), actual="allow", severity="critical"
                )
            ]
        )
        light = Report(
            results=[
                _step(expected=StepExpectation("block", "", "p"), actual="allow", severity="low")
            ]
        )
        assert heavy.weighted_attack_success_rate() == light.weighted_attack_success_rate() == 1.0
        mixed = Report(
            results=[
                _step(
                    expected=StepExpectation("block", "", "p"), actual="allow", severity="critical"
                ),
                _step(expected=StepExpectation("block", "", "p"), actual="block", severity="low"),
            ]
        )
        # 8/9 of the total weight survived, not 1/2 of the count.
        assert mixed.weighted_attack_success_rate() == pytest.approx(8 / 9)

    def test_empty_report_is_not_a_division_error(self) -> None:
        report = Report()
        assert report.attack_success_rate() == 0.0
        assert report.false_positive_rate() == 0.0
        assert report.is_clean()

    def test_gap_rate(self) -> None:
        report = Report(
            results=[
                _step(expected=StepExpectation("block", "", "provenance")),
                _step(expected=StepExpectation("block", "", "structural")),
            ]
        )
        assert report.gap_rate() == 0.5


class TestVerdict:
    def test_shipped_build_is_clean_on_its_own_layer(self, report: Report) -> None:
        """The structural layer has no false positives and no regressions on the
        full corpus.

        `benign-template-docs` is the case that makes this a real assertion
        rather than a formality: the content does contain chat-template tokens,
        and the corpus grades it `flag` rather than `allow` precisely because
        an analyst genuinely should see it. What is forbidden is *blocking* it.
        """
        assert not report.false_positives(), report.false_positives()
        assert not report.regressions(), report.regressions()
        assert report.is_clean()

    def test_documented_tokens_are_flagged_but_never_blocked(self, report: Report) -> None:
        """Grading the docs case as `flag` is only honest if the gateway really
        does stop short of blocking it. Assert the non-action directly."""
        docs = [r for r in report.results if r.case_id == "benign-template-docs"]
        assert docs, "corpus case went missing"
        assert [r.actual for r in docs] == ["allow", "flag"]
        assert docs[1].outcome == "match"

    def test_regressions_and_false_positives_are_separate(self) -> None:
        report = Report(
            results=[
                _step(expected=StepExpectation("block", "", "structural"), actual="allow"),
                _step(expected=StepExpectation("allow", "", None), actual="flag"),
            ]
        )
        assert len(report.regressions()) == 1
        assert len(report.false_positives()) == 1
        assert not report.is_clean()


class TestBootstrap:
    def test_ci_brackets_the_point_estimate(self, report: Report) -> None:
        low, high = report.bootstrap_ci(Report.attack_success_rate, samples=200)
        point = report.attack_success_rate()
        assert low <= point <= high

    def test_ci_is_deterministic(self, report: Report) -> None:
        first = report.bootstrap_ci(Report.false_positive_rate, samples=200)
        second = report.bootstrap_ci(Report.false_positive_rate, samples=200)
        assert first == second

    def test_single_case_has_no_interval(self) -> None:
        """With one case there is nothing to resample; reporting 0.0-0.0 would
        look like a precise measurement instead of an absence of one."""
        report = Report(results=[_step()])
        low, high = report.bootstrap_ci(Report.false_positive_rate)
        assert low != low and high != high  # NaN


# -- the gate is load-bearing ----------------------------------------------


class BrokenInspector:
    """Catches nothing. Used to prove the harness can fail."""

    name = "broken"

    def inspect_request(self, message: Message, ctx: SessionContext) -> Verdict:
        return ALLOW

    def inspect_response(self, message: Message, ctx: SessionContext) -> Verdict:
        return ALLOW


class OverzealousInspector:
    """Blocks everything. Used to prove false positives are caught."""

    name = "overzealous"

    def inspect_request(self, message: Message, ctx: SessionContext) -> Verdict:
        return Verdict.of("block", Finding("overzealous", "critical", "blocks all"))

    def inspect_response(self, message: Message, ctx: SessionContext) -> Verdict:
        return Verdict.of("block", Finding("overzealous", "critical", "blocks all"))


class GateLoadBearing:
    def test_a_useless_detector_is_caught(self, cases: list[Case]) -> None:
        report = replay(cases, [BrokenInspector()])
        assert not report.is_clean()
        assert report.regressions(), "a detector that catches nothing must regress"

    def test_a_blocking_detector_is_caught(self, cases: list[Case]) -> None:
        """The opposite failure: a 'perfect' detector that blocks ordinary
        traffic. Perfect recall, total uselessness."""
        report = replay(cases, [OverzealousInspector()])
        assert not report.is_clean()
        assert report.false_positives()
        assert report.false_positive_rate() > 0.5

    def test_ablation_baseline_is_worse_than_the_detector(
        cases: list[Case], report: Report
    ) -> None:
        baseline = replay(cases, [])
        assert baseline.attack_success_rate() >= report.attack_success_rate()
        assert baseline.detection_rate() <= report.detection_rate()


# -- replay mechanics -------------------------------------------------------


class TestReplay:
    def test_every_step_is_replayed(self, cases: list[Case], report: Report) -> None:
        assert len(report.results) == sum(len(c.trace) for c in cases)

    def test_split_filtering(self, cases: list[Case]) -> None:
        dev = replay(cases, [StructuralInspector()], split="dev")
        assert {r.case_id for r in dev.results} == {c.id for c in cases if c.split == "dev"}

    def test_state_does_not_leak_between_cases(self, cases: list[Case]) -> None:
        """Two runs of the same corpus must agree exactly, or a case's taint is
        influencing the next case's verdict."""
        inspectors = [StructuralInspector()]
        first = replay(cases, inspectors)
        second = replay(cases, inspectors)
        assert [(r.case_id, r.index, r.actual) for r in first.results] == [
            (r.case_id, r.index, r.actual) for r in second.results
        ]

    def test_responses_are_correlated(self, cases: list[Case]) -> None:
        """A response must be attributed to the request that caused it, which is
        what lets a tool result be told apart from a tool listing."""
        case = next(c for c in cases if c.id == "tool_poisoning-001")
        ctx = SessionContext()
        pipeline = InspectorPipeline((StructuralInspector(),))
        seen: list[str | None] = []
        for step in case.trace:
            message = Message(step["message"])
            if step["direction"] == "host->upstream":
                ctx.note_request(message)
            else:
                seen.append(ctx.method_for_response(message))
                pipeline.run_response(message, ctx)
        assert "tools/list" in seen

    def test_latency_is_measured(self, cases: list[Case], report: Report) -> None:
        assert all(r.nanos > 0 for r in report.results)
        assert report.latency()["p50"] > 0

    def test_single_case_replay(self, cases: list[Case]) -> None:
        case = cases[0]
        results = replay_case(case, InspectorPipeline((StructuralInspector(),)))
        assert len(results) == len(case.trace)


# -- the specific claims the corpus makes ----------------------------------


class TestKnownBehaviour:
    def test_unicode_tag_payload_is_blocked(self, cases: list[Case]) -> None:
        """The one attack the structural layer is built to stop."""
        case = next(c for c in cases if c.id == "tool_poisoning-002")
        results = replay_case(case, InspectorPipeline((StructuralInspector(),)))
        assert results[-1].actual == "block"
        assert "unicode-tag" in results[-1].rules

    def test_causality_laundering_is_not_caught(self, cases: list[Case]) -> None:
        """Documented gap, asserted so it cannot be forgotten.

        This case has no suspicious string anywhere; nothing short of a
        provenance engine can see it. If this test ever starts failing, the
        provenance layer exists and the coverage-debt numbers need updating.
        """
        case = next(c for c in cases if c.id == "causality_laundering-001")
        results = replay_case(case, InspectorPipeline((StructuralInspector(),)))
        assert results[-1].actual == "allow"
        assert results[-1].expected.layer == "provenance"
        assert results[-1].outcome == "gap"

    def test_sharded_egress_defeats_per_step_dlp(self, cases: list[Case]) -> None:
        """No single request is remarkable, so a per-message rule cannot help."""
        case = next(c for c in cases if c.id == "sharded_egress-001")
        results = replay_case(case, InspectorPipeline((StructuralInspector(),)))
        assert all(r.actual == "allow" for r in results)

    def test_benign_emoji_passes(self, cases: list[Case], report: Report) -> None:
        """The false positive the ZWJ exemption exists to prevent."""
        offenders = [r for r in report.false_positives() if "zero-width" in r.rules]
        assert not offenders, f"zero-width rule is over-firing: {offenders}"

    def test_bidi_is_detected_but_not_blocked_by_default(self, cases: list[Case]) -> None:
        """Detection and blocking are separate decisions, and this is the case
        that shows it: the rule fires, the default severity floor holds it at
        'flag' because the floor is a policy choice an operator may lower."""
        case = next(c for c in cases if c.id == "tool_poisoning-003")
        result = replay_case(case, InspectorPipeline((StructuralInspector(),)))[-1]
        assert "bidi-control" in result.rules
        assert result.actual == "flag"
        assert result.expected.verdict == "flag"
        assert result.outcome == "match"

    def test_lowering_the_floor_escalates_to_a_block(self, cases: list[Case]) -> None:
        """Same corpus, same rules, one operator flag changed. The tunable has to
        actually move the decision, or the README is overstating it."""
        case = next(c for c in cases if c.id == "tool_poisoning-003")
        pipeline = InspectorPipeline((StructuralInspector(block_at="high"),))
        result = replay_case(case, pipeline)[-1]
        assert result.actual == "block"

    def test_observe_only_floor_never_blocks(self, cases: list[Case]) -> None:
        """`--block-at none` is the measurement mode: it must let every attack
        through while still reporting, which is what the FPR figures rely on."""
        pipeline = (StructuralInspector(block_at=None),)
        report = replay(cases, pipeline)
        assert not [r for r in report.results if r.actual == "block"]
        assert report.detection_rate() > 0, "observe-only must still detect"
