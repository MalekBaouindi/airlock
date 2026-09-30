"""The report is what an operator reads to decide whether the build is sound.

`src/airlock/eval/report.py` had 10% line coverage -- it was imported by the CLI
and the smoke test proved it did not crash, and nothing else. That is the weakest
place to leave a gap, because it is the code that turns the corpus into the
sentence "0.0% ASR, no regressions", and a bug there misreports a working build
without breaking a single test.

So every number here is computed by hand in a comment and then checked against
what the renderer prints. The inputs are synthetic and small on purpose: a real
corpus cannot tell you which figure is wrong, because it has no expected value.
`classify` derives each outcome, as in `test_harness`, so no test asserts on a
state the pipeline never produces.
"""

from __future__ import annotations

import pytest

from airlock.eval.harness import (
    Report,
    StepExpectation,
    StepResult,
    classify,
)
from airlock.eval.report import render

LAYERS = ("structural", "provenance", "policy")


def step(
    *,
    expected: str = "allow",
    layer: str | None = None,
    actual: str = "allow",
    case_id: str = "case",
    family: str = "fam",
    index: int = 0,
    kind: str = "attack",
    severity: str = "medium",
    layers: tuple[str, ...] = LAYERS,
) -> StepResult:
    expectation = StepExpectation(expected, "", layer)  # type: ignore[arg-type]
    return StepResult(
        case_id=case_id,
        family=family,
        kind=kind,
        index=index,
        direction="upstream->host",
        expected=expectation,
        actual=actual,  # type: ignore[arg-type]
        rules=("r1",),
        rule_order=("r1",),
        outcome=classify(expectation, actual, layers),  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
    )


def verdict_token(text: str) -> str:
    """The standalone headline verdict, ignoring the prose around it.

    The renderer prints the verdict on its own line and then defines what it
    means, so the word appears in the definition regardless. Matching a bare
    `PASS` against the whole document would read a failing run as passing.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in {"PASS", "FAIL"}:
            return stripped
    raise AssertionError(f"no standalone verdict line in:\n{text}")


class TestHeadlineVerdict:
    def test_a_clean_build_passes(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="block", layer="provenance", actual="block"),
                step(expected="allow", kind="benign"),
            ],
        )
        assert verdict_token(render(report)) == "PASS"

    def test_one_false_positive_fails_the_build(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="block", layer="provenance", actual="block"),
                step(expected="allow", actual="block", kind="benign", case_id="chat"),
            ],
        )
        assert verdict_token(render(report)) == "FAIL"

    def test_the_definition_does_not_contain_a_bare_pass_on_a_failing_run(self) -> None:
        # `airlock eval | grep PASS` is a thing people do. A definition line that
        # spells the token unconditionally makes that grep lie, so the explanation
        # is phrased around "a passing run" instead.
        report = Report(
            layers=LAYERS,
            results=[step(expected="allow", actual="block", kind="benign")],
        )
        text = render(report)
        assert verdict_token(text) == "FAIL"
        assert "PASS" not in text

    def test_the_failing_step_is_named(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                step(
                    expected="allow",
                    actual="flag",
                    kind="benign",
                    case_id="doc_page",
                    index=4,
                )
            ],
        )
        text = render(report)
        assert "doc_page" in text
        assert "step 4" in text


class TestAttackSuccessRate:
    def test_the_denominator_is_expected_harm_steps_only(self) -> None:
        """Adding benign traffic must not move the attack rate.

        The tempting denominator is every step in the report. It is wrong in the
        flattering direction: a corpus padded with benign steps would dilute a
        real attack rate toward zero.
        """
        attacks = [
            step(expected="block", layer="provenance", actual="block"),
            step(expected="block", layer="provenance", actual="allow"),
        ]
        bare = Report(layers=LAYERS, results=list(attacks))
        # 1 of 2 expected-harm steps survived.
        assert bare.attack_success_rate() == 0.5
        assert "50.0%" in render(bare)

        padded = Report(
            layers=LAYERS,
            results=[
                *attacks,
                *(step(expected="allow", actual="allow", kind="benign") for _ in range(50)),
            ],
        )
        assert padded.attack_success_rate() == 0.5
        assert "50.0%" in render(padded)

    def test_a_flag_is_detection_but_not_mitigation(self) -> None:
        """Flagging leaves the message in front of the model.

        So it counts as detection (something happened) and as a surviving attack
        (nothing stopped), which is the pair of numbers that has to disagree.
        """
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="block", layer="provenance", actual="flag"),
                step(expected="block", layer="provenance", actual="block"),
            ],
        )
        assert report.attack_success_rate() == 0.5
        assert report.detection_rate() == 1.0
        text = render(report)
        assert "50.0%" in text
        assert "100.0%" in text

    def test_weighted_asr_prices_a_miss_by_severity(self) -> None:
        """One critical miss outranks several low ones.

        Unweighted both are a single step, which flattens exactly the difference
        the weighting exists to express.
        """
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="block", layer="provenance", actual="allow", severity="critical"),
                step(expected="block", layer="provenance", actual="block", severity="low"),
            ],
        )
        assert report.attack_success_rate() == 0.5
        # critical 8.0 of (8.0 + 1.0) total.
        assert report.weighted_attack_success_rate() == 8 / 9
        assert "88.9%" in render(report)


class TestFalsePositiveRate:
    def test_an_accidental_flag_is_a_false_positive_not_noise(self) -> None:
        """Only a flag the corpus asked for counts as analyst noise.

        Folding every flagged benign step into the noise floor would make the two
        companion numbers move together: a detector that started flagging ordinary
        traffic on its own would raise the noise count at the same moment it raised
        the false positive rate, and the whole reason the noise floor is reported
        separately is that a 0.0% FPR must not be readable as "quiet everywhere".
        """
        report = Report(
            layers=LAYERS,
            results=[
                step(
                    expected="flag",
                    actual="flag",
                    kind="benign",
                    case_id="deliberate",
                ),
                step(
                    expected="allow",
                    actual="flag",
                    kind="benign",
                    case_id="accidental",
                ),
            ],
        )
        assert [r.case_id for r in report.false_positives()] == ["accidental"]
        assert report.false_positive_rate() == 1.0
        text = render(report)
        assert "1 step" in text
        assert "deliberate" in text
        assert verdict_token(text) == "FAIL"

    def test_the_rate_shows_its_own_denominator(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="allow", actual="allow", kind="benign"),
                step(expected="allow", actual="flag", kind="benign"),
                step(expected="allow", actual="allow", kind="benign"),
            ],
        )
        assert report.false_positive_rate() == 1 / 3
        assert "1/3 expected-allow steps" in render(report)

    def test_flagging_on_purpose_is_noise_not_a_false_positive(self) -> None:
        """A benign step graded `flag` is the corpus saying "yes, flag this".

        Treating it as a false positive would mean the control noise floor shows
        up twice: once as analyst noise and once as a failure, and the FPR would
        move for a detector that behaved exactly as specified.
        """
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="flag", actual="flag", kind="benign", case_id="chat_template_doc"),
                step(expected="allow", actual="allow", kind="benign"),
            ],
        )
        assert report.false_positives() == []
        assert report.false_positive_rate() == 0.0
        assert report.is_clean()
        text = render(report)
        assert "1 step" in text
        assert "chat_template_doc" in text


class TestGaps:
    def test_a_step_no_layer_owns_is_a_gap_not_a_regression(self) -> None:
        """A missing layer is a fact about the build, not a bug in it.

        Filing it as a regression would make every future layer look broken on
        the day it is added, and would make `PASS` unreachable for any report
        that mentions a capability this build does not have.
        """
        report = Report(
            layers=("structural",),
            results=[
                step(
                    expected="block",
                    layer="semantic",
                    actual="allow",
                    case_id="x",
                    layers=("structural",),
                ),
            ],
        )
        assert [r.outcome for r in report.results] == ["gap"]
        assert report.regressions() == []
        assert verdict_token(render(report)) == "PASS"
        # Still counted as a surviving attack -- absence of a detector is not
        # protection.
        assert report.attack_success_rate() == 1.0

    def test_a_family_with_no_owned_steps_reads_zero_over_zero(self) -> None:
        report = Report(
            layers=("structural",),
            results=[
                step(
                    expected="block",
                    layer="policy",
                    actual="allow",
                    family="egress",
                    layers=("structural",),
                ),
            ],
        )
        assert "0/0" in render(report)


class TestDegenerateInput:
    def test_an_empty_report_renders_without_dividing_by_zero(self) -> None:
        """`--split` that matches nothing is a typo, not a crash."""
        text = render(Report(layers=LAYERS, results=[]))
        assert verdict_token(text) == "PASS"
        assert "0.0%" in text

    def test_a_report_with_no_attack_steps_reports_zero_rather_than_erroring(
        self,
    ) -> None:
        report = Report(
            layers=LAYERS,
            results=[step(expected="allow", actual="allow", kind="benign")],
        )
        assert report.attack_success_rate() == 0.0
        assert "0.0%" in render(report)

    def test_the_interval_brackets_the_point_estimate(self) -> None:
        # Nine cases, one surviving attack among them.
        report = Report(
            layers=LAYERS,
            results=[
                step(
                    expected="block",
                    layer="provenance",
                    actual="allow" if n == 0 else "block",
                    case_id=f"c{n}",
                    index=n,
                )
                for n in range(10)
            ],
        )
        low, high = report.bootstrap_ci(Report.attack_success_rate)
        assert 0.0 <= low <= report.attack_success_rate() <= high <= 1.0

    def test_one_case_has_no_interval_and_says_so_loudly(self) -> None:
        """A bootstrap over a single case cannot exist.

        The cases are the unit of independence, so there is nothing to resample.
        Returning a real-looking interval would be the actual bug here; the
        refusal is deliberate, and it renders as `nan%` rather than as a number,
        so a reader cannot mistake it for a measured bound.
        """
        report = Report(
            layers=LAYERS,
            results=[step(expected="block", layer="provenance", actual="allow")],
        )
        low, high = report.bootstrap_ci(Report.attack_success_rate)
        assert low != low and high != high  # both NaN
        assert "nan" in render(report)


class TestLatency:
    @pytest.mark.parametrize(
        ("nanos", "rendered"),
        [
            (999, "999ns"),
            (1_500, "1.5us"),
            (2_500_000, "2.50ms"),
            (3_000_000_000, "3.00s"),
        ],
    )
    def test_each_unit_is_scaled_exactly_once(self, nanos: int, rendered: str) -> None:
        """Structural inspection is sub-microsecond.

        Rounded to whole microseconds most steps print as a flat `0us`, which
        flattens the distribution and hides the tail that matters -- so the
        report keeps nanosecond precision and scales up as the numbers grow.
        """
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="allow", actual="allow", kind="benign", index=0),
                StepResult(
                    case_id="slow",
                    family="fam",
                    kind="benign",
                    index=1,
                    direction="upstream->host",
                    expected=StepExpectation("allow", "", None),
                    actual="allow",
                    outcome="match",
                    nanos=nanos,
                ),
            ],
        )
        text = render(report)
        assert f"max {rendered}" in text

    def test_p50_is_the_median_not_the_mean(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                StepResult(
                    case_id=f"c{n}",
                    family="fam",
                    kind="benign",
                    index=0,
                    direction="upstream->host",
                    expected=StepExpectation("allow", "", None),
                    actual="allow",
                    outcome="match",
                    nanos=n,
                )
                for n in (1_000, 1_000, 1_000_000)
            ],
        )
        assert report.latency()["p50"] == 1_000
        assert "p50 1.0us" in render(report)


class TestRenderedText:
    def test_the_title_and_case_count_are_present(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                step(case_id="alpha", index=0),
                step(case_id="alpha", index=1),
                step(case_id="beta", index=0),
            ],
        )
        text = render(report, title="airlock evaluation (test split)")
        assert "airlock evaluation (test split)" in text
        assert "2 cases, 3 steps" in text

    def test_a_clean_run_says_so_in_words(self) -> None:
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="block", layer="provenance", actual="block"),
                step(expected="allow", actual="allow", kind="benign"),
            ],
        )
        assert "no regressions" in render(report)

    def test_rendering_is_stable(self) -> None:
        """The report feeds CI logs; a report that reshuffles between runs on the
        same corpus makes a diff unreadable and hides the change that matters."""
        report = Report(
            layers=LAYERS,
            results=[
                step(expected="block", layer="provenance", actual="block", family="b"),
                step(expected="block", layer="policy", actual="flag", family="a"),
                step(expected="allow", actual="allow", kind="benign", family="c"),
            ],
        )
        assert render(report) == render(report)
