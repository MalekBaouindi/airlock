"""Rendering evaluation results.

The formatting decisions here are the difference between a useful report and a
misleading one:

* Every number is shown next to its denominator, because "87% detection" means
  something very different over 15 cases than over 1500.
* Gaps are printed in their own column, never folded into a pass rate. A table
  that only shows match/miss invites reading a covered family as a caught one.
* Failure rows are printed first. A report whose last line is a success table
  gets skimmed past the parts that need attention.
* Interpretation is printed as prose, not as a column. A wide explanatory
  column forces Rich to shrink the numeric ones, and "87.5%" rendered as "87."
  is a worse defect than having no interpretation on screen.
* Nothing is allowed to disappear into a clean number. Benign content that is
  flagged on purpose still gets its own line, so a 0% false-positive rate can
  never be read as "the detector was quiet everywhere".
"""

from __future__ import annotations

from typing import Any

from airlock.eval.harness import Report, StepResult

BAR_FULL = "#"
BAR_EMPTY = "."


def _pct(value: float) -> str:
    return f"{value * 100:5.1f}%"


def _bar(fraction: float, width: int = 20) -> str:
    filled = round(fraction * width)
    return BAR_FULL * filled + BAR_EMPTY * (width - filled)


def _table(
    console: Any,
    title: str,
    columns: list[str],
    rows: list[list[str]],
    widths: dict[str, int] | None = None,
) -> None:
    from rich.table import Table

    table = Table(title=title, expand=False)
    for index, column in enumerate(columns):
        # An explicit minimum width keeps a long neighbouring column from
        # squeezing a number down to its first digit. Taking the max of the
        # hint and the widest actual cell stops a short value like "1" from
        # leaving the column wider than it needs to be.
        kwargs: dict[str, Any] = {"no_wrap": True, "overflow": "fold"}
        if widths and column in widths:
            content = max((len(r[index]) for r in rows), default=0)
            kwargs["min_width"] = max(widths[column], content)
        table.add_column(column, **kwargs)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def render(report: Report, *, title: str = "airlock evaluation") -> str:
    import io

    from rich.console import Console

    # Recorded to a buffer rather than stdout: the caller decides where the text
    # goes. Printing from here *and* returning the text duplicated every report.
    console = Console(record=True, width=100, file=io.StringIO())

    attack_steps = report.attack_steps()
    benign_steps = report.benign_steps()
    cases = {r.case_id for r in report.results}

    console.print(f"\n[bold]{title}[/bold]")
    console.print(
        f"{len(cases)} cases, {len(report.results)} steps "
        f"({len(attack_steps)} expected-harm, {len(benign_steps)} expected-allow)\n"
    )

    # -- failures first ----------------------------------------------------

    regressions = report.regressions()
    # Deliberate flags on control content. These are graded as matches, so they
    # would otherwise vanish from a clean FPR and quietly inflate it later.
    noise = [
        r
        for r in report.results
        if r.kind == "benign" and r.expected.verdict == "flag" and r.actual == "flag"
    ]
    false_positives = report.false_positives()
    if regressions or false_positives:
        failure_rows = [
            [
                r.case_id,
                f"step {r.index}",
                r.family,
                r.expected.verdict,
                r.actual,
                ",".join(r.rules) or "-",
            ]
            for r in (*false_positives, *regressions)
        ]
        _table(
            console,
            f"FAILURES ({len(failure_rows)}) - these steps do not match the corpus",
            ["case", "at", "family", "expected", "actual", "rules"],
            failure_rows,
        )
    else:
        console.print(
            "[green]no regressions: every structural step and every "
            "expected-allow step behaved as specified[/green]"
        )

    # -- headline ----------------------------------------------------------

    asr = report.attack_success_rate()
    wasr = report.weighted_attack_success_rate()
    detect = report.detection_rate()
    fpr = report.false_positive_rate()

    low, high = report.bootstrap_ci(Report.attack_success_rate)
    dlow, dhigh = report.bootstrap_ci(Report.detection_rate)

    # Interpretation lives in footnotes rather than a fourth column. A wide
    # prose column forces Rich to squeeze the numeric ones, and a squeezed
    # "87.5%" rendering as "87." is worse than no interpretation at all.
    _table(
        console,
        "headline",
        ["metric", "value", "95% CI (bootstrap over cases)"],
        [
            ["attack success rate", _pct(asr), f"[{_pct(low)}, {_pct(high)}]"],
            ["weighted ASR", _pct(wasr), "-"],
            ["detection rate", _pct(detect), f"[{_pct(dlow)}, {_pct(dhigh)}]"],
            [
                "false positive rate",
                _pct(fpr),
                f"{sum(r.actual != 'allow' for r in benign_steps)}/"
                f"{len(benign_steps)} expected-allow steps",
            ],
            [
                "control noise floor",
                f"{len(noise)} step{'' if len(noise) == 1 else 's'}",
                "-",
            ],
        ],
        widths={"value": 10, "metric": 20},
    )
    console.print(
        "[dim]ASR counts every expected-harm step no layer stopped, including "
        "layers that do not exist yet; lower is better.[/]\n"
        "[dim]weighted ASR prices each miss by case severity. Detection rate "
        "counts any non-allow and flatters itself. Control noise floor is "
        "benign content flagged on purpose: analyst noise, not a broken "
        "call.[/]"
    )
    for r in noise:
        console.print(
            f"  noise: {r.case_id} step {r.index + 1} -> {r.actual} "
            f"({', '.join(r.rules) or 'no rule'})"
        )

    # -- per family --------------------------------------------------------

    rows: list[list[str]] = []
    for family, results in sorted(report.by_family().items()):
        harmful = [r for r in results if r.expected.verdict in ("block", "modify")]
        detection = [r for r in results if r.expected.verdict == "flag"]
        kind = results[0].kind
        if not harmful:
            # A family whose only non-allow steps are `flag` may still be an
            # attack family, so the kind comes from the corpus rather than from
            # the verdicts -- inferring it would let a mislabelled case quietly
            # reclassify itself as a control.
            caught = sum(r.actual in ("block", "modify") for r in detection)
            rows.append(
                [
                    family,
                    kind,
                    f"{len(results)}",
                    f"{caught}/{len(detection)}" if detection else "-",
                    _bar(caught / len(detection) if detection else 0.0, 10),
                    "-",
                    "-",
                ]
            )
            continue

        # `owned` is the subset this build is responsible for; gap steps are
        # excluded from both halves so a family with no owned steps reads 0/0
        # rather than a negative fraction.
        # Ownership is read from the report's running-layer set, not restated
        # here, so a newly added layer's wins show up in this table instead of
        # being filed as gaps.
        owned_steps = [r for r in harmful if report.owns(r.expected.layer)]
        gaps = len(harmful) - len(owned_steps)
        caught = sum(r.actual in ("block", "modify") for r in owned_steps)
        flagged_only = sum(r.actual == "flag" for r in owned_steps)
        rows.append(
            [
                family,
                kind,
                f"{len(results)}",
                f"{caught}/{len(owned_steps)}",
                _bar(caught / len(owned_steps) if owned_steps else 0.0, 10),
                f"{flagged_only}",
                f"{gaps}/{len(harmful)}",
            ]
        )

    _table(
        console,
        "per family",
        ["family", "kind", "steps", "stopped/owned", "caught", "flag-only", "gaps"],
        rows,
    )

    # -- coverage debt -----------------------------------------------------

    gaps_by_layer: dict[str, list[StepResult]] = {}
    for result in attack_steps:
        layer = result.expected.layer
        if layer and not report.owns(layer):
            gaps_by_layer.setdefault(layer, []).append(result)

    if gaps_by_layer:
        console.print(
            "[yellow]coverage debt[/yellow] - expected-harm steps attributed to "
            "layers that do not exist yet:\n"
        )
        for layer, results in sorted(gaps_by_layer.items()):
            families = sorted({r.family for r in results})
            console.print(
                f"  {layer:<12} {len(results):>3} step(s)  "
                f"across {len(families)} famil{'y' if len(families) == 1 else 'ies'}: "
                f"{', '.join(families)}"
            )
        console.print(
            "\n  These are counted as attacks that succeed. They are not detector bugs.\n"
        )

    # -- cost --------------------------------------------------------------

    latency = report.latency()

    def _ns(value: float) -> str:
        # Seconds are a real case here, not a hypothetical one: the semantic
        # layer asks a local model, and "840.30ms" would read as a rounding
        # error rather than as the price of a layer an agent waits on.
        if value >= 1_000_000_000:
            return f"{value / 1_000_000_000:.2f}s"
        if value >= 1_000_000:
            return f"{value / 1_000_000:.2f}ms"
        if value >= 1_000:
            return f"{value / 1_000:.1f}us"
        return f"{value:.0f}ns"

    console.print(
        f"inspection cost per step: p50 {_ns(latency['p50'])}, "
        f"p95 {_ns(latency['p95'])}, max {_ns(latency['max'])}"
    )

    verdict = "PASS" if report.is_clean() else "FAIL"
    colour = "green" if report.is_clean() else "red"
    console.print(f"\n[{colour}bold]{verdict}[/{colour}bold]")
    # "A passing run means", not "PASS means": the definition is printed on every
    # report, including failing ones, and a document that spells the bare token
    # either way makes `airlock eval | grep PASS` agree with a build that failed.
    console.print(
        f"[dim]A passing run means: no false positives, and every step owned by "
        f"a layer in this build\n({' + '.join(report.layers) or 'none'}) matched the "
        f"corpus. It does not mean the attacks were stopped.[/dim]"
    )

    return console.export_text()
