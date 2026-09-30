"""A security decision may not depend on iteration order.

The worst bug this project shipped was a verdict that changed with
`PYTHONHASHSEED`: a rule read a host out of every host mentioned in a URL rather
than the one in its authority, and `set` iteration decided which one it found
first. It passed every test, because the tests ran under one seed.

So this is not a spot check on the rule that regressed. It fingerprints *every*
per-step decision the corpus produces -- structural, provenance and policy, through
the same correlation the relay uses -- and requires the fingerprints to be
identical across seeds.

Aggregate rates are not enough, for two reasons. `airlock eval --json` reports only
aggregates, and two different sets of per-step verdicts can average to the same number.
And a step can keep its verdict while its rule set changes underneath, which is what
happened when an injected `next(iter(found))` left every case `block` and simply
dropped a rule from half of them.

What is fingerprinted, precisely: the expected verdict, the actual verdict, the
outcome, the set of rule names, and the order the pipeline emitted them in. The order
cannot change a verdict -- the action is a rank maximum over a tuple of inspectors --
but the audit log records findings in that order, so drift there is drift in what gets
written down. An earlier version of this file sorted the rules and normalised the
order away; injecting `sorted(verdict.findings, key=hash)` into the pipeline then
passed the entire suite, this test included.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = ROOT / "scripts" / "fingerprint.py"

SEEDS = ("0", "1", "2", "3", "5", "8")


def fingerprint(seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run(
        [sys.executable, str(FINGERPRINT)],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=True,
    )
    return result.stdout


@pytest.fixture(scope="module")
def per_seed() -> dict[str, str]:
    return {seed: fingerprint(seed) for seed in SEEDS}


def test_the_fingerprint_covers_every_step(per_seed: dict[str, str]) -> None:
    # A determinism check over a handful of steps would be a check that passes
    # because it is small, so it asserts it saw the whole corpus, and that the
    # corpus it saw contains every verdict the policy file can produce.
    lines = [line for line in per_seed["0"].splitlines() if not line.startswith("#")]
    assert len(lines) > 100
    verdicts = {line.split("\t")[4] for line in lines}
    assert verdicts == {"allow", "flag", "block"}, f"only saw {verdicts}"


def test_no_seed_changes_a_single_verdict(per_seed: dict[str, str]) -> None:
    reference = per_seed[SEEDS[0]]
    for seed, text in per_seed.items():
        if text == reference:
            continue
        expected = reference.splitlines()
        actual = text.splitlines()
        assert len(expected) == len(actual), f"seed {seed} produced a different step count"
        for want, got in zip(expected, actual, strict=True):
            assert want == got, (
                f"seed {seed} decided differently from seed {SEEDS[0]}:\n"
                f"  {SEEDS[0]}: {want}\n"
                f"  {seed}: {got}"
            )


def test_the_policy_layer_is_actually_in_the_fingerprint(per_seed: dict[str, str]) -> None:
    # Otherwise a future edit could quietly drop the policy layer and this test
    # would keep passing on the two layers underneath it.
    assert "policy" in per_seed["0"]
    assert "structural" in per_seed["0"]
    assert "provenance" in per_seed["0"]


def test_the_fingerprint_is_not_vacuous(per_seed: dict[str, str]) -> None:
    # A run where every step is `allow` would satisfy determinism perfectly and
    # prove nothing, so the fingerprint has to contain real verdicts to compare.
    outcomes = {
        line.split("\t")[5]
        for line in per_seed["0"].splitlines()
        if not line.startswith("#") and len(line.split("\t")) > 5
    }
    assert len(outcomes) > 1, f"only one outcome in the whole corpus: {outcomes}"


def test_the_fingerprint_records_finding_order_not_just_the_rule_set(
    per_seed: dict[str, str]
) -> None:
    # The order column has to be present and has to differ from the sorted set
    # somewhere, or it is decoration and the guard above is weaker than it reads.
    lines = [line for line in per_seed["0"].splitlines() if not line.startswith("#")]
    multi = [line for line in lines if line.count("\t") == 7]
    assert multi, "no step carried findings, so the order column was never exercised"
    assert any(
        line.split("\t")[6] != line.split("\t")[7]
        for line in multi
    ), "every step's emission order was already sorted; nothing is being compared"
