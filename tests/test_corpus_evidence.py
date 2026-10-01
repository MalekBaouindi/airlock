"""What the corpus can and cannot tell you about over-blocking.

A false-positive rate is only evidence about paths the traffic actually takes, so
"0.0% FPR" is a statement about this corpus and nothing more. These tests put
deliberately broken policy layers in front of the corpus and require the corpus to
notice -- the difference between measuring false positives and reporting a low
number.

They exist because the corpus was measurably blind in a specific way. It could
already catch a layer refusing *every* destination: four benign transcripts fetched
URLs and one posted to an internal endpoint, so a blanket refusal scored 26% FPR.
It could not catch a layer refusing exactly the surfaces the policy decides by rule.
Nothing in the corpus sent a calendar invitation, used the collector shard, or sent
mail at all, so breaking those scored the same 0.0% as a correct implementation --
and the mail case was the sharpest of them, since the policy file's own note argues
that a policy refusing outbound mail would be switched off within a week.

Every surface is enumerated from the policy file rather than hard-coded, so adding
a surface to a policy without giving it benign traffic fails here instead of quietly
measuring as clean.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from airlock.cli import _load_policy, build_layers
from airlock.eval.harness import load_corpus, replay
from airlock.inspect.base import Finding, Verdict
from airlock.inspect.policy import PolicyInspector, Surface

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
POLICY = Path(__file__).resolve().parents[1] / "examples" / "corpus-workspace-policy.json"

#: Destination-shaped field names, for the cases that sweep rather than target.
DESTINATION_FIELDS = ("url", "to", "target", "host", "attendees")


def _refusing(reason: str, refuse: Any) -> type[PolicyInspector]:
    """A policy layer that blocks whatever ``refuse(tool, arguments)`` selects.

    The real policy logic still runs for everything else, so these layers are
    precise defects rather than a different policy.
    """

    class Refusing(PolicyInspector):
        def inspect_request(self, message: Any, ctx: Any) -> Verdict:
            if message.method != "tools/call":
                return Verdict.allow()
            arguments = message.params.get("arguments")
            if not isinstance(arguments, dict):
                return Verdict.allow()
            if refuse(message.tool_name, arguments):
                return Verdict.of(
                    "block",
                    Finding(rule="refuses-a-permitted-surface", severity="high", detail=reason),
                )
            return PolicyInspector.inspect_request(self, message, ctx)

    return Refusing


def _sweep() -> type[PolicyInspector]:
    return _refusing(
        "refuses every destination-shaped field",
        lambda _tool, arguments: any(f in arguments for f in DESTINATION_FIELDS),
    )


def _surface_refuser(tool: str, argument: str) -> type[PolicyInspector]:
    """Refuse one named (tool, argument) pair from a policy file."""
    return _refusing(
        f"{tool}.{argument} is permitted by this policy",
        lambda t, arguments: t == tool and argument in arguments,
    )


@pytest.fixture(scope="module")
def corpus() -> list[Any]:
    return load_corpus(CORPUS)


@pytest.fixture(scope="module")
def policy() -> Any:
    return _load_policy(str(POLICY))


@pytest.fixture(scope="module")
def surfaces(policy: Any) -> list[tuple[str, str]]:
    """Every (tool, argument) pair the policy has an opinion about."""
    return [(tool, argument) for tool, table in policy.surfaces.items() for argument in table]


def false_positive_rate(corpus: list[Any], policy: Any, layer: type[PolicyInspector]) -> float:
    return replay(corpus, [layer(policy)], split=None).false_positive_rate()


def benign_false_positives(
    corpus: list[Any], policy: Any, layer: type[PolicyInspector]
) -> list[Any]:
    """False positives an over-blocker causes to *benign* traffic only.

    Measured over the whole corpus, this question has a trap. `sharded_egress-002`
    deliberately contains steps that must be allowed -- sub-threshold fragments,
    indistinguishable from ordinary traffic -- so a layer refusing the collector
    shard scores seven false positives from that attack transcript against one from
    the benign transcript that actually justifies the rule. The rule is justified
    by benign traffic, so only benign traffic may be allowed to justify it here.

    An attack transcript is not evidence that an operator would be unaffected.
    """
    benign = [case for case in corpus if case.kind == "benign"]
    return replay(benign, [layer(policy)], split=None).false_positives()


class TestTheCorrectLayerIsClean:
    def test_no_false_positives(self, corpus: list[Any], policy: Any) -> None:
        assert replay(corpus, build_layers("all", policy), split=None).false_positive_rate() == 0.0


class TestEveryPermittedSurfaceIsExercised:
    """Breaking one surface must cost more than breaking nothing.

    This is the corpus-level half of the argument: a surface no benign step ever
    uses has no false-positive evidence behind it, however good the detector is.
    """

    def test_benign_traffic_uses_destination_shaped_fields(self, corpus: list[Any]) -> None:
        assert self._benign_destination_steps(corpus), (
            "no benign step uses a destination-shaped field, so a false-positive "
            "rate measured here says nothing about destination handling"
        )

    def test_every_policy_surface_has_a_benign_caller(
        self, corpus: list[Any], surfaces: list[tuple[str, str]]
    ) -> None:
        exercised = {
            (tool, argument) for _, tool, argument in self._benign_destination_steps(corpus)
        }
        unexercised = [f"{t}.{a}" for t, a in surfaces if (t, a) not in exercised]
        assert not unexercised, (
            f"policy surfaces with no benign traffic: {unexercised}. A layer "
            "refusing those measures exactly as clean as a correct one, so this is "
            "a gap in the evidence rather than in the policy."
        )

    def _benign_destination_steps(self, corpus: list[Any]) -> list[tuple[str, str, str]]:
        found: list[tuple[str, str, str]] = []
        for case in corpus:
            if case.kind != "benign":
                continue
            for entry in case.trace:
                message = entry["message"]
                if message.get("method") != "tools/call":
                    continue
                params = message.get("params") or {}
                arguments = params.get("arguments") or {}
                for field in DESTINATION_FIELDS:
                    if field in arguments:
                        found.append((case.id, str(params.get("name")), field))
        return found


class TestTheCorpusSeesOverBlocking:
    def test_refusing_every_destination_is_caught(self, corpus: list[Any], policy: Any) -> None:
        assert benign_false_positives(corpus, policy, _sweep())

    def test_narrow_and_gross_over_blocking_are_told_apart(
        self, corpus: list[Any], policy: Any, surfaces: list[tuple[str, str]]
    ) -> None:
        """A coarse signal cannot distinguish the two, so it learns nothing."""
        gross = len(benign_false_positives(corpus, policy, _sweep()))
        narrow = max(
            len(benign_false_positives(corpus, policy, _surface_refuser(tool, argument)))
            for tool, argument in surfaces
        )
        assert gross > narrow, (
            f"refusing one surface costs {narrow} benign false positive(s) but "
            f"refusing all of them costs {gross}; the corpus cannot tell which "
            "defect it saw"
        )


def _each_surface() -> list[Any]:
    """Parametrise over the policy file's own surfaces."""
    policy = _load_policy(str(POLICY))
    return [
        pytest.param(tool, argument, id=f"{tool}.{argument}")
        for tool, table in policy.surfaces.items()
        for argument in table
    ]


def _each_allow_rule() -> list[Any]:
    """Parametrise over individual allow *entries*, not just whole surfaces.

    A surface can look exercised while one of its rules is dead: `http_post.url`
    has two entries, and a corpus with only the `metrics.internal` traffic looks
    covered until the collector shard breaks. Per-surface checks miss that, so the
    finer grain is tested too.
    """
    policy = _load_policy(str(POLICY))
    return [
        pytest.param(tool, argument, entry, id=f"{tool}.{argument}~{entry}")
        for tool, table in policy.surfaces.items()
        for argument, surface in table.items()
        for entry in surface.allow
    ]


def _destinations(value: Any) -> list[str]:
    """Destination strings in one argument, which may be a list of recipients."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _rule_refuser(tool: str, argument: str, entry: str) -> type[PolicyInspector]:
    """Refuse exactly the destinations one allow entry permits.

    Matching is delegated to a real ``Surface`` holding only that entry, so this
    cannot drift from the semantics the policy layer enforces.
    """
    rule = Surface(allow=(entry,), anywhere=False)

    def refuse(seen_tool: str | None, arguments: dict[str, Any]) -> bool:
        if seen_tool != tool or argument not in arguments:
            return False
        return any(rule.permits(d) for d in _destinations(arguments[argument]))

    return _refusing(f"{tool}.{argument} permits {entry}", refuse)


@pytest.mark.parametrize(("tool", "argument", "entry"), _each_allow_rule())
def test_refusing_one_permitted_allow_rule_is_caught(
    corpus: list[Any], policy: Any, tool: str, argument: str, entry: str
) -> None:
    """Each allow entry needs a benign caller that specifically matches it.

    Without this, deleting the corpus's only collector-shard transcript leaves the
    surface looking exercised by the `metrics.internal` traffic, and a shard that
    no longer works measures as a clean 0.0%.
    """
    hits = benign_false_positives(corpus, policy, _rule_refuser(tool, argument, entry))
    assert hits, (
        f"refusing the destinations {tool}.{argument} permits via {entry!r} "
        "flagged no benign traffic, i.e. it was invisible. No benign transcript "
        "uses a destination matching that entry."
    )


@pytest.mark.parametrize(("tool", "argument"), _each_surface())
def test_refusing_one_permitted_surface_is_caught(
    corpus: list[Any], policy: Any, tool: str, argument: str
) -> None:
    """The unit of over-blocking an operator would actually ship.

    A policy that broke one destination field is the realistic regression -- someone
    tightens an allowlist or misreads a suffix. Each must be visible in the FPR.
    """
    rate = len(benign_false_positives(corpus, policy, _surface_refuser(tool, argument)))
    assert rate > 0, (
        f"refusing {tool}.{argument} -- which this policy permits -- flagged no "
        "benign traffic, i.e. it was invisible. No benign transcript uses it."
    )
