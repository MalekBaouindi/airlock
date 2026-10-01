"""The staleness check: does the policy file still decide what the traffic uses?

These are about the *file*, not the gateway, so none of them run a detector.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from airlock.eval.harness import Case, load_corpus
from airlock.eval.policy_check import PolicyCheck, SurfaceUse, check_policy
from airlock.inspect.policy import Policy, Surface

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples/corpus-workspace-policy.json"


def case(
    tool: str,
    arguments: dict,
    *,
    verdict: str = "allow",
    kind: str = "attack",
    split: str = "test",
    case_id: str = "c-1",
) -> Case:
    return Case(
        id=case_id,
        kind=kind,
        family="f",
        variant="v",
        severity="medium",
        description="",
        citation="",
        claim="",
        split=split,
        trace=(
            {
                "direction": "host->upstream",
                "expect": {"verdict": verdict, "reason": ""},
                "message": {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                },
            },
        ),
    )


class TestTheQuestionItAsks:
    def test_a_field_the_file_names_is_not_a_gap(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=("a.example",))}})
        check = check_policy(policy, [case("http_post", {"url": "https://a.example/v1"})])
        assert check.is_clean
        assert [s.decision for s in check.surfaces] == ["restricted"]

    def test_a_field_the_file_ignores_is_a_gap(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=("a.example",))}})
        check = check_policy(policy, [case("send_email", {"to": "x@b.example"})])
        assert not check.is_clean
        assert [s.surface for s in check.gaps] == ["send_email.to"]

    def test_the_file_being_empty_is_all_gaps(self) -> None:
        check = check_policy(
            Policy(surfaces={}),
            [
                case("http_post", {"url": "https://a.example"}),
                case("send_email", {"to": "x@b.example"}),
                case("web_fetch", {"url": "https://c.example"}),
            ],
        )
        assert not check.is_clean
        assert len(check.gaps) == 3

    def test_an_open_surface_is_a_decision_not_a_gap(self) -> None:
        # The distinction the whole command turns on: writing `anywhere: true` is
        # a person choosing to permit everything, which is not the same as
        # forgetting the field. Reporting them together would teach operators to
        # silence the check by deleting a rule.
        policy = Policy(surfaces={"send_email": {"to": Surface(anywhere=True)}})
        check = check_policy(policy, [case("send_email", {"to": "x@b.example"})])
        assert check.is_clean
        assert [s.surface for s in check.loose] == ["send_email.to"]

    def test_a_wildcard_tool_decides_every_argument(self) -> None:
        policy = Policy(surfaces={"*": {"url": Surface(allow=("a.example",))}})
        check = check_policy(
            policy,
            [
                case("http_post", {"url": "https://a.example"}),
                case("send_post", {"url": "https://a.example"}),
            ],
        )
        assert check.is_clean
        assert len(check.surfaces) == 2


class TestWhatItRefusesToCount:
    def test_a_payload_is_not_a_destination(self) -> None:
        # `headers` and `body` are where secrets ride out, but deciding what is
        # secret is provenance's job. A check that demanded rules for them would
        # push every operator toward a second copy of the secret patterns, and
        # that copy would rot.
        policy = Policy(surfaces={})
        check = check_policy(
            policy,
            [case("http_post", {"url": "https://a.example", "body": "deploy key: <vault value>"})],
        )
        assert [s.surface for s in check.surfaces] == ["http_post.url"]

    def test_responses_are_not_egress(self) -> None:
        # A response brings data in. The policy layer does not judge those, so
        # the check must not report them either, or it would demand a rule for
        # something the engine would never enforce.
        inbound = case("http_post", {"url": "https://a.example"})
        step = dataclasses.replace(
            inbound,
            trace=(
                {
                    "direction": "upstream->host",
                    "expect": {"verdict": "allow", "reason": ""},
                    "message": {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"name": "http_post", "arguments": {"url": "https://a.example"}},
                    },
                },
            ),
        )
        assert check_policy(Policy(surfaces={}), [step]).surfaces == ()

    def test_a_field_with_no_value_is_not_a_surface(self) -> None:
        # An empty argument is a surface that exists on no call; reporting it
        # would make the command cry wolf about keys the corpus happens to carry.
        check = check_policy(Policy(surfaces={}), [case("http_post", {"url": ""})])
        assert check.surfaces == ()

    def test_a_list_argument_counts_as_one_surface(self) -> None:
        policy = Policy(
            surfaces={"create_calendar_event": {"attendees": Surface(allow=("@a.example",))}}
        )
        check = check_policy(
            policy,
            [
                case(
                    "create_calendar_event",
                    {"attendees": ["x@a.example", "y@a.example"]},
                )
            ],
        )
        assert check.is_clean
        assert check.surfaces[0].calls == 1
        assert check.surfaces[0].destinations == frozenset({"x@a.example", "y@a.example"})


class TestUrgency:
    def test_a_gap_the_corpus_would_block_through_is_urgent(self) -> None:
        policy = Policy(surfaces={})
        check = check_policy(
            policy,
            [
                case(
                    "http_post",
                    {"url": "https://evil.example"},
                    verdict="block",
                    case_id="exfil-001",
                )
            ],
        )
        gap = check.gaps[0]
        assert gap.expected_harm_undecided
        assert gap.harm_steps == 1
        assert gap.attack_cases == frozenset({"exfil-001"})

    def test_a_gap_on_a_step_meant_to_be_allowed_is_not_urgent(self) -> None:
        # Every delivery case in the corpus fetches a URL and is *supposed* to
        # be allowed: the request brings instructions in and the harm lands
        # later. Ranking by attack traffic would shout about a field working.
        policy = Policy(surfaces={})
        check = check_policy(
            policy,
            [
                case(
                    "web_fetch",
                    {"url": "https://docs.example"},
                    verdict="allow",
                    case_id="framing-001",
                )
            ],
        )
        gap = check.gaps[0]
        assert not gap.expected_harm_undecided
        assert gap.harm_steps == 0
        assert gap.attack_cases == frozenset({"framing-001"}), "still context, not urgency"

    def test_urgent_gaps_sort_first(self) -> None:
        policy = Policy(surfaces={})
        check = check_policy(
            policy,
            [
                case("web_fetch", {"url": "https://docs.example"}, case_id="w"),
                case("http_post", {"url": "https://evil.example"}, verdict="block", case_id="p"),
            ],
        )
        assert [s.surface for s in check.surfaces] == ["http_post.url", "web_fetch.url"]


class TestTheRealCorpus:
    """The check has to be right about the corpus it ships with, or it is noise."""

    def test_the_shipped_example_decides_everything_the_traffic_uses(self) -> None:
        check = check_policy(Policy.load(EXAMPLE), load_corpus(CORPUS))
        assert check.is_clean, [s.surface for s in check.gaps]

    def test_deleting_one_rule_is_reported_with_the_step_it_drops(self) -> None:
        base = Policy.load(EXAMPLE)
        stale = dataclasses.replace(
            base,
            surfaces={
                tool: {arg: s for arg, s in surfaces.items() if arg != "url"}
                if tool == "http_post"
                else surfaces
                for tool, surfaces in base.surfaces.items()
            },
        )
        check = check_policy(stale, load_corpus(CORPUS), split="test")
        assert not check.is_clean
        assert [s.surface for s in check.gaps] == ["http_post.url"]
        assert check.gaps[0].expected_harm_undecided

    def test_a_benign_destination_is_reported_too(self) -> None:
        # The check is about the file, not about the attack: if the rule is gone,
        # the allowed destination loses its rule just as surely as the denied
        # ones do. Only a per-destination verdict would tell them apart, and the
        # corpus does not grade that.
        base = Policy.load(EXAMPLE)
        stale = dataclasses.replace(
            base,
            surfaces={
                tool: {arg: s for arg, s in surfaces.items() if arg != "url"}
                if tool == "http_post"
                else surfaces
                for tool, surfaces in base.surfaces.items()
            },
        )
        gap = check_policy(stale, load_corpus(CORPUS), split="test").gaps[0]
        assert "metrics.internal" in gap.destinations

    def test_splits_are_reported_separately(self) -> None:
        cases = load_corpus(CORPUS)
        for split in ("dev", "test"):
            check = check_policy(Policy.load(EXAMPLE), cases, split=split)
            assert check.cases > 0
            assert check.is_clean

    def test_the_file_and_the_traffic_agree_in_both_directions(self) -> None:
        # A surface the traffic uses and the file omits is a hole. A surface the
        # file names and the traffic never uses is the same rot in the other
        # direction: a note nobody has re-read, usually left behind by a tool
        # that was renamed. Both are worth failing on, and the corpus is the only
        # evidence either way that this project has.
        policy = Policy.load(EXAMPLE)
        used = {s.surface for s in check_policy(policy, load_corpus(CORPUS)).surfaces}
        named = {f"{tool}.{arg}" for tool, surfaces in policy.surfaces.items() for arg in surfaces}
        assert used == named

    def test_the_calendar_attendee_list_is_inside_the_scope(self) -> None:
        # Regression: reading provenance's narrower host-extracting list here made
        # the check blind to `attendees`, which has no host to extract. The
        # surface the policy layer was built to close was the one it could not
        # report going stale.
        used = {s.surface for s in check_policy(Policy.load(EXAMPLE), load_corpus(CORPUS)).surfaces}
        assert "create_calendar_event.attendees" in used


class TestNoModelNoState:
    def test_the_answer_does_not_depend_on_a_detector(self) -> None:
        # Nothing in this module imports an inspector, which is why it can run
        # without a judge and gives the same answer every time. If a future
        # change makes it behavioural, this should start failing to import.
        source = (CORPUS.parent / "src/airlock/eval/policy_check.py").read_text()
        for banned in (
            "StructuralInspector",
            "ProvenanceInspector",
            "PolicyInspector",
            "LocalModel",
        ):
            assert banned not in source


class TestTheReportShape:
    def test_sort_key_orders_decision_then_urgency(self) -> None:
        anywhere = SurfaceUse("t", "a", 1, frozenset(), 0, frozenset(), "anywhere", "")
        restricted = SurfaceUse("t", "a", 1, frozenset(), 0, frozenset(), "restricted", "")
        gap = SurfaceUse("t", "a", 1, frozenset(), 0, frozenset(), "undecided", "")
        urgent = SurfaceUse("t", "a", 1, frozenset(), 3, frozenset(), "undecided", "")
        ordered = sorted([restricted, gap, anywhere, urgent], key=lambda s: s.sort_key)
        assert [s.decision for s in ordered] == ["undecided", "undecided", "anywhere", "restricted"]
        assert ordered[0] is urgent, "the gap the corpus would block through comes first"

    def test_an_empty_check_is_clean_and_says_nothing(self) -> None:
        empty = PolicyCheck(surfaces=(), cases=0, calls=0)
        assert empty.is_clean
        assert empty.gaps == [] and empty.loose == []


def test_the_example_file_is_valid_json_with_a_note_per_surface() -> None:
    raw = json.loads(EXAMPLE.read_text())
    assert raw["version"] == 1
    for tool, surfaces in raw["surfaces"].items():
        for arg, surface in surfaces.items():
            assert surface.get("note"), f"{tool}.{arg} has no note"
            assert "allow" in surface or "anywhere" in surface
