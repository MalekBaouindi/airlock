"""Tests for the policy layer, with no policy file on disk that matters.

The engine here is small enough to test exhaustively, and the parts that are
easy to get wrong are all in the matching: a URL and a bare host are the same
destination, a port is not a different destination, `notexample.com` is not
`example.com`, and a recipient list is a destination field too. Every one of
those is a way to write an allowlist that reads as a policy and is not one.

What is *not* tested is whether the example policy in `examples/` is a good
policy. That is a judgement about a deployment, it is measured by
`airlock eval`, and a unit test asserting it would only assert that this file
and that judgement were written on the same day.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from airlock.cli import build_layers
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.policy import (
    ANY_TOOL,
    Policy,
    PolicyError,
    PolicyInspector,
    Surface,
    candidates,
    normalise,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/corpus-workspace-policy.json"


def write(tmp_path: Path, surfaces: dict, version: object = 1) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": version, "surfaces": surfaces}))
    return path


def call(name: str, arguments: dict) -> Message:
    return Message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )


def test_a_destination_the_policy_does_not_name_is_refused() -> None:
    policy = Policy(surfaces={"http_post": {"url": Surface(allow=("metrics.internal",))}})
    verdict = PolicyInspector(policy).inspect_request(
        call("http_post", {"url": "https://telemetry.example.net/ingest"}),
        SessionContext(),
    )
    assert verdict.action == "block"
    assert verdict.findings[0].rule == "destination-not-permitted"
    # The detail names the field and the host, because "something was blocked"
    # is not something an operator can act on at 3am.
    assert "http_post.url" in verdict.findings[0].detail
    assert "telemetry.example.net" in verdict.findings[0].detail


class TestNormalisation:
    """One destination, many spellings. An allowlist that compares strings is a
    allowlist an attacker writes around."""

    @pytest.mark.parametrize(
        ("written", "called"),
        [
            ("metrics.internal", "https://metrics.internal/v2/ingest"),
            ("metrics.internal", "HTTPS://Metrics.Internal/v2/ingest"),
            ("metrics.internal", "https://metrics.internal:9090/v2/ingest"),
            ("metrics.internal", "//metrics.internal/v2"),
            ("metrics.internal", "  metrics.internal  "),
            ("metrics.internal", "https://user:pw@metrics.internal/v2"),
        ],
    )
    def test_spellings_of_one_destination_match(self, written: str, called: str) -> None:
        assert Surface(allow=(written,)).permits(called)

    @pytest.mark.parametrize(
        ("rule", "destination", "expected"),
        [
            (".example.com", "example.com", True),
            (".example.com", "a.b.example.com", True),
            (".example.com", "notexample.com", False),
            (".example.com", "example.com.evil.net", False),
            ("@acmecorp.example", "notes@acmecorp.example", True),
            ("@acmecorp.example", "notes@notacmecorp.example", False),
            ("@acmecorp.example", "https://acmecorp.example/x", False),
        ],
    )
    def test_wildcards_do_not_overreach(self, rule: str, destination: str, expected: bool) -> None:
        assert Surface(allow=(rule,)).permits(destination) is expected

    def test_a_port_is_not_a_different_destination(self) -> None:
        assert normalise("https://metrics.internal:9090/v2") == "metrics.internal"

    def test_userinfo_is_dropped_rather_than_treated_as_a_host(self) -> None:
        # `https://metrics.internal@evil.example/` is a request to evil.example
        # with a username, and an allowlist that stopped at the first `@` would
        # permit it.
        assert normalise("https://metrics.internal@evil.example/") == "evil.example"


class TestCandidateExtraction:
    def test_every_member_of_a_recipient_list_is_a_destination(self) -> None:
        # A calendar invite that is fine for the first attendee and an
        # exfiltration for the second is not half as bad as one for the first.
        assert candidates(["a@x.example", "b@evil.example"]) == [
            "a@x.example",
            "b@evil.example",
        ]

    def test_nested_structures_are_not_destinations(self) -> None:
        # `str()` of a dict is a surface nobody wrote down in the policy, and
        # inferring one here is how the engine ends up judging a field the
        # operator never agreed to be a destination.
        assert candidates({"Authorization": "Bearer x"}) == []

    def test_empty_and_whitespace_values_are_not_destinations(self) -> None:
        assert candidates("") == []
        assert candidates("   ") == []


class TestTheSurfaceIsTheUnit:
    def test_a_tool_the_policy_knows_nothing_about_is_not_judged(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=("metrics.internal",))}})
        verdict = PolicyInspector(policy).inspect_request(
            call("create_calendar_event", {"attendees": ["notes@evil.example"]}),
            SessionContext(),
        )
        assert verdict.action == "allow"

    def test_the_wildcard_tool_applies_to_everything_else(self) -> None:
        policy = Policy(
            surfaces={
                ANY_TOOL: {"attendees": Surface(allow=("@acmecorp.example",))},
                "http_post": {"url": Surface(allow=("metrics.internal",))},
            }
        )
        inspector = PolicyInspector(policy)
        assert (
            inspector.inspect_request(
                call("create_calendar_event", {"attendees": ["notes@evil.example"]}),
                SessionContext(),
            ).action
            == "block"
        )
        # A tool's own entry wins over the wildcard, so one tool can be
        # loosened without touching the rest.
        policy = Policy(
            surfaces={
                ANY_TOOL: {"url": Surface(allow=("metrics.internal",))},
                "http_post": {"url": Surface(allow=("collector.example.net",))},
            }
        )
        inspector = PolicyInspector(policy)
        assert (
            inspector.inspect_request(
                call("http_post", {"url": "https://collector.example.net/x"}),
                SessionContext(),
            ).action
            == "allow"
        )
        assert (
            inspector.inspect_request(
                call("web_hook", {"url": "https://collector.example.net/x"}),
                SessionContext(),
            ).action
            == "block"
        )

    def test_an_explicit_anywhere_is_not_the_same_as_being_omitted(self) -> None:
        policy = Policy(surfaces={"send_email": {"to": Surface(anywhere=True)}})
        verdict = PolicyInspector(policy).inspect_request(
            call("send_email", {"to": "anyone@anywhere.example"}), SessionContext()
        )
        assert verdict.action == "allow"

    def test_every_permitted_destination_produces_no_finding(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=(".acmecorp.example",))}})
        for url in [
            "https://api.acmecorp.example/v1",
            "https://acmecorp.example/v1",
            "https://a.b.acmecorp.example/v1:443",
        ]:
            assert (
                PolicyInspector(policy)
                .inspect_request(call("http_post", {"url": url}), SessionContext())
                .action
                == "allow"
            )

    def test_one_bad_destination_among_good_ones_is_still_a_refusal(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=("metrics.internal",))}})
        verdict = PolicyInspector(policy).inspect_request(
            call(
                "http_post",
                {"url": "https://metrics.internal/v1", "mirror": "https://evil.example/"},
            ),
            SessionContext(),
        )
        assert verdict.action == "allow"  # `mirror` is not a surface the policy names

        policy = Policy(
            surfaces={
                "http_post": {
                    "url": Surface(allow=("metrics.internal",)),
                    "mirror": Surface(allow=()),
                }
            }
        )
        verdict = PolicyInspector(policy).inspect_request(
            call(
                "http_post",
                {"url": "https://metrics.internal/v1", "mirror": "https://evil.example/"},
            ),
            SessionContext(),
        )
        assert verdict.action == "block"


class TestTheRequestLegOnly:
    def test_responses_are_never_judged(self) -> None:
        """A policy is about where data leaves.

        Judging what comes back would be a second, weaker copy of provenance,
        and it would produce findings on the response half of every session.
        """
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=())}})
        response = Message({"jsonrpc": "2.0", "id": 1, "result": {"content": "evil.example"}})
        assert (
            PolicyInspector(policy).inspect_response(response, SessionContext()).action == "allow"
        )

    def test_a_call_with_no_arguments_is_allowed(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=())}})
        message = Message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "http_post"}}
        )
        assert PolicyInspector(policy).inspect_request(message, SessionContext()).action == "allow"

    def test_a_non_tools_call_method_is_ignored(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=())}})
        message = Message({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {}})
        assert PolicyInspector(policy).inspect_request(message, SessionContext()).action == "allow"

    def test_the_layer_accumulates_nothing(self) -> None:
        """It is stateless, and it says so, because the harness resets every
        stateful layer between cases and a layer that silently lacks the method
        is a layer that will accumulate state later without a test noticing."""
        inspector = PolicyInspector(Policy(surfaces={}))
        assert inspector.reset() is None


class TestLoading:
    def test_a_missing_file_is_an_error_rather_than_an_empty_policy(self, tmp_path) -> None:
        # The alternative is a policy that permits everything, which is
        # indistinguishable from no policy until the day it matters.
        with pytest.raises(PolicyError, match="no policy file"):
            Policy.load(tmp_path / "absent.json")

    def test_invalid_json_names_the_file(self, tmp_path) -> None:
        path = tmp_path / "policy.json"
        path.write_text("{not json")
        with pytest.raises(PolicyError, match="not valid JSON"):
            Policy.load(path)

    def test_an_unknown_version_is_refused(self, tmp_path) -> None:
        path = write(tmp_path, {"http_post": {"url": {"allow": []}}}, version=2)
        with pytest.raises(PolicyError, match="unsupported policy version"):
            Policy.load(path)

    def test_empty_surfaces_are_refused(self, tmp_path) -> None:
        path = write(tmp_path, {})
        with pytest.raises(PolicyError, match="non-empty"):
            Policy.load(path)

    def test_saying_anywhere_and_allowlist_at_once_is_refused(self, tmp_path) -> None:
        # One of the two is a mistake, and a policy that permits everything and
        # also lists two destinations is one nobody can reason about.
        path = write(tmp_path, {"t": {"a": {"anywhere": True, "allow": ["x"]}}})
        with pytest.raises(PolicyError, match="one of them is a mistake"):
            Policy.load(path)

    def test_a_non_list_allowlist_is_refused(self, tmp_path) -> None:
        path = write(tmp_path, {"t": {"a": {"allow": "x"}}})
        with pytest.raises(PolicyError, match="must be a list"):
            Policy.load(path)

    def test_entries_are_lowercased_once_so_matching_does_not_have_to(self, tmp_path) -> None:
        policy = Policy.load(write(tmp_path, {"t": {"a": {"allow": ["Metrics.INTERNAL"]}}}))
        assert policy.surface_for("t", "a") is not None
        assert policy.surface_for("t", "a").permits("https://metrics.internal/x")  # type: ignore[union-attr]


class TestShippedConfiguration:
    def test_all_includes_the_policy_layer_exactly_when_there_is_a_policy(self) -> None:
        assert [layer.name for layer in build_layers("all")] == ["structural", "provenance"]
        policy = Policy.load(EXAMPLE)
        assert [layer.name for layer in build_layers("all", policy)] == [
            "structural",
            "provenance",
            "policy",
        ]

    def test_asking_for_the_policy_layer_without_a_policy_is_an_error(self) -> None:
        # Otherwise `--layers policy` would quietly measure nothing, and a
        # report full of zeros reads as "the layer is useless" rather than
        # "the layer was not there".
        with pytest.raises(SystemExit, match="needs a policy file"):
            build_layers("policy")

    def test_the_example_policy_loads_and_says_what_it_thinks_about(self) -> None:
        policy = Policy.load(EXAMPLE)
        assert policy.described_tools() == [
            "create_calendar_event",
            "http_post",
            "send_email",
            "web_fetch",
        ]
        # Every surface carries a reason. A policy file with bare allowlists
        # cannot be reviewed six months later, and an unreviewable policy file
        # is a policy file nobody reviews.
        for tool, table in policy.surfaces.items():
            for argument, surface in table.items():
                assert surface.note, f"{tool}.{argument} has no reason recorded"

    def test_a_note_is_not_a_rule(self) -> None:
        """The `note` field is documentation. A file whose notes disagree with
        its allowlists is wrong in a way nothing detects, which is why the
        corpus's two policy steps are read against the *rules*."""
        policy = Policy.load(EXAMPLE)
        http = policy.surface_for("http_post", "url")
        assert http is not None
        assert http.permits("https://metrics.internal/v2/ingest")
        assert not http.permits("https://metrics.example.com/v2/ingest")
        assert not http.permits("https://telemetry.acmecorp-views.dev/ingest")


class TestDecisions:
    def test_a_refusal_is_a_block_not_a_flag(self) -> None:
        """The corpus calls these steps `block`, and the reason is that the
        request is the last moment at which anything can be done about it. A
        flag on a request is a flag on the way out of the building."""
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=())}})
        verdict = PolicyInspector(policy).inspect_request(
            call("http_post", {"url": "https://evil.example"}), SessionContext()
        )
        assert verdict.action == "block"

    def test_findings_carry_a_severity_the_relay_can_threshold(self) -> None:
        policy = Policy(surfaces={"http_post": {"url": Surface(allow=())}})
        verdict = PolicyInspector(policy).inspect_request(
            call("http_post", {"url": "https://evil.example"}), SessionContext()
        )
        assert verdict.findings[0].severity == "critical"
