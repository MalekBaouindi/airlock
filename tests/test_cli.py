"""CLI contract tests.

The command line is the entire adoption surface, so the things a user actually
types have to be tested -- especially the exit codes, because that is what a
supervisor or CI step reacts to.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from airlock.audit.log import AuditLog, Finding, verify_chain
from airlock.cli import main


@pytest.fixture
def log_with_session(tmp_path: Path) -> Path:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(
        session_id="s1",
        direction="host->upstream",
        kind="request",
        decision="allow",
        method="tools/call",
        tool="read_file",
    )
    log.append(
        session_id="s1",
        direction="upstream->host",
        kind="response",
        decision="block",
        method="tools/call",
        findings=[
            Finding("unicode-tag", "critical", "hidden text", owasp="MCP03"),
        ],
    )
    return log.path


class TestTopLevel:
    def test_bare_invocation_prints_usage(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([]) == 0
        assert "usage:" in capsys.readouterr().out

    def test_help(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--help"]) == 0
        assert "airlock proxy" in capsys.readouterr().out

    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--version"]) == 0
        assert capsys.readouterr().out.strip()

    def test_unknown_command_is_a_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["frobnicate"]) == 2
        assert "unknown command" in capsys.readouterr().err


class TestProxyArgumentHandling:
    def test_missing_separator_is_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A missing '--' must fail loudly rather than silently guessing which
        arguments belong to the upstream server."""
        assert main(["proxy", "python3", "server.py"]) == 2
        assert "missing '--'" in capsys.readouterr().err

    def test_empty_upstream_is_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["proxy", "--"]) == 2
        assert "no upstream command" in capsys.readouterr().err

    def test_upstream_flags_are_not_parsed_as_ours(self, tmp_path: Path) -> None:
        """`--audit` after the separator belongs to the server, not to us.

        Driven through the real installed entry point in a subprocess, because
        this is a claim about argv handling on a live stdio transport.
        """
        import subprocess
        import sys

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "airlock.cli",
                "proxy",
                "--audit",
                str(tmp_path / "ours.jsonl"),
                "--",
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1:], file=sys.stderr)",
                "--audit",
                "/theirs.jsonl",
            ],
            input=b"",
            capture_output=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr.decode()
        # The upstream received its own flag, and we kept our own audit path.
        assert b"--audit /theirs.jsonl" in completed.stderr
        assert (tmp_path / "ours.jsonl").exists()


class TestVerify:
    def test_intact_chain_exits_zero(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["verify", str(log_with_session)]) == 0
        assert "chain intact" in capsys.readouterr().out

    def test_tampered_chain_exits_nonzero(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        lines = log_with_session.read_text().splitlines()
        record = json.loads(lines[1])
        record["decision"] = "allow"
        lines[1] = json.dumps(record)
        log_with_session.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(log_with_session)]) == 1
        assert "TAMPERED" in capsys.readouterr().err

    def test_missing_file_exits_nonzero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["verify", str(tmp_path / "nope.jsonl")]) == 1
        assert "no such audit log" in capsys.readouterr().err

    def test_intact_chain_prints_the_head_to_compare_outside(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # "Intact" on its own is not a claim the chain can support, so the command
        # has to hand back the number an operator can actually check against
        # something outside the file.
        assert main(["verify", str(log_with_session)]) == 0
        out = capsys.readouterr().out
        assert f"head: {verify_chain(log_with_session).head}" in out
        assert "removed from the end" in out

    def test_a_torn_final_record_exits_two_not_one(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # 1 means something was edited. 2 means the log stopped early. The
        # responses are different -- look for an edit, or look for a full disk --
        # and a monitor can act on the difference.
        log_with_session.write_text(
            log_with_session.read_text() + '{"seq": 99, "ts": 1, "sessi'
        )
        assert main(["verify", str(log_with_session)]) == 2
        err = capsys.readouterr().err
        assert "TRUNCATED" in err
        assert "partial write" in err
        assert "TAMPERED" not in err


class TestReplay:
    def test_renders_all_records(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["replay", str(log_with_session)]) == 0
        out = capsys.readouterr().out
        assert "2 record(s)" in out
        assert "unicode-tag" in out

    def test_decision_filter(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["replay", str(log_with_session), "--decisions", "block"]) == 0
        out = capsys.readouterr().out
        assert "1 record(s)" in out

    @pytest.mark.parametrize("columns", [60, 100, 200])
    def test_rule_name_survives_any_terminal_width(
        self, log_with_session: Path, capsys: pytest.CaptureFixture[str], columns: int
    ) -> None:
        """The reason for a block must never be truncated or dropped.

        An incident review on a narrow terminal is exactly when this column
        matters, so the layout drops other columns before it gives up this one.
        """
        import os

        os.environ["COLUMNS"] = str(columns)
        try:
            assert main(["replay", str(log_with_session)]) == 0
        finally:
            del os.environ["COLUMNS"]
        out = capsys.readouterr().out
        assert "unicode-tag" in out
        assert "…" not in out.split("findings")[-1]

    def test_missing_file_exits_nonzero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["replay", str(tmp_path / "nope.jsonl")]) == 1


class TestChainIntegrityAfterCLIUse:
    def test_verify_agrees_with_library(self, log_with_session: Path) -> None:
        assert verify_chain(log_with_session).ok
        assert main(["verify", str(log_with_session)]) == 0


class TestEvalJsonAgreesWithTheTable:
    """`--json` and the rendered table come from one set of definitions.

    The JSON block used to grade families with its own rule -- "any layer other
    than structural owns this step" -- while the table asked the report whether
    the layer was actually running. On a full run they disagreed about 7 of 12
    families, and the JSON was wrong in the direction that flatters: gaps reported
    where the table had none, and `stopped: 0` next to families the table had
    caught two steps of. A dashboard reading that would have reported a project
    that caught nothing and had outstanding coverage debt, from a run that caught
    everything and had none.
    """

    POLICY = "examples/corpus-workspace-policy.json"

    @pytest.mark.parametrize("layers", ["all", "provenance", "policy", "structural", "none"])
    def test_per_family_matches_the_shared_grade(self, tmp_path: Path, layers: str) -> None:
        out = tmp_path / "report.json"
        assert main(
            ["eval", "--split", "test", "--layers", layers, "--policy", self.POLICY,
             "--json", str(out)]
        ) == 0
        payload = json.loads(out.read_text())

        from airlock.cli import _load_policy, build_layers
        from airlock.eval.harness import load_corpus, replay

        report = replay(
            load_corpus(Path(__file__).resolve().parents[1] / "corpus"),
            build_layers(layers, _load_policy(self.POLICY)),
            split="test",
        )
        stats = report.family_stats()
        assert set(payload["per_family"]) == set(stats)
        for family, got in payload["per_family"].items():
            assert got == stats[family].as_json(), family

    def test_the_headline_numbers_match_the_report(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        main(["eval", "--split", "test", "--policy", self.POLICY, "--json", str(out)])
        payload = json.loads(out.read_text())

        from airlock.cli import _load_policy, build_layers
        from airlock.eval.harness import load_corpus, replay

        report = replay(
            load_corpus(Path(__file__).resolve().parents[1] / "corpus"),
            build_layers("all", _load_policy(self.POLICY)),
            split="test",
        )
        assert payload["attack_success_rate"] == report.attack_success_rate()
        assert payload["weighted_attack_success_rate"] == report.weighted_attack_success_rate()
        assert payload["detection_rate"] == report.detection_rate()
        assert payload["false_positive_rate"] == report.false_positive_rate()
        assert payload["clean"] is report.is_clean()

    def test_missing_parent_directories_are_created(self, tmp_path: Path) -> None:
        out = tmp_path / "deep" / "nested" / "report.json"
        assert main(["eval", "--split", "test", "--policy", self.POLICY, "--json", str(out)]) == 0
        assert json.loads(out.read_text())["clean"] is True


class TestProxyLayersMatchWhatEvalMeasures:
    """The proxy and `eval` must be able to reach the same configuration.

    This is the invariant the code comments keep asserting and nothing was
    holding: `build_layers("all")` builds structural + provenance + policy, and
    the documented deployment invocation has to reach the same set, in the same
    order -- the first `modify` wins the replacement, so order is load-bearing.
    A layer that appears in one command and not the other is how a published
    number stops describing the thing it was measured on.
    """

    POLICY = "examples/corpus-workspace-policy.json"

    def _layers(self, **overrides: object) -> list[str]:
        from airlock.cli import _load_policy, build_proxy_layers

        kwargs: dict[str, object] = {
            "no_structural": False,
            "block_at": "critical",
            "provenance": True,
            "semantic": False,
            "policy": _load_policy(self.POLICY),
        }
        kwargs.update(overrides)
        return [i.name for i in build_proxy_layers(**kwargs)]  # type: ignore[arg-type]

    def test_the_documented_invocation_is_the_configuration_eval_measures(self) -> None:
        from airlock.cli import _load_policy, build_layers

        assert self._layers() == [i.name for i in build_layers("all", _load_policy(self.POLICY))]

    def test_provenance_is_opt_in_and_that_is_documented_as_an_ablation(self) -> None:
        assert self._layers(provenance=False) == ["structural", "policy"]

    def test_the_proxy_flags_enumerate_sets_no_single_layers_value_reaches(self) -> None:
        """Worth knowing rather than fixing.

        `--layers structural` means exactly structural and drops the policy
        layer, which is what makes it an ablation. The proxy keeps the policy
        layer whenever a file resolves and has no way to switch provenance off
        and the policy off at once. So `proxy --policy p` (structural+policy)
        is a configuration `eval` cannot be asked for by name, and someone
        reproducing a proxy run in `eval` has to know that.

        The alternative -- making `--layers structural` include the policy layer
        whenever one is loaded -- would make the ablation table measure two
        layers while labelling it one, so the sets stay as they are and the
        `--layers` help says which reading it takes.
        """
        from airlock.cli import _load_policy, build_layers

        policy = _load_policy(self.POLICY)
        # `semantic` is left out: building it needs a model server, and it is
        # never a policy layer, so it cannot make structural+policy reachable.
        reachable = {
            tuple(i.name for i in build_layers(choice, policy))
            for choice in ("all", "structural", "provenance", "policy", "none")
        }
        assert ("structural", "policy") not in reachable

    def test_no_policy_means_no_policy_layer(self) -> None:
        assert self._layers(policy=None) == ["structural", "provenance"]

    def test_structural_can_be_switched_off(self) -> None:
        assert self._layers(no_structural=True) == ["provenance", "policy"]

    def test_observe_only_keeps_the_layer_and_relaxes_the_threshold(self) -> None:
        """`--block-at none` measures detection without stopping anything.

        The layer has to stay: observe-only with no detectors would report a
        quiet session rather than a decision to watch, which is the number this
        mode exists to collect.
        """
        assert self._layers(block_at="none") == ["structural", "provenance", "policy"]

    def test_an_unknown_severity_is_refused_rather_than_silently_mismatched(self) -> None:
        from airlock.cli import build_proxy_layers

        with pytest.raises(ValueError, match="unknown severity"):
            build_proxy_layers(
                no_structural=False,
                block_at="criticalish",
                provenance=False,
                semantic=False,
                policy=None,
            )

    def test_the_structural_threshold_is_the_one_that_was_asked_for(self) -> None:
        from airlock.cli import build_proxy_layers

        for level in ("info", "low", "medium", "high", "critical"):
            [inspector] = build_proxy_layers(
                no_structural=False,
                block_at=level,
                provenance=False,
                semantic=False,
                policy=None,
            )
            assert inspector.block_at == level
