"""Command-line interface.

    airlock proxy   -- <upstream command> [args...]   run the interposition gateway
    airlock replay  <audit.jsonl>                     inspect a recorded session
    airlock verify  <audit.jsonl>                     check the hash chain

The proxy is invoked exactly where an MCP server would be, so adopting it is a
one-line change to a host's server configuration: replace the server command
with ``airlock proxy -- <server command>``.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

from airlock import __version__
from airlock.audit.log import AuditLog, iter_records, verify_chain
from airlock.gateway.stdio_proxy import StdioProxy, UpstreamSpec
from airlock.inspect.base import Inspector, InspectorPipeline
from airlock.inspect.structural import StructuralInspector
from airlock.provenance.inspector import ProvenanceInspector

DEFAULT_AUDIT_PATH = Path(".airlock/audit.jsonl")

SEVERITY_CHOICES = ("info", "low", "medium", "high", "critical", "none")


def build_proxy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock proxy",
        description="Interpose on a stdio MCP server.",
    )
    parser.add_argument(
        "--audit",
        type=Path,
        default=DEFAULT_AUDIT_PATH,
        help=f"audit log path (default: {DEFAULT_AUDIT_PATH})",
    )
    parser.add_argument(
        "--capture",
        choices=("none", "digest", "full"),
        default="digest",
        help="how much message content to retain in the audit log (default: digest)",
    )
    parser.add_argument(
        "--block-at",
        choices=SEVERITY_CHOICES,
        default="critical",
        help=(
            "lowest severity that blocks rather than flags; 'none' makes the "
            "gateway observe-only, which is what the false-positive measurements use"
        ),
    )
    parser.add_argument(
        "--no-structural",
        action="store_true",
        help="disable the structural detector (ablation: run with no detectors)",
    )
    parser.add_argument(
        "--provenance",
        action="store_true",
        help="enable the provenance layer: track taint sources and block egress",
    )
    parser.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="-- followed by the upstream server command and its arguments",
    )
    return parser


def cmd_proxy(argv: Sequence[str]) -> int:
    # Split on the first bare "--" ourselves: argparse's REMAINDER keeps the
    # separator, and the upstream command may use flags that would otherwise be
    # parsed as ours.
    if "--" not in argv:
        print(
            "error: missing '--' separator before the upstream command\n"
            "usage: airlock proxy [options] -- <command> [args...]",
            file=sys.stderr,
        )
        return 2
    split = list(argv).index("--")
    our_args, upstream_argv = list(argv[:split]), list(argv[split + 1 :])
    if not upstream_argv:
        print("error: no upstream command given after '--'", file=sys.stderr)
        return 2

    args = build_proxy_parser().parse_args(our_args)

    inspectors: list[Inspector] = []
    if not args.no_structural:
        block_at = None if args.block_at == "none" else args.block_at
        inspectors.append(StructuralInspector(block_at=block_at))
    if args.provenance:
        inspectors.append(ProvenanceInspector())

    pipeline = InspectorPipeline(inspectors=inspectors)
    audit = AuditLog(args.audit, capture=args.capture)
    proxy = StdioProxy(UpstreamSpec.from_argv(upstream_argv), pipeline, audit)
    try:
        return asyncio.run(proxy.run())
    except KeyboardInterrupt:
        return 130


def cmd_replay(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock replay", description="Inspect a recorded session."
    )
    parser.add_argument("audit", type=Path, help="path to an audit log")
    parser.add_argument(
        "--decisions",
        default=None,
        help="comma-separated decisions to show, e.g. block,flag (default: all)",
    )
    args = parser.parse_args(list(argv))

    if not args.audit.exists():
        print(f"error: no such audit log: {args.audit}", file=sys.stderr)
        return 1

    wanted = None
    if args.decisions:
        wanted = {d.strip() for d in args.decisions.split(",") if d.strip()}

    from rich.console import Console
    from rich.table import Table

    console = Console()
    # Under a narrow terminal a seven-column table does not degrade gracefully:
    # rich silently squeezes the last column off the screen, which is the one
    # that says *why* something was blocked. Drop the low-value columns instead
    # so the decision and the reason are always readable.
    width = console.width
    compact = width < 100
    title = f"airlock session replay - {args.audit}" if not compact else "airlock session replay"
    table = Table(title=title, show_lines=False, expand=False)
    table.add_column("seq", justify="right", style="dim", no_wrap=True)
    if not compact:
        table.add_column("direction", style="cyan", no_wrap=True)
    table.add_column("kind", no_wrap=True)
    table.add_column("decision", no_wrap=True)
    if not compact:
        table.add_column("method", style="magenta", no_wrap=True)
    table.add_column("tool", no_wrap=True)
    table.add_column("findings", overflow="fold", min_width=18)

    shown = 0
    for record in iter_records(args.audit):
        decision = record.get("decision", "allow")
        if wanted is not None and decision not in wanted:
            continue
        shown += 1
        style = {
            "block": "bold red",
            "flag": "yellow",
            "modify": "blue",
        }.get(decision, "green")
        findings = record.get("findings") or []
        # One rule per line, no wrapping: "unicode-t…\ne-tag" is useless in an
        # incident review, and the terminal is often narrower than the table.
        rendered = "\n".join(f"{f['rule']} ({f['severity']})" for f in findings) or "-"
        row = [str(record.get("seq"))]
        if not compact:
            row.append(record.get("direction", ""))
        row.append(record.get("kind", ""))
        row.append(f"[{style}]{decision}[/{style}]")
        if not compact:
            row.append(record.get("method") or "-")
        row.append(record.get("tool") or "-")
        row.append(rendered)
        table.add_row(*row)

    console.print(table)
    console.print(f"{shown} record(s)")
    return 0


def cmd_verify(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock verify", description="Verify the audit chain has not been altered."
    )
    parser.add_argument("audit", type=Path, help="path to an audit log")
    args = parser.parse_args(list(argv))

    if not args.audit.exists():
        print(f"error: no such audit log: {args.audit}", file=sys.stderr)
        return 1

    result = verify_chain(args.audit)
    if result.ok:
        print(f"ok: {result.records} record(s), chain intact")
        return 0
    print(
        f"TAMPERED: {result.reason} (verified up to {result.records} record(s))",
        file=sys.stderr,
    )
    return 1


def cmd_eval(argv: Sequence[str]) -> int:
    """Score the gateway against the labelled corpus."""
    import json

    from airlock.eval.harness import load_corpus, replay, validate_corpus
    from airlock.eval.report import render

    parser = argparse.ArgumentParser(
        prog="airlock eval", description="Evaluate the gateway against the corpus."
    )
    parser.add_argument("--corpus", type=Path, default=Path("corpus"), help="corpus directory")
    parser.add_argument(
        "--split",
        choices=("dev", "test", "all"),
        default="all",
        help="score only one partition (default: all)",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write results as JSON")
    parser.add_argument(
        "--ablation",
        action="store_true",
        help="run the no-detector baseline alongside the full configuration",
    )
    parser.add_argument(
        "--layers",
        default="all",
        choices=("all", "structural", "provenance", "none"),
        help="which detector layers to run (default: all)",
    )
    args = parser.parse_args(list(argv))

    def build_layers(choice: str) -> list[Inspector]:
        """Assemble the requested detector layers.

        Layers are constructed independently so the ablation can attribute a
        detection to the layer that earned it rather than to the pipeline.
        """
        if choice == "none":
            return []
        if choice == "structural":
            return [StructuralInspector()]
        if choice == "provenance":
            return [ProvenanceInspector()]
        return [StructuralInspector(), ProvenanceInspector()]

    if not args.corpus.exists():
        print(f"error: no such corpus: {args.corpus}", file=sys.stderr)
        return 2

    cases = load_corpus(args.corpus)
    if not cases:
        print(f"error: no cases found under {args.corpus}", file=sys.stderr)
        return 2

    problems = validate_corpus(cases)
    if problems:
        print("error: the corpus is malformed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    split = None if args.split == "all" else args.split
    inspectors = build_layers(args.layers)
    report = replay(cases, inspectors, split=split)

    if args.ablation:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="ablation: what each layer contributes")
        table.add_column("configuration", no_wrap=True, min_width=22)
        table.add_column("ASR", justify="right", no_wrap=True, min_width=7)
        table.add_column("detect", justify="right", no_wrap=True, min_width=7)
        table.add_column("FPR", justify="right", no_wrap=True, min_width=7)
        table.add_column("owned recall", justify="right", no_wrap=True, min_width=13)

        # Each configuration is run on its own so a detection can be attributed
        # to the layer that earned it. "Owned recall" is the number that matters
        # when reading the middle rows: ASR stays high as long as any layer is
        # missing, so it cannot distinguish a layer that helps from one that
        # does nothing.
        configurations: list[tuple[str, list[Inspector], str]] = [
            ("no detectors", [], "the undefended baseline this project has to beat"),
            (
                "structural only",
                [StructuralInspector()],
                "Unicode and template-token carriers",
            ),
            (
                "provenance only",
                [ProvenanceInspector()],
                "taint sources, sharded egress, untrusted destinations",
            ),
            (
                "both (shipped)",
                [StructuralInspector(), ProvenanceInspector()],
                "the configuration `airlock proxy` runs with --provenance",
            ),
        ]
        for name, layers, _note in configurations:
            run = replay(cases, layers, split=split)
            owned = [
                r
                for r in run.attack_steps()
                if r.expected.verdict in ("block", "modify") and run.owns(r.expected.layer)
            ]
            stopped = sum(r.is_mitigated for r in owned)
            table.add_row(
                name,
                f"{run.attack_success_rate() * 100:.1f}%",
                f"{run.detection_rate() * 100:.1f}%",
                f"{run.false_positive_rate() * 100:.1f}%",
                f"{stopped}/{len(owned)}" if owned else "-",
            )
        console.print(table)
        # Prose goes below the table. A note column steals the width the
        # numbers need, and a one-character-wide note is worse than no note.
        for name, _, note in configurations:
            console.print(f"[dim]  {name}: {note}[/dim]")
        missing = sorted(
            {
                r.expected.layer
                for r in report.attack_steps()
                if r.expected.layer and not report.owns(r.expected.layer)
            }
        )
        console.print(
            f"[dim]Not implemented yet: {', '.join(missing) or 'nothing'}. Their "
            "steps are reported as coverage debt, and count as successful "
            "attacks.[/dim]\n"
        )

    print(render(report, title=f"airlock evaluation ({args.split} split)"))

    if args.json:
        payload = {
            "split": args.split,
            "steps": len(report.results),
            "attack_success_rate": report.attack_success_rate(),
            "weighted_attack_success_rate": report.weighted_attack_success_rate(),
            "detection_rate": report.detection_rate(),
            "false_positive_rate": report.false_positive_rate(),
            "gap_rate": report.gap_rate(),
            "clean": report.is_clean(),
            "latency_ns": report.latency(),
            "failures": [
                {
                    "case": r.case_id,
                    "step": r.index,
                    "family": r.family,
                    "expected": r.expected.verdict,
                    "actual": r.actual,
                    "outcome": r.outcome,
                    "rules": list(r.rules),
                }
                for r in report.results
                if r.outcome in ("false-positive", "mismatch")
            ],
            "per_family": {
                family: {
                    "steps": len(results),
                    "stopped": sum(
                        r.actual in ("block", "modify")
                        and not (r.expected.layer and r.expected.layer != "structural")
                        for r in results
                    ),
                    "gaps": sum(
                        r.expected.layer is not None and r.expected.layer != "structural"
                        for r in results
                    ),
                }
                for family, results in sorted(report.by_family().items())
            },
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"\nwrote {args.json}")

    return 0 if report.is_clean() else 1


USAGE = f"""airlock {__version__} - runtime provenance enforcement for MCP

usage:
  airlock proxy  [options] -- <command> [args...]   interpose on a stdio MCP server
  airlock replay <audit.jsonl>                      inspect a recorded session
  airlock verify <audit.jsonl>                      check the hash chain
  airlock eval   [options]                          score against the corpus

examples:
  airlock proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp
  airlock replay .airlock/audit.jsonl --decisions block,flag
  airlock verify .airlock/audit.jsonl
  airlock eval --split test --ablation --json results/eval.json

run 'airlock <command> --help' for command options.
"""


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if args[0] in ("--version", "-V", "version"):
        print(__version__)
        return 0

    command, rest = args[0], args[1:]
    handlers = {
        "proxy": cmd_proxy,
        "replay": cmd_replay,
        "verify": cmd_verify,
        "eval": cmd_eval,
    }
    handler = handlers.get(command)
    if handler is None:
        print(f"error: unknown command {command!r}\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    return handler(rest)


if __name__ == "__main__":
    raise SystemExit(main())
