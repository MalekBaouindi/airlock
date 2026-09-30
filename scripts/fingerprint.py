"""Per-step decision fingerprint, for comparing runs across hash seeds.

`airlock eval --json` reports aggregates, and two different sets of per-step
verdicts can aggregate to identical rates. A determinism claim needs the
per-step answers, so this prints one line per step and nothing else: no timings,
no ordering that depends on anything but the corpus.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from airlock.eval.harness import load_corpus, replay
from airlock.inspect.policy import Policy, PolicyInspector
from airlock.inspect.structural import StructuralInspector
from airlock.provenance.inspector import ProvenanceInspector


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    corpus = load_corpus(root / "corpus")
    policy = Policy.load(root / "examples" / "corpus-workspace-policy.json")
    inspectors = [StructuralInspector(), ProvenanceInspector(), PolicyInspector(policy)]
    report = replay(corpus, inspectors)

    for result in report.results:
        rules = ",".join(result.rules)
        # Both the sorted set and the emission order: the verdict cannot depend on
        # the second, but the audit log records findings in it, and a fingerprint
        # that normalised the order away would be blind to drift in either.
        order = ",".join(result.rule_order)
        print(
            f"{result.case_id}\t{result.index}\t{result.direction}\t"
            f"{result.expected.verdict}\t{result.actual}\t{result.outcome}\t"
            f"{rules}\t{order}"
        )
    # Anything not on the per-step path that could still move a number.
    print(f"#\tlayers={','.join(report.layers)}\tasr={report.attack_success_rate()}")
    print(f"#\tfpr={report.false_positive_rate()}\tclean={report.is_clean()}")
    print(f"#\tfailures={len(report.regressions())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
