"""Does the policy file still describe the traffic the agents actually make?

A policy layer can only enforce what its file names, so the file is the layer's
blind spot: an operator who deletes one surface gets a quieter gateway, not a
louder one. The evaluation already shows the consequence on a split -- forgetting
``http_post.url`` puts ``framing_sweep-002`` back through -- but only for the
corpus that happens to exercise the field.

This module answers the question the evaluation cannot: which destination-shaped
fields does the traffic use that the file says nothing about. It walks transcripts
directly and never runs a detector, because the question is about the *file*, not
about behaviour: no model server, no state, and the same answer every run.

Two design decisions, both about not lying:

* Destination surfaces are recognised with ``RECIPIENT_ARGUMENTS``, which lives
  beside the policy matching rules rather than in this module, so the set of
  fields a policy is expected to decide and the rules that decide them cannot
  drift apart. It is deliberately wider than provenance's ``DESTINATION_ARGUMENTS``;
  see the note there for why a narrower list would be blind to the calendar
  attendee list.
* Sensitivity-shaped fields (``headers``, ``body``, ``description``) are not
  reported as gaps. Deciding what is secret is provenance's job, and a policy file
  that repeated it would rot into a second copy of the secret patterns. The check
  asks only where data may go.

A field the check cannot see is a field the engine would not treat as a
destination either, so the honest limit is stated in the report rather than left
for someone to discover in production.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from airlock.eval.harness import Case
from airlock.inspect.policy import RECIPIENT_ARGUMENTS, Policy, candidates, normalise

#: What the file says about a surface. ``restricted`` and ``anywhere`` are both
#: decisions; only ``undecided`` is a hole, and conflating the first two would
#: train operators to silence the check by writing ``anywhere``.
Decision = Literal["restricted", "anywhere", "undecided"]

_RANK: dict[Decision, int] = {"undecided": 0, "anywhere": 1, "restricted": 2}


@dataclass(frozen=True)
class SurfaceUse:
    """One destination-shaped field, as the traffic used it."""

    tool: str
    argument: str
    #: Tool calls that carried a value for this field.
    calls: int
    #: Normalised destinations seen, so `HTTPS://Metrics.internal:8443/v1` and
    #: `metrics.internal` collapse to one entry.
    destinations: frozenset[str]
    #: Steps on this field the corpus expected to be blocked.
    harm_steps: int
    #: Attack cases that sent something out through this field.
    attack_cases: frozenset[str]
    decision: Decision
    #: The surface's own note, which is what makes a stale file reviewable.
    note: str

    @property
    def surface(self) -> str:
        return f"{self.tool}.{self.argument}"

    @property
    def is_gap(self) -> bool:
        return self.decision == "undecided"

    @property
    def expected_harm_undecided(self) -> bool:
        """A block the corpus expected here, which this file cannot produce.

        This is the row that matters, and it is deliberately not the same thing
        as "an attack case touched this field". A `web_fetch` sits on an attack
        path in every delivery case in the corpus and is *supposed* to be
        allowed -- the request brings instructions in, and the harm lands on a
        later step. Ranking by attack traffic would shout about the field doing
        its job; ranking by expected harm asks the only question that is about
        the file: did anything need blocking here that the file will not block?
        """
        return self.is_gap and self.harm_steps > 0

    @property
    def sort_key(self) -> tuple[int, int, int, str, str]:
        return (
            _RANK[self.decision],
            0 if self.expected_harm_undecided else 1,
            -self.harm_steps,
            self.tool,
            self.argument,
        )


@dataclass(frozen=True)
class PolicyCheck:
    """The surfaces a split exercised, against what the file decided about them."""

    surfaces: tuple[SurfaceUse, ...]
    cases: int
    #: Tool calls that carried a destination, across every surface.
    calls: int

    def _with(self, decision: Decision) -> list[SurfaceUse]:
        return [s for s in self.surfaces if s.decision == decision]

    @property
    def gaps(self) -> list[SurfaceUse]:
        """Surfaces the traffic used and the file never mentioned."""
        return self._with("undecided")

    @property
    def loose(self) -> list[SurfaceUse]:
        """Surfaces the operator explicitly left open."""
        return self._with("anywhere")

    @property
    def is_clean(self) -> bool:
        return not self.gaps


def _arguments_of(message: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """The (tool, arguments) of a tool call, or None for anything else."""
    if message.get("method") != "tools/call":
        return None
    params = message.get("params") or {}
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        return None
    name = params.get("name")
    return (name if isinstance(name, str) else "", arguments)


def check_policy(
    policy: Policy,
    cases: Sequence[Case],
    *,
    split: str | None = None,
) -> PolicyCheck:
    """Cross-reference a policy file against the traffic a split contains."""
    calls: dict[tuple[str, str], int] = {}
    seen: dict[tuple[str, str], set[str]] = {}
    harm: dict[tuple[str, str], int] = {}
    attackers: dict[tuple[str, str], set[str]] = {}
    notes: dict[tuple[str, str], str] = {}
    decisions: dict[tuple[str, str], Decision] = {}
    case_count = 0

    for case in cases:
        if split is not None and case.split != split:
            continue
        case_count += 1
        for step in case.trace:
            if step["direction"] != "host->upstream":
                # A response is data coming back, not data going out. The
                # policy layer does not judge those, so neither does the check.
                continue
            parsed = _arguments_of(step["message"])
            if parsed is None:
                continue
            tool, arguments = parsed
            expected_harm = step["expect"]["verdict"] != "allow"
            for argument in sorted(set(arguments) & RECIPIENT_ARGUMENTS):
                if not candidates(arguments[argument]):
                    continue
                key = (tool, argument)
                calls[key] = calls.get(key, 0) + 1
                seen.setdefault(key, set()).update(
                    normalise(value) for value in candidates(arguments[argument])
                )
                harm[key] = harm.get(key, 0) + (1 if expected_harm else 0)
                if case.kind == "attack":
                    attackers.setdefault(key, set()).add(case.id)

                surface = policy.surface_for(tool, argument)
                if surface is not None:
                    decisions[key] = "anywhere" if surface.anywhere else "restricted"
                    notes[key] = surface.note
                else:
                    # Keep an existing decision: a later call in another case does
                    # not un-decide a field an earlier one found covered.
                    decisions.setdefault(key, "undecided")

    surfaces = tuple(
        SurfaceUse(
            tool=tool,
            argument=argument,
            calls=calls[(tool, argument)],
            destinations=frozenset(seen[(tool, argument)]),
            harm_steps=harm[(tool, argument)],
            attack_cases=frozenset(attackers.get((tool, argument), ())),
            decision=decisions[(tool, argument)],
            note=notes.get((tool, argument), ""),
        )
        for tool, argument in sorted(calls)
    )
    return PolicyCheck(
        surfaces=tuple(sorted(surfaces, key=lambda s: s.sort_key)),
        cases=case_count,
        calls=sum(calls.values()),
    )
