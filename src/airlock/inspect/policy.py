"""Policy: where data is allowed to go.

The other two layers that exist are mechanical. The structural detector
matches shapes. Provenance tracks where a value came from and refuses to let
it reach a sink. Both of them answer the same question -- *did this value get
here from somewhere untrustworthy?* -- and both are blind in the same place.

**A taint tracker can only stop values it has seen flow.** The corpus makes
this concrete: a transcript where the agent posts a workspace signing key in a
header never contains the key. It came from the environment, it was never a
tool result, so there is no taint to track and the tracker has nothing to say.
The workspace knows perfectly well that key is not supposed to go to a
metrics host, and that knowledge is not a fact about any message. It is a fact
about the deployment.

So this layer states the rule the other two cannot reach: **a destination is
permitted, and anything not enumerated is refused.** Two properties of that
sentence are the whole design.

*It is goal-shaped, not surface-shaped.* A rule that names a goal -- "do not
exfiltrate", "no sensitive tool calls" -- is unfalsifiable and unenforceable,
because it has to be re-argued for every destination an attacker picks. The
corpus has a case for that: exfiltration to a domain on no denylist, to a host
nobody thought of. A rule that enumerates the exfiltration *surface* generalises,
because the attacker runs out of places to go rather than out of phrases to
try. The unit of the rule is therefore a `(tool, argument)` pair, not a tool.

*The surface is named at the argument level, because that is where it moves.*
"Trusted tools may send data" is not a policy; every mail client, calendar tool
and HTTP wrapper is a trusted tool, and each has some argument that names a
recipient. The corpus has a case for that too: a sink that is on the allowlist
and a tool that is trusted, and an attack anyway, because the recipient field
was never constrained. So the policy says which arguments carry destinations
and what may appear in them, and a field it does not mention is a field nobody
decided anything about.

**What this layer deliberately does not do.** It does not decide whether a
value is sensitive; that is provenance, and duplicating it here is how a policy
file grows secret patterns that rot. It does not constrain what an agent may
read: a fetch cannot exfiltrate what the agent already holds, and a policy that
constrained fetches would break the ability to read documentation, which is
how most attacks arrive. And it does not infer destinations by guessing
argument names, because a guess is exactly the surface that gets forgotten --
a field the engine cannot name is a field the policy cannot constrain. The
policy file names them, so the gap is visible in review rather than silent at
runtime.

The policy is configuration, so it is a file, and a missing file is a missing
layer rather than a default allowlist. An empty allowlist that permits nothing
would be a different product: one that breaks on the first tool call and gets
switched off, which is the outcome this project is trying to avoid.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.audit.log import Decision, Finding
from airlock.gateway.jsonrpc import Message
from airlock.gateway.session import SessionContext
from airlock.inspect.base import Verdict

#: Argument name that applies to every tool, so a policy can constrain a
#: destination field without listing every tool that has one.
ANY_TOOL = "*"

#: The finding rule. One name for one thing: a destination the policy does not
#: permit. Distinct names per surface would be tidier in a report and worse in
#: practice, because they would make the count of policy refusals depend on how
#: the operator happened to name their arguments.
RULE = "destination-not-permitted"

#: A policy is about egress, and an egress sink has to be named by something the
#: policy file chose. The engine does not guess.
_SURFACES_KEY = "surfaces"


class PolicyError(ValueError):
    """The policy file is not usable.

    Raised at load time rather than at first call, so an operator finds out
    while starting the gateway instead of on the first request that happens to
    touch the broken entry.
    """


#: Argument names whose value names who receives the data. This is the set of
#: fields a policy file is expected to have an opinion about, and it is wider
#: than provenance's ``DESTINATION_ARGUMENTS`` on purpose.
#:
#: Provenance needs a narrower list, because it extracts a *host* to reason about
#: sharding and trust, and only a URL or an address yields one. A policy asks a
#: different question -- who is this addressed to -- and the corpus's
#: `create_calendar_event` step is addressed to a list of `attendees`, which has
#: no host to extract. Reading the narrower list here would make the
#: policy-check command blind to the exact surface the policy layer exists to
#: close, which is a way of shipping a check that cannot fail on the bug it was
#: written for.
#:
#: Content-shaped fields are absent, and their absence is the design: `body`,
#: `description`, `subject` and the rest carry the payload, and whether that
#: payload is secret is provenance's question. A policy file that also answered
#: it would grow a second copy of the secret patterns, and the second copy would
#: rot. The corpus pairs the two layers exactly this way: the calendar invite
#: rides its description along to the attendees, so constraining *who is invited*
#: covers the field without ever naming it.
RECIPIENT_ARGUMENTS = frozenset(
    {
        "attendees",
        "bcc",
        "cc",
        "channel",
        "destination",
        "endpoint",
        "recipients",
        "to",
        "uri",
        "url",
        "webhook",
    }
)


def normalise(value: str) -> str:
    """Reduce a destination to the thing a policy is allowed to name.

    A URL and a bare host are the same destination and have to compare equal,
    or an allowlist is trivially bypassed by writing the entry one way and the
    call the other. So: strip the scheme, drop userinfo, drop the path and the
    port, and lowercase.

    Userinfo is only dropped when a scheme was present. `https://user:pw@host`
    is a request to host with a username in front of it, and an allowlist that
    stopped at the first `@` would permit a request to an attacker's host by
    spelling the permitted host where the username goes. A bare
    `someone@example.com` has no scheme and is a *recipient*, not a URL, so its
    local part is kept -- a policy that matches recipient domains needs it.
    """
    text = value.strip().lower()
    scheme = "://" in text
    if text.startswith("//"):
        text = text[2:]
    if scheme:
        text = text.split("://", 1)[1]
    if "/" in text:
        text = text.split("/", 1)[0]
    if scheme and "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):  # IPv6 literal
        return text.partition("]")[0] + "]"
    host, sep, port = text.partition(":")
    if sep and port.isdigit():
        return host
    return text


def candidates(value: Any) -> list[str]:
    """Every destination named by one argument value.

    A recipient field is a list more often than not, and a policy that only
    read the string case would pass a call whose second recipient was an
    attacker's. Numbers and nested objects are not destinations and are skipped
    rather than stringified: `str()` of a dict is a surface nobody wrote down.
    """
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(candidates(item))
        return out
    return []


@dataclass(frozen=True, slots=True)
class Surface:
    """One destination field, and what may appear in it."""

    #: Permitted destinations. An empty tuple with `anywhere=False` permits
    #: nothing, which is a real policy an operator may want: a field that is
    #: never allowed to carry a destination at all.
    allow: tuple[str, ...] = ()
    #: An explicit "this field is not a destination, or is a mediated one". Kept
    #: distinct from an empty `allow` so a policy file can say it thought about
    #: the field and decided, rather than leaving a reader to guess whether the
    #: omission was a decision.
    anywhere: bool = False
    #: Why the file says what it says. An operator reading a policy six months
    #: after writing it needs the reason more than the rule.
    note: str = ""

    def permits(self, destination: str) -> bool:
        if self.anywhere:
            return True
        host = normalise(destination)
        for entry in self.allow:
            if entry.startswith("@"):
                # A recipient rule, matched on the domain after the @.
                if "@" in host and host.rsplit("@", 1)[1] == entry[1:]:
                    return True
                continue
            if entry.startswith("."):
                # Suffix wildcard: ".example.com" covers example.com and
                # anything under it, and does not cover "notexample.com".
                if host == entry[1:] or host.endswith(entry):
                    return True
                continue
            if host == entry:
                return True
        return False


@dataclass(frozen=True, slots=True)
class Policy:
    """A parsed policy file: tool -> argument -> surface."""

    surfaces: dict[str, dict[str, Surface]] = field(default_factory=dict)
    source: str = "<none>"

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        """Read a policy file, or refuse to guess at one.

        There is deliberately no `Policy.default()`. A built-in allowlist would
        be a list of destinations somebody chose on a machine that is not the
        operator's, and it would be the list that silently permits the
        exfiltration, because it is the list that ships by default.
        """
        path = Path(path)
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise PolicyError(f"no policy file at {path}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError(f"{path}: expected an object at the top level")
        version = raw.get("version")
        if version != 1:
            raise PolicyError(f"{path}: unsupported policy version {version!r}")
        raw_surfaces = raw.get(_SURFACES_KEY)
        if not isinstance(raw_surfaces, dict) or not raw_surfaces:
            raise PolicyError(
                f"{path}: 'surfaces' must be a non-empty object mapping a tool "
                f"to the arguments that carry destinations"
            )
        return cls(surfaces=_parse_surfaces(raw_surfaces, path), source=str(path))

    def surface_for(self, tool: str, argument: str) -> Surface | None:
        """The rule for one field, or None if the policy has no opinion.

        A tool's own entry wins over the wildcard, so a policy can constrain one
        tool's recipient field without loosening or tightening every other.
        """
        for table in (self.surfaces.get(tool), self.surfaces.get(ANY_TOOL)):
            if table and argument in table:
                return table[argument]
        return None

    def described_tools(self) -> list[str]:
        return sorted(self.surfaces)


def _parse_surfaces(raw: dict[str, Any], path: Path) -> dict[str, dict[str, Surface]]:
    surfaces: dict[str, dict[str, Surface]] = {}
    for tool, arguments in raw.items():
        if not isinstance(arguments, dict):
            raise PolicyError(f"{path}: surfaces[{tool!r}] must be an object")
        table: dict[str, Surface] = {}
        for argument, spec in arguments.items():
            if not isinstance(spec, dict):
                raise PolicyError(f"{path}: surfaces[{tool!r}][{argument!r}] must be an object")
            anywhere = spec.get("anywhere", False)
            allow = spec.get("allow", [])
            if anywhere and allow:
                raise PolicyError(
                    f"{path}: surfaces[{tool!r}][{argument!r}] says both "
                    f"'anywhere' and an allowlist; one of them is a mistake"
                )
            if not anywhere and not isinstance(allow, list):
                raise PolicyError(f"{path}: surfaces[{tool!r}][{argument!r}].allow must be a list")
            table[argument] = Surface(
                allow=tuple(str(entry).lower() for entry in allow),
                anywhere=bool(anywhere),
                note=str(spec.get("note", "")),
            )
        surfaces[tool] = table
    return surfaces


class PolicyInspector:
    """Refuses a call whose destination field the policy does not permit."""

    name = "policy"

    def __init__(self, policy: Policy, *, block_at: str = "critical") -> None:
        self.policy = policy
        self._block_at = block_at

    def reset(self) -> None:
        """Nothing accumulates, so there is nothing to clear.

        Declared anyway. The evaluation harness resets every stateful layer
        between cases, and a layer that silently lacks the method is a layer
        that will accumulate state later without anyone noticing.
        """

    def inspect_request(self, message: Message, ctx: SessionContext) -> Verdict:
        if message.method != "tools/call":
            return Verdict.allow()
        tool = message.tool_name
        if tool is None:
            return Verdict.allow()
        arguments = message.params.get("arguments")
        if not isinstance(arguments, dict) or not arguments:
            return Verdict.allow()

        refusals: list[Finding] = []
        for argument in sorted(arguments):
            surface = self.policy.surface_for(tool, argument)
            if surface is None:
                # The policy has no opinion about this field. Not a pass on
                # the merits: a destination nobody named is a hole in the
                # policy file, and the README says so rather than pretending
                # the layer checked it.
                continue
            for destination in candidates(arguments[argument]):
                if surface.permits(destination):
                    continue
                refusals.append(
                    Finding(
                        rule=RULE,
                        severity="critical",
                        detail=(
                            f"{tool}.{argument} names {normalise(destination)!r}, "
                            f"which the policy at {self.policy.source} does not "
                            f"permit"
                        ),
                        owasp="MCP2",
                    )
                )
        if not refusals:
            return Verdict.allow()
        action: Decision = "block"
        return Verdict.of(action, *refusals)

    def inspect_response(self, message: Message, ctx: SessionContext) -> Verdict:
        """Responses are not egress, so a destination policy has nothing to say.

        A policy is about where data leaves. What comes back is provenance's
        business, and judging it here would be a second, weaker version of the
        same judgement.
        """
        return Verdict.allow()


__all__ = [
    "ANY_TOOL",
    "RECIPIENT_ARGUMENTS",
    "RULE",
    "Policy",
    "PolicyError",
    "PolicyInspector",
    "Surface",
    "candidates",
    "normalise",
]
