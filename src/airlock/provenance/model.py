"""Taint tracking for values that crossed an untrusted boundary.

The threat model this module implements is not "a suspicious string appeared".
It is: *a value entered the agent's context from somewhere it does not control,
and that value reached somewhere it can leave*. The middle of that sentence is
where the interesting attacks live, and it is invisible to any detector that
looks at one message at a time.

Four things are tracked, because each defeats a different per-message detector:

``sensitive-read``
    Content read from a path that is treated as a secret store. The classic
    exfiltration shape: read the key, then post it somewhere.

``untrusted-result``
    Content returned by any tool. Not necessarily secret, but attacker-
    influenced: a fetched page, an issue comment, a directory listing.

``denial``
    Facts learned from a *refusal*. ``EACCES: permission denied for
    /etc/shadow (file exists)`` returns no protected data, so flat taint
    tracking reports nothing -- yet the existence of the file is exactly the
    secret being laundered. The denial is the source.

``memory``
    Values the agent stores and recalls across turns. A sleeper channel works
    by decoupling intake from effect, so the value that reaches the sink may
    never have appeared in a single tool result. When untrusted content names a
    memory key, the value behind that key is attacker-influenced even though
    the agent wrote it itself.

Two properties of the design are worth stating because they are the difference
between this and a keyword scanner:

*   Matching is done by taking secret-shaped fragments **out of the sink** and
    asking whether each appears in a known atom. Checking ``atom in sink``
    instead would miss every partial leak, which is the case that matters.
*   State is session-scoped. A drip across twenty requests is one event, and a
    per-turn analyzer sees twenty clean turns.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final, Literal

Origin = Literal["sensitive-read", "untrusted-result", "denial", "memory", "indirection"]

#: Paths whose *content* is treated as secret. Matched against the request the
#: agent issued, not the result, because a denied read must still register.
SENSITIVE_PATH = re.compile(
    r"""
      (?:^|/)etc/(?:shadow|passwd-|sudoers)
    | \.ssh/
    | id_(?:rsa|dsa|ecdsa|ed25519)
    | \.aws/credentials
    | \.netrc\b
    | \.config/gcloud
    | (?:^|/)secrets?/
    | (?:^|/)\.env(?:\.[a-z]+)?$
    | \.(?:pem|p12|pfx|keystore|jks)$
    # The leading `(?:^|/)` matters: without it this also matches the tail of
    # `SELECT id FROM credentials`, where "credentials" is a table name and not
    # a path. A space is not a path separator, and treating it as one makes
    # every column read on such a table look like a secret read.
    | (?:^|/)credentials(?:\.[a-z]+)?$
    | (?:^|/)secrets?\.(?:json|ya?ml|toml)$
    """,
    re.VERBOSE | re.IGNORECASE,
)

#: Identifiers naming a store of secrets, in a *structured* query rather than
#: a path. A `SELECT token FROM credentials` is as much a secret read as
#: `read /run/secrets/api_token`, and the path regex above cannot see it: there
#: is no path in the argument, only a table name. Without this, a credential
#: exfiltrated out of a database is invisible -- the read looks ordinary and the
#: value arrives at the sink with nothing to match against.
#:
#: This is deliberately a *naming* heuristic, and a weak one. A database holding
#: credentials in a table called `tokens_v2` evades it, and a benign query
#: against a table called `credentials` trips it. The false-positive cost is
#: bounded -- the worst outcome is a block on a legitimate query, which an
#: operator can see and allow -- while the miss is a silent leak. It is recorded
#: here as a heuristic rather than presented as coverage.
SENSITIVE_IDENTIFIER = re.compile(
    r"""
      \b(?:credentials?|secrets?|api[_-]?keys?|tokens?|passwords?)\b
    | \bprivate[_-]?key\b
    | \baccess[_-]?key\b
    """,
    re.VERBOSE | re.IGNORECASE,
)

#: Argument names whose values are queries or expressions rather than paths.
#: Checked separately because a path-shaped regex over a SQL string is noise.
QUERY_ARGUMENTS: Final = ("sql", "query", "statement", "expr", "filter", "where")

#: Hostnames that cannot be registered by an outside party. `.internal` and
#: `.local` are reserved and absent from the public root zone, and RFC1918
#: space is not routed on the internet. This is a real property, not a naming
#: convention -- which is why it is safe to treat as a trust anchor.
INTERNAL_SUFFIXES: Final = (".internal", ".local", ".localhost", ".home.arpa", ".lan")

_HOST = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
_URL = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*)://([^/\s?#\"']+)")

#: Minimum length before a sink fragment is worth testing against an atom.
#: Below this, ordinary prose ("staging", "internal") collides with real values
#: and the false-positive rate climbs faster than the recall.
MIN_ATOM = 8

#: How much reconstructed outbound text to retain. Enough for a drip spread
#: across a conversation, bounded so a long session cannot grow without limit.
MAX_OUTBOUND = 4096

#: How much source content to retain for substring matching. A secret file is
#: small, but tool output is not, and an unbounded copy of it would turn this
#: module into the plaintext archive the audit log deliberately refuses to be.
MAX_SOURCE_CHARS = 8192

#: Fragments smaller than this are not individually interesting; they are kept
#: only because they may be a piece of a larger reconstruction.
_FRAGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9+/=_.:@\-]*")


def is_internal_host(host: str) -> bool:
    """Is this destination outside the reach of an internet attacker?"""
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain"):
        return True
    if host.endswith(INTERNAL_SUFFIXES):
        return True
    # Strip a port, then try the remainder as a literal address.
    bare = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def hosts_in(text: str) -> set[str]:
    """Every hostname a piece of untrusted text names.

    This is the *free text* question -- a tool result or a memory value can name
    any number of hosts, and all of them are evidence. It is not the question to
    ask about a destination field; see :func:`host_of_destination`.
    """
    found: set[str] = set()
    for match in _URL.finditer(text):
        authority = match.group(1)
        host = authority.rsplit("@", 1)[-1]
        # Lowercased like the other branch below. Without this a single
        # mixed-case URL contributed two spellings of one host, and because the
        # destination lookup lowercases its query, only the lowercase spelling
        # could ever be found -- the other sat in the map forever, matching
        # nothing, to be re-inserted by the next echo of the same URL.
        found.add((host.rsplit(":", 1)[0] if host.count(":") == 1 else host).lower())
    found.update(m.group(0).lower() for m in _HOST.finditer(text))
    return {h for h in found if h}


def host_of_destination(value: str) -> str:
    """The single host a destination *field* is addressed to.

    A destination field names one place to send data, and the question is which
    place: the authority of the URL, or the domain of a bare address. It is not
    "every host this string mentions", and conflating the two is a bypass in
    both directions.

    Too wide -- every host mentioned -- lets the caller choose the answer, since
    a URL is free to name another host in its query:
    ``https://attacker.example/collect?ref=api.internal`` is addressed to
    ``attacker.example``, and a scan of the whole string returns both and lets
    the second one win. It also made the verdict depend on set iteration order,
    and Python randomises string hashing per process, so the *same* session
    blocked on some runs and allowed on others. A gateway that decides by hash
    seed is not a gateway.

    Too narrow -- only a bare host -- misses a protocol-relative URL, a port, an
    IPv6 literal and a bare recipient, each of which a deployment really uses.

    Deliberately not case-folded past the ASCII host, and deliberately not
    resolving anything: a name that looks internal is judged by
    :func:`is_internal_host` downstream, on the string as written.
    """
    text = value.strip().lower()
    if not text:
        return ""

    # A scheme, or the protocol-relative form, means the authority starts after
    # `//`. Anything else is a bare host or a bare address, where the part before
    # the first `/` is the whole thing.
    if "://" in text:
        text = text.split("://", 1)[1]
    elif text.startswith("//"):
        text = text[2:]

    # Path, query and fragment are not part of the address. A fragment is cut
    # before the userinfo `@` is resolved, or `host#@evil.example` would send
    # the request to evil.example.
    for separator in ("/", "?", "#"):
        text = text.split(separator, 1)[0]
    if not text:
        return ""

    if "@" in text:
        # `https://user:pw@host` is a request to host, and a bare
        # `someone@example.com` is a message to example.com. Both reduce to what
        # follows the last `@`, which is the only reading that is right for each.
        text = text.rsplit("@", 1)[1]
    if not text:
        return ""

    if text.startswith("["):  # IPv6 literal: [::1]:8443
        host, closing, _ = text.partition("]")
        return host + "]" if closing else text
    host, separator, port = text.partition(":")
    if separator and port.isdigit():
        return host
    # A non-numeric port is malformed rather than a different host, and the whole
    # string is returned so it matches no allowlist entry. Failing closed on a
    # name that cannot resolve is the cheaper mistake.
    return text


def atoms_of(text: str) -> set[str]:
    """Every candidate secret fragment in a piece of text.

    One function is used for both sides of a comparison. Sources turn their
    content into atoms, sinks turn their payload into atoms, and a leak is an
    intersection of the two. Keeping them in the same token space is what makes
    a *partial* leak detectable: the sink only has to contain a fragment the
    source also contains, not the whole value.
    """
    out: set[str] = set()
    for raw in _FRAGMENT.finditer(text):
        token = raw.group(0).strip(".,;:")
        if len(token) >= MIN_ATOM:
            out.add(token)
        # Data is commonly delimited by `key=value` and `a&b` rather than by
        # whitespace, so `part=postgres://u:p@h` has to yield the URL and not
        # the whole pair.
        for part in re.split(r"[=&]", token):
            part = part.strip(".,;:")
            if len(part) >= MIN_ATOM:
                out.add(part)
        # A denial reports `/home/user/.ssh/id_ed25519`; the agent then reports
        # `id_ed25519`. Matching only the full path would miss the paraphrase,
        # which is the entire point of laundering the fact instead of the file.
        if "/" in token:
            base = token.rsplit("/", 1)[-1]
            if len(base) >= MIN_ATOM:
                out.add(base)
    return out


@dataclass(frozen=True, slots=True)
class TaintSource:
    """One place untrusted or secret material entered the context."""

    origin: Origin
    label: str
    #: Bounded copy of the content, used for substring matching. A leak is
    #: almost never the whole value -- `postgres://analytics:s3cr3t` out of a
    #: longer URL is the interesting case -- so the sink fragment has to be
    #: tested for containment, not equality.
    text: str = ""
    #: Candidate secret tokens, used to recognise a sharded reconstruction.
    atoms: frozenset[str] = frozenset()
    #: Hostnames the content named. Used by the destination rule. Mutable
    #: because a host the agent had already chosen can be withdrawn when a
    #: result turns out to echo it back; see `TaintStore.forget_untrusted_hosts`.
    hosts: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class EgressMatch:
    """Evidence that tainted material reached an outbound sink."""

    rule: str
    origin: Origin
    source_label: str
    fragment: str
    detail: str


@dataclass
class TaintStore:
    """Session-scoped provenance state.

    One instance per connection. Resetting between corpus cases is the
    evaluation harness's job, not this class's: a leak that only exists because
    of what happened twenty turns ago is a real leak, and pretending otherwise
    would be measuring the wrong system.
    """

    sources: list[TaintSource] = field(default_factory=list)
    #: memory key -> value, for the indirection rule.
    memory: dict[str, str] = field(default_factory=dict)
    #: Memory keys that untrusted content told the agent to read.
    pointed_at: set[str] = field(default_factory=set)
    #: Reconstructed outbound text, in order, for shard reconstruction.
    outbound: str = ""

    # -- source recording ---------------------------------------------------

    def note_read(self, label: str, text: str, *, sensitive: bool) -> None:
        """Record a successful read whose content is now in the context."""
        origin: Origin = "sensitive-read" if sensitive else "untrusted-result"
        self.sources.append(
            TaintSource(
                origin=origin,
                label=label,
                text=text[:MAX_SOURCE_CHARS] if sensitive else "",
                atoms=frozenset(atoms_of(text)) if sensitive else frozenset(),
                hosts=set(hosts_in(text)),
            )
        )

    def note_denial(self, label: str, text: str) -> None:
        """Record facts learned from a refusal.

        The denial is a taint source precisely because it returns no protected
        data. What it returns is the *shape* of the thing being protected, and
        that shape is what gets reported outward.
        """
        self.sources.append(
            TaintSource(
                origin="denial",
                label=label,
                text=text[:MAX_SOURCE_CHARS],
                atoms=frozenset(atoms_of(text)),
                hosts=set(hosts_in(text)),
            )
        )

    def note_memory_write(self, key: str, value: str) -> None:
        self.memory[key] = value
        self.sources.append(TaintSource(origin="memory", label=key))

    def note_pointer(self, key: str) -> None:
        """Untrusted content named a memory key."""
        self.pointed_at.add(key)

    # -- queries ------------------------------------------------------------

    def secret_sources(self) -> list[TaintSource]:
        """Sources whose content is allowed to trigger a literal match."""
        return [s for s in self.sources if s.text and s.origin != "memory"]

    def untrusted_hosts(self) -> dict[str, TaintSource]:
        hosts: dict[str, TaintSource] = {}
        for source in self.sources:
            for host in source.hosts:
                hosts.setdefault(host, source)
        return hosts

    def forget_untrusted_hosts(self, owned: str | Iterable[str]) -> None:
        """Stop blaming a host that a result merely echoed back.

        `owned` is what the agent itself named in the request. A server that
        reports what it did -- "200 OK https://api.example.net/x" -- puts that
        host into the agent's context, and the naive reading treats the context
        as the place the host came from. But the agent typed the host into the
        request; it did not learn it here. Marking it untrusted makes the second
        ordinary call to that API a block, which is the most common request
        pattern there is.

        It is an iterable because a call can be addressed to several places at
        once -- `to` is a list more often than a string -- and forgetting only
        the first would leave the others to be blamed for an echo the agent
        asked for.

        Only a host already attributed to a source that named it is touched, so a
        result which echoes the requested URL *and* links somewhere else still
        taints the other destination.
        """
        if isinstance(owned, str):
            owned = [owned]
        needles = {host.lower() for host in owned if host}
        if not needles:
            return
        for source in self.sources:
            for needle in needles & source.hosts:
                source.hosts.discard(needle)

    def record_outbound(self, payload: str) -> str:
        """Append to the reconstructed outbound stream and return it."""
        self.outbound = (self.outbound + payload)[-MAX_OUTBOUND:]
        return self.outbound

    def rollback_outbound(self, payload: str) -> None:
        """Undo the most recent `record_outbound`, for a request that was blocked.

        The stream exists to reconstruct secrets that *left* the process, so a
        refused request must not contribute to it: one blocked exfiltration would
        otherwise leave the secret resident in the buffer, where every later
        request in the session matches it and the gateway blocks all egress
        forever. That is the false-positive shape that gets a proxy switched off.

        Callers must not roll back a partial fragment. A drip is stopped by the
        block, and the attacker may well resume; the fragments already recorded
        are what let the next request be recognised as a continuation, so
        discarding them would hand the attacker a fresh start for free.
        """
        if not payload or not self.outbound.endswith(payload):
            # The bound truncated, or the state moved on. Rebuilding from the
            # full stream would be worse than leaving it alone, and silently
            # corrupting the reconstruction is the one failure the prefix rule
            # cannot detect.
            return
        self.outbound = self.outbound[: -len(payload)]
        if len(self.outbound) > MAX_OUTBOUND:
            self.outbound = self.outbound[-MAX_OUTBOUND:]

    def match_fragments(self, payload: str) -> list[EgressMatch]:
        """Which of this payload's fragments came from a tainted source?"""
        hits: list[EgressMatch] = []
        seen: set[tuple[str, str]] = set()
        candidates = atoms_of(payload)
        for source in self.secret_sources():
            for fragment in candidates:
                # Containment, not equality: a partial leak is a substring of
                # the source, and the basename of a path the denial reported is
                # a substring of the path it reported.
                if fragment not in source.text:
                    continue
                key = (source.label, fragment)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    EgressMatch(
                        rule="egress-tainted-value",
                        origin=source.origin,
                        source_label=source.label,
                        fragment=fragment,
                        detail=(
                            f"{len(fragment)}-character fragment from {source.origin} "
                            f"{source.label} reached an outbound sink"
                        ),
                    )
                )
        return hits

    def match_reconstruction(self, atom_source: TaintSource) -> EgressMatch | None:
        """Did the outbound stream rebuild, or start rebuilding, a known atom?

        Handles the sharded case, where no single request contains enough to
        match. Requires a *contiguous* run, because a character-class or
        entropy check is defeated by splitting -- but a full token assembled in
        order is not.

        The prefix case is checked as well as the complete one, and that is what
        makes a drip fail *while it is happening* instead of on its final
        request. Waiting for the whole atom means the attacker picks the moment
        of detection, and a session that stops one character short never trips
        the rule at all.
        """
        stream = self.outbound
        for atom in atom_source.atoms:
            if len(atom) < MIN_ATOM:
                continue
            if atom in stream:
                return EgressMatch(
                    rule="egress-sharded",
                    origin=atom_source.origin,
                    source_label=atom_source.label,
                    fragment=atom,
                    detail=(
                        f"a {len(atom)}-character value from {atom_source.label} was "
                        "reassembled from fragments across requests"
                    ),
                )
            partial = self._longest_suffix_prefix(stream, atom)
            if partial is not None:
                return EgressMatch(
                    rule="egress-sharded-prefix",
                    origin=atom_source.origin,
                    source_label=atom_source.label,
                    fragment=partial,
                    detail=(
                        f"{len(partial)}/{len(atom)} characters of a {atom_source.label} "
                        "value, reassembled across requests"
                    ),
                )
        return None

    @staticmethod
    def _longest_suffix_prefix(stream: str, atom: str) -> str | None:
        """The longest suffix of `stream` that is a proper prefix of `atom`.

        A suffix, not a substring: the drip appends in order, so the growing
        head of the secret sits at the end of the outbound stream. Testing
        substrings anywhere in the stream would also catch a secret quoted
        earlier in the session and then unrelated traffic, which is a
        false-positive source for no gain in recall.
        """
        limit = min(len(stream), len(atom) - 1)
        for size in range(limit, MIN_ATOM - 1, -1):
            if stream[-size:] == atom[:size]:
                return stream[-size:]
        return None

    def match_destination(self, host: str) -> EgressMatch | None:
        """Was this destination chosen by untrusted content, and is it external?"""
        if is_internal_host(host):
            return None
        source = self.untrusted_hosts().get(host.lower())
        if source is not None and source.origin == "denial":
            return None
        if source is not None:
            return EgressMatch(
                rule="egress-untrusted-destination",
                origin=source.origin,
                source_label=source.label,
                fragment=host,
                detail=(
                    f"destination {host} was named by untrusted content "
                    f"({source.label}) and is not an internal host"
                ),
            )
        # Not seen in tool output. It may still be a value the agent recalled
        # from memory because untrusted content pointed it there.
        for key in self.pointed_at:
            value = self.memory.get(key, "")
            if host and host in value:
                return EgressMatch(
                    rule="egress-memory-indirection",
                    origin="indirection",
                    source_label=key,
                    fragment=host,
                    detail=(
                        f"destination {host} came from memory key {key!r}, which "
                        "untrusted content referenced"
                    ),
                )
        return None


def strings_in(value: Any) -> Iterable[str]:
    """Every string anywhere inside a decoded JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from strings_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings_in(item)
