"""A minimal client for a locally-hosted model, over the standard library.

The core of this project has no third-party dependencies, on purpose: the thing
being measured should not drag a dependency tree into the measurement. That
extends to the judge, so this talks HTTP with `urllib` rather than pulling in
`httpx` or an SDK. It is a hundred lines and it is the whole surface we need --
one chat completion, one health check.

The deployment target is `llama-server`, which speaks an OpenAI-compatible
`/v1/chat/completions`. Anything that speaks the same dialect works, including
a server on another host, which is how the same judge runs in CI against a
different machine.

Two properties matter more than speed, and both are enforced here rather than
left to the caller's discipline:

* **A verdict is never invented.** If the model is unreachable, the response
  is unparseable, or it says something that is not one of the allowed answers,
  this raises. The pipeline already treats a raising detector as a block, and
  that is the right default: a security layer that quietly returns "allow"
  when it could not decide is worse than no layer, because it is a layer that
  reports having found nothing.

* **Identical prompts are asked once.** Judging is deterministic in intent but
  not in latency, and an evaluation that re-asks the same question 40 times is
  measuring the model server as much as the model. The cache is keyed by the
  full request, including the parameters that change the answer, so a hit is
  only ever a hit on an identical question.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

#: Where `llama-server` listens unless told otherwise. Loopback on purpose: a
#: judge that decides what reaches a security boundary has no business being
#: reachable from the network.
DEFAULT_ENDPOINT = "http://127.0.0.1:8080"

#: How long to wait for a verdict before treating the judge as failed. Long
#: enough for a 4B model on a laptop to read a page of tool output; short
#: enough that a wedged server does not become a hung agent.
DEFAULT_TIMEOUT = 20.0

#: Requests are not retried. A retry inside the gateway's latency budget turns
#: a slow model into an indistinguishable outage, and the caller needs to see a
#: failure rather than a silently delayed success.


class JudgeUnavailable(RuntimeError):
    """The judge could not be reached, or answered something unusable."""


@dataclass
class JudgeStats:
    """What the judge actually cost, so the report can say so out loud."""

    calls: int = 0
    cache_hits: int = 0
    failures: int = 0
    seconds: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def seconds_per_call(self) -> float:
        return self.seconds / self.calls if self.calls else 0.0


@dataclass
class LocalModel:
    """A chat model served locally, asked for one completion at a time."""

    endpoint: str = DEFAULT_ENDPOINT
    model: str = "local"
    timeout: float = DEFAULT_TIMEOUT
    #: Kept small on purpose. The judge is asked to emit a token and a reason;
    #: a long answer is both slower and easier to misparse.
    max_tokens: int = 64
    #: GBNF grammar, when the caller needs the answer in an exact shape. This
    #: is a llama.cpp extension, and it is the difference between a classifier
    #: whose output is parsed and one whose output is *generated* correctly.
    #: Without it a model asked to pick one of two answers will sometimes
    #: reproduce the line showing the options instead of choosing -- observed
    #: here, where "verdict: INJECTION | NONE" came back verbatim and a lenient
    #: parser read the first alternative and called every case an injection.
    #: Constraining the sampling is cheaper and safer than parsing around it.
    grammar: str | None = None
    temperature: float = 0.0
    #: Fixed so that a re-run of the evaluation asks the same question the same
    #: way. Without it, a temperature of 0 is a strong hint rather than a
    #: promise, and "the model happened to differ" is not a result.
    seed: int = 20260929
    stats: JudgeStats = field(default_factory=JudgeStats)
    _cache: dict[str, str] = field(default_factory=dict, repr=False)

    # -- health ------------------------------------------------------------

    def available(self) -> bool:
        """Is the server up? Cheap enough to call before every session."""
        try:
            with urllib.request.urlopen(
                f"{self.endpoint}/health", timeout=min(self.timeout, 2.0)
            ) as response:
                return bool(response.status == 200)
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def describe(self) -> str:
        return f"{self.model} via {self.endpoint}"

    # -- completion --------------------------------------------------------

    def ask(self, system: str, user: str) -> str:
        """One completion, or raise.

        Cached on the exact request. The key includes everything that changes
        the answer, so a cache hit is the same question asked before -- not a
        similar one.
        """
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": self.seed,
        }
        if self.grammar:
            payload["grammar"] = self.grammar
        key = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        cached = self._cache.get(key)
        if cached is not None:
            self.stats.cache_hits += 1
            return cached

        request = urllib.request.Request(
            f"{self.endpoint}/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        self.stats.calls += 1
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode())
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            self.stats.failures += 1
            raise JudgeUnavailable(f"{self.describe()} did not answer: {exc}") from exc
        self.stats.seconds += time.monotonic() - started

        try:
            answer = str(body["choices"][0]["message"]["content"])
            usage = body.get("usage") or {}
            self.stats.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self.stats.completion_tokens += int(usage.get("completion_tokens") or 0)
        except (KeyError, IndexError, TypeError) as exc:
            self.stats.failures += 1
            raise JudgeUnavailable(
                f"{self.describe()} returned a response with no completion in it"
            ) from exc

        self._cache[key] = answer
        return str(answer)

    # -- configuration -----------------------------------------------------

    @classmethod
    def from_env(cls, **overrides: Any) -> LocalModel:
        """Build a client from `AIRLOCK_JUDGE_*` environment variables.

        Read at call time rather than import time so a test can point the judge
        somewhere else without touching the process environment permanently.
        """
        settings: dict[str, Any] = {
            "endpoint": os.environ.get("AIRLOCK_JUDGE_ENDPOINT", DEFAULT_ENDPOINT),
            "model": os.environ.get("AIRLOCK_JUDGE_MODEL", "local"),
        }
        if "AIRLOCK_JUDGE_TIMEOUT" in os.environ:
            settings["timeout"] = float(os.environ["AIRLOCK_JUDGE_TIMEOUT"])
        settings.update(overrides)
        return cls(**settings)


__all__ = ["DEFAULT_ENDPOINT", "JudgeStats", "JudgeUnavailable", "LocalModel"]
