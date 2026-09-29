# airlock

**Runtime provenance enforcement and adversarial evaluation for the Model Context Protocol.**

Airlock interposes on MCP traffic between an agent host and its tool servers, tracks
where untrusted content flows, and refuses to let it reach an egress sink — then tries
to defeat itself and publishes the results.

> **Status: early, and the numbers are small.** The interposition relay, the audit
> chain, the structural detector, and the evaluation harness are implemented. The
> provenance engine, policy engine, and local-LLM detector are not. The measured
> attack success rate below is **87.5%** — the harness is honest about the fact that
> one of the four layers it grades is shipping and three are not yet written.

## Why

MCP security tooling today is almost entirely *connect-time config scanning*: read
`mcp.json`, pattern-match the server command, print findings. OWASP's own description
of tool poisoning names why that is insufficient:

> The root cause is a trust gap between connect-time and runtime. Tool descriptions are
> reviewed once, when the agent first connects to a server. Tool responses go straight
> into the LLM context with no equivalent check. **That unguarded runtime channel is what
> the attacker abuses.**

Airlock works on that channel.

The second problem is measurement. Existing tools report vulnerabilities found; they do
not report **false positives on benign traffic**, which is the number that decides whether
a gateway can be switched on at all. This project treats the false-positive rate as a
first-class result, alongside attack success.

## What it does

```
host  ──stdio──►  airlock  ──stdio──►  upstream MCP server
                     │
                     ├── structural detectors   (deterministic, offline, zero-cost)
                     ├── provenance tracking    (taint across tool results)
                     ├── policy engine          (fail-closed, sink-enumerated)
                     └── audit log              (append-only, hash-chained)
```

Adoption is a one-line change to a host's server configuration:

```jsonc
// before
{ "mcpServers": { "filesystem": { "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] } } }

// after
{ "mcpServers": { "filesystem": { "command": "airlock",
  "args": ["proxy", "--", "npx", "-y",
           "@modelcontextprotocol/server-filesystem", "/tmp"] } } }
```

No cooperation is required from the upstream server. Airlock owns the subprocess's pipes.

## Install

```bash
uv sync --extra dev          # core + tests
uv sync --extra dev --extra integration   # + real MCP SDK, for the integration suite
```

## Usage

```bash
# interpose on a server
airlock proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp

# observe-only (measure detection without blocking anything)
airlock proxy --block-at none -- npx -y @modelcontextprotocol/server-filesystem /tmp

# inspect a session
airlock replay .airlock/audit.jsonl --decisions block,flag

# confirm the audit trail has not been altered
airlock verify .airlock/audit.jsonl
```

## Design notes

**Untyped envelopes, on purpose.** The relay forwards any JSON-RPC method, including ones
that do not exist in today's MCP specification. An attacker who can make the gateway drop
traffic it does not recognise has found an evasion primitive, so "unknown method" must
never mean "discard".

**Fail-closed, with one exception.** A detector that raises is treated as a block. An
unparseable line is forwarded verbatim and logged, because dropping a frame we cannot read
would break the agent while hiding the event.

**Detectors observe, policy decides.** Detectors report findings and severities; whether a
finding is fatal depends on where the tainted content is flowing. This separation is what
makes the layer-by-layer ablation meaningful.

**The audit log is tamper-evident.** Records are hash-chained; deleting, editing or
reordering any record invalidates every record after it. Payload capture defaults to
digest-only, because a security tool whose logs become a plaintext archive of agent
traffic is its own vulnerability.

## Evaluation

The corpus is a set of **labelled transcripts** with per-step expected verdicts, not
isolated attack strings. A string-matching corpus cannot represent an attack that contains
no suspicious string — which is exactly the causality-laundering class. See
[`corpus/schema.md`](corpus/schema.md).

Attack families are selected by having a *published adversary*: each one tests a concrete
claim that some existing defense class fails against it. A family with no citation is not
admitted.

| family | source | claim under test |
|---|---|---|
| `tool_poisoning` | OWASP MCP03 | baseline every competitor claims to catch |
| `causality_laundering` | arXiv:2604.04035 | leak via denial feedback, invisible to flat taint |
| `framing_sweep` | arXiv:2608.27092 | reframing defeats surface filters |
| `agent_data_injection` | SNU/UIUC, Jul 2026 | corrupts facts, not instructions; input guardrails at 0% |
| `sharded_egress` | arXiv:2602.22450 | split secrets defeat per-request thresholds |
| `sleeper_channel` | arXiv:2605.13471 | intake and effect decoupled in time |
| `policy_generality` | arXiv:2608.27092 | naming the goal does not generalise |

### Grading a partial build without inflating its numbers

Two things are graded independently for every step: `expect.verdict`, what a complete
system should do, and `expect.layer`, which component of *this* system is accountable
for it. A step this build cannot handle is reported as a **gap**, not a regression — but
it still counts fully toward attack success rate. Nothing is written off.

The line that stays hard: a step attributed to a layer that exists must match its corpus
verdict, and any non-`allow` result on an `allow` step is a false positive. Both fail the
run regardless of what is under construction.

### Results

Held-out `test` split, measured by `make eval`. `dev` is for iteration; the splits are
disjoint and each contains steps the shipped layer owns.

| metric | value | 95% CI (bootstrap over cases) |
|---|---|---|
| attack success rate | 87.5% | [57.1%, 100.0%] |
| weighted ASR | 81.0% | – |
| detection rate | 12.5% | [0.0%, 42.9%] |
| false positive rate | 0.0% | 0/33 expected-allow steps |
| control noise floor | 1 step | `benign-template-docs`, `template-token` |

16 cases, 47 steps, 8 expected-harm. Structural layer: **1/1 owned step stopped**
(invisible Unicode tag characters), 0 false positives, p50 8.3µs / p95 35.1µs
inspection cost per step.

Read this honestly: **87.5% attack success is the real number.** The remaining seven
misses are attributed to layers that do not exist yet — 6 to provenance (denial
feedback, reframed instructions, sharded secrets, sleeper channels) and 1 to policy.
The 12.5% detection rate is over a corpus deliberately built from attacks a lexical
filter cannot see, and is not comparable to a vendor's headline figure.

The control noise floor is tracked separately from the false-positive rate so a 0.0% FPR
cannot be misread as "the detector was quiet everywhere". One step is flagged on
purpose: a documentation page that literally contains chat-template tokens. Flagging it
is correct — an analyst should see it. Blocking it would make documentation about chat
templates unreadable, and the corpus grades the severity, not the silence.

The corpus is small and hand-built, so the intervals are wide and the point estimates
should be read as a working measurement, not a benchmark.

## Layout

```
src/airlock/
  gateway/     stdio relay, JSON-RPC envelopes, session correlation
  inspect/     detectors (structural today; provenance, rules, local LLM next)
  audit/       hash-chained log, chain verification
corpus/        labelled transcripts + benign traffic
eval/          harness, adaptive red team, report generation
tests/         unit + integration (real MCP servers)
```

## License

Apache-2.0.
