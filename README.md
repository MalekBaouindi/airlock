# airlock

**Runtime provenance enforcement and adversarial evaluation for the Model Context Protocol.**

Airlock interposes on MCP traffic between an agent host and its tool servers, tracks
where untrusted content flows, and refuses to let it reach an egress sink — then tries
to defeat itself and publishes the results.

> **Status: early, and the numbers are small.** The interposition relay, the audit
> chain, the structural detector, the provenance engine, and the evaluation harness
> are implemented. The policy engine and the local-LLM detector are not. Held-out
> attack success rate is **12.5%** at 0% false positives, with 6 of 6 owned steps
> stopped — the residual is two `policy` steps, and the harness names them rather
> than folding them into a rounder figure.

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
                     ├── provenance tracking    (taint sources -> egress sinks)
                     ├── policy engine          (not implemented yet)
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
airlock proxy --provenance -- npx -y @modelcontextprotocol/server-filesystem /tmp

# structural layer only (ablation: what does provenance add?)
airlock proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp

# observe-only (measure detection without blocking anything)
airlock proxy --provenance --block-at none -- npx -y @modelcontextprotocol/server-filesystem /tmp

# inspect a session
airlock replay .airlock/audit.jsonl --decisions block,flag

# confirm the audit trail has not been altered
airlock verify .airlock/audit.jsonl
```

## Design notes

**One response per request, even when the gateway answers.** The relay tracks
outstanding requests so a dying upstream produces an error instead of an agent
that waits forever. A blocked request is answered by the gateway and never
reaches the upstream, so it has to leave that set — otherwise the sweep at
shutdown treats it as unanswered and sends a *second* error for the same id.
JSON-RPC has no way to express two responses to one request, and a client that
already handled the first is now reading a reply it never asked for.

**Findings never quote the value they matched.** The audit log is digest-only so
that it does not become a plaintext archive of every secret the gateway saw. The
leak to watch for is a human-readable detail string, so the reconstruction
findings report *how much* of which source matched, not the matched text.

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
disjoint and each contains steps for every layer this build ships.

| metric | value | 95% CI (bootstrap over cases) |
|---|---|---|
| attack success rate | 12.5% | [0.0%, 42.9%] |
| weighted ASR | 9.5% | – |
| detection rate | 87.5% | [57.1%, 100.0%] |
| false positive rate | 0.0% | 0/33 expected-allow steps |
| control noise floor | 1 step | `benign-template-docs`, `template-token` |

16 cases, 47 steps, 8 expected-harm. p50 17.7µs / p95 63.2µs inspection cost per step.

**6 of 6 owned steps stopped, 0 false positives.** The two remaining misses are both
`policy`-layer steps — sending a workspace signing key to a host that is not the
workspace, and creating a calendar event with attendees the transcript never
introduced. That layer is not written yet, so those are reported as coverage debt.

The `dev` split scores 13.0% ASR with 0% false positives and holds three more steps
of unimplemented debt (`semantic` ×2, `policy` ×1), and both splits PASS. The gap
between the splits is not overfitting — it is the corpus working. Three dev steps
were regraded while building this layer, twice in the same direction: four steps
claimed `provenance` credit for secrets that never entered the transcript
(`<vault value>`, `<service account token>`), which taint tracking cannot catch by
construction, and 24 drip steps demanded a block on a single character.

Ablation, same split:

| configuration | ASR | detection | FPR | owned recall |
|---|---|---|---|---|
| no detectors | 100.0% | 0.0% | 0.0% | – |
| structural only | 87.5% | 12.5% | 0.0% | 1/1 |
| provenance only | 25.0% | 75.0% | 0.0% | 5/5 |
| both (shipped) | **12.5%** | 87.5% | 0.0% | **6/6** |

Read the ablation rather than the headline. ASR stays high while any layer is missing,
so on its own it cannot tell a layer that helps from one that does nothing; owned
recall is the column that does that, and it is why the layers are constructed
separately rather than fused into one detector.

The provenance layer is the reason the number moved. It tracks four kinds of source —
a read from a secret path, any tool result, **a denial**, and agent memory — and three
ways material reaches a sink. Two of those are worth calling out because no per-message
detector can express them:

- **Denials are a taint source.** `EACCES: permission denied for /etc/shadow (file
  exists)` returns no protected data, so flat taint tracking reports nothing — but the
  existence of the file is precisely what is being laundered.
- **Reconstruction is contiguous, and it fires mid-drip.** A secret posted one
  character per request to rotating subdomains is reassembled across 24 messages.
  Shuffled fragments do not reassemble, which is why the rule requires a
  contiguous run rather than a character-class or entropy check. The prefix
  variant matches the growing *suffix* of the outbound stream, so the block lands
  on the 8th character rather than on whichever request completes the token — an
  attacker picks between stopping before the threshold and being stopped before
  finishing. Matching anywhere in the stream instead of at its end would be
  simpler and wrong: one leak would make every later request in the session look
  tainted.

The false-positive boundary here is the one that decides whether any of this is
deployable. `benign-egress` is structurally identical to the sleeper-channel case — a
host read from a file becomes the request destination — and the only thing separating
them is that `metrics.internal` sits under a reserved suffix and `partner-cdn.io` does
not. A hostname an outside attacker cannot obtain is a real trust anchor; a naming
convention is not, and this would not be a defensible rule without that difference.

**Known limits, stated rather than buried.** Sharded reassembly needs 8 characters
of a contiguous run, so a leak truncated below that is not detected. The corpus
grades those first seven steps `allow` rather than pretending they are caught: a
request carrying `t` is not evidence, and a gateway that blocked it would block
all traffic. A compromised
*internal* host is trusted by definition. And the `is_internal_host` test is a
heuristic about the hostname, not a verification of the resolved address, so DNS
rebinding defeats it.

The control noise floor is tracked separately from the false-positive rate so a 0.0%
FPR cannot be misread as "the detector was quiet everywhere". One step is flagged on
purpose: a documentation page that literally contains chat-template tokens. Flagging
it is correct — an analyst should see it. Blocking it would make documentation about
chat templates unreadable, and the corpus grades the severity, not the silence.

The corpus is small and hand-built, so the intervals are wide and the point estimates
should be read as a working measurement, not a benchmark.

## Layout

```
src/airlock/
  gateway/     stdio relay, JSON-RPC envelopes, session correlation
  inspect/     structural detector, verdict combination
  provenance/  taint sources, egress sinks, destination trust
               (rollback on block, so one refused leak cannot poison a session)
  audit/       hash-chained log, chain verification
  eval/        corpus replay, metrics, report generation
corpus/        labelled transcripts + benign traffic
tests/         unit + integration (real MCP servers)
```

## License

Apache-2.0.
