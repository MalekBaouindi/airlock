# airlock

**Runtime provenance enforcement and adversarial evaluation for the Model Context Protocol.**

Airlock interposes on MCP traffic between an agent host and its tool servers, tracks
where untrusted content flows, and refuses to let it reach an egress sink — then tries
to defeat itself and publishes the results.

> **Status: early, and the numbers are small.** The interposition relay, the audit
> chain, the structural detector, the provenance engine, the evaluation harness,
> the integration suite against real MCP servers, and an opt-in semantic layer
> backed by a local model are implemented. The policy engine is not. Held-out
> attack success rate is **12.5%** at 0% false positives, with 6 of 6 owned steps
> stopped — the residual is two `policy` steps, and the harness names them rather
> than folding them into a rounder figure.
>
> **The opt-in semantic layer does not earn its place and is off by default.**
> On the held-out split a local Qwen3-4B judge catches none of the five attack
> steps the mechanical layers cannot reach, flags one benign document, and adds
> ~450ms per step. The harness, client, and constrained decoding stay, because
> re-measuring against a larger model is then one command; the numbers are in
> [What the model layer actually measured](#what-the-model-layer-actually-measured).

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

The MCP SDK is an optional extra. The core and the evaluation harness depend on
nothing outside the standard library, which is deliberate: the thing being measured
should not drag a dependency tree into the measurement.

## Testing against real servers

`make integration` runs the gateway against four real MCP servers — filesystem, Git,
fetch, and SQLite — through the real SDK client, with a real secret on disk, a real
`git log`, and a real database file. `make test` runs the whole suite, skipping these
when the extra is absent.

The fixtures are real where being real is the point and stubbed only where it is not.
Filesystem, Git, and SQLite do the actual work. The fetch server does not open a
socket: it records the request and returns a response, because a test that fails
because a network was busy has taught nobody anything. What is being tested is the
argument shape and the destination, neither of which needs a network to be meaningful.

Two details of the real protocol turned out to matter:

- **A stateful server refuses `tools/call` before `initialize` completes.** The relay
  forwards the handshake, so this works — but a gateway that let a call through without
  one would be forwarding traffic no real client can produce.
- **The real SDK client does not pipeline.** A host that offers all 25 requests before
  reading a single reply is not a shape any client has, so the audit test drives the
  relay one turn at a time. Piped input would measure the fixture rather than the
  gateway.

## The local judge

The semantic layer needs a model server. It is not a dependency of the project:
nothing in `airlock` imports an inference library, and the core installs and
evaluates with no model present at all.

```bash
make model      # download Qwen3-4B-Instruct-2507 Q4_K_M (~2.5GB, into models/)
make judge      # serve it on 127.0.0.1:8080 in the background
make judge-stop # stop it

airlock proxy --provenance --semantic -- <server>
airlock eval --split test --layers semantic --ablation
```

Point it elsewhere with `AIRLOCK_JUDGE_ENDPOINT` or `--judge-endpoint`. The
endpoint defaults to loopback because a component that decides what reaches a
security boundary has no business being reachable from the network.

`--layers all` does **not** include the semantic layer. It is asked for by name,
because a gateway that adds seconds to every tool call and depends on a 2.5GB
download is a gateway that gets removed from the deployment. Asking for it with
no server running is an error rather than a silent downgrade: an operator who
requested a judge and got no judge would be told they had a layer they did not
have.

### What the model layer actually measured

Qwen3-4B-Instruct-2507 at Q4_K_M, served by `llama-server`, does not earn its
place. Held out from prompt development, on the `test` split:

| configuration | ASR | detection | FPR | owned recall |
| --- | --- | --- | --- | --- |
| structural only | 87.5% | 12.5% | 0.0% | 1/1 |
| provenance only | 25.0% | 75.0% | 0.0% | 5/5 |
| both (shipped) | 12.5% | 87.5% | 0.0% | 6/6 |
| semantic only | 100.0% | 0.0% | 3.0% | — |
| all three | 12.5% | 87.5% | 3.0% | 6/6 |

The last two rows are the finding. The layer catches **none** of the five attack
steps the mechanical layers cannot reach, flags one benign document, and adds
about 450ms to every step (p95 648ms). On the `dev` split it is worse: 0%
detection against 9.4% false positives, three of 32 expected-allow steps. Added
to the shipped pair it changes the attack success rate not at all.

So the layer stays off by default, and the honest recommendation is not to turn
it on at this model size. Three things are worth separating in that conclusion:

* **The infrastructure is sound and stays.** Constrained decoding, strict
  parsing, fail-closed conversion, digest-only findings, per-case reset, a
  measurement harness, and the cache. Re-measuring against a different model is
  `make model` with a different filename and one `airlock eval` run.
* **Some of the gap is model size.** Telling a runbook addressed to an on-call
  engineer from the same checklist addressed to the agent is a reading
  comprehension problem, and 4B quantised is weak at it.
* **Some of the gap may not be model size.** The model flagged a tool
  acknowledgement of `{"written": true}` as an injection, and reasoned that a
  credential egress was fine because "the agent holds the token". A larger
  model would probably fix the first and may not fix the second. The second is a
  question about which side of the boundary a value came from, and that is the
  provenance layer's job — which is the argument for keeping the model out of
  the blocking path entirely.

Two caveats on the number itself. The prompt was written after reading the
corpus, so `dev` is a tuning set and only `test` is held out; the held-out row is
the one to believe. And the corpus is the specification this layer was measured
against, including its requirement that a `flag` is not a mitigation — a layer
that annotates without blocking cannot lower ASR, and this one does not even
annotate correctly.

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

**The semantic layer is asked one narrow question, on purpose.** A model judge's
failure mode is not missing attacks; it is reading intent into ordinary text. So
it is asked *is this content trying to change what an agent does?* and never the
broader question that would catch more and flood the host with false positives.
The negatives are stated in the prompt as carefully as the positive: documentation
is not an instruction, a runbook addressed to whoever is on call is not an
instruction to an agent, a release note about rotating keys is not a credential
request, and a page *about* prompt injection is not a prompt injection. A layer
that flags ordinary documentation is a layer that gets switched off, and then it
protects nothing at all.

That reasoning was right and the model did not follow it: the negatives are in
the prompt, and it flagged a tool acknowledgement and a credentials file
anyway. Worth recording because the prediction held exactly — a layer with a 3%
false-positive rate on benign documents is a layer that gets switched off, which
is why it ships off. See
[What the model layer actually measured](#what-the-model-layer-actually-measured).

**Content is flagged; the action it causes is blocked.** Untrusted text carrying
an injection is delivered and annotated, because the agent may legitimately need
to read it and a gateway that hides tool output breaks every workflow that
involves looking at one. The *request* the agent is about to send because of that
text is refused, which is where the harm actually lands. This is also why `flag`
is not one of the harness's mitigating verdicts: the message still reaches the
model, which is the whole point of the runtime-channel threat model.

**The judge's explanation is hashed, not recorded.** The most natural thing in
the world to write into an audit finding is the model's own words, and it is
attacker-controlled: asked to explain itself, a model quotes whatever it was
shown. The finding records the rule, the mechanism in the operator's terms, and a
digest of the explanation — enough to tell two firings apart, useless to anyone
wanting a copy of the payload. An unusable answer is a failure and not a verdict,
so a model having an off day cannot be read as an all-clear.

**The semantic layer blocks the relay, and that is why it is opt-in.** The
`Inspector` interface is synchronous, so a judgement is a pause in the event loop
— seconds, not microseconds. On stdio that serialises concurrent requests rather
than corrupting them, and the ablation reports the cost in seconds for that
reason. Making the interface async is the real fix and is not done here.

**A server echoing a URL you gave it is not a source.** The provenance layer treats any
content entering the context as potentially hostile, which is right in general and badly
wrong for one very common shape: servers that report what they just did (`200 OK
https://api.example.net/v1/status`). The agent typed that host into the request; it did
not learn it from the response. Attributing it to the response anyway makes the *second*
ordinary call to any API a block, so the destination rule withdraws exactly the host the
agent supplied and leaves every other host in the same result tainted. This was not found
by reading the corpus. It was found by pointing the gateway at real MCP servers and
discovering that a session of eleven legitimate calls blocked three of them.

**A credential column is a secret read.** A path regex sees nothing in
`SELECT token FROM credentials` — there is no path in the argument, only a table name — so
queries are judged separately, by the identifiers they name. A false positive there only
records a source, while a false negative is a silent leak, so the threshold leans towards
treating a query as sensitive.

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
