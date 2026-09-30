# airlock

**Runtime provenance enforcement and adversarial evaluation for the Model Context Protocol.**

Airlock interposes on MCP traffic between an agent host and its tool servers, tracks
where untrusted content flows, and refuses to let it reach an egress sink — then tries
to defeat itself and publishes the results.

> **Status: early, and the numbers are small.** The interposition relay, the audit
> chain, the structural detector, the provenance engine, the policy layer, the
> evaluation harness, the integration suite against real MCP servers, and an
> opt-in semantic layer backed by a local model are implemented. Held-out attack
> success rate is **0.0%** at 0% false positives, with 8 of 8 owned steps
> stopped — read [the caveat on that number](#the-policy-file) before quoting it,
> because it depends on a policy file, and the policy file is written by a human
> and goes stale. Without one, the same split scores 12.5%, and the harness names
> the two steps it cannot serve rather than folding them into a rounder figure.
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
                     ├── policy layer           (where data may go; needs a policy file)
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

## The policy file

Airlock does not ship an allowlist, and the absence is deliberate. A built-in list
of destinations was chosen on someone else's machine, and it would be the list
that silently permits the exfiltration — the one nobody reads. So the policy layer
loads a file you write, and no file means no layer, which the report says out loud.

```jsonc
{
  "version": 1,
  "surfaces": {
    "http_post": {
      "url": {
        "allow": ["metrics.internal", ".collector.example.net"],
        "note": "why these, in words an operator will still recognise later"
      }
    },
    "send_email": {
      "to": { "anywhere": true, "note": "mail is store-and-forward; provenance judges the body" }
    }
  }
}
```

```bash
airlock proxy --provenance --policy my-workspace.json -- <server>
airlock eval --split test --policy examples/corpus-workspace-policy.json
make eval     # the corpus workspace, with its policy
```

`examples/corpus-workspace-policy.json` is the policy for the workspace the corpus
transcripts are set in, and it is what the numbers below were measured with.

**The unit of the rule is a `(tool, argument)` pair, not a tool.** A rule that names
a goal — "do not exfiltrate" — is re-argued for every destination an attacker picks,
so it never generalises. The corpus has the case: exfiltration to a domain on no
denylist. A rule that enumerates the exfiltration *surface* does generalise, and
the surface is where data actually moves. So `send_email` is not a trusted tool that
cannot be abused, and `http_post` is not an egress tool; each has fields, and the
policy constrains the fields.

**Which is also the only reason a trusted tool is not a safe one.** The corpus pairs
this with a case where the sink is allowlisted, the tool is trusted, and the attack
lands anyway, because the recipient field was never constrained. An engine that
guessed which arguments are destinations would have the same hole with a different
name; so the policy file names them, and a field it does not mention is a field
nobody decided anything about.

**What it does not do.** It does not decide whether a value is sensitive — that is
provenance, and duplicating it is how a policy file grows secret patterns that rot.
Payload fields (`body`, `description`, `subject`) are absent from the example file
for the same reason: the corpus's calendar step rides its description along to
attendees nobody invited, and constraining *who is invited* covers the field without
ever naming it. And it does not refuse external mail, because outbound mail is
mediated by the workspace's own MTA and the interesting question about a message is
its body.

**Reads are open, and that is a claim rather than an oversight.** `web_fetch.url` is
`anywhere: true` in the example file. The reasoning is that a fetch brings the
response *into* the transcript, where provenance judges it, and every delivery case
in the corpus does its damage on a later step. An allowlist could not separate the
two anyway: the attack transcripts fetch the same hosts the agent legitimately
reads — `docs.example.com` appears on both sides — so a list narrow enough to be
safe would break reading documentation.

It is still not free, and the file says so: material pasted into a query string is
sent *outbound* by that surface, and policy alone will not stop it. Only provenance
will, and only if it has seen the material. That is the kind of limitation that
belongs in the file rather than in a changelog, so it is in the note.

### What the policy file is worth, and what it costs

`structural + provenance` and `policy only` each leave one harm step on the held-out
split. Together they leave none, because they fail differently: provenance cannot
see a credential that never crossed the boundary as a value, and a destination
allowlist cannot tell a sharded exfiltration from a sharded upload.

| policy file | ASR | detection | FPR | what the harness names |
|---|---|---|---|---|
| `examples/corpus-workspace-policy.json` | **0.0%** | 100.0% | 0.0% | – |
| same file, `http_post.url` deleted | 12.5% | 87.5% | 0.0% | `framing_sweep-002` |
| only the mail rule | 12.5% | 87.5% | 0.0% | `framing_sweep-002` |
| no policy file configured | 12.5% | 87.5% | 0.0% | reported as coverage debt |

The second row is the honest cost of this layer, and it is worth more than the
first: forget one field and the exfiltration it covered succeeds silently in
production, while the corpus keeps saying 0.0% as long as the file is right. Every
layer in this project fails visibly; this one fails by going stale, which is why a
policy file carries a `note` per surface and why the harness names the case it
cannot serve.

**Three caveats on the 0.0%, since it is the number that would be quoted.** The
corpus is a closed world: sixteen cases in one workspace, so "every destination is
either allowlisted or an attack" happens to be true here and is false of any real
deployment. The allowlist was written by someone who had read the corpus, though it
contains only destinations the benign traffic uses. And the wildcard
`.collector.example.net` is a deliberate trade — it covers the sharded collector
without listing twenty-five hostnames, and it would also cover
`attacker.collector.example.net`.

### Keeping the file honest

A configuration file fails the way a program does not: deleting a line makes the
gateway quieter, and every other signal in the system still says the file is fine.
The evaluation catches the consequence on a split it happens to contain, which for
`http_post.url` is `framing_sweep-002` and a 12.5% ASR — but only as long as someone
runs it and reads the number. So the question is asked directly:

```
$ airlock policy-check --policy examples/corpus-workspace-policy.json
every destination field the traffic uses is decided by the file (2 of them
deliberately open; --all to read the notes)
26 case(s), 48 tool call(s) with a destination, 4 destination field(s) seen
```

Delete `http_post.url` from that file and it exits 1, names the field, and says how
many steps the corpus expects to be blocked through it. That is a CI step, and it is
the only check in the project that can fail on a change to a file rather than to
code.

Two things it deliberately will not do. It does not run a detector — the question is
about the file, so there is no model server, no state, and the same answer every
time. And it does not rank by whether an attack case touched a field, because every
delivery case in the corpus fetches a URL and is *supposed* to be allowed; it ranks
by whether a block was expected there, which is a question about the file. The scope
it cannot see is printed on every run: a field the engine does not recognise as a
destination is not counted, and a surface the corpus never exercises is not evidence
that it is covered.

It found one real gap in the example file it shipped with, on the first run:
`web_fetch.url`, which is now an explicit `anywhere` with the reasoning above.

### Asking the server instead of guessing

That last limit is not a caveat, it is a design flaw with one honest way out. The
checker reads its vocabulary of field names out of the corpus, so the corpus chose the
vocabulary — and a server free to call an argument `target` hands the policy layer a
field nobody looked at. A field nobody looked at is not a field that was found safe; it
is the same shape as the provenance bug where the verdict depended on the hash seed.

So there is a second command that goes and asks:

```
$ airlock discover --policy workspace.json -- npx -y @scope/server-fetch
sync_artifact 1.4.0 (protocol 2025-06-18)

  fetch_url
    Fetches a URL.
   ~ url: string

  sync_artifact
    Pushes an artifact somewhere.
     artifact: string
   ~ target: string
     options: object
   ~ options.url: string
     options.retries: integer

2 argument(s) this policy does not govern:
   ~ sync_artifact.target
   ~ sync_artifact.options.url
```

It runs the server, completes the handshake, follows the `tools/list` cursor to the
last page and reports what the server says it accepts. `target` is in
`RECIPIENT_ARGUMENTS` nowhere and in no enforced list — the corpus could not have found
it, and a policy written from the corpus cannot govern it. Exit code is `1` when a
conventional destination name is ungoverned, so it works as a CI step against a pinned
server.

Three things it deliberately will not claim. **A schema cannot say what a field
carries**: `target` may hold a webhook, a shard, or a colour, so `~` is a reading aid
and every argument is listed, not only the flagged ones, because a field with an
ordinary name can still point somewhere. **It is not enforcement**: the proxy stays a
pure relay, still decides only what the file says, and nothing discovered here can move
a verdict — this is an operator reading a surface before writing a policy. **It sees one
server**: a server that never answers `tools/list`, or that writes a banner to the
stdout wire, is reported as unseen rather than guessed at from tool names.

Being the parser of a server's JSON makes it the newest untrusted-input reader in the
project, so it was probed like one (`make probe-schema`). A schema nested a few
thousand levels deep killed it with a `RecursionError` traceback — a denial of service
from a single field, in the one command whose whole job is to describe a surface to a
human. The walk is now iterative and bounded, and every bound it applies is *reported*:
objects nested more than six deep, more than five hundred arguments on one tool, and
any tool entry that could not be read at all each produce a note, because the one
failure this command must not have is a report that quietly describes less than the
server does. A report that hides what it did not read is indistinguishable from a
report of a smaller server.

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

These two rows predate the policy layer and were measured with no policy file
configured, which is why their owned recall matches the shipped pair above them
rather than the 8/8 the full configuration now reaches.

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

# confirm the audit trail has not been altered; prints the chain head to compare
# against the log pipeline's own record count, because a clean tail deletion is
# indistinguishable from a log that ended on its own
airlock verify .airlock/audit.jsonl

# is the policy file still deciding what the traffic actually does?
airlock policy-check --policy examples/corpus-workspace-policy.json

# ask a server what it accepts, rather than inferring it from the corpus
airlock discover --policy workspace.json -- npx -y @scope/server-fetch
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

**A security decision may not depend on iteration order.** The provenance layer
resolved a destination by taking an arbitrary element of the set of hosts a string
mentioned. A URL is free to name a second host in its query, so
`https://attacker.example/collect?ref=api.internal` produced a two-element set and
the verdict followed whichever came first — and Python randomises string hashing
per process, so the *same* transcript blocked on some `PYTHONHASHSEED` values and
allowed on others. Three seeds out of twelve let the exfiltration through. No unit
test could have caught it: inside one process the order is fixed, so the test
passes, and the corpus never contained a destination naming two hosts.

It is the kind of bug that survives a green suite by construction, which is why the
regression test spawns subprocesses with fixed seeds rather than calling the code
twice — but one transcript is still only one transcript. So there is also a check
over *every* per-step decision the corpus produces: `scripts/fingerprint.py` prints
the expected verdict, the actual verdict, the outcome, the rule set and the order the
pipeline emitted those rules in, and `tests/test_determinism.py` requires six seeds to
produce byte-identical output. `airlock eval --json` cannot answer this, because it
reports aggregates and two different sets of per-step verdicts can average to the same
number — which is exactly what happened when the bug above was injected again during
this work: every case stayed `block`, and half of them quietly lost a rule.

Both halves of the fingerprint are load-bearing. An earlier version sorted the rule
names, on the reasoning that finding order cannot affect a verdict — the action is a
rank maximum over a tuple of inspectors, so it cannot — and adding
`sorted(verdict.findings, key=hash)` to the pipeline then passed the entire suite,
this check included. It now records the emission order too, because the audit log
writes findings down in that order. The same function also read only the first recipient of a list, so the same
address blocked as a string and allowed as a one-item list. Both were found by
asking what the function was *for* — "which place is this field addressed to" — and
noticing it was answering a different question, "which hosts does this text
mention". A destination field is parsed, now, and the two layers are pinned by a
test to name the same host for the same URL.

**A check on a file has to ask the file's question.** `policy-check` could have
reported which tools the corpus calls with an egress-shaped field, since that list is
easy to produce and would have looked more thorough. It asks instead which fields
*name a recipient*, because that is the set a policy file is expected to have an
opinion about, and it takes that set from the policy module beside the rules that
use it. An earlier version read provenance's narrower host-extracting list and was
blind to `attendees` — the one surface with no host to extract, and the one the layer
was built for. A check that cannot fail on the bug it was written for is worse than
no check, because it gets trusted.

**An unexamined field is not a field that was found safe.** Every list of destination
names in this project traces back to the corpus, which means the corpus chose the
vocabulary and a server free to call an argument `target` gets a field no rule ever
reads. The tempting fix is for the proxy to fetch `tools/list` at startup, and it was
rejected: the proxy is a pure relay, never speaks first, and the first thing it would
have to do is correlate a response of its own through the same attribution logic that
already has to distinguish a `tools/call` result from a `tools/list` result. Trading a
documented blind spot for a subtle one is not a trade. So `discover` is a separate
command, against a server the operator names, before the policy is written — which
also means the answer is worth having *then*. A schema still cannot say what a field
carries, so it reports every argument and marks only the conventional ones.

**A policy file is configuration, and configuration is not code.** The layer it
enables is deterministic, offline, and about as clever as an allowlist, but the list
itself is written by a person who knows the deployment — and the engine is built so
that the list is the only part that can be wrong. It cannot judge sensitivity, infer
destinations, or guess which arguments carry them, so a stale file produces misses
the harness names, never blocks nobody asked for. A layer that inferred those things
would cover more on paper and be wrong in ways no evaluation of a closed corpus
would surface.

**A destination allowlist does not decide, it enumerates.** The temptation is to
write the rule once and let the engine work out the rest: for a tool marked as
egress, block anything untainted. That rule is a goal, and goals do not generalise
past the destinations anyone thought of when it was written. The policy file's unit
is the `(tool, argument)` pair instead, so the question stays concrete enough to
answer — where does this field go — and a new sink has to be added to the file to
be covered. Enumerating is more work per tool and it is the only version whose
coverage you can read off the file.

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

**A hash chain cannot see its own tail.** Records are hash-chained, so editing a record,
deleting one from the middle, or reordering two of them invalidates every record after it.
Deleting records from the *end* does not, and this is the limit of the primitive rather
than a gap in the implementation: each record commits to the one before it, so the
survivors are exactly as consistent as they ever were and the leak has left no gap to
find. So `airlock verify` does not stop at a verdict — it prints the chain head, the one
number that a shorter log cannot fake, to be compared against a line count from the log
pipeline or a SIEM copy. A record that was half-written when the process died is the one
tail loss the log itself can see, and it is reported as `TRUNCATED` with exit code `2`,
separately from tampering, because the useful next step is different in each case. Payload
capture defaults to digest-only, because a security tool whose logs become a plaintext
archive of agent traffic is its own vulnerability.

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
| attack success rate | 0.0% | [0.0%, 0.0%] |
| weighted ASR | 0.0% | – |
| detection rate | 100.0% | [100.0%, 100.0%] |
| false positive rate | 0.0% | 0/33 expected-allow steps |
| control noise floor | 1 step | `benign-template-docs`, `template-token` |

16 cases, 47 steps, 8 expected-harm. p50 25.2µs / p95 71.5µs inspection cost per step.

**8 of 8 owned steps stopped, 0 false positives, nothing left as coverage debt.** The
two steps that used to be unserved are the ones a taint tracker cannot see: a
workspace signing key posted in a header, and a calendar invite to attendees the
transcript never introduced. Neither secret ever entered the transcript as a value,
so there was no taint to track. The policy file closes them, and the ablation below
is the honest version of that claim — each layer alone still leaves one harm step
standing.

The `dev` split scores 0.0% ASR at 0% false positives with an empty coverage-debt
list, and both splits PASS. The gap between the splits earlier in this project was
not overfitting — it was the corpus working. Four steps had claimed `provenance`
credit for secrets that never entered the transcript (`<vault value>`,
`<service account token>`), which taint tracking cannot catch by construction, and
24 drip steps demanded a block on a single character.

Ablation, same split:

| configuration | ASR | detection | FPR | owned recall |
|---|---|---|---|---|
| no detectors | 100.0% | 0.0% | 0.0% | – |
| structural only | 87.5% | 12.5% | 0.0% | 1/1 |
| provenance only | 25.0% | 75.0% | 0.0% | 5/5 |
| policy only | 12.5% | 87.5% | 0.0% | 2/2 |
| structural + provenance | 12.5% | 87.5% | 0.0% | 6/6 |
| **structural + provenance + policy** | **0.0%** | 100.0% | 0.0% | **8/8** |

Read the ablation rather than the headline. ASR stays high while any layer is missing,
so on its own it cannot tell a layer that helps from one that does nothing; owned
recall is the column that does that, and it is why the layers are constructed
separately rather than fused into one detector.

The two middle rows are the argument for shipping three layers rather than the best
one. Each offline layer on its own leaves a harm step standing, and they leave
*different* ones: `policy only` misses the sharded exfiltration because a
destination allowlist cannot tell a sharded upload from a sharded theft, and
`structural + provenance` misses the two steps whose credentials never appear in the
transcript at all. Neither is a better detector than the other. They fail on
different things, and a gateway only reaches 0.0% because both are present.

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
  inspect/     structural detector, policy layer, verdict combination
  provenance/  taint sources, egress sinks, destination trust
               (rollback on block, so one refused leak cannot poison a session)
  audit/       hash-chained log, chain verification
  discover.py  ask a live server what its tools accept
  eval/        corpus replay, metrics, report generation, policy-file check
scripts/       smoke check, per-step decision fingerprint, hostile-schema probe
corpus/        labelled transcripts + benign traffic
examples/      policy files, e.g. the corpus workspace's
tests/         unit + integration (real MCP servers)
```

## License

Apache-2.0.
