# Corpus format

The corpus is the measuring instrument for this project, so its format is
specified before the detectors that consume it. Every case is a **labelled
transcript** with a per-step expected verdict, not a naked payload.

That choice is deliberate. A corpus of isolated attack strings measures pattern
matching. A corpus of transcripts measures *whether the gateway stopped the
harmful effect*, which is the only question that matters operationally. The
causality-laundering attack, for instance, contains no suspicious string at all
— it is only visible as a relationship between two steps. A string-matching
corpus could not represent it, and any score derived from one would be
meaningless for it.

## Layout

```
corpus/
  schema.md              this file
  attacks/
    <family>.jsonl       one case per line
  benign/
    <category>.jsonl     one non-attack case per line (false-positive corpus)
```

Records are newline-delimited JSON so the corpus diffs cleanly and streams
without loading everything into memory.

## Case record

```jsonc
{
  "id": "causality-laundering-001",   // globally unique, stable; never reused
  "family": "causality_laundering",   // attack family, or "benign"
  "variant": "denial-oracle-existence",
  "severity": "high",                 // impact if the gateway misses it
  "description": "one line, plain language",
  "source": {
    "citation": "arXiv:2604.04035",
    "claim": "flat taint tracking cannot see this because no sensitive value
              enters the tool-result channel"
  },
  "trace": [
    {
      "direction": "host->upstream",
      "message": { "jsonrpc": "2.0", "id": 1, "method": "...", "params": {} },
      "expect": { "verdict": "allow", "reason": "benign read" }
    }
  ]
}
```

### Field semantics

| Field | Meaning |
|---|---|
| `id` | Stable identifier. Results reference cases by id, so an id must never be repurposed for a different scenario. |
| `kind` | `attack` or `benign`. Stated, never inferred from the verdicts — deriving it from outcomes would let a mislabelled case quietly reclassify itself as a control. |
| `family` | Groups cases for per-family attack-success reporting. |
| `variant` | The specific technique within the family. A family with several variants is how we distinguish "caught the technique" from "caught the wording". |
| `severity` | Consequence if missed. Drives the weighted headline number; unweighted counts flatter a detector that catches only the easy cases. |
| `source.citation` | Where the technique is documented. Every attack case must cite a source; an invented attack measures only our own imagination. |
| `source.claim` | The concrete prior claim the case is designed to test. This is what makes a *negative* result reportable. |
| `trace[].direction` | `host->upstream` for a request, `upstream->host` for a result. |
| `trace[].message` | A raw JSON-RPC envelope. Untyped, exactly as it would cross the wire. |
| `trace[].expect.verdict` | `allow`, `flag`, `block`, or `modify`. |
| `trace[].expect.reason` | Why this verdict, in one sentence. |
| `trace[].expect.layer` | Which layer is accountable for this step: `structural`, `provenance`, `semantic`, `policy`, or `null` for benign steps. Present on every non-`allow` step. |

### Expected verdicts are the ground truth

`allow` — traffic that must pass untouched. Any `flag`, `block` or `modify` here
counts against the false-positive rate.

`flag` — detection is expected, but blocking would be wrong because the content
is not yet at a harmful sink. Recording this separately from `block` is what
lets the report distinguish *detection* quality from *policy* quality; a detector
that flags everything but blocks nothing scores well on one and badly on the
other, and collapsing the two would hide that.

`block` — the gateway must stop this message. This is reserved for steps where
harm actually occurs: a tainted value reaching an egress sink, or an instruction
arriving from a channel the agent has no reason to trust.

`modify` — sanitise in place and continue (e.g. strip invisible characters).
Counts as a successful mitigation, but reported separately because it changes
the payload the agent sees.

### Verdict and layer answer different questions

`verdict` is what a *complete* system should do with this step. `layer` is
which component of *this* system is accountable for it. Keeping them separate is
what makes a partial result legible instead of merely discouraging.

When a step the current build cannot possibly handle comes back `allow`:

* the step is scored as a **gap**, not a **mismatch** — the miss is real and
  counts fully toward attack success rate, but it is not filed as a regression
  in a layer that is working as specified;
* the layer responsible is named in the report's coverage-debt section, which
  is the list the next milestone is built from;
* the corresponding layer's own recall is unaffected, so a build cannot look
  good by being pointed at attacks it was never meant to catch.

The line that stays hard: a step attributed to a layer that *does* exist must
match its corpus verdict, and any non-`allow` result on a step labelled `allow`
is a false positive. Both fail the evaluation regardless of which layer is
under construction.

## Attack families

Each family exists because a published result claims an existing defense class
fails against it. That is the selection criterion — a family earns its place by
having a documented adversary, not by being easy to generate.

| Family | Source | Claim under test |
|---|---|---|
| `tool_poisoning` | OWASP MCP03; Invariant Labs | Malicious instructions in tool *descriptions* reach the model but not the user. The baseline every competitor claims to catch. |
| `causality_laundering` | arXiv:2604.04035 | Leak travels through *denial feedback*, not returned data. Structurally invisible to flat taint tracking. |
| `framing_sweep` | arXiv:2608.27092 | Robustness measured on overtly-worded injections overstates safety; reframing the same goal defeats surface filters. |
| `agent_data_injection` | SNU/UIUC/Largosoft, Jul 2026 | Corrupts *facts* rather than issuing instructions. Input guardrails measured at 0% effect. |
| `sharded_egress` | arXiv:2602.22450 | Splitting a secret across requests defeats per-request DLP thresholds. |
| `sleeper_channel` | arXiv:2605.13471 | Intake and effect decoupled across time; nothing is anomalous in either step alone. |
| `policy_generality` | arXiv:2608.27092 | A policy that names the goal does not generalise; one that enumerates the exfiltration surface does. |

## Benign corpus

Non-attack traffic. This half of the corpus is not optional: a gateway with
perfect attack recall and a 20% false-positive rate is undeployable, and the
false-positive rate is the number these tools habitually omit.

Benign cases must be *realistic* and must include the adversarial-but-legitimate
cases that a lazy detector would flag, so that the false-positive rate is a
measured cost rather than a claimed one:

* text legitimately containing the word "ignore", "system", "instruction"
* source code containing shell metacharacters, paths, URLs
* legitimate zero-width characters (copy-pasted from PDFs, CJK text with ZWJ
  emoji sequences)
* credentials-shaped strings that are documented examples, not live secrets
* multi-turn reads where the same file is fetched twice

## Versioning

The corpus is frozen by content hash, and every reported number records that
hash. Detectors are not tuned against the evaluation split: the corpus is split
into `dev` and `test` partitions, and any change made after seeing a `test`
result is disclosed in the report rather than quietly absorbed.
