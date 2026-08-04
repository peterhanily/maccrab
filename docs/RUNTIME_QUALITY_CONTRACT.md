# Runtime Quality Contract

This document is a release policy, not a claim that the current candidate
passes it. A resource limit is part of detection correctness: a feature that
fills its queue, sheds evidence, or spends most of its time admission-blocked
is unavailable even when its process stays alive.

The reference qualification host and workload must be recorded with each
candidate. Thresholds may be revised before a candidate is built, with a
written rationale; they are never relaxed after a failed run merely to make
that candidate pass.

## Feature contract

Every runtime feature must identify all of the following before it is enabled
by default:

| Field | Required answer |
|---|---|
| Security outcome | What attack or operator decision does the feature improve? |
| Inputs | Which events, stores, permissions, and trust boundaries does it consume? |
| Output | What durable evidence, alert, or UI state does it produce? |
| Failure mode | What happens on overload, corruption, timeout, or unavailable dependencies? |
| Resource budget | Maximum queue, memory, persistent bytes, write rate, CPU time, and latency. |
| Conservation | Which counters prove every accepted item became completed, queued, or explicitly shed? |
| Quality measure | Detection recall/precision, operator TP/FP outcome, or another outcome metric. |
| Degraded state | How the heartbeat, CLI, MCP, and dashboard tell the same truthful story. |
| Verification | Focused failure tests plus the installed-host probe that exercises the shipped form. |
| Owner and removal rule | Who maintains it and when insufficient value causes it to be disabled or removed. |

Features without a complete contract remain experimental and off by default.

## Data-plane architecture

### Ingress and detection

- The Endpoint Security callback performs bounded copying and a conservative,
  generated rule-interest check. It may discard only events proven irrelevant
  to every enabled built-in, single-event, sequence, and graph rule. Unknown
  rule shapes fail open into detection.
- Priority security events and rule-relevant file events have independent,
  bounded lanes. Queue overflow is a last-resort fault, not an ordinary form of
  file-event sampling.
- Repeated low-value observations are coalesced only after any rule that needs
  their individual order/count has evaluated them. Every semantic admission or
  coalescing reason has fixed-cardinality source, class, and reason counters.
- Detection continues in memory when optional persistence is unavailable. The
  product must say which history/evidence features degraded; it must not report
  the detector as wholly healthy.

### Persistence

Raw events serve three different products and therefore require separate
budgets:

1. A compact correlation-recovery tier preserves either a bounded, rule-hash-
   bound checkpoint of live sequence state or at least the previous 15 minutes
   of sequence-relevant events for chronological rehydration. It has no FTS
   index or copied alert evidence and cannot be evicted by hunt or UI-search
   traffic. Merely retaining events does not count as recovery: restart and
   rule-reload tests must prove that partial state is actually restored.
2. Interactive event history is a bounded forensic/search tier. It may use
   semantic coalescing or sampling under pressure, but exposes exact gaps and
   never claims that a sample is a complete event history.
3. Alert evidence is owned and capped with alerts. It cannot make the event
   journal's configured budget mathematically unreachable.

Hot retention should rotate or delete bounded shards/pages. A periodic
prune/full-VACUUM/refill cycle is not an acceptable steady state. Configuration
loading rejects or safely clamps any combination whose fixed schema/index
floor, evidence budget, transaction reserve, and required journal window
cannot fit beneath its cap.

### TraceGraph

TraceGraph is a bounded derived index, not a second raw-event archive.

- A generated graph-interest policy admits process lifecycle, security-relevant
  file classes, relevant network/TCC events, AI-attributed activity, and every
  event shape required by graph rules. Ordinary unrelated file churn does not
  create graph mutations.
- Identical entity/edge observations are coalesced by stable identity. Changed
  security attributes and anchor-producing events flush synchronously; normal
  last-seen/count deltas flush in bounded batches.
- Telemetry distinguishes events considered, irrelevant events, coalesced
  observations, attempted rows, changed rows, transactions, physical-family
  growth, admission trips, and shed mutations.
- Retention recovery must leave enough headroom to avoid immediate re-blocking.
  Repeated delete/refill oscillation fails qualification even if the hard cap
  itself holds.

### AI features

Deterministic evidence and authorization always exist without an LLM. An LLM
may summarize or rank that evidence, but cannot become the sole source of a
block, trust decision, or factual attribution.

Each AI feature needs versioned prompts/models, content-free latency/token/cost
and fallback telemetry, an operator-reviewed TP/FP corpus, held-out evaluation,
rollback, and evidence provenance. Learned rules require a review/test/approve
workbench; they never auto-install. Features that cannot demonstrate security
yield relative to their privacy, cost, latency, and false-positive burden stay
off by default. The inventory, evaluation rail, and prioritized capability
roadmap live in [`AI_FEATURE_QUALITY.md`](AI_FEATURE_QUALITY.md).

## Next-candidate installed-host gate

The next release candidate must pass one uninterrupted 900-second epoch on the
reference Mac using the recorded normal-plus-burst workload:

| Surface | Blocking requirement |
|---|---|
| Process | One engine PID for the epoch; no crash, watchdog exit, or relaunch. |
| Conservation | Offered equals completed + queued + in-flight + explicitly shed at every lane and persistence boundary. |
| Priority fidelity | Zero priority-lane, kernel, callback-copy, or upstream collector loss. |
| File fidelity | Zero unclassified queue loss. Semantic rejects/coalesces must be attributable to a tested reason that is conservative against the complete enabled rule corpus. |
| Correlation continuity | At least 900 seconds of sequence recovery coverage, zero checkpoint/journal shed, and a restart + rule-reload probe that proves eligible partials survive while expired or rule-hash-mismatched state does not. |
| Event storage | No unreachable-budget fault and no prune/VACUUM/refill loop. Search-tier gaps, if any, reconcile exactly and are visible. |
| TraceGraph | At least 99% writable duty, no mutation shed in the reference workload, no recovery oscillation, and bounded coalescing telemetry. |
| Disk writes | Engine average at most 1 MiB/s over the epoch and no 60-second interval above 4 MiB/s; no macOS disk-writes diagnostic. |
| CPU | Engine average at most 0.50 CPU core over the epoch. Background GUI p95 at most 10% of one core. |
| Memory | Engine RSS at most 450 MiB and growth from minute 5 to minute 15 at most 64 MiB. |
| Disk safety | Every SQLite family stays beneath its exact DB+WAL+SHM cap and preserves the configured free-space floor. |
| Rules | Sealed rules synchronize before readers, corpus parity holds, and ordinary launch produces no administrator-password flow. |
| Shipped tools | `maccrabctl version` and `maccrab-mcp --version` execute after signing and directly from the mounted DMG under normal SIP/AMFI policy. |
| Evidence | Candidate report binds source commit/tree, DMG SHA-256, signing/notarization, payload inventory, and the complete host measurements above. |

The first repaired host run may make a threshold look unrealistic. That is a
design review signal: measure where the cost comes from, change the feature or
the pre-declared contract, and build a new candidate. Do not reinterpret a
failed metric after seeing the result.

## Verification cadence

Use focused suites and deterministic fixtures while developing. At source
freeze, run one complete Swift suite and one clean local-CI gate. Then build one
universal signed/notarized candidate and run the installed-host gate above.
Repeat the expensive full gates only for a reproduced flake, a concurrency-risk
change, or a new source tree. This keeps assurance high without using repeated
full builds as a substitute for targeted reasoning.
