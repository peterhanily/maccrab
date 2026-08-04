# AI Feature Quality and Product Direction

MacCrab protects AI-assisted work, but it must not become an unmeasured pile of
AI-labelled features. Deterministic evidence collection, attribution, policy,
and response remain useful with every model disabled. Model-backed behavior is
advisory unless a separately tested deterministic control authorizes the same
decision.

This document records the audit disposition and the quality bar for further AI
work. It is a roadmap, not a claim that every existing surface already meets the
bar.

## Product model

The AI protection surface has four layers:

1. **Identity and activity** — identify an AI application, its descendants,
   session, tools, MCP servers, filesystem activity, and egress.
2. **Deterministic controls** — credential, project-boundary, prompt-injection,
   tool-change, permission, and network policies with explicit evidence.
3. **Correlation and explanation** — join events into a reproducible evidence
   bundle and explain what happened without inventing facts.
4. **Evaluation and learning** — measure operator-confirmed yield and propose
   improvements through reviewable, reversible changes.

No higher layer may compensate for a missing lower layer. In particular, an LLM
summary cannot repair incomplete identity, dropped events, or unauthenticated
telemetry.

## Current audit disposition

| Capability | Useful core | Current gap | Disposition |
|---|---|---|---|
| AI tool registry, process/session tracking, and MCP attribution | Kernel-correlated identity for AI activity | Coverage and confidence need a versioned corpus; stale process/session state must be measurable | Keep; make this the common identity substrate |
| Credential Fence | Deterministic sensitive-path evidence | Path semantics have drifted across ES admission and graph classification; ownership is still partly basename-based | Keep; use one typed path catalog and signed-identity ownership |
| Project Boundary | Makes out-of-project writes visible | Dynamic project/session demand is not available early enough to bound every file callback; routine package-manager behavior creates noise | Keep; publish atomic session demand and learn only from operator verdicts |
| AI Network Sandbox | Describes agent-attributed egress | The current surface is monitor-oriented; strict enforcement is not a complete product contract | Label monitor-only until policy, exception, rollback, and on-host enforcement tests exist |
| File/prompt injection scanning | Deterministic marker and content checks | Cache invalidation, parser unification, synchronous file work, and duplicated marker logic weaken performance and consistency | Consolidate into one bounded Unicode/document pipeline |
| Prompt intent and package intent scoring | Adds prioritization context | Blast radius is narrow, asynchronous results can arrive after the decision, and heuristic versus model yield is not compared | Advisory; do not gate until evaluation proves incremental value |
| LLM alert investigation, batch triage, and summaries | Can reduce operator reading time | Existing latency/token/fallback counters are not tied to operator outcomes; evidence grounding needs one bundle contract | Keep optional; make every assertion cite deterministic evidence IDs |
| Rule generation | Potential authoring assistant | No production model path and generated output is not a safe installable-rule contract | Convert to a review/test/approve workbench; never auto-install |
| Alert clustering and stylometric attribution | Research signals | Model/LLM paths are orphaned or heuristic-only in important call paths, and calibration is not demonstrated | Experimental and off until held-out evaluation |
| Bayesian/statistical/baseline learners | Potential host-specific prioritization | Missing deduplication, decay/session boundaries, frozen evaluation, promotion criteria, versioning, and rollback | No autonomous promotion; rebuild around an evaluation registry |
| MCP behavioral baseline and config monitor | Detects tool/config change | Coverage misses some current client formats and baseline restoration/change approval is incomplete | Keep deterministic inventory; add manifest hashing and approval workflow |
| Agent traces / OTLP correlation | Cross-store session context | Producer/consumer lifecycle, authentication, replay resistance, and kernel-identity binding are incomplete | Treat self-reported spans as untrusted context until authenticated |
| HoneyPrompt / deception | High-signal tripwire potential | Configuration, deployment inventory, ownership, and cleanup are not one closed lifecycle | Keep opt-in until deployment-to-detection parity is proven |

## Required evaluation rail

Every model, prompt, heuristic, and learned detector registers a versioned
feature identity and publishes content-free operational metrics:

- invocation, success, timeout, cancellation, circuit-breaker, and fallback
  counts;
- latency distribution, input/output token counts, and estimated cost;
- model/provider/prompt version and deterministic evidence-bundle version;
- candidate decision, deterministic fallback decision, and whether they agree;
- operator verdict (`true_positive`, `false_positive`, `useful_context`,
  `not_useful`, or `unknown`) without storing prompt/event content in telemetry;
- cohort and held-out evaluation identifier, promotion state, and rollback
  version.

Conservation is explicit:

```text
invoked = succeeded + failed + timed_out + cancelled + in_flight
succeeded = model_used + deterministic_fallback_used
reviewed = true_positive + false_positive + useful_context + not_useful
```

A feature may be enabled by default only when its held-out result shows useful
incremental security or operator-time value over the deterministic baseline,
within a declared privacy/cost/latency budget. “The model returned an answer” is
not a quality result.

## Highest-value missing capabilities

These are ordered by foundations and operator value, not novelty.

1. **Content-free evaluation registry and operator verdict corpus.** This is the
   prerequisite for improving or retiring every current AI feature.
2. **Deterministic evidence bundle.** One cross-store, versioned bundle of event,
   process lineage, rule, graph, file, network, and policy facts; optional model
   summaries cite bundle item IDs and can be regenerated.
3. **AI permissions and egress view.** Show what each AI session could access,
   actually accessed, changed, executed, and contacted, including uncertainty
   and event gaps.
4. **MCP/tool manifest pinning and rug-pull approval.** Hash executable/config/
   manifest identities; require an explicit review when capabilities, command,
   publisher, or network destination changes.
5. **Unified Unicode prompt/document pipeline.** Normalize once, parse by file
   type, scan once, cache by content identity, and feed the same result to rules,
   injection evidence, UI, and evaluation.
6. **Authenticated agent telemetry.** Bind OTLP/agent spans to a local process
   identity and session with authentication, freshness, replay protection, and
   an explicit untrusted mode for third-party self-reporting.
7. **Human-approved detection workbench.** Generate a candidate rule, compile it,
   replay it against positive/negative corpora, show performance and diffs, then
   require approval and preserve rollback. No direct model-to-live-rule path.

## Sustainable feature lifecycle

Each AI feature moves through these states:

```text
research -> shadow -> operator-opt-in -> default-on -> retired
```

- **Research:** isolated corpus tests; no production invocation.
- **Shadow:** computes a candidate decision but cannot alert/block; comparison
  with deterministic behavior is recorded.
- **Operator opt-in:** clear privacy/cost disclosure, bounded resource use, and
  rollback.
- **Default-on:** held-out and installed-host gates pass, false-positive budget
  is met, fallbacks are deterministic, and all claims are evidence-grounded.
- **Retired:** insufficient yield, duplicate capability, unmaintained model, or
  repeated budget failure removes the runtime path and preserves only migration
  compatibility where needed.

Adding a new feature is not success. A smaller set of observable, well-evaluated
features that operators trust is the product goal.
