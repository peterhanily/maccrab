# Runtime Quality Contract

This document is a release policy, not a claim that the current candidate
passes it. A resource limit is part of detection correctness: a feature that
fills its queue, sheds evidence, or spends most of its time admission-blocked
is unavailable even when its process stays alive.

The reference qualification host and workload must be recorded with each
candidate. Thresholds may be revised before a candidate is built, with a
written rationale; they are never relaxed after a failed run merely to make
that candidate pass.

The inherited CPU/write/drain ceilings below are provisional regression
thresholds, not independently accepted workstation budgets. Earlier write and
GUI thresholds were changed using observations of the candidate series; a
passing result cannot validate that choice. Release acceptance still requires
a recorded workload, independently justified user-facing resource targets, and
measurements of the actual statistics the validator enforces.

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
  observations, attempted rows, proof-safe physical-write-suppressed events and
  rows, changed rows, transactions, physical-family growth, admission trips,
  and shed mutations. Physical suppression is not loss: at every sample,
  entity plus edge observations must equal attempted rows plus coalesced no-op
  rows plus physically suppressed rows plus pending rows. Both suppression
  counters are cumulative and monotonic.
- Retention recovery must leave enough headroom to avoid immediate re-blocking.
  Repeated delete/refill oscillation fails qualification even if the hard cap
  itself holds.
- Recovery is orthogonal to hard storage admission. Foreground graph writers
  wait behind only the current bounded SQLite quantum in a fixed actor-owned
  queue; recovery preempts before another quantum when writers are waiting.
  Every heartbeat must conserve `waits = current + releases + cancellations +
  closed`, keep the waiter high-watermark within the fixed 1,024-mutation
  production limit, and report
  saturation separately from `blocked`. A candidate must remain accepting for
  at least 99% of samples, enter the epoch with zero cumulative saturation and
  never saturate during it, drain all waiters at the final boundary, and keep
  both completed maximum and live oldest waits at or below five seconds.

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
| Process | One engine PID and boot identity for the epoch; monotonic engine uptime at least 250 seconds at t0 and consistent with captured heartbeat intervals. Every observation also binds the native process-start identity and running CDHash to an attested arm64 or x86_64 system-extension slice, with an unchanged executable path and candidate file hash. Signed version/build checks use actual bounded endpoint inspection times. No crash, watchdog exit, or relaunch. |
| Conservation | Offered equals completed + queued + in-flight + explicitly shed at every lane and persistence boundary. |
| Fixed workload | The minute-5 burst must move and fully drain both ingress and event-persistence lanes with zero persistence shed. The drain deadline is offset 780 seconds. At flow-through boundaries, a queue may remain at most 512, non-growing, with positive completions and zero in-flight work; transient queues must be empty at t0. Its measured peak must reach at least 1,274 combined offered events/s, the previously observed failure-state rate; a conserving idle collector does not pass. |
| Priority fidelity | Zero priority-lane, kernel, callback-copy, or upstream collector loss. |
| File fidelity | Zero unclassified queue loss. Semantic rejects/coalesces must be attributable to a tested reason that is conservative against the complete enabled rule corpus. |
| Correlation continuity | At least 900 seconds of sequence recovery coverage and zero checkpoint/journal shed. The source-bound phase-1 clean CI exercises restart, rule reload, expiry, and rule-hash mismatch semantics; the installed engine must also log a successful non-empty SIGHUP reload with no rejection/error and survive later samples. The runtime report does not claim a live restart it did not perform. |
| Event storage | No unreachable-budget fault and no prune/VACUUM/refill loop. Search-tier gaps, if any, reconcile exactly and are visible. |
| TraceGraph | Hard-writable and foreground-mutation-accepting at every captured observation (the 99% sample-fraction floors permit no failed sample in the fixed 31-sample epoch), no mutation/ingest shed, no failed event/batch/row epoch delta, and no recovery oscillation. The bounded recovery-writer ledger must conserve at every sample; its high-watermark stays within the fixed limit, saturation is false and its cumulative counter remains zero throughout, completed and live waits never exceed five seconds, and the final waiter count/oldest wait are zero. Batch/row/observation/coalescing/physical-suppression accounting remains exact. The rule-neutral minute-5 burst must produce positive equal physical-suppressed event and row deltas. Proof-safe suppression is separate from loss and monotonic; no unmeasured coalescing-bound assertion is accepted. |
| TraceStore | Agent Traces and the loopback receiver are enabled. `traces.db` is available, unblocked, below its writer-admission threshold and free-space floor, and not recovering at every sample. A fixed OTLP span must increase and fully drain the real TraceStore ingest ledger with zero shed. |
| Disk writes | Provisional engine average at most 8 MiB/s over the epoch; every captured interval and every sample-aligned span up to 60 seconds at most 48 MiB/s; no macOS disk-writes diagnostic. |
| CPU | Engine average at most 0.50 CPU core over the epoch. Provisional background GUI nearest-rank p95 of `ps pcpu` snapshots at most 20% of one core, including the prescribed burst. Exactly one running candidate GUI must be present at every sample with unchanged PID, native process-start identity, executable path, candidate file hash and kernel-reported running CDHash. The running CDHash must identify an attested arm64 or x86_64 candidate slice; signed version/build identity is checked at the epoch boundaries using actual bounded inspection timestamps. Missing or ambiguous GUI presence fails; measured zero CPU from a verified present GUI is valid. |
| Memory | Engine physical footprint (phys_footprint) at most 450 MiB and growth from minute 5 to minute 15 at most 64 MiB. |
| Disk safety | Every SQLite family stays beneath its exact DB+WAL+SHM cap and preserves the configured free-space floor. |
| Rules | Sealed rules synchronize before readers, corpus parity holds, and ordinary launch produces no administrator-password flow. |
| AI quality | Both configured and unconfigured AI are valid declared configurations. Each prewarm and minute-5 harmless HIGH-alert trigger must create exactly one committed alert for its unique executable path. With AI configured, that same stable alert ID must acquire schema-valid investigation JSON and reconcile with conserving schema-2 telemetry: newly started operations, `accepted == started`, zero final rejection, zero unattributed requests, and no unfinished operation. With AI unconfigured, no investigation operation may be claimed and the causal committed alerts are still required. Configuration cannot change during the epoch. |
| Shipped tools | `maccrabctl version` and `maccrab-mcp --version` execute after signing and directly from the mounted DMG under normal SIP/AMFI policy. |
| Evidence | Candidate report binds source commit/tree, DMG SHA-256, signing/notarization, payload inventory, and the complete host measurements above. |

### Machine-readable evidence

`scripts/candidate-qualification.py` is the executable form of this table. GUI CPU percentages are sampled `ps` observations, not interval CPU-counter deltas. Per-sample native running-image identity, file hashes and endpoint signing checks bind the GUI evidence to the candidate. This also distinguishes an older process still running after its app was replaced on disk. The checks do not attest which screen is visible or prove interaction, continuous between-sample presence, or sub-interval CPU/write peaks. The operator must also exercise the packaged dashboard as prescribed. Sample-aligned rolling write checks reuse the captured cumulative deltas; they are not arbitrary continuous sliding windows.
`release.sh` records the inspected candidate at
`.qualification-evidence/MacCrab-v<VERSION>.candidate.json` and creates the
intentionally failing template
`.qualification-evidence/MacCrab-v<VERSION>.runtime.json`. Do not edit that
template into a PASS. After installing the exact DMG, run the recorder printed
by `release.sh`:

```bash
sudo /usr/bin/python3 -I scripts/candidate-qualification.py record-runtime \
  --candidate-manifest .qualification-evidence/MacCrab-v<VERSION>.candidate.json \
  --dmg .build/MacCrab-v<VERSION>.dmg --source-root . \
  --output .qualification-evidence/MacCrab-v<VERSION>.runtime.json
```

Phase 1 captures the successful `scripts/ci-local.sh --clean` transcript before
the candidate is built. The candidate manifest binds its digest, terminal tail,
line count, timestamps, and source commit/tree. The installed-host recorder
validates and copies that receipt. It deliberately launches neither `swift build` nor
`swift test`, and does not run the process-heavy rule linter inside the daemon
process epoch it is about to qualify.

The command verifies the installed process identity, executes both shipped
tools from a read-only `/Volumes` mount, prewarms the exact alert-investigation
path, records 31 samples, runs the fixed bounded burst at minute 5, and sends
the live rule-reload probe at minute 7.5. The prewarm and burst each execute a
harmless `/dev/tcp` command-line token (they open no network connection) from a
per-run unique copy of `/bin/echo`, avoiding the one-hour rule/executable
deduplication window while triggering the stable high-severity reverse-shell
rule and its real installed alert-investigation path. The recorder opens the
installed `alerts.db` read-only and no-follow, binds that exact unique process
path and the trigger-time boundary as query parameters, requires exactly one
new causal row, retains its stable alert ID, and validates the investigation
JSON stored on that same row when AI is configured. With AI unconfigured, it
still requires the causal committed alert and rejects invented investigation
activity. A global telemetry increase without that row is
not proof.

The pressure files are created only beneath the unique
`/Users/Shared/MacCrabQualificationRuntime-<run-id>` tree. Before starting, the
recorder checks that representative paths do not match a fixed filename
predicate in any stable sequence's later-step corpus. A separate small,
non-networking shell probe exercises sequence journal admission and expiry;
bulk pressure and sequence continuity are distinct proofs. The workload must
exit by offset 390, every required boundary must satisfy its declared drain
contract by offset 780, and every
process in its dedicated process group is terminated and reaped on failure.
Both transitive workload executors and their SHA-256 values are part of the
workload binding. The recorder leaves a restart-safe
`.runtime.json.capture.json` while sampling, including the failing phase and
reason when it aborts. A passing report embeds each raw
rich heartbeat, heartbeat-file digest/ownership, Darwin process counters, and
complete SQLite-family observation; it then canonically hashes and normalizes
those observations. The verifier repeats that normalization, reconciles sample
timestamps to epoch start plus offset, recomputes CPU/write aggregates and p95,
and enforces every numerical limit above. Every sample carries cumulative engine
CPU and disk-write totals, engine physical footprint (phys_footprint), GUI background CPU, the complete
conservation-boundary snapshot, all five zero-loss counters, and LLM quality
state. Aggregate PASS fields must reconcile to those raw observations.

Before recording, enable Agent Traces/the loopback receiver and record whether
an alert-investigation LLM is configured. Initial readiness requires every storage family,
loss/conservation ledger, and circuit state to be sound, then drains pending
queues before prewarm. It permits the one expected never-used-backend state:
configured schema-2 telemetry with no prior successful request may still report
`healthy=false`. The recorder then runs the exact alert-only prewarm outside the
measured epoch. It requires the causal persisted row, accepted telemetry, full
LLM health, and a complete transient-work queue drain before setting
`start_wall` and capturing offset 0, so prewarm work is not counted as an epoch
delta. The sequence journal's `queued` gauge is durable detection working state,
not transient writer work: it may remain nonzero while its conservation ledger,
exact pending-depth cross-check, continuity state, and zero shed/eviction gates
hold. All later samples require full LLM readiness when configured. An unconfigured
backend instead requires zero investigation operations throughout. Both modes
require at least 250 seconds of monotonic engine uptime before t0.

The recorder fails before starting the 900-second timer when the running engine
has any cumulative loss/shed/eviction or failed-write counter, an unreachable
or sticky storage budget, a blocked alert family, a non-accepting or saturated
TraceGraph recovery-writer barrier, a non-writable TraceStore, an
open/failed configured LLM backend, an over-cap SQLite family, or a free-space-floor
violation. It also fails during the epoch as soon as one of those states
appears; it does not wait out the remaining samples. In particular, it never
derives shed from a balancing residual and never invents offered/completed
counters from queue depth. `sequence_checkpoint.conservation`,
`sequence_journal_conservation`, and
`traces_storage_admission.ingest_conservation` must come from their enabled
producers. A disabled or startup-blocked TraceStore does not publish a synthetic
zero ledger and cannot qualify. This is a release-readiness requirement, not an
operator field to fill by hand.

The runtime schema has an explicit completeness inventory. Conservation must contain
exactly these shipping boundaries: `priority-ingress`, `file-ingress`,
`priority-event-persistence`, `file-event-persistence`,
`sequence-checkpoint`, `sequence-journal`, `trace-graph-mutation`, and
`trace-store-ingest`. Disk safety must measure at least `events.db`,
`alerts.db`, `campaigns.db`, `tracegraph.db`, `traces.db`, and
`attribution_overrides.db`; any additional discovered SQLite family must also be
listed and measured with its exact configured cap (pass
`--sqlite-cap NAME=BYTES` only for a newly shipped family whose cap is not yet
published by the heartbeat). Adding a lane, persistence boundary, or database requires
a gate/schema update so omission cannot manufacture a pass.

### Clean process epoch versus erased state

The report embeds a versioned counter-scope policy. Loss and failed-outcome
counters are absolute across the current process and retained durable evidence
ledgers. Completed-wait maxima and saturation history cover the entire current
process, including startup and prewarm; maxima are never subtracted. Current
faults must be absent at every observation. CPU and disk rates use captured
epoch deltas and actual windows. These deliberately strict qualification rules
are distinct from product health, where a verified recovery can clear an active
fault while preserving lifetime error history. Warmup does not erase losses.

Cumulative process counters make a previously contaminated daemon epoch
ineligible. Preserve the failed capture, heartbeat, status output, and relevant
logs first; then gracefully deactivate and reactivate Protection (or install
and activate the exact candidate) and confirm that both the engine PID and boot identity changed. The recorder
binds the process start identity and monotonic age in every observation; PID
reuse alone cannot satisfy this contract.
Wait for startup storage recovery to finish and run the recorder again with
the shipping configuration and existing databases. This obtains a fresh
process epoch without concealing whether the repaired candidate can recover
real retained state.

Do not delete SQLite files, run `make clear-data`, raise a configured cap,
disable a configured LLM or TraceStore, or use `--sqlite-cap` for a shipping family to turn
a failed run green. `make clear-data` is especially unsafe while the installed
system extension owns open databases. A wiped-data run is a separate
clean-install test lane and cannot rescue publication after the retained-state
lane fails. Historical process-lifetime counters that disappear after the one
documented restart are an operational reset; a blocked/over-budget store,
backend failure, or any loss that persists or recurs under the candidate is a
candidate defect and requires a new candidate.

After the first `release.sh` phase has preserved a candidate,
`VERSION=<VERSION> make test-corpus` invokes the containment recorder. The
recorder itself verifies the full candidate, requires the clean exact source
checkout both before and after its tests, builds the corpus binaries in a fresh
private SwiftPM scratch path under a fixed sanitized environment, and mounts
the bound DMG read-only. The mounted
candidate's signed `maccrabctl` then signs and tests three deny-default bundles:
the exact shipped example and the source-built C and Swift adversarial probes.
This executes the candidate-statically-linked runner/broker and its exact signed
sibling trampoline. The report binds each executed candidate binary's payload
hash, Developer ID, Team ID, signing identifier and CDHash, plus the complete
build/control/sign/run transcripts. While a throwaway file sentinel and fixed
loopback listener are live, the same freshly built C and Swift probe bytes must
first run unsandboxed and produce their complete positive `leak.*` deny-control
sets; reachability is checked both before and after the candidate runs. PASS
then requires the sandboxed third-party lane, exit zero, terminal `ok`, exactly
one expected artifact, and zero `leak.*` artifacts for every candidate run. It
derives its own timestamps;
there is no standalone success-attestation or caller-supplied timestamp path.
The publisher independently recomputes the complete Tier-B source digest.
Both reports bind the candidate manifest, source commit/tree, exact DMG SHA-256
and payload inventory. `release.sh` validates them once before clean CI and
again at the irreversible publication boundary, then continuously rehashes all
three evidence files and the DMG. It never rebuilds a qualified candidate.

The first repaired host run may make a threshold look unrealistic. That is a
design review signal: measure where the cost comes from, change the feature or
the pre-declared contract, and build a new candidate. Do not reinterpret a
failed metric after seeing the result.

## Verification cadence

Use source review and deterministic fixtures while developing. At source
freeze, run one complete serial Swift suite under a deadline and one clean
local-CI gate; a filtered pass is not a suite verdict. Then build one
universal signed/notarized candidate and run the installed-host gate above.
Repeat the expensive full gates only for a reproduced flake, a concurrency-risk
change, or a new source tree. This keeps assurance high without using repeated
full builds as a substitute for targeted reasoning.
