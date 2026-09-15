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
measurements of the actual statistics the validator enforces. Live qualification
now requires an accepted, candidate-source-bound public policy in
[`RELEASE_RESOURCE_BASELINE.json`](RELEASE_RESOURCE_BASELINE.json), plus its exact
private accepted reference evidence for installed recording and final verification.
The public policy excludes machine identifiers, paths, process IDs, timestamps and
raw samples. A source-only policy check does not qualify the installed host; the
private receipt must pass the complete unchanged capture and same-host checks.
The three candidate-derived write/GUI constants remain only for deterministic
offline fixtures.
See [the reference measurement procedure](RESOURCE_BASELINE.md).

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
  their individual order/count has evaluated them. Source tests check
  conservative admission and coalescing policies. The installed gate currently
  has no complete histogram of semantic admission or coalescing reasons.
- Detection continues in memory when optional persistence is unavailable. The
  product must say which history/evidence features degraded; it must not report
  the detector as wholly healthy.

Native ES collector health uses callback-boundary progress and the existing
coverage canary, independently of normalized event output. Intentional callback
filtering and quiet downstream event windows do not imply a failed poll. The
proof-age deadline is **935 seconds**: the existing maximum 900-second canary
interval, 20-second settle, and three 5-second store rechecks. A successful
callback establishes initial progress; the canary must still complete within
that deadline even while other callbacks continue. Failed, cancelled, unspawned,
unknown, and overdue probes remain visible until a new verified probe completes.
The existing canary verifies EXEC delivery and retained-store presence; it does
not independently verify every subscribed event family or both split client
queues. This deadline is not a total database-query execution guarantee. Existing native
initialization/subscription failures, ended streams, client-split degradation and
loss counters remain independently visible; an ended stream cannot be revived by
old callback or probe results. The correction schedules no additional probes.

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

Events maintenance targets include both the maximum supported base transaction
and its separate terminal-settlement headroom: two 32-MiB reserves, plus the
file lane's priority reserve. The no-DML startup reprobe proves those same terms
under SQLite's writer lock. This is capacity for one transaction at that instant;
it does not guarantee loss-free traffic between periodic maintenance samples.
Maintenance retains its separately bounded cap-plus-one-reserve recovery path.

The factory events/evidence envelope is 476 MiB: a 376-MiB event family and the
existing 100-MiB evidence tier. 376 is the smallest whole-MiB family preserving
the previous default's 274-MiB proactive allowance after the extra transaction
reserve and proportional priority reserve are included. It also preserves the
previous 272-MiB retention target. This arithmetic correction is not a measured
sustainable-throughput claim. The minimum event family is 112 MiB, retaining
32 MiB after both transaction reserves and the 16-MiB priority floor. Explicit
larger custom budgets remain authoritative; an unmet retention target stays
visible. The 15-minute forensic floor is unchanged.

Alert-capture live status permits ordinary queueing while the oldest outstanding
item is at most **90 seconds** old and the active operation is at most
**45 seconds** old. The active target allows the existing 30 s exact-snapshot
pressure-retry window, a final 5 s SQLite read busy wait, and two 5 s write busy
allowances for evidence and its terminal context. The oldest-item target allows
one preceding operation and the current one; a larger progressing queue can
still exceed the evidence-latency target. These are responsiveness targets,
not total SQL execution timeouts or changes to qualification/shutdown limits.
The fixed ring stores one monotonic enqueue instant per admitted item; its head
and the active item determine the oldest age in O(1). Missing, nonfinite,
negative, or inconsistent timing cannot certify outstanding work healthy.
Cancellation settles the live lane as reported shed while retaining its durable
pending context. Completion clears only the settled item's age, and lifetime
failure/shed counters and durable evidence gaps remain visible.

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
- Live dashboard status permits ordinary pending and in-flight batches only
  while their oldest original enqueue age is at most **10.25 seconds**. This
  responsiveness deadline is the 250 ms daemon coalescing window plus two
  existing 5 s SQLite busy-wait allowances: one preceding in-flight batch and
  then the current batch. It is not a total transaction execution guarantee;
  SQLite can wait independently at multiple statements. The producer retains
  at most two monotonic instants, one per pending/in-flight batch, and preserves
  the original age through handoff. New arrivals and completed older batches
  cannot reset the age of other outstanding work. Missing or invalid age with
  outstanding work fails visibly; an idle older producer remains compatible.
  Commit/failure settlement clears only that batch's age, while failed totals
  stay visible for the process epoch. This live status deadline does not relax
  qualification's existing zero-loss, conservation, recovery-wait, or final
  drain requirements.
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

### Retained lookup and diagnostic history

AI-network finding suppression remembers at most 5,000 unresolved destination IPs
for one hour using a monotonic clock. Repeated observations do not extend the
deadline. Capacity eviction permits a subsequent finding for that IP. Browser
extension family/version histories, reported background items, and MDM content
paths each retain 4,096 recent keys; a forgotten identity can be reported again.
Successful MDM inventory reads also remove paths that are no longer present.
Supply-chain prevention retains a 1,024-record audit tail and a separate
saturating lifetime blocked count.

Package metadata and attestation caches retain at most 128 entries and 8 MiB of
charged payload weight per analyzer. This charge is accounting based on response
and key bytes, not a measured process-memory bound. Monotonic TTL and least-recent
use determine eviction. Registry facts are cached independently of each caller's
prior-builder comparison. Each analyzer permits four active registry requests and
16 waiters per request; saturation returns unavailable enrichment. A request whose
last waiter cancels retains its active slot until the loader finishes, and its
late result cannot repopulate the cache. Installed resource measurements remain
required.

New MISP observations use feed provenance and the existing feed age/category
limits, including when the separate abuse.ch refresh is disabled. Operator Custom
records retain their independent pin when the same IOC appears in another feed.
Older caches may contain MISP observations already labeled Custom; their original
source cannot be recovered reliably. These ambiguous records stay preserved and
can exceed the feed caps or consume all feed capacity. Review of those legacy
pins remains necessary; this correction does not infer ownership or discard
operator-provided indicators.

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
| Fixed workload | The minute-5 burst must move and fully drain both ingress and event-persistence lanes with zero persistence shed and positive new persisted outcomes in each lane. The drain deadline is offset 780 seconds. A base-persistence lane may retain at most 512 newly admitted events in total across queued and in-flight work, with positive completions, only when the global contiguous terminal prefix has reached the preceding distinct heartbeat's admitted prefix. Both UInt64 watermarks must reconcile with the same actor's base ledger and remain monotonic across adjacent captures; poison and repairable journal gaps remain zero. This prefix covers both base lanes, not terminal overlays or upstream preparation. Each ingress lane has one serial FIFO consumer. It may retain at most 512 queued plus in-flight events, with at most one in flight and positive completions, only when completions cover the preceding distinct heartbeat's begun-offer count. The producer reserves offered and handoff counters together before yielding, so that count already bounds all previously yielded FIFO work; handoffs are not added a second time. Current handoffs must be zero: evictions and termination results must all have been published before accepting that proof. The required per-lane UInt64 handoff gauges cannot exceed begun offers, are independent of writer generations, and reconcile with the raw heartbeat. Before a yield settles, backlog estimates may include its reservation. Other flow-through boundaries retain their bounded non-growing-queue and zero-in-flight rule, except the graph age rule below. At t0, a required raw post-prewarm readiness anchor must prove the same earlier-work retirement for base persistence and ingress; current and anchor handoffs must be zero. Every other transient start queue remains empty except the separately age-bounded graph. The nearest heartbeats bracketing actual process execution must show at least 38,220 combined offered events and a mean of at least 1,274/s over independently measured workload duration. Bracketing counts include ambient traffic; leading/trailing slack and the heartbeat peak remain reported evidence. |
| Priority fidelity | Zero priority-lane, kernel, callback-copy, or upstream collector loss. |
| File fidelity | Zero unclassified queue loss. Semantic policy coverage is source-test-only, bound to the successful preinstall clean-CI receipt and a recomputed source rule-corpus digest. Installed semantic rejects/coalesces are not certified by this gate. |
| Correlation continuity | At least 900 seconds of sequence recovery coverage and zero checkpoint/journal shed. The source-bound phase-1 clean CI exercises restart, rule reload, expiry, and rule-hash mismatch semantics; the installed engine must also log a successful non-empty SIGHUP reload with no rejection/error and survive later samples. The runtime report does not claim a live restart it did not perform. |
| Event storage | No unreachable-budget fault and no prune/VACUUM/refill loop. Search-tier gaps, if any, reconcile exactly and are visible. The search index must be verified healthy at every sample: `search_index_degraded=false` and `search_index_reason=healthy`. Pending FTS repair remains visible as incomplete search evidence and cannot qualify a release. |
| TraceGraph | Hard-writable and foreground-mutation-accepting at every captured observation (the 99% sample-fraction floors permit no failed sample in the fixed 31-sample epoch), no mutation/ingest shed, no failed event/batch/row epoch delta, and no recovery oscillation. The bounded recovery-writer ledger must conserve at every sample; its high-watermark stays within the fixed limit, saturation is false and its cumulative counter remains zero throughout, completed and live waits never exceed five seconds, and the final waiter count/oldest wait are zero. Original oldest outstanding write age must be a finite nonnegative measurement at most 10.25 seconds at every sample, matching the existing 0.25-second coalescing plus two 5-second busy-wait responsiveness policy; an idle graph reports age zero. At anchored start and later drain boundaries, positive graph completions may coexist with at most 512 queued events and 1,024 pending rows only with zero event/batch/row in-flight work and original age plus heartbeat age at most 10.25 seconds. Without a valid earlier anchor, pending graph work cannot pass t0. These sampled checks do not certify continuous between-sample latency. Batch/row/observation/coalescing/physical-suppression accounting remains exact. The rule-neutral minute-5 burst must produce positive equal physical-suppressed event and row deltas. Proof-safe suppression is separate from loss and monotonic. |
| TraceStore | Agent Traces and the loopback receiver are enabled. `traces.db` is available, unblocked, below its writer-admission threshold and free-space floor, and not recovering at every sample. A fixed OTLP span must increase and fully drain the real TraceStore ingest ledger with zero shed. |
| Disk writes | Engine epoch-average writes and the maximum of every captured interval and sample-aligned span up to 60 seconds must remain within independently reviewed reference-host budgets; no macOS disk-writes diagnostic. Both baseline and candidate use these same statistics. Missing reference measurements fail release qualification. |
| CPU | Engine average at most 0.50 CPU core over the epoch. Background GUI nearest-rank p95 of `ps pcpu` snapshots, including the prescribed burst, must remain within its independently reviewed reference-host budget. Exactly one running candidate GUI must be present at every sample with unchanged PID, native process-start identity, executable path, candidate file hash and kernel-reported running CDHash. The running CDHash must identify an attested arm64 or x86_64 candidate slice; signed version/build identity is checked at the epoch boundaries using actual bounded inspection timestamps. Missing or ambiguous GUI presence fails; measured zero CPU from a verified present GUI is valid. |
| Memory | Engine physical footprint (phys_footprint) at most 450 MiB and growth from minute 5 to minute 15 at most 64 MiB. |
| Disk safety | Every SQLite family stays beneath its exact DB+WAL+SHM cap and preserves the configured free-space floor. |
| Rules | Sealed rules synchronize before readers, corpus parity holds, and ordinary launch produces no administrator-password flow. |
| AI quality | Both configured and unconfigured AI are valid declared configurations. Each prewarm and minute-5 harmless HIGH-alert trigger must create exactly one committed alert for its unique executable path. With AI configured, that same stable alert ID must acquire schema-valid investigation JSON and reconcile with conserving schema-2 telemetry: newly started operations, `accepted == started`, zero final rejection, zero unattributed requests, and no unfinished operation. With AI unconfigured, no investigation operation may be claimed and the causal committed alerts are still required. Configuration cannot change during the epoch. |
| Shipped tools | `maccrabctl version` and `maccrab-mcp --version` execute after signing and directly from the mounted DMG under normal SIP/AMFI policy. |
| Evidence | Candidate report binds source commit/tree, DMG SHA-256, signing/notarization, payload inventory, and the complete host measurements above. |

The persistence prefix and graph-age rules distinguish recently admitted work
from an older backlog even when ambient arrivals make a sampled queue grow.
Their bounds come from the existing qualification ceiling and product
coalescing/responsiveness policy. GA3's actual offset-780 failure remains
retained as FAILED: its heartbeat did not publish the required writer prefix,
so it cannot be retroactively qualified. A new candidate must publish that
evidence and complete fresh source, artifact and installed qualification.
GA5's later offset-780 failure also remains FAILED. Its evidence showed a
cleared earlier writer prefix and a new database batch, but it lacked the
new ingress handoff telemetry needed to settle the offer/loss publication
race. The corrected policy counts bounded current work while proving older
work completed; it does not excuse an old stalled prefix or an unpublished
loss result. A new candidate must emit these gauges and complete fresh
qualification. The existing 512-event bound, graph policy, workload, drain
deadlines, and accepted reference resource measurements and ceilings are
unchanged; no candidate-derived resource relaxation is part of this correction.

### Machine-readable evidence

The file-fidelity row declares `semantic_validation_scope: source-tests-only`.
Its `source_rule_corpus_sha256` binds the reviewed checkout's `Rules` tree and
is recomputed during verification. The preinstall clean-CI receipt covers the
source policy tests and corpus linting; running/sealed corpus identity is
checked separately by the Rules row. No runtime semantic-reason histogram is
produced or inferred. Legacy `complete_rule_corpus_evaluated` and
`semantic_reasons` attestations are rejected, including an empty reason list.

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
the live rule-reload probe at minute 13 (offset 780 seconds). The prewarm and
burst each execute a harmless `/dev/tcp` command-line token (they open no
network connection) from a
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
LLM health, then observes a post-proof producer heartbeat and a distinct later
readiness heartbeat within the single existing 300-second post-prewarm drain
budget, including actual t0. The required `start_readiness` evidence embeds the
exact raw earlier observation, its digest, and the causal prewarm proof. Both
the anchor capture and its producer heartbeat must follow that proof and
strictly precede t0, with capture and producer gaps at most 75 seconds. Native
engine/GUI identity, version/build, boot, uptime, cumulative ledgers and LLM
configuration must remain consistent. The recorder, full verifier and standalone
workload derivation independently normalize and validate this evidence. A Boolean
readiness claim or missing, stale, repeated, foreign-epoch or post-t0 anchor is
insufficient. Earlier writer admissions must be terminal, and pending base/ingress
work must satisfy the existing prefix/FIFO, progress and 512-event rules. Graph
work retains its original-age limit including heartbeat age. Terminal overlays
and other transient start queues remain empty: their later-epoch generic progress
rule does not prove an old blocked item completed. Actual t0 counters remain the
measurement baseline; this proves retirement at each sampled boundary, not that
every downstream event causally originating in prewarm is absent. The sequence journal's `queued` gauge is durable detection working state,
not transient writer work: it may remain nonzero while its conservation ledger,
exact pending-depth cross-check, continuity state, and zero shed/eviction gates
hold. All later samples require full LLM readiness when configured. An unconfigured
backend instead requires zero investigation operations throughout. Both modes
require at least 250 seconds of monotonic engine uptime before t0.

Readiness diagnostics preserve each distinct producer snapshot once in a private
record file, plus the latest observation when an attempt fails. The capture binds
those file digests and retains a completed causal prewarm proof even if drain
later fails. Repeated heartbeat reads are deduplicated; only small references
are rewritten, and the record count is bounded by the existing polling budgets.
These diagnostics and the start anchor are outside the unchanged 31-sample,
900-second resource/workload epoch. Later diagnostic captures cannot retroactively
qualify a failed attempt. A changed verifier schema requires fresh source-bound
evidence, with unchanged resource limits, workload volume and drain deadlines.

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
