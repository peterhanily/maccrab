# Known limits

Behaviour in the shipped build that is **measured, bounded, observable, and accepted** —
as distinct from a defect, which blocks a release.

A limit does not belong here because it is inconvenient to fix. It belongs here only if
all five hold:

1. It is a resource cost or performance property, not a correctness failure.
2. It is bounded, and **the bound is measured**, not estimated.
3. It is observable — by the user, or in a counter an operator can read.
4. It is not a regression against the previously shipped version.
5. It has a named owner and a target release.

Anything that fails one of those is a defect and blocks the release. In particular,
something that degrades detection, evidence, or protection **silently** is always a
defect, however small the rate — a limit nobody can see is a deferred bug wearing a
disguise.

**A limit is not accepted until it is written here, in user-facing language, with its
measured number, in the same commit that accepts it.**

---

## v1.22.6

Most of the items below are functional limits rather than resource costs. Each says what
it affects, its bound or reach, and how to see it.

### Events can be dropped during sustained extreme bursts

Under sustained extreme event bursts, such as large `npm` or Playwright installs while
other heavy work runs, the engine can drop events. The drops measured so far were file
activity.

Before detection, an event can be dropped at three main points, and each counts its drops
in the engine's heartbeat:

- **The kernel.** macOS drops Endpoint Security messages that MacCrab does not take in
  time (`es_kernel_dropped_by_type`).
- **The sensor hand-off.** Each Endpoint Security client hands its messages to a worker
  that holds at most 4,096. Once three-quarters of it is in use, ordinary file opens and
  other unreserved messages are shed. File writes can use most of the last quarter.
  Process starts, forks and exits, login-item additions and kernel-extension loads can
  use all of it, and so can credential and agent-content reads, up to 32 of 256 reserved
  slots per process (`es_copy_backpressure_dropped_by_type`; `maccrabctl status` shows
  the total).
- **The detection lanes.** Events then wait in one of two buffers of 100,000 events, and
  a full buffer drops its oldest event (`merged_file_dropped_total`,
  `merged_priority_dropped_total`). File creates, writes, closes, renames and deletes, and
  the file opens admitted for AI-tool monitoring, ride the file lane. Process, network,
  privacy-permission and unified-log events, login-item additions, and, within
  per-process budgets, persistence writes, execute-permission changes and credential and
  agent-content reads ride the priority lane.

The measured drops were in the file lane. The priority lane can drop too: unified-log
messages, such as those from the TCC, sudo and CoreServices subsystems, have no rate limit
of their own, so a flood of them can crowd out process events there. If the sensor falls
back to a single Endpoint Security client, file-permission changes share one admission
tier with ordinary file opens, and protected file reads share the file-write tier, so an
open flood or a write flood can shed them.

**Measured.** On a development Mac with non-default storage settings, and with optional
enrichments and local AI analysis switched on, about five minutes of concurrent `npm ci`,
builds, `playwright install` and end-to-end tests dropped about 200,000 file-lane events;
bursts of 40 seconds or less dropped none. That was a pre-release build with the same
event lanes, before this release's sequence-rule changes, which cut the per-event work in
such bursts. This release has not been measured under the same load.

**What it means for you.** While a burst outpaces the engine, detections that depend on
the dropped events can be missed. Nothing bounds the loss except the length of the
burst. It is not silent: every drop is counted, and a loss of 15% or more of events in
two of four 30-second intervals, or any loss during a spike in file activity, marks the
sensor as degraded in the app's System workspace and in `maccrabctl status` and raises a
Sensor Degraded alert.

**Owner:** engine · **Target:** not yet scheduled.

### Sequence rules at capacity

Sequence rules keep recent later-step events so that a chain whose first step is
processed late can still complete. That history holds at most 8,192 entries and 7.5 MiB,
shared by all sequence rules. When it is full, the engine first retires expired entries.
It then folds one process's repeated entries for the second step of an eligible rule into
that process's earliest entry, and only then discards the oldest entry of the rule
holding the most history. Discards are counted in `sequence_pending_steps_evicted_total`.
While they continue, `maccrabctl status` reports sequence-state continuity as degraded,
with the counts, and the app shows protection as degraded.

**Measured** in tests on the shipped stable rules: 10,000 writes from four processes are
folded in one pass, removing 8,182 entries with nothing discarded, and the late install
step still fires `supply_chain_full_kill_chain`. With the history already full, 1,000
writes from 1,000 different processes discard 1,000 entries, all from the flooding rule's
own history.

The bounds:

- **Folding keeps a process's earliest entry.** If an ancestor of that process runs
  (execs) the chain's first program after the process's first matching write, and the
  engine processes that program start only after the fold, the chain can be missed where
  a later, folded write would have completed it. npm and pnpm install scripts cannot
  produce this order, because the shell that starts their chain exists before anything
  it runs can write.
- **Folding is throttled.** After a fold that removes fewer than 256 entries, the engine
  does not try to fold that rule again until 256 more entries have been admitted, so up
  to 255 entries can be discarded that a fold would have kept. A burst from a few
  processes writing thousands of times folds thousands of entries at once and is not
  throttled.
- **The order of rules for one event can vary.** When one event matches several sequence
  rules while the history is full, the order in which the engine handles those rules can
  differ between engine runs. It can decide which rule's history is folded and, within the
  bound above, whether that event causes a discard.
- **History restored at startup is never folded.** If a nearly full history is restored
  when the engine starts, for example after an upgrade, and a burst follows while that
  history is still inside its rule's window, restored entries are discarded instead. This
  affects only the entries restored at that start.
- **Exact timestamp ties.** When two processes' entries have exactly the same timestamp,
  an alert may cite either one as evidence. Whether the rule fires does not change.

**Owner:** engine · **Target:** not yet scheduled.

### Sequence chains completed on a late middle step

When a chain's middle step is processed after a later step, the engine now replays the
kept later steps and can complete the chain then (`advance_replay_completions_total` in
the heartbeat). The bounds:

- **The first middle event processed wins.** When two events could fill a chain's middle
  step and the later one is processed first, it fills the step and is not replaced, so a
  last step timed between the two cannot complete the chain. This predates this release.
- **Windows run on processing time.** A rule's window is measured from when the engine
  processes each event, not from when it happened. When one detection lane runs L seconds
  behind the other, a chain whose steps ride different lanes can have up to L seconds more
  or less than the rule's window. This predates this release.
- **Discarded history cannot be replayed.** An entry discarded at capacity (see above)
  cannot complete a chain. The discard is counted.
- **Process ancestry learned late.** Replay decides process relations from the ancestry
  recorded when each event was processed. A relation that can be proved only from
  ancestry learned later is used only when a new first step replays the rule's whole
  history.
- **Upgrade.** Partial chains that stalled under an earlier version and are restored at
  the upgrade are not completed by this replay. This affects one rule window, once.
- **The alert is raised on the middle step.** A chain completed this way raises its alert
  on the middle step's event, so the alert's process and file, its deduplication and any
  response action configured for the rule use the middle step's process and file, not the
  last step's.

**Owner:** engine · **Target:** not yet scheduled.

### Detection › Rules and rule overrides

- **The rules list applies the rule profile to your own rules.** Under the default stable
  profile, Detection › Rules shows a rule you made with the wizard (status experimental),
  or an override without `status: stable`, as Disabled, and its toggle says the engine
  disabled it. The engine never applies the profile to user rules: it runs such a rule
  when its own `user_rules/<id>.json` has `"enabled": true`. Changing its severity keeps
  it running.
- **Some tools do not check overrides the way the engine does.** The engine ignores
  some user rule files, such as one its own account does not own, one in a folder others
  can write, or one whose content fails its checks, and runs the bundled rule with that
  id, if there is one.
  - Detection › Rules can show a rule as disabled, with Enable rule, when only an override
    the engine ignores disables it, although the engine runs the bundled rule. Enable then
    removes that override if it only disabled the bundled rule, and otherwise saves an
    enabled version of it, owned by the engine.
  - Requested rule changes can say "Saved configuration confirmed" for an override whose
    content the engine ignores.
  - A severity change, in the dashboard or with `maccrabctl rule severity`, builds on the
    existing override, so if the engine ignores that override's content, it ignores the
    new one too, and the change does not apply.
  - The engine's rule-install handler, which the dashboard, `maccrabctl` and MCP use,
    saves rule files without checking that the engine can load them or that the rule's id
    matches the file name. Only requests from root or the signed-in administrator reach
    it.
  - The YAML editor shows a rule's saved YAML even when the engine ignored its JSON, and
    the YAML viewer shows only the bundled rule's YAML, never your override.
  - MCP `explain_alert` can show a rule from `compiled_rules/auto_generated`, which holds
    generated rule candidates the engine does not load, when no rule the engine loads has
    the alert's id.
- **`maccrabctl rule enable` and `maccrabctl rule disable` do not last.** They edit the
  bundled rule's file in `compiled_rules`. After `maccrabctl rules reload` the engine
  applies the change, but at its next start it reinstalls the bundled rules from the app,
  and the change is lost. For a lasting change, use Disable rule or Enable rule in
  Detection › Rules, which saves an override in `user_rules`.
- **Re-enabling a rule can keep a severity from before an update.** When you disable a
  bundled rule, its override records the rule's severity at that time. If an update then
  changes that rule's default severity, Enable cannot tell the recorded severity from one
  you chose, so it re-enables the rule at the recorded severity. Choose Default in the
  rule's severity control to return to the current default.

**Owner:** app and CLI · **Target:** not yet scheduled.

### Other detection limits

- Browser and Electron apps under /Applications are recognised by their path, without a
  signature check, when routine noise is quieted. An administrator can write there.
- A reverse shell whose connection comes from a process other than the shell that
  started it, such as a forked subshell or a program the shell runs in a new process,
  does not complete the reverse-shell sequence rule.

**Owner:** engine · **Target:** not yet scheduled.

---

## v1.22.0

The properties below still require qualification against the final candidate.
Listing them here does not accept a release limit or replace a completed runtime
evidence record.

### Disk write volume during heavy activity

MacCrab writes considerably more to disk than the raw size of the events it stores.

**Development observations** (an earlier installed 1.22.0 candidate): about **0.05–0.25 MB/s at ambient load**
(30–42 events/s), rising to **~35 MB/s during a heavy activity burst**. Per event
admitted, a base-insert commit writes ~24 WAL frames (~98 KB) while carrying only ~3
events, because 16 separate database structures are touched per transaction and roughly
43 KB of that is a fixed per-transaction cost that does not shrink with batch size.

These observations are not a completed qualification record for the current source.
The final candidate must be measured using the same intervals and percentiles as the
resource gate, including a comparable run of the previously shipped version.

**Why it happens.** Each event has an immutable base record and a later enrichment
revision. Base admission reserves and queues the record before analysis; it is not a
durable commit at that point. Settlement joins the base write before storing the
revision. Small transactions and updates to multiple database structures can amplify
writes. Alerts retain their bounded trigger and expose whether journal verification
succeeded; an alert alone is not proof that all related journal evidence is durable.

**What it means for you.** Disk activity depends on workload, retained history and
maintenance. We do not yet have a qualified daily-write estimate, an SSD-endurance
claim, or a measured non-regression result for this candidate.

**Reducing it** requires measured work on transaction batching and storage costs while
preserving immutable evidence, bounded memory, and alert/evidence status. A major-version
change is not established as necessary by the current implementation.

**Owner:** engine · **Target:** final v1.22.0 resource qualification; separately measured
batching improvements afterward.

### Startup validates retained event history

The upgrade migrates legacy event history into a checksummed journal. On subsequent
engine starts, journal and search-index integrity validation still runs before event
producers start. This recurring work scales with retained history.

**What it means for you.** The app reports starting or unavailable until the engine
reports ready. Detection is not active during that phase. Earlier development captures
showed startup work taking approximately two minutes; that is neither a one-time cost
nor a qualified bound for every store. Final qualification must include cold starts with
representative retained history and explicit handling of insufficient storage space.
Schema work must fit the configured database-family cap and the volume's free-space
floor. The separate schema budget removes the fixed index-size refusal; it does not
make an over-cap or low-space legacy store self-recovering. When startup is refused,
normal post-start retention cannot run. A supported recovery procedure remains part
of upgrade qualification.

**Owner:** storage · **Target:** final v1.22.0 upgrade and cold-start qualification.

### There is no qualified downgrade target for this database format

v1.22.0 upgrades the on-disk databases and installs a deliberate barrier against
incompatible event-store writes by older MacCrab versions.

**What it means for you.** Do not open a v1.22.0 database with v1.21.5 or the unshipped
v1.21.6 hotfix prefix. Those older recovery paths can move the database aside and start
with empty history instead of refusing the incompatible format cleanly. The prefix is
not a supported rollback target. Preserve a consistent pre-upgrade backup before any
upgrade rehearsal; restoring older data requires a documented procedure with the engine
fully stopped. Reinstalling an older app alone does not restore the older database.

**Owner:** storage/release · **Target:** a qualified recovery procedure before v1.22.0
publication. No automatic downgrade is currently promised.

---

## Not limits — fixed in v1.22.0

Recorded so they are not mistaken for accepted behaviour:

- **Terminal evidence could be shed silently under load.** An unoverridden 5-second
  internal default could drop an event's enrichment overlay without advancing the
  storage-error counter. The base record has a separate admission/commit lifecycle;
  both boundaries must be accounted for. Fixed: settlement uses one shared 30-second
  deadline, including the preparation-memory wait, and reports residual shed with its
  reason. This makes the outcome observable; it does not accept terminal evidence
  loss as a release limit or establish a measured worst-case latency.
- **The dashboard re-verified the entire event journal on every refresh**, pinning a CPU
  core while open. Fixed: it reads the engine's published counters instead.
- **Buffered events could be lost on shutdown** when a drain left work behind and the
  flush timer had already been cancelled. Fixed.
