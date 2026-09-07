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
