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

### Disk write volume during heavy activity

MacCrab writes considerably more to disk than the raw size of the events it stores.

**Measured** (installed host, build 1.22.0): about **0.05–0.25 MB/s at ambient load**
(30–42 events/s), rising to **~35 MB/s during a heavy activity burst**. Per event
admitted, a base-insert commit writes ~24 WAL frames (~98 KB) while carrying only ~3
events, because 16 separate database structures are touched per transaction and roughly
43 KB of that is a fixed per-transaction cost that does not shrink with batch size.

**Why it happens.** Evidence is committed durably *before* analysis runs, so each event's
immutable record and its post-analysis enrichment are separate transactions. That
ordering is the guarantee that an alert can never be durable while the evidence behind it
is not.

**What it means for you.** On a normal workstation this is a few GB per day — well under
5% of the rated yearly write endurance of the SSD in a modern Mac. It is unchanged from
v1.21.x; this release does not make it worse.

**Reducing it** requires committing the base record and its enrichment in one
transaction, which means moving evidence admission to *after* analysis. That inverts the
durability guarantee above, so it is a major-version change.

**Owner:** engine · **Target:** v1.23/v2.0, gated on burst-time write attribution first
(the ambient measurement does not explain the burst figure, and ranking remediation off
the wrong term would waste the work).

### First launch after upgrading takes longer than usual

This release migrates the event database to a checksummed journal format and rebuilds its
index.

**Measured:** ~27s migration + ~84s index rebuild on a clean host (≈2 minutes). On a
large or previously-wedged database it can be longer.

**What it means for you.** On the first start after upgrading, the menubar icon may look
idle and detection is not yet running. It completes on its own and does not recur.

**Owner:** storage · **Target:** progress indication in the next release.

### Downgrading below v1.21.6 is not supported

v1.22.0 upgrades the on-disk databases and installs a deliberate write barrier so that an
older MacCrab cannot write to — and therefore cannot corrupt — a newer database.

**What it means for you.** Rolling back to **v1.21.5 or earlier** leaves the security
extension unable to start. Roll back to **v1.21.6**, which refuses the newer database
cleanly and keeps running, and only if v1.21.6 was installed before the upgrade.

**Owner:** storage · **Target:** v1.21.6 ships the graceful refusal; this entry is
removed once v1.21.5 is no longer a plausible rollback target.

---

## Not limits — fixed in v1.22.0

Recorded so they are not mistaken for accepted behaviour:

- **Terminal evidence could be shed silently under load.** An unoverridden 5-second
  internal default meant a slow database commit could drop the enrichment overlay on an
  event, invisibly to every operator-facing counter. The immutable record, detection and
  alerting were never affected. Fixed: the whole settlement now shares one documented
  30-second budget (which *lowers* the worst-case from 35s), and any residual shed is
  reported with its reason.
- **The dashboard re-verified the entire event journal on every refresh**, pinning a CPU
  core while open. Fixed: it reads the engine's published counters instead.
- **Buffered events could be lost on shutdown** when a drain left work behind and the
  flush timer had already been cancelled. Fixed.
