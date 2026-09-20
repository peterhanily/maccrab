# Event-store upgrade qualification

The v1.22.0 incident included a repeatable pre-ingestion refusal during a
Sparkle upgrade with a saved 300 MiB events envelope. The reported error was
`legacy bootstrap checkpoint does not fit the unchanged family cap`.
Increasing the setting to 600 MiB eventually produced a ready heartbeat.
The later `live cap=597 MiB` log described the configured allowance including
legacy evidence, not the minimum space the store needed. The available log
excerpt does not explain every intervening relaunch.

## Storage contract

The daemon opts into a fixed temporary allowance for an existing, unfinished
journal upgrade. Before schema changes, it records the database identity and
the greater of the configured family cap and:

`inherited family bytes + inherited sidecar bytes + 2 × transaction reserve`

The allowance covers migration and physical compaction. Restarting resumes
that same recorded ceiling; it does not grant another increment. Physical
free-space checks and transaction limits remain in force. Only an explicit
configuration increase can raise the allowance. Fresh stores, completed
upgrades, and read-only consumers receive no migration allowance.

Receipt version 2 binds the volume's persistent UUID, inode, and database birth
time. The recorded device number is diagnostic only: macOS can assign a
different number when the same volume is mounted after reboot. No-follow file,
ownership, link-count and same-call identity checks still guard the UUID lookup.
A completed version-1 receipt from an unpublished candidate retains ordinary
policy. An unfinished version-1 receipt lacks persistent volume identity and
fails closed without creating or increasing an allowance.

Before producers start, boot must reach the configured startup target,
restore the configured policy, and prove ordinary priority and file writes
admissible. Only then is the receipt marked complete. A cap that cannot hold
the protected retained data can still fail readiness; this mechanism does not
authorize deleting protected history or silently increasing the saved limit.

## Automated regression checks

The normal Swift test suite includes `EventStoreLegacyUpgradeTests`, which
constructs the shipped v1.21.5 schema without using a developer's databases.
Its lowered-cap case uses the production transaction reserve, retains exact
events and alert evidence, resumes after journal finalization, and requires
the daemon's real pre-producer recovery helper to reach write readiness under
the original cap. Additional cases cover interrupted migration, disk refusal,
durable progress, and the fixed allowance receipt.

Run the focused checks with:

```sh
SWT_EXPERIMENTAL_MAXIMUM_PARALLELIZATION_WIDTH=1 swift test --no-parallel \
  --filter 'EventStoreLegacyUpgradeTests|EventStoreLegacyUpgradeEnvelopeTests|EventStoreStartupRetryTests|UpgradeBootHeartbeatTests|V2ProtectionStatusTests|V2DaemonControlReloadTests|EventReadStartupTests'
```

A successful test run on an already-migrated store is not evidence for the
predecessor upgrade. Do not substitute an optional local measurement harness
for these self-contained regressions.

### Local verification, 2026-09-19

Verification covered 4,753 executed tests across split runs; 12 opt-in tests
were skipped. All seven predecessor-upgrade tests passed, including the
production-reserve lowered-cap case and interrupted migration at both caps.
The remaining suite exposed an outdated exact subprocess inventory after
removal of the reload signal fallbacks. After updating that inventory, a
rebuilt 33-test focused run passed, including storage-envelope, heartbeat,
reload, menu-health, and subprocess checks. No migration implementation
changed after the predecessor-upgrade suite passed.

The deterministic pre-release audit and localization format checks passed.
The new strings have explicit English fallbacks in non-English catalogs;
native translation and packaged visual review remain outstanding. These
results do not include the installed release qualification below.

### macOS 14 compatibility regression, 2026-09-20

Candidate `1.22.1.1150` failed a real Sparkle upgrade from the published
`1.21.5.1018` app on macOS 14.8.7. It migrated 63,604 events, then aborted
before producing a fresh healthy runtime heartbeat. Repeated relaunches did
not recover. Its signed artifact and failed observations are preserved and
must not qualify a later candidate.

The failing binary's return address identifies a cross-module asynchronous
`TaskLocal.withValue` binding of a Core-owned value. The older runtime pushes
its binding above the caller's temporary payload; the caller then frees that
payload out of task-stack order. An isolated two-module reproduction on the
same macOS 14 guest aborts with the original binding and passes with
non-inlined binding helpers in Core. The comparison also passes with the
production Swift 5 language mode and macOS 13 deployment target. That target
setting is not evidence of execution on macOS 13.

`EventJournalAdmissionContextTests` checks nested nil bindings, throwing and
cancellation unwinding, actor isolation, child inheritance, and shared lease
ownership. These tests and the isolated comparison do not replace an installed
upgrade and runtime qualification of the replacement signed candidate.

The focused source run passed 55 tests in seven suites, including all six new
scope tests and the existing alert-trigger, deferred-enrichment, pipeline
memory, and selected journal-receipt checks. The initial compile attempt was
invalidated by a concurrent formatting edit and is retained as a failed
attempt; the successful rerun used unchanged source.

### Reboot identity regression, 2026-09-20

Candidate 1.22.1.1151 reached readiness in one verified native process after a
real v1.21.5 Sparkle upgrade on macOS 14.8.7. Its migration ledger conserved
41,734 events. Comparison preserved the 14 predeclared fresh event records and
all 850 legacy evidence rows exactly; excluded ambient records were outside the
event-ID conservation claim. A later health check recorded 3,065 file-write
copy-backpressure drops. The fast snapshot is a possible contributor, but
neither per-process attribution nor a subsecond offered-rate peak was measured.
That failed health check remains failed; this is not a qualified release.

A subsequent normal OS reboot kept the engine ready with zero observed drops,
but changed the database's mount device number while its inode and birth time
remained unchanged. Version-1 receipts used that transient number as persistent
identity. A regression run against the old implementation changed only the
saved device number and proved that it discarded a pending allowance and
refused completion. Version-2 receipts use persistent volume identity instead.
Their tests cover unchanged fixed ceilings, completion, replacement identity,
malformed UUIDs, and conservative handling of old receipts. Candidate 1151 and
its failed reports are preserved; the source change requires a new candidate.

The replacement source passed 24 focused tests in four suites, including all
legacy migration, fixed-envelope, startup-retry and boot-heartbeat cases
(370.924 seconds). This includes the production-reserve lowered-cap fixture
and the device-change regression that failed against the prior implementation.
Installed qualification of the new signed artifact remains required.

### Runtime resource qualification, 2026-09-20

Candidate 1.22.1.1152 completed the 900-second reference-host capture in one
native process, but failed final CPU validation: 482.735 CPU-seconds over
900 seconds is 0.53637 cores, above the unchanged 0.50-core limit. The measured
workload met its required pressure and the sampled loss checks held. This is
a failed qualification; a completed capture is not a passing report.

A separate diagnostic repeat and exact-candidate symbolication identified
repeated credential-hint and sensitive-key searches as a performance lead.
The replacement uses fixed ASCII match tables and retains the previous
whole-string fallback for any non-ASCII input. A standalone optimized
comparison passed 687,248 differential checks across 171,812 synthetic strings,
including short-value boundaries, every hint, controls, case, and Unicode.
Microbenchmark savings do not establish installed CPU compliance. The source
change requires a new signed candidate and fresh installed qualification;
1152's failure and diagnostic profile remain preserved.

The replacement source passed 27 focused privacy and journal-admission tests
in six suites (21.702 seconds). This includes differential ASCII matching,
late-Unicode fallback, dynamic-map redaction and collision handling, existing
credential syntax, and canonical event preparation. Full clean CI and the
replacement candidate's installed checks remain separate requirements.

### Dashboard recovery and snapshot feedback, 2026-09-20

Candidate 1.22.1.1153 passed its 900-second reference-host runtime check,
including the unchanged CPU and event-loss limits. A real Sparkle upgrade
from published v1.21.5 on macOS 14 then reached native engine readiness in
58.069 seconds and displayed migration progress, but did not qualify.

The subsequent paced database snapshot failed its fresh health check with
7,264 file-write copy-backpressure drops. Those are real detection-input
losses. Later recovery does not erase the failed check. Conservation and
reboot checks were not completed for this attempt.

A controlled comparison then copied the same preserved offline snapshot in
the same engine process, with unchanged protection settings. The copy under
an existing forensic-output prefix added no drops; an identical copy into a
monitored directory added 8,066 write drops. Both copies produced identical
185,147,392-byte files. The guest's SQLite 3.43.2 reported a 20,000-page spill
threshold, and file growth showed roughly 78 MiB remaining buffered despite
the helper's 16-page steps and 25-millisecond pauses. SQLite requires both its
cache-size and spill thresholds to be exceeded before spilling dirty pages;
callback pacing alone does not bound the final write burst.
See [SQLite's cache-spill documentation](https://www.sqlite.org/pragma.html#pragma_cache_spill).

Setting only the new snapshot destination connection's cache and spill
thresholds to 32 pages produced the same bytes in a monitored directory with
zero new drops and 45,736 processed write events. The source, engine process,
saved configuration and exclusions stayed unchanged. Readbacks verified the
destination settings before and after backup. The initial 100-second control
timed out; separately declared 150-second diagnostics completed their copies
in 107–110 seconds. Future snapshots use that operation bound while retaining
the sealed cohort's independent expiry deadline and strict loss checks.
These diagnostics correct the measurement method; they do not qualify 1153
or establish lossless operation for arbitrary write bursts.

The dashboard also remained offline after the engine became ready. Bringing
the window forward and using Show Dashboard did not recover it; the normal
Reconnect button did, without an engine restart. A regression against the
unchanged source reproduced inactive-window startup recovery staying offline.
The correction retains pending recovery until a healthy provider opens and
allows recovery without a focus edge. Periodic workspace refreshes remain
foreground-only. This source change requires a new signed candidate and
fresh installed qualification.

The replacement source passed 42 focused tests in five suites, including five
new startup-recovery cases and the existing dashboard lifecycle, source-read
deferral and handoff checks. The inactive-ready regression failed against the
prior source before the correction. Full clean CI and installed qualification
of the replacement artifact remain separate requirements.

## Installed release qualification

These tests qualify source behavior, not Sparkle, signing, installation, or
the shipped system-extension process. Before publishing a successor:

1. Preserve a predecessor-created database family and configuration on a
   disposable test host. Include a lowered-cap store large enough to require
   temporary headroom and a default-cap control.
2. Install the exact signed candidate through the supported upgrade path.
   Keep the predecessor fixture untouched so each candidate starts with an
   actual migration rather than a no-op. Include macOS 14 runtime execution:
   compilation for an older deployment target and a run on a newer build Mac
   do not exercise the older Swift concurrency implementation.
3. Record artifact hash, predecessor/candidate versions, configuration,
   initial family size, migration conservation, time to ready, and final
   ordinary admission. Check restart both during migration and after schema
   finalization, including a full OS reboot with an unfinished receipt. Verify
   the persistent volume/database binding and unchanged ceiling after remount;
   a process-only restart does not cover this boundary. Verify the dashboard and
   menu bar stay unready until monitoring starts.
4. Run the existing installed runtime qualification against that same
   candidate. Retain failed attempts as failures; source changes require a
   new candidate and qualification.

Removing an appcast item pauses Sparkle offers only. Direct downloads and
Homebrew are separate distribution channels. A database migrated forward
must not be assumed compatible with an older app; follow the
[rollback runbook](ROLLBACK_RUNBOOK.md).
