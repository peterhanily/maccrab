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

Additional self-contained regressions pin defects that earlier installed lanes
exposed, so a later candidate cannot reintroduce them unnoticed:
`EventJournalAdmissionContextTests` covers cross-module task-local bindings on
the older Swift concurrency runtime, including nested nil bindings, throwing
and cancellation unwinding, actor isolation and child inheritance;
`EventStoreMaintenanceCheckpointTests` pins the non-waiting maintenance
checkpoint, which defers reclamation on SQLite's actual contention result
rather than on WAL size; the legacy-upgrade suite migrates a predecessor
fixture, runs the scheduled maintenance sweep with its default arguments and
compares every inherited alert-evidence row; and the receipt tests cover a
changed device number after remount, replacement identity, malformed UUIDs and
conservative handling of version-1 receipts.

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

### Qualification lanes

Each signed candidate is qualified against a database family created by
the published predecessor, through the supported upgrade path. The lanes
below are all required; a candidate that fails any of them is recorded as
failed, its observations never qualify a later candidate, and any source
change requires a new signed candidate and a fresh run of every lane.

Predecessor upgrade at the default cap. A real upgrade from the published
predecessor over a preserved event store must reach a fresh healthy runtime
heartbeat in one native process, and its migration ledger must conserve every
source event. Repeated relaunches, an interrupted observation, or a restart
that eventually reaches readiness do not establish an uninterrupted upgrade.

Predecessor upgrade at a lowered cap. The same upgrade with a saved events
envelope small enough that migration needs the temporary allowance described
in the storage contract. The candidate must reach ordinary write readiness
under the original cap without deleting protected history or increasing the
saved limit, and the recorded ceiling must survive a restart unchanged.

Positive control. The lowered-cap fixture is also booted under the published
build known to refuse it, to prove that the fixture reproduces the refusal and
that the lane can fail. A lane that has never failed against a known-bad build
is not evidence.

Cohort and legacy-evidence conservation. A predeclared cohort of event records
and every inherited alert-evidence row are compared key by key and byte by
byte before and after upgrade, and again after the scheduled maintenance sweep
has run with its default arguments. Comparing only the rows the dashboard
displays does not establish preservation. Snapshots taken for comparison must
pass a fresh zero-loss health check in the same engine process; the snapshot
destination bounds its cache and spill thresholds so the copy itself does not
burst writes into a monitored directory and register as detection-input loss.

OS-reboot survival. A full OS reboot while a receipt is unfinished must keep
the engine ready, keep the migration ceiling unchanged after the volume
remounts, and complete the receipt without a new allowance. A process-only
restart does not cover this boundary, and the dashboard and menu bar must
report unready until monitoring actually starts.

Every lane also runs the installed runtime qualification against the same
candidate: a fixed-length reference capture in one native process with
unchanged CPU, memory and event-loss limits, followed by fresh health checks.
A completed capture is not a passing report; the limits decide.

Removing an appcast item pauses Sparkle offers only. Direct downloads and
Homebrew are separate distribution channels. A database migrated forward
must not be assumed compatible with an older app; follow the
[rollback runbook](ROLLBACK_RUNBOOK.md).
