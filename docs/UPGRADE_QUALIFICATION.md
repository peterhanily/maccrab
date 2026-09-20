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
   finalization. Verify the dashboard and menu bar stay unready until
   monitoring starts.
4. Run the existing installed runtime qualification against that same
   candidate. Retain failed attempts as failures; source changes require a
   new candidate and qualification.

Removing an appcast item pauses Sparkle offers only. Direct downloads and
Homebrew are separate distribution channels. A database migrated forward
must not be assumed compatible with an older app; follow the
[rollback runbook](ROLLBACK_RUNBOOK.md).
