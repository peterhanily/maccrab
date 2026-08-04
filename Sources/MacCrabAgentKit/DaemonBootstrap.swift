// DaemonBootstrap.swift
//
// Shared entry-point logic invoked from both the SPM `maccrabd`
// executable (Sources/maccrabd/main.swift) and the Xcode
// `MacCrabAgent` system extension (Sources/MacCrabAgent/main.swift).
//
// Extracted so the two deployment shapes (standalone LaunchDaemon
// fallback and proper ES SystemExtension) share an identical
// initialization sequence and only differ at the outermost entry
// point. The sysext version additionally sets up XPC in Phase 3;
// the LaunchDaemon version handles the `--background` re-spawn flag.

import Foundation
import MacCrabCore

/// Opaque handle returned by `DaemonBootstrap.prepare`. Callers hold
/// it for the lifetime of the daemon so ARC doesn't reclaim the
/// dispatch-based signal and timer sources, and so the supervisor stays
/// live for SIGTERM-triggered graceful shutdown. Fields are internal on
/// purpose — outside callers don't reach inside.
public struct DaemonHandles {
    let state: DaemonState
    let signalHandles: SignalHandlers.Handles
    let timerHandles: DaemonTimers.Handles
    let supervisor: MonitorSupervisor
}

public enum DaemonBootstrap {

    /// Run the full daemon boot sequence (component wiring + monitor
    /// tasks + timers) and return handles the caller should keep alive.
    ///
    /// - Parameter printBanner: when `true`, emit the ASCII startup
    ///   banner to stdout. The LaunchDaemon entry point prints it; the
    ///   system-extension entry point suppresses it since sysextd
    ///   captures the process stdout into log archives where the banner
    ///   is noise rather than signal.
    public static func prepare(printBanner: Bool = true) async -> DaemonHandles {
        logger.info("MacCrab daemon initialising")

        let state = await DaemonSetup.initialize()

        // Start the bounded recovery lane before any monitor/event consumer can
        // mutate sequence state. DaemonSetup has already loaded the complete
        // sequence corpus and attempted its fingerprint-bound restore.
        await state.sequenceCheckpointCoordinator.startPeriodicCheckpointing(
            engine: state.sequenceEngine
        )

        // Clear any stale cumulative storage-error total left by an older build:
        // rewrite storage_errors.json from the (empty-on-boot) rolling 24h window
        // so a long-past burst (field-observed ~1M, stale for weeks) stops showing
        // in the dashboard + diagnostics. Best-effort; no-op for the non-root dev
        // daemon (can't write the root-owned release path).
        await StorageErrorTracker.shared.refreshSnapshot()

        if printBanner {
            await StartupBanner.print(state: state)
        }

        // Shared supervisor for every background monitor task. Created
        // before signal handlers so SIGTERM can call shutdown() against
        // it. MonitorTasks registers its 12 named tasks under this
        // supervisor; DaemonTimers' dispatch-based timers are retained
        // separately via timerHandles.
        let supervisor = MonitorSupervisor()

        await MonitorTasks.start(state: state, supervisor: supervisor)

        // Primary stream producers start deterministically—never through an
        // outer fire-and-forget Task that can resurrect after shutdown. Their
        // internal workers are stopped by the central finalizer before driver
        // and consumer joins are declared clean.
        await state.networkCollector.start()
        await state.tccMonitor.start()
        logger.info("Network and TCC primary collectors active")

        let startTime = Date()
        let timerHandles = DaemonTimers.start(
            state: state,
            eventCount: { UInt64(_sharedEventCount.get()) },
            alertCount: { UInt64(_sharedAlertCount.get()) },
            startTime: startTime
        )
        let signalHandles = SignalHandlers.install(
            state: state,
            supervisor: supervisor,
            timerLifecycle: timerHandles.lifecycle,
            livenessLifecycle: timerHandles.livenessLifecycle
        )

        return DaemonHandles(
            state: state,
            signalHandles: signalHandles,
            timerHandles: timerHandles,
            supervisor: supervisor
        )
    }

    /// Run the main event-processing loop. Blocks until the event
    /// stream ends (typically SIGTERM / sysextd teardown). The event
    /// count globals below are read by the periodic timers to report
    /// throughput without requiring a tighter coupling.
    public static func runEventLoop(handles: DaemonHandles) async {
        // v1.21.4 (F2/A1): start the batched events.db writer's partial-flush
        // timer so below-threshold batches still reach disk on a bounded cadence.
        await handles.state.eventWriter.startFlushLoop()
        // v1.21.4 (F2/A2): two consumers, one per split stream. The file
        // consumer drains the high-volume file-write family; the priority
        // consumer drains everything else (exec/network/tcc/auth) from its OWN
        // bounded buffer, so a file flood can't evict high-value events. Both
        // feed the same actor engines + the same batched writer — safe because
        // EventLoop.run holds no loop-local mutable state (all state is in
        // DaemonState's actors + Sendable counters); cross-collector reordering
        // into the engines already existed before the split.
        let streams = await handles.state.mergedEventStreams()
        // v1.21.4 (audit #211): the alerts-emitted counter is no longer passed
        // to the loop — AlertSink now owns the increment (the single chokepoint
        // every emission path flows through), and it was wired the SAME
        // `_sharedAlertCount` instance in DaemonState.init, so the heartbeat
        // read below is unchanged.
        guard let consumers = await handles.state.eventIngestionLifecycle
            .spawnConsumers(
                priority: {
                    await EventLoop.run(
                        state: handles.state,
                        lane: .priority,
                        eventStream: streams.priority,
                        eventCount: _sharedEventCount
                    )
                },
                file: {
                    await EventLoop.run(
                        state: handles.state,
                        lane: .file,
                        eventStream: streams.file,
                        eventCount: _sharedEventCount
                    )
                }
            ) else {
            return
        }
        _ = await (consumers.priority.value, consumers.file.value)

        // Stream termination, signals, and essential-source recovery all use
        // this one ordered implementation. The lifecycle claim inside it makes
        // simultaneous terminal causes idempotent.
        _ = await DaemonShutdownCoordinator.finalize(
            state: handles.state,
            supervisor: handles.supervisor,
            timerLifecycle: handles.timerHandles.lifecycle,
            livenessLifecycle: handles.timerHandles.livenessLifecycle,
            totalDeadline: 3.75,
            context: "event streams ended"
        )
    }

    /// The full bootstrap + run. Most callers want this; the split
    /// version (prepare + runEventLoop) exists for the sysext target,
    /// which starts an XPC listener between the two steps (Phase 3).
    public static func runForever(printBanner: Bool = true) async {
        // v1.7.6: write the startup marker as the first action — before
        // storage init, before any actor wiring. Pure synchronous file
        // write. The dashboard reads `sysext_started.json` mtime to
        // confirm the binary actually launched (vs. sysextd-stuck "I
        // think I activated it but the process never started").
        // v1.9.0: source the version from MacCrabVersion.current so the
        // marker doesn't drift behind the bundle on every release —
        // pre-fix the literal had bit-rotted from v1.7.12 → present.
        DaemonSetup.writeStartupMarker(
            supportDir: "/Library/Application Support/MacCrab",
            version: MacCrabVersion.current
        )
        let handles = await prepare(printBanner: printBanner)
        // Keep the handles alive for the lifetime of the event loop.
        // Swift ARC otherwise reclaims the dispatch sources.
        defer {
            _ = handles.signalHandles
            _ = handles.timerHandles
            _ = handles.supervisor
        }
        await runEventLoop(handles: handles)
    }

    /// Keep every graceful-exit surface honest about whether the newest
    /// in-flight multi-event detections reached their durable recovery point.
    /// Success is quiet; a skip or failure is a protection-degraded condition.
    static func reportSequenceCheckpointFlush(
        _ result: SequenceCheckpointWriteResult,
        context: String,
        requiresCleanBoundary: Bool,
        ingestionQuiesced: Bool,
        dirtyAfterFlush: Bool
    ) {
        switch result {
        case .failed(let detail):
            logger.fault("Sequence checkpoint flush failed during \(context, privacy: .public): \(detail, privacy: .public)")
            return
        case .alreadyInProgress:
            logger.fault("Sequence checkpoint flush skipped during \(context, privacy: .public): another operation remained in progress after periodic-lane join")
            return
        case .notDue, .budgetDeferred:
            logger.fault("Sequence checkpoint forced flush returned an invalid periodic-only result during \(context, privacy: .public)")
            return
        case .written(_), .unchanged:
            break
        }
        if requiresCleanBoundary && (!ingestionQuiesced || dirtyAfterFlush) {
            let reason = !ingestionQuiesced
                ? "one or more ingestion, timer, monitor, or derived-work mutation planes did not drain before their deadline"
                : "sequence state changed during the forced passes"
            logger.fault("Sequence checkpoint during \(context, privacy: .public) is BEST EFFORT, not a clean shutdown boundary: \(reason, privacy: .public)")
            return
        }
        switch result {
        case .written(let bytes):
            if dirtyAfterFlush {
                logger.notice("Sequence checkpoint advanced during \(context, privacy: .public) (\(bytes) bytes); newer live state remains dirty within the configured crash RPO")
            } else {
                logger.info("Sequence checkpoint is current during \(context, privacy: .public) (\(bytes) bytes)")
            }
        case .unchanged:
            if dirtyAfterFlush {
                logger.fault("Sequence checkpoint reported unchanged but remained dirty during \(context, privacy: .public)")
            } else {
                logger.info("Sequence checkpoint already current during \(context, privacy: .public)")
            }
        case .failed, .alreadyInProgress, .notDue, .budgetDeferred:
            // Returned above with the more specific failure detail.
            break
        }
    }
}

// Event/alert counters live at file scope so the timer callbacks can
// close over them. Moving them into DaemonHandles would require inout
// semantics the dispatch sources can't express — simpler to keep them
// here and document their purpose.
// v1.17 DEPS-01: previously `nonisolated(unsafe) var ...: UInt64`, which
// raced — written from EventLoop's async processing thread while the
// dispatch-source heartbeat timers read them from another thread.
// LockedCounter (NSLock-backed, used elsewhere in this module) makes the
// shared read/write safe. The timer read closures convert Int -> UInt64.
let _sharedEventCount = LockedCounter()
let _sharedAlertCount = LockedCounter()
