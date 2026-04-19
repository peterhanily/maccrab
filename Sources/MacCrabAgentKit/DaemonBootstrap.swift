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

        if printBanner {
            await StartupBanner.print(state: state)
        }

        // Shared supervisor for every background monitor task. Created
        // before signal handlers so SIGTERM can call shutdown() against
        // it. MonitorTasks registers its 12 named tasks under this
        // supervisor; DaemonTimers' dispatch-based timers are retained
        // separately via timerHandles.
        let supervisor = MonitorSupervisor()

        let signalHandles = SignalHandlers.install(state: state, supervisor: supervisor)
        await MonitorTasks.start(state: state, supervisor: supervisor)

        let startTime = Date()
        let timerHandles = DaemonTimers.start(
            state: state,
            eventCount: { _sharedEventCount },
            alertCount: { _sharedAlertCount },
            startTime: startTime
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
        let stream = handles.state.mergedEventStream()
        await EventLoop.run(
            state: handles.state,
            eventStream: stream,
            eventCount: &_sharedEventCount,
            alertCount: &_sharedAlertCount
        )
    }

    /// The full bootstrap + run. Most callers want this; the split
    /// version (prepare + runEventLoop) exists for the sysext target,
    /// which starts an XPC listener between the two steps (Phase 3).
    public static func runForever(printBanner: Bool = true) async {
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
}

// Event/alert counters live at file scope so the timer callbacks can
// close over them. Moving them into DaemonHandles would require inout
// semantics the dispatch sources can't express — simpler to keep them
// here and document their purpose.
nonisolated(unsafe) var _sharedEventCount: UInt64 = 0
nonisolated(unsafe) var _sharedAlertCount: UInt64 = 0
