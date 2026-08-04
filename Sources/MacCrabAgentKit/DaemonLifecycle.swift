// DaemonLifecycle.swift
// MacCrabAgentKit
//
// Joinable lifecycle boundaries for rule reload and the main event-ingestion
// plane. A source/consumer that is merely cancelled is not yet stopped; every
// graceful persistence/checkpoint claim is downstream of these joins.

import Foundation
import MacCrabCore
import Darwin
import os

/// Process-exit intent is recorded before routing every terminal condition
/// through the one SIGTERM finalizer. Essential-sensor recovery retains its
/// EX_TEMPFAIL status without bypassing persistence/evidence teardown.
enum DaemonExitRequest {
    private static let requestedCode = OSAllocatedUnfairLock<Int32>(
        initialState: 0
    )

    static func requestRelaunch() {
        requestedCode.withLock { code in
            if code == 0 { code = 75 }
        }
        _ = kill(getpid(), SIGTERM)
    }

    static func exitCode() -> Int32 {
        requestedCode.withLock { $0 }
    }
}

/// Serializes live rule-reload admission against terminal shutdown. Once
/// shutdown begins, subsequent SIGHUPs are refused; an already-running reload
/// is cancelled and joined through the owning timer lifecycle rather than
/// making the shutdown-claim actor wait without a deadline.
actor DaemonLifecycleCoordinator {
    private var reloadInProgress = false
    private var shuttingDown = false
    private var finalizerClaimed = false

    func beginRuleReload() -> Bool {
        guard !shuttingDown, !reloadInProgress else { return false }
        reloadInProgress = true
        return true
    }

    func endRuleReload() {
        guard reloadInProgress else { return }
        reloadInProgress = false
    }

    /// Returns true only to the one caller responsible for persistence flushes
    /// and process teardown. Signal delivery and stream termination can happen
    /// together; without this claim both paths race the same writer/checkpoint.
    func beginShutdown() -> Bool {
        shuttingDown = true
        guard !finalizerClaimed else { return false }
        finalizerClaimed = true
        return true
    }

    func isShuttingDown() -> Bool { shuttingDown }
}

/// An unstructured-task deadline race. Structured task groups always await all
/// children before leaving scope—even after `cancelAll()`—so they cannot bound
/// a child that is itself stuck awaiting an uncooperative task.
private final class BooleanDeadlineRace: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var resolved = false

    init(_ continuation: CheckedContinuation<Bool, Never>) {
        self.continuation = continuation
    }

    func resolve(_ value: Bool) {
        let pending: CheckedContinuation<Bool, Never>? = lock.withLock {
            guard !resolved else { return nil }
            resolved = true
            let result = continuation
            continuation = nil
            return result
        }
        pending?.resume(returning: value)
    }
}

/// One implementation for every bounded graceful-task join. Returning false
/// means the caller hit its deadline; it does not pretend cancellation itself
/// was completion.
enum BoundedTaskJoin {
    static func waitForAll(
        _ tasks: [Task<Void, Never>],
        deadline: TimeInterval
    ) async -> Bool {
        guard !tasks.isEmpty else { return true }
        return await withCheckedContinuation { continuation in
            let race = BooleanDeadlineRace(continuation)
            Task.detached(priority: .utility) {
                for task in tasks { await task.value }
                race.resolve(true)
            }
            let nanoseconds = UInt64(
                min(max(0, deadline) * 1_000_000_000, Double(UInt64.max))
            )
            DispatchQueue.global().asyncAfter(
                deadline: .now() + .nanoseconds(Int(clamping: nanoseconds))
            ) {
                race.resolve(false)
            }
        }
    }
}

/// Owns every `driveSource` and EventLoop consumer task plus both merged-stream
/// continuations. `shutdown` first stops admission, then waits for consumers to
/// drain the already-admitted prefix. A deadline miss is returned as `false`;
/// callers may perform a best-effort checkpoint but must not call it clean.
actor EventIngestionLifecycle {
    private enum Phase { case accepting, stopping, stopped }

    private var phase: Phase = .accepting
    private var priorityContinuation: AsyncStream<EventPipelineEnvelope>.Continuation?
    private var fileContinuation: AsyncStream<EventPipelineEnvelope>.Continuation?
    private var driverTasks: [Task<Void, Never>] = []
    private var consumerTasks: [Task<Void, Never>] = []
    private var shutdownResult: Bool?
    private var shutdownWaiters: [CheckedContinuation<Bool, Never>] = []

    func configure(
        priority: AsyncStream<EventPipelineEnvelope>.Continuation,
        file: AsyncStream<EventPipelineEnvelope>.Continuation
    ) {
        guard phase == .accepting else {
            priority.finish()
            file.finish()
            return
        }
        precondition(priorityContinuation == nil && fileContinuation == nil)
        priorityContinuation = priority
        fileContinuation = file
    }

    /// Create and register work in the same actor turn. Creating a Task first
    /// and awaiting a later registration lets shutdown capture an empty ledger
    /// while the unregistered task is already mutating.
    @discardableResult
    func spawnDriver(
        _ operation: @escaping @Sendable () async -> Void
    ) -> Task<Void, Never>? {
        guard phase == .accepting else { return nil }
        let task = Task { await operation() }
        driverTasks.append(task)
        return task
    }

    @discardableResult
    func spawnConsumer(
        _ operation: @escaping @Sendable () async -> Void
    ) -> Task<Void, Never>? {
        guard phase == .accepting else { return nil }
        let task = Task { await operation() }
        consumerTasks.append(task)
        return task
    }

    func spawnConsumers(
        priority: @escaping @Sendable () async -> Void,
        file: @escaping @Sendable () async -> Void
    ) -> (priority: Task<Void, Never>, file: Task<Void, Never>)? {
        guard phase == .accepting else { return nil }
        let priorityTask = Task { await priority() }
        let fileTask = Task { await file() }
        consumerTasks.append(priorityTask)
        consumerTasks.append(fileTask)
        return (priorityTask, fileTask)
    }

    func shutdown(deadline: TimeInterval) async -> Bool {
        if let shutdownResult { return shutdownResult }
        if phase == .stopping {
            return await withCheckedContinuation { continuation in
                shutdownWaiters.append(continuation)
            }
        }

        phase = .stopping
        for task in driverTasks { task.cancel() }
        priorityContinuation?.finish()
        fileContinuation?.finish()

        let tracked = driverTasks + consumerTasks
        let clean = await BoundedTaskJoin.waitForAll(
            tracked,
            deadline: max(0, deadline)
        )
        if !clean {
            // The admitted prefix did not drain in time. Stop further mutation
            // before the process-level hard deadline; the caller will surface
            // that its final checkpoint is only best effort.
            for task in consumerTasks { task.cancel() }
            _ = await BoundedTaskJoin.waitForAll(tracked, deadline: 0.25)
        }

        driverTasks.removeAll(keepingCapacity: false)
        consumerTasks.removeAll(keepingCapacity: false)
        priorityContinuation = nil
        fileContinuation = nil
        phase = .stopped
        shutdownResult = clean
        let waiters = shutdownWaiters
        shutdownWaiters.removeAll(keepingCapacity: false)
        for waiter in waiters { waiter.resume(returning: clean) }
        return clean
    }
}

/// Owns every dispatch-timer handler as a joinable task plane.
///
/// Cancelling a DispatchSource only prevents future fires; a handler that has
/// already launched an unstructured Task continues mutating stores. This
/// lifecycle closes that gap: submission and shutdown share one lock, every
/// accepted handler is counted and retained, and terminal teardown cancels all
/// sources before joining the exact accepted prefix.
struct DaemonTimerLifecycleSnapshot: Sendable, Equatable {
    let accepting: Bool
    let offeredHandlers: UInt64
    let acceptedHandlers: UInt64
    let completedHandlers: UInt64
    let rejectedHandlers: UInt64
    let closedRejectedHandlers: UInt64
    let overloadShedHandlers: UInt64
    let coalescedHandlers: UInt64
    let coalescedByLabel: [String: UInt64]
    let rejectedByLabel: [String: UInt64]
    let inlineFallbackHandlers: UInt64
    let inlineFallbacksByLabel: [String: UInt64]
    let inFlightHandlers: Int
    let maximumInFlightHandlers: Int

    var conservesAcceptedHandlers: Bool {
        acceptedHandlers == completedHandlers + UInt64(inFlightHandlers)
    }

    var conservesOfferedHandlers: Bool {
        offeredHandlers
            == acceptedHandlers + inlineFallbackHandlers + rejectedHandlers
                + coalescedHandlers
    }
}

enum DaemonWorkSubmissionResult: Sendable, Equatable {
    case accepted
    case ranInlineOnOverload
    case coalesced
    case rejectedAfterClose
}

final class DaemonTimerLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private var accepting = true
    private var nextID: UInt64 = 0
    private var offeredHandlers: UInt64 = 0
    private var acceptedHandlers: UInt64 = 0
    private var completedHandlers: UInt64 = 0
    private var rejectedHandlers: UInt64 = 0
    private var closedRejectedHandlers: UInt64 = 0
    private var overloadShedHandlers: UInt64 = 0
    private var coalescedHandlers: UInt64 = 0
    private var coalescedByLabel: [String: UInt64] = [:]
    private var rejectedByLabel: [String: UInt64] = [:]
    private var inlineFallbackHandlers: UInt64 = 0
    private var inlineFallbacksByLabel: [String: UInt64] = [:]
    private var tasks: [UInt64: Task<Void, Never>] = [:]
    private var taskLabels: [UInt64: String] = [:]
    private var activeLabels: Set<String> = []
    private var timers: [DispatchSourceTimer] = []
    private var shutdownResult: Bool?
    private var shutdownTask: Task<Bool, Never>?
    private let maximumInFlightHandlers: Int
    private let coalesceByLabel: Bool

    init(
        maximumInFlightHandlers: Int = 256,
        coalesceByLabel: Bool = false
    ) {
        self.maximumInFlightHandlers = max(1, maximumInFlightHandlers)
        self.coalesceByLabel = coalesceByLabel
    }

    func register(_ timer: DispatchSourceTimer) {
        lock.lock()
        if accepting {
            timers.append(timer)
            lock.unlock()
        } else {
            lock.unlock()
            timer.cancel()
        }
    }

    @discardableResult
    func submit(
        label: String,
        operation: @escaping @Sendable () async -> Void
    ) -> Bool {
        lock.lock()
        offeredHandlers &+= 1
        guard accepting else {
            rejectedHandlers &+= 1
            closedRejectedHandlers &+= 1
            rejectedByLabel[label, default: 0] &+= 1
            lock.unlock()
            return false
        }
        if coalesceByLabel, activeLabels.contains(label) {
            coalescedHandlers &+= 1
            coalescedByLabel[label, default: 0] &+= 1
            lock.unlock()
            return false
        }
        guard tasks.count < maximumInFlightHandlers else {
            rejectedHandlers &+= 1
            overloadShedHandlers &+= 1
            rejectedByLabel[label, default: 0] &+= 1
            lock.unlock()
            return false
        }
        nextID &+= 1
        let id = nextID
        acceptedHandlers &+= 1
        // Keep the lock held until insertion. A very short task may reach
        // complete(id:) immediately, but it cannot remove itself before its
        // handle is present in the ledger.
        let task = Task(priority: .utility) { [weak self] in
            guard !Task.isCancelled else {
                self?.complete(id: id)
                return
            }
            await operation()
            self?.complete(id: id)
        }
        tasks[id] = task
        taskLabels[id] = label
        activeLabels.insert(label)
        lock.unlock()
        _ = label // fixed-cardinality debug label; never user-controlled data.
        return true
    }

    /// Detection-plane admission with a lossless overload fallback. When the
    /// asynchronous lane is full, the owning EventLoop consumer performs the
    /// operation inline, so overload creates measured backpressure rather than
    /// silently dropping a security decision. Once shutdown closes admission,
    /// late producers are rejected instead of escaping the final boundary.
    @discardableResult
    func submitOrRunInlineOnOverload(
        label: String,
        operation: @escaping @Sendable () async -> Void
    ) async -> DaemonWorkSubmissionResult {
        let admission = admitWithInlineFallback(
            label: label,
            operation: operation
        )
        if admission == .ranInlineOnOverload {
            await operation()
        }
        return admission
    }

    private func admitWithInlineFallback(
        label: String,
        operation: @escaping @Sendable () async -> Void
    ) -> DaemonWorkSubmissionResult {
        lock.lock()
        offeredHandlers &+= 1
        guard accepting else {
            rejectedHandlers &+= 1
            closedRejectedHandlers &+= 1
            rejectedByLabel[label, default: 0] &+= 1
            lock.unlock()
            return .rejectedAfterClose
        }
        if coalesceByLabel, activeLabels.contains(label) {
            coalescedHandlers &+= 1
            coalescedByLabel[label, default: 0] &+= 1
            lock.unlock()
            return .coalesced
        }
        if tasks.count >= maximumInFlightHandlers {
            inlineFallbackHandlers &+= 1
            inlineFallbacksByLabel[label, default: 0] &+= 1
            lock.unlock()
            return .ranInlineOnOverload
        }
        nextID &+= 1
        let id = nextID
        acceptedHandlers &+= 1
        let task = Task(priority: .utility) { [weak self] in
            guard !Task.isCancelled else {
                self?.complete(id: id)
                return
            }
            await operation()
            self?.complete(id: id)
        }
        tasks[id] = task
        taskLabels[id] = label
        activeLabels.insert(label)
        lock.unlock()
        _ = label
        return .accepted
    }

    private func complete(id: UInt64) {
        lock.withLock {
            guard tasks.removeValue(forKey: id) != nil else { return }
            if let label = taskLabels.removeValue(forKey: id) {
                activeLabels.remove(label)
            }
            completedHandlers &+= 1
        }
    }

    func snapshot() -> DaemonTimerLifecycleSnapshot {
        lock.withLock {
            DaemonTimerLifecycleSnapshot(
                accepting: accepting,
                offeredHandlers: offeredHandlers,
                acceptedHandlers: acceptedHandlers,
                completedHandlers: completedHandlers,
                rejectedHandlers: rejectedHandlers,
                closedRejectedHandlers: closedRejectedHandlers,
                overloadShedHandlers: overloadShedHandlers,
                coalescedHandlers: coalescedHandlers,
                coalescedByLabel: coalescedByLabel,
                rejectedByLabel: rejectedByLabel,
                inlineFallbackHandlers: inlineFallbackHandlers,
                inlineFallbacksByLabel: inlineFallbacksByLabel,
                inFlightHandlers: tasks.count,
                maximumInFlightHandlers: maximumInFlightHandlers
            )
        }
    }

    func shutdown(deadline: TimeInterval) async -> Bool {
        let shared: Task<Bool, Never> = lock.withLock {
            if let shutdownResult {
                return Task { shutdownResult }
            }
            if let shutdownTask { return shutdownTask }
            accepting = false
            let capturedTimers = timers
            let capturedTasks = Array(tasks.values)
            timers.removeAll(keepingCapacity: false)
            let task = Task {
                for timer in capturedTimers { timer.cancel() }
                for task in capturedTasks { task.cancel() }
                return await BoundedTaskJoin.waitForAll(
                    capturedTasks,
                    deadline: max(0, deadline)
                )
            }
            shutdownTask = task
            return task
        }
        let joined = await shared.value
        lock.withLock {
            if shutdownResult == nil { shutdownResult = joined }
            shutdownTask = nil
        }
        return joined
    }
}

private struct MonotonicShutdownDeadline: Sendable {
    private let endNanoseconds: UInt64

    init(seconds: TimeInterval) {
        let duration = UInt64(
            min(max(0, seconds) * 1_000_000_000, Double(UInt64.max))
        )
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(duration)
        endNanoseconds = addition.overflow ? UInt64.max : addition.partialValue
    }

    func remaining(maximum: TimeInterval? = nil) -> TimeInterval {
        let now = DispatchTime.now().uptimeNanoseconds
        let value = now >= endNanoseconds
            ? 0
            : Double(endNanoseconds - now) / 1_000_000_000
        if let maximum { return min(value, max(0, maximum)) }
        return value
    }
}

private final class ShutdownValueBox<Value: Sendable>: @unchecked Sendable {
    private let lock = OSAllocatedUnfairLock<Value?>(initialState: nil)
    func store(_ value: Value) { lock.withLock { $0 = value } }
    func load() -> Value? { lock.withLock { $0 } }
}

struct DaemonShutdownResult: Sendable {
    let producerPlane: Bool
    let ingestionPlane: Bool
    let timerPlane: Bool
    let livenessPlane: Bool
    let monitorPlane: Bool
    let startupPlane: Bool
    let heavyEnrichmentPlane: Bool
    let detectionWorkPlane: Bool
    let advisoryWorkPlane: Bool
    let outputWorkPlane: Bool
    let uebaPersistence: Bool
    let writer: Bool
    let evidence: Bool
    let evidenceShutdown: AlertSinkShutdownResult?
    let graph: Bool
    let checkpoint: SequenceCheckpointWriteResult?
    let checkpointDirty: Bool

    var checkpointClean: Bool {
        guard !checkpointDirty, let checkpoint else { return false }
        switch checkpoint {
        case .written, .unchanged:
            return true
        case .notDue, .budgetDeferred, .alreadyInProgress, .failed:
            return false
        }
    }

    var cleanMutationBoundary: Bool {
        producerPlane && ingestionPlane && timerPlane && livenessPlane
            && monitorPlane && startupPlane && heavyEnrichmentPlane
            && detectionWorkPlane
            && advisoryWorkPlane && outputWorkPlane && uebaPersistence
            && writer && evidence
            && graph && checkpointClean
    }
}

/// The sole graceful-finalization implementation for stream termination,
/// SIGTERM/SIGINT, and essential-sensor recovery. Every phase consumes the
/// residual of one monotonic deadline, so individual nominal timeouts cannot
/// add up beyond the process-level allowance.
enum DaemonShutdownCoordinator {
    static func finalize(
        state: DaemonState,
        supervisor: MonitorSupervisor,
        timerLifecycle: DaemonTimerLifecycle,
        livenessLifecycle: DaemonTimerLifecycle,
        totalDeadline: TimeInterval,
        context: String
    ) async -> DaemonShutdownResult? {
        guard await state.daemonLifecycle.beginShutdown() else { return nil }
        let deadline = MonotonicShutdownDeadline(seconds: totalDeadline)

        // Stop sources and every task that can still produce alerts/events.
        // These operations run concurrently but share the same residual cap.
        let producerBudget = deadline.remaining(maximum: 1.5)
        async let producers = boundedProducerStop(
            state: state,
            deadline: producerBudget
        )
        async let ingestion = state.eventIngestionLifecycle.shutdown(
            deadline: producerBudget
        )
        async let timers = timerLifecycle.shutdown(deadline: producerBudget)
        async let liveness = livenessLifecycle.shutdown(
            deadline: producerBudget
        )
        async let monitors = supervisor.shutdown(deadline: producerBudget)
        async let startup = state.startupWorkLifecycle.shutdown(
            deadline: producerBudget
        )
        let producerResults = await (
            producers, ingestion, timers, liveness, monitors, startup
        )

        // Both ingestion consumers and the quiet-period drain timer are now
        // stopped. Seal heavyweight admission, terminalize/join every accepted
        // worker, drain its exact patch prefix, and run dependency-filtered
        // matches before any alert/output/persistence authority is sealed.
        let heavyEnrichment = await DeferredEnrichmentDispatcher.shutdown(
            state: state,
            deadlineSeconds: deadline.remaining(maximum: 0.75)
        )
        if !heavyEnrichment.clean {
            logger.fault("Heavy-enrichment shutdown was unclean during \(context, privacy: .public): plane_accepting=\(heavyEnrichment.plane.accepting), queued=\(heavyEnrichment.plane.queuedRequests), running=\(heavyEnrichment.plane.runningRequests), physical_workers=\(heavyEnrichment.plane.physicalWorkers), deferred_results=\(heavyEnrichment.plane.deferredResults), retained_events=\(heavyEnrichment.buffer.retainedEvents), buffered_patches=\(heavyEnrichment.buffer.bufferedPatches), orphan_patches=\(heavyEnrichment.buffer.orphanPatches), plane_conserved=\(heavyEnrichment.plane.requestsConserved), buffer_conserved=\(heavyEnrichment.buffer.reservationConserved && heavyEnrichment.buffer.slotsConserved && heavyEnrichment.buffer.eventsConserved && heavyEnrichment.buffer.patchesConserved)")
        }

        // Producers are closed, so this is the exact derivative prefix to
        // cancel/join. Independent lanes prevent slow outputs/models from
        // consuming detection capacity.
        let workBudget = deadline.remaining(maximum: 0.75)
        async let detection = state.detectionWorkLifecycle.shutdown(
            deadline: workBudget
        )
        async let advisory = state.advisoryWorkLifecycle.shutdown(
            deadline: workBudget
        )
        async let outputs = state.outputWorkLifecycle.shutdown(
            deadline: workBudget
        )
        let workResults = await (detection, advisory, outputs)

        // UEBA observations are admitted from the detection lane. Persist only
        // after that lane has quiesced so the file represents an exact terminal
        // prefix, and make a timeout/failure part of shutdown truth rather than
        // silently discarding the learned model.
        let uebaPersistence: Bool
        if let ueba = state.uebaEngine {
            uebaPersistence = await boundedValue(
                deadline: deadline.remaining(maximum: 0.5)
            ) {
                await ueba.save()
            } ?? false
        } else {
            uebaPersistence = true
        }

        let writerClean = await bounded(
            deadline: deadline.remaining(maximum: 0.75)
        ) {
            await state.eventWriter.shutdown()
        }

        let evidenceBudget = deadline.remaining(maximum: 0.75)
        let evidenceShutdown = await boundedValue(
            deadline: evidenceBudget
        ) {
            await state.alertSink.shutdownEvidenceCapture(
                timeout: .nanoseconds(
                    Int64(max(0, evidenceBudget) * 1_000_000_000)
                )
            )
        }
        let evidenceClean = evidenceShutdown?.clean ?? false
        if let evidenceShutdown, !evidenceShutdown.clean {
            logger.fault("AlertSink shutdown was unclean during \(context, privacy: .public): pending evidence=\(evidenceShutdown.pending), alert admissions in flight=\(evidenceShutdown.alertAdmissionsInFlight), shed at deadline=\(evidenceShutdown.shedAtDeadline)")
        } else if evidenceShutdown == nil {
            logger.fault("AlertSink shutdown exceeded the total deadline during \(context, privacy: .public)")
        }

        let graphClean = await boundedValue(
            deadline: deadline.remaining(maximum: 0.5)
        ) {
            guard let bridge = state.causalGraphBridge else { return true }
            do {
                try await bridge.flushPending()
                return true
            } catch {
                logger.error("TraceGraph shutdown flush failed during \(context, privacy: .public): \(error.localizedDescription, privacy: .public)")
                return false
            }
        } ?? false

        let checkpoint = await boundedValue(
            deadline: deadline.remaining()
        ) {
            await state.sequenceCheckpointCoordinator.forceFlush(
                engine: state.sequenceEngine
            )
        }
        let telemetry = await state.sequenceCheckpointCoordinator.telemetry(
            engine: state.sequenceEngine
        )
        let result = DaemonShutdownResult(
            producerPlane: producerResults.0,
            ingestionPlane: producerResults.1,
            timerPlane: producerResults.2,
            livenessPlane: producerResults.3,
            monitorPlane: producerResults.4,
            startupPlane: producerResults.5,
            heavyEnrichmentPlane: heavyEnrichment.clean,
            detectionWorkPlane: workResults.0,
            advisoryWorkPlane: workResults.1,
            outputWorkPlane: workResults.2,
            uebaPersistence: uebaPersistence,
            writer: writerClean,
            evidence: evidenceClean,
            evidenceShutdown: evidenceShutdown,
            graph: graphClean,
            checkpoint: checkpoint,
            checkpointDirty: telemetry.dirty
        )

        if !result.cleanMutationBoundary {
            logger.fault("Daemon shutdown boundary was BEST EFFORT during \(context, privacy: .public): producers=\(result.producerPlane), ingestion=\(result.ingestionPlane), timers=\(result.timerPlane), liveness=\(result.livenessPlane), monitors=\(result.monitorPlane), startup=\(result.startupPlane), heavy_enrichment=\(result.heavyEnrichmentPlane), detection=\(result.detectionWorkPlane), advisory=\(result.advisoryWorkPlane), outputs=\(result.outputWorkPlane), ueba_persistence=\(result.uebaPersistence), writer=\(result.writer), evidence=\(result.evidence), graph=\(result.graph), checkpoint=\(result.checkpointClean), checkpoint_dirty=\(result.checkpointDirty)")
        }

        if let checkpoint {
            DaemonBootstrap.reportSequenceCheckpointFlush(
                checkpoint,
                context: context,
                requiresCleanBoundary: true,
                ingestionQuiesced: result.cleanMutationBoundary,
                dirtyAfterFlush: telemetry.dirty
            )
        } else {
            logger.fault("Sequence checkpoint exceeded the total shutdown deadline during \(context, privacy: .public); final state is BEST EFFORT")
        }
        return result
    }

    /// Seal every runtime producer concurrently, then fold every bounded join
    /// into one truth value. A collector which has not started yet is sealed as
    /// well, preventing a queued supervisor/startup task from resurrecting it
    /// after terminal shutdown begins.
    private static func stopRuntimeProducers(
        state: DaemonState,
        deadline: TimeInterval
    ) async -> Bool {
        let collector = state.collector
        let unifiedLog = state.ulCollector
        let eslogger = state.esloggerCollector
        let kdebug = state.kdebugCollector
        let tcc = state.tccMonitor
        let network = state.networkCollector
        let fsEvents = state.fsEventsCollector
        let esHealth = state.esHealthMonitor
        let eventTap = state.eventTapMonitor
        let systemPolicy = state.systemPolicyMonitor
        let mcp = state.mcpMonitor
        let ultrasonic = state.ultrasonicMonitor
        let usb = state.usbMonitor
        let clipboard = state.clipboardMonitor
        let browser = state.browserExtMonitor
        let dns = state.dnsCollector
        let rootkit = state.rootkitDetector
        let sdr = state.sdrDeviceMonitor
        let btm = state.btmSnapshotMonitor
        let edr = state.edrMonitor
        let selfDefense = state.selfDefense
        let sequenceCheckpoint = state.sequenceCheckpointCoordinator
        let threatIntel = state.threatIntel
        let certificateTransparency = state.ctMonitor
        let baseline = state.baselineEngine
        let fleet = state.fleetClient
        let receiver = state.otlpReceiver
        let operationDeadline = max(0, deadline)

        return await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                guard let collector else { return true }
                return await collector.stopAndJoin(
                    deadline: operationDeadline
                )
            }
            group.addTask {
                guard let unifiedLog else { return true }
                return await unifiedLog.stopAndJoin(
                    deadline: operationDeadline
                )
            }
            group.addTask {
                guard let eslogger else { return true }
                return await eslogger.stopAndJoin(
                    deadline: operationDeadline
                )
            }
            group.addTask {
                guard let kdebug else { return true }
                return await kdebug.stopAndJoin(
                    deadline: operationDeadline
                )
            }
            group.addTask { await tcc.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await network.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await fsEvents.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await esHealth.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await eventTap.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await systemPolicy.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await mcp.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await ultrasonic.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await usb.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await clipboard.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await browser.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await dns.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await rootkit.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await sdr.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await btm.stopAndJoin(deadline: operationDeadline) }
            group.addTask { await edr.stopAndJoin(deadline: operationDeadline) }
            group.addTask {
                await selfDefense.stop(deadline: operationDeadline)
            }
            group.addTask {
                await sequenceCheckpoint.stopPeriodicCheckpointing()
                return true
            }
            group.addTask {
                await threatIntel.stop(deadline: operationDeadline)
            }
            group.addTask {
                await certificateTransparency.shutdown()
                return true
            }
            group.addTask {
                await baseline.stopAutoSaveAndJoin(
                    deadline: operationDeadline
                )
            }
            group.addTask {
                guard let fleet else { return true }
                return await fleet.stop(deadline: operationDeadline)
            }
            group.addTask {
                guard let receiver else { return true }
                return await receiver.stop(
                    joinTimeoutSeconds: operationDeadline
                ).cleanlyStopped
            }

            var clean = true
            for await joined in group {
                clean = clean && joined
            }
            return clean
        }
    }

    private static func boundedProducerStop(
        state: DaemonState,
        deadline: TimeInterval
    ) async -> Bool {
        await boundedValue(deadline: deadline) {
            await stopRuntimeProducers(
                state: state,
                deadline: deadline
            )
        } ?? false
    }

    private static func bounded(
        deadline: TimeInterval,
        operation: @escaping @Sendable () async -> Void
    ) async -> Bool {
        guard deadline > 0 else { return false }
        let task = Task { await operation() }
        let joined = await BoundedTaskJoin.waitForAll(
            [task],
            deadline: deadline
        )
        if !joined { task.cancel() }
        return joined
    }

    private static func boundedValue<Value: Sendable>(
        deadline: TimeInterval,
        operation: @escaping @Sendable () async -> Value
    ) async -> Value? {
        guard deadline > 0 else { return nil }
        let box = ShutdownValueBox<Value>()
        let task = Task {
            box.store(await operation())
        }
        guard await BoundedTaskJoin.waitForAll([task], deadline: deadline) else {
            task.cancel()
            return nil
        }
        return box.load()
    }
}
