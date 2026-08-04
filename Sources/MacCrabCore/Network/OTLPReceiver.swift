// OTLPReceiver.swift
// MacCrabCore
//
// v1.9 — OTLP/HTTP receiver (wired; config-gated).
//
// Listens on 127.0.0.1:<port> (default 4318 — the OTel ecosystem's
// canonical OTLP/HTTP port). Accepts POST /v1/traces with a protobuf body,
// decodes it, and writes ingested spans into traces.db (attributes are
// sanitized + AES-GCM-encrypted at rest with the shared DB key).
//
// Started from DaemonSetup.buildState (boot) and DaemonSetup
// .applyAgentTracesConfig (SIGHUP reload) when the agent-traces config
// asks for it. Not a stub — the class is live on any daemon whose config
// has enabled + receiverEnabled set.
//
// Hard invariants from Plan v3:
//   * Loopback only. NWListener bound to 127.0.0.1 explicitly via
//     `requiredLocalEndpoint` (AI-15 — `requiredInterfaceType` alone left the
//     socket on the WILDCARD address: `netstat` showed `tcp46 *.4318 LISTEN`).
//     Connection handlers still refuse any non-loopback peer, as defence in
//     depth.
//     CONSEQUENCE, and the one operational trap that bind introduces: it is
//     IPv4-only, so an exporter configured with `http://localhost:4318` can
//     resolve to ::1 and get connection-refused where the wildcard bind used to
//     accept it. Every snippet we ship already says 127.0.0.1 explicitly
//     (AgentSpansCommand.swift, the `agentTraces.*` strings in all 14 locales,
//     docs/AGENT_TRACES.md) — keep it that way; do not "helpfully" rewrite any
//     of them to `localhost`.
//   * Bind failure surfaces loudly — we do NOT silently fall back to a
//     different port (that would make the user-facing setup snippet lie).
//   * Default-off: the daemon starts the receiver only when the master
//     (env MACCRAB_AGENT_TRACES=1 OR agent_traces_config.json
//     `agent_traces_enabled`) AND `receiverEnabled` are both on. The
//     dashboard's "Receive agent traces" toggle writes both; a dev run
//     can use env vars instead.

import Foundation
import Network
import os.log

public enum OTLPReceiverError: Error, LocalizedError, Equatable {
    case bindFailed(String)
    case alreadyRunning
    case notRunning
    case invalidPort(Int)

    public var errorDescription: String? {
        switch self {
        case let .bindFailed(m): return "OTLPReceiver: bind failed: \(m)"
        case .alreadyRunning:    return "OTLPReceiver: already running"
        case .notRunning:        return "OTLPReceiver: not running"
        case let .invalidPort(p): return "OTLPReceiver: invalid port \(p)"
        }
    }
}

/// Lightweight summary of receiver activity. Surfaced via `metricsSnapshot()`
/// for the dashboard's diagnostics panel and the `maccrabctl status` line.
public struct OTLPReceiverMetrics: Sendable, Codable, Equatable {
    public var requestsAccepted: UInt64
    public var requestsRejectedNonLoopback: UInt64
    public var requestsBadRequest: UInt64
    public var bodyDecodeErrors: UInt64
    public var resourceSpansSeen: UInt64
    public var bytesReceived: UInt64
    // PR-3b additions:
    public var spansPersisted: UInt64
    public var spanInsertErrors: UInt64
    public var attributesKeyRedacted: UInt64
    public var attributesValueRedacted: UInt64
    /// v1.9 audit Phase-1.4: connection-deadline expiries. Indicator of
    /// slow-loris or genuinely broken peers.
    public var connectionDeadlineExceeded: UInt64

    public init() {
        self.requestsAccepted = 0
        self.requestsRejectedNonLoopback = 0
        self.requestsBadRequest = 0
        self.bodyDecodeErrors = 0
        self.resourceSpansSeen = 0
        self.bytesReceived = 0
        self.spansPersisted = 0
        self.spanInsertErrors = 0
        self.attributesKeyRedacted = 0
        self.attributesValueRedacted = 0
        self.connectionDeadlineExceeded = 0
    }
}

/// Result of one fully buffered OTLP request. Public solely to make the exact
/// pre-decode/pre-persist behavior adversarially testable without binding a
/// real port in CI.
public struct OTLPReceiverIngestResult: Sendable, Equatable {
    public let status: Int
    public let body: String

    public init(status: Int, body: String) {
        self.status = status
        self.body = body
    }
}

/// Exact ownership ledger for the receiver's two asynchronous planes. This is
/// intentionally separate from ``OTLPReceiverMetrics``: those counters describe
/// OTLP payload semantics, while this snapshot answers the lifecycle question
/// an operator needs during reload/shutdown: did every admitted connection and
/// body-processing task reach a terminal owner?
public struct OTLPReceiverLifecycleSnapshot: Sendable, Codable, Equatable {
    public let acceptingListeners: Bool
    public let listenersAccepted: UInt64
    public let listenersCompleted: UInt64
    public let listenersRejectedAfterSeal: UInt64
    public let activeListeners: Int
    public let readyListeners: Int
    public let acceptingConnections: Bool
    public let connectionsAccepted: UInt64
    public let connectionsCompleted: UInt64
    public let connectionsRejectedAfterSeal: UInt64
    public let connectionsRejectedAtCapacity: UInt64
    public let activeConnections: Int
    public let acceptingBodyTasks: Bool
    public let bodyTasksAccepted: UInt64
    public let bodyTasksCompleted: UInt64
    public let bodyTasksCancelled: UInt64
    public let bodyTasksRejected: UInt64
    public let bodyTaskCancellationRequests: UInt64
    public let bodyTasksInFlight: Int
    public let maximumBodyTasks: Int
    public let acceptingCallbackTasks: Bool
    public let callbackTasksAccepted: UInt64
    public let callbackTasksCompleted: UInt64
    public let callbackTasksCancelled: UInt64
    public let callbackTasksRejected: UInt64
    public let callbackTaskCancellationRequests: UInt64
    public let callbackTasksInFlight: Int
    public let maximumCallbackTasks: Int
    /// Includes the caller while `stop()` is taking its return snapshot. Values
    /// above one mean another start/stop/terminal transition is still suspended.
    public let lifecycleOperationsInProgress: Int
    /// Result of the most recent bounded shutdown join. Nil means this receiver
    /// has not yet attempted a shutdown.
    public let lastShutdownClean: Bool?
    public let shutdownTimeouts: UInt64

    public var connectionsConserved: Bool {
        connectionsAccepted == connectionsCompleted + UInt64(activeConnections)
    }

    public var listenersConserved: Bool {
        listenersAccepted == listenersCompleted + UInt64(activeListeners)
    }

    public var bodyTasksConserved: Bool {
        bodyTasksAccepted
            == bodyTasksCompleted + bodyTasksCancelled + UInt64(bodyTasksInFlight)
    }

    public var callbackTasksConserved: Bool {
        callbackTasksAccepted
            == callbackTasksCompleted + callbackTasksCancelled
                + UInt64(callbackTasksInFlight)
    }

    public var cleanlyStopped: Bool {
        !acceptingListeners
            && activeListeners == 0
            && readyListeners == 0
            && !acceptingConnections
            && !acceptingBodyTasks
            && !acceptingCallbackTasks
            && activeConnections == 0
            && bodyTasksInFlight == 0
            && callbackTasksInFlight == 0
            && lifecycleOperationsInProgress <= 1
            && listenersConserved
            && connectionsConserved
            && bodyTasksConserved
            && callbackTasksConserved
            && lastShutdownClean == true
    }
}

/// Lock-backed task ownership used because Network.framework calls arrive on a
/// dispatch queue, outside the receiver actor. Registration happens before the
/// task can escape, shutdown seals registration before taking the task handles,
/// and completion removes exactly one handle. The exact conservation equation
/// is therefore stable even when a cancellation-uncooperative store operation
/// outlives the bounded join deadline.
final class OTLPBodyTaskLifecycle: @unchecked Sendable {
    struct Snapshot: Sendable, Equatable {
        let accepting: Bool
        let accepted: UInt64
        let completed: UInt64
        let cancelled: UInt64
        let rejected: UInt64
        let cancellationRequests: UInt64
        let inFlight: Int
        let maximumInFlight: Int
        let lastShutdownClean: Bool?
        let shutdownTimeouts: UInt64

        var conservesAccepted: Bool {
            accepted == completed + cancelled + UInt64(inFlight)
        }
    }

    private let lock = NSLock()
    private let maximumInFlight: Int
    private var accepting = false
    private var nextID: UInt64 = 0
    private var tasks: [UInt64: Task<Void, Never>] = [:]
    private var cancellationRequestedIDs: Set<UInt64> = []
    private var accepted: UInt64 = 0
    private var completed: UInt64 = 0
    private var cancelled: UInt64 = 0
    private var rejected: UInt64 = 0
    private var cancellationRequests: UInt64 = 0
    private var lastShutdownClean: Bool?
    private var shutdownTimeouts: UInt64 = 0
    init(maximumInFlight: Int) {
        self.maximumInFlight = max(1, maximumInFlight)
    }

    /// Re-open only after every task from the prior generation has terminated.
    /// A timed-out shutdown can therefore never be hidden by a listener restart.
    func open() -> Bool {
        lock.withLock {
            guard !accepting, tasks.isEmpty else { return false }
            accepting = true
            lastShutdownClean = nil
            return true
        }
    }

    @discardableResult
    func submit(
        _ operation: @escaping @Sendable () async -> Void
    ) -> Bool {
        lock.lock()
        guard accepting, tasks.count < maximumInFlight else {
            rejected &+= 1
            lock.unlock()
            return false
        }
        nextID &+= 1
        let id = nextID
        accepted &+= 1
        // The lock remains held until the handle is installed. A very short
        // operation may reach `finish` immediately, but it cannot remove a
        // handle that registration has not yet published.
        let task = Task(priority: .utility) { [weak self] in
            guard !Task.isCancelled else {
                self?.finish(id: id, observedCancellation: true)
                return
            }
            await operation()
            self?.finish(id: id, observedCancellation: Task.isCancelled)
        }
        tasks[id] = task
        lock.unlock()
        return true
    }

    /// Used when a fully-buffered body reaches the receiver after connection
    /// admission has already been sealed. It was never accepted, but the drop
    /// must remain visible rather than disappearing between ledgers.
    func recordRejected() {
        lock.withLock { rejected &+= 1 }
    }

    private func finish(id: UInt64, observedCancellation: Bool) {
        lock.withLock {
            guard tasks.removeValue(forKey: id) != nil else { return }
            cancellationRequestedIDs.remove(id)
            if observedCancellation {
                cancelled &+= 1
            } else {
                completed &+= 1
            }
        }
    }

    /// Synchronously closes admission and sends cancellation to every owned
    /// handle. The returned handles are a point-in-time join set; later
    /// registration is impossible until `open()` succeeds after a clean drain.
    @discardableResult
    func sealAndCancel() -> [Task<Void, Never>] {
        let captured: [Task<Void, Never>] = lock.withLock {
            accepting = false
            for (id, _) in tasks where cancellationRequestedIDs.insert(id).inserted {
                cancellationRequests &+= 1
            }
            return Array(tasks.values)
        }
        for task in captured { task.cancel() }
        return captured
    }

    func shutdown(deadline: TimeInterval) async -> Bool {
        let captured = sealAndCancel()
        let joined = await OTLPBoundedTaskJoin.waitForAll(
            captured,
            deadline: max(0, deadline)
        )
        return lock.withLock {
            // `waitForAll == true` proves its captured prefix terminated. The
            // empty check also protects against implementation drift.
            let clean = joined && tasks.isEmpty
            lastShutdownClean = clean
            if !clean { shutdownTimeouts &+= 1 }
            return clean
        }
    }

    func snapshot() -> Snapshot {
        lock.withLock {
            Snapshot(
                accepting: accepting,
                accepted: accepted,
                completed: completed,
                cancelled: cancelled,
                rejected: rejected,
                cancellationRequests: cancellationRequests,
                inFlight: tasks.count,
                maximumInFlight: maximumInFlight,
                lastShutdownClean: lastShutdownClean,
                shutdownTimeouts: shutdownTimeouts
            )
        }
    }
}

/// A task-group timeout is not a timeout: leaving the group still waits for all
/// children. This one-shot race lets shutdown return an explicit unclean result
/// while the lifecycle continues to retain and account for an uncooperative
/// body task until it actually terminates.
private final class OTLPJoinDeadlineRace: @unchecked Sendable {
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

private enum OTLPBoundedTaskJoin {
    static func waitForAll(
        _ tasks: [Task<Void, Never>],
        deadline: TimeInterval
    ) async -> Bool {
        guard !tasks.isEmpty else { return true }
        return await withCheckedContinuation { continuation in
            let race = OTLPJoinDeadlineRace(continuation)
            Task.detached(priority: .utility) {
                for task in tasks { await task.value }
                race.resolve(true)
            }
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .nanoseconds(
                    OTLPDeadline.nanoseconds(deadline)
                )
            ) {
                race.resolve(false)
            }
        }
    }
}

private enum OTLPDeadline {
    static func nanoseconds(_ seconds: TimeInterval) -> Int {
        guard !seconds.isNaN, seconds > 0 else { return 0 }
        guard seconds.isFinite else { return Int.max }
        let maximumSeconds = Double(Int.max) / 1_000_000_000
        return Int(min(seconds, maximumSeconds) * 1_000_000_000)
    }
}

/// Synchronous ownership for the Network.framework listener itself. Cancelling
/// an `NWListener` is only a request; the socket is not known to be released
/// until its state handler publishes `.cancelled` or `.failed`. Keeping that
/// terminal acknowledgement in the same conservation ledger prevents a reload
/// from racing a still-owned port after `stop()` returned.
final class OTLPListenerLifecycle: @unchecked Sendable {
    struct Snapshot: Sendable, Equatable {
        let accepting: Bool
        let accepted: UInt64
        let completed: UInt64
        let rejectedAfterSeal: UInt64
        let active: Int
        let ready: Int

        var conservesAccepted: Bool {
            accepted == completed + UInt64(active)
        }
    }

    struct Completion: Sendable, Equatable {
        let wasReady: Bool
        let cancellationWasRequested: Bool
    }

    private struct Entry: @unchecked Sendable {
        let generation: UInt64
        let listener: NWListener
        var started = false
        var ready = false
        var cancellationRequested = false
    }

    /// Atomically cross the start/cancel boundary. `NWListener.start` is
    /// asynchronous and non-throwing; holding the ownership lock across that
    /// call ensures shutdown either removes a listener that never started or
    /// cancels one whose terminal callback is guaranteed to be armed.
    @discardableResult
    func start(
        _ listener: NWListener,
        generation expected: UInt64,
        queue: DispatchQueue
    ) -> Bool {
        lock.lock()
        let id = ObjectIdentifier(listener)
        guard accepting,
              var entry = entries[id],
              entry.generation == expected,
              !entry.cancellationRequested else {
            lock.unlock()
            return false
        }
        entry.started = true
        entries[id] = entry
        listener.start(queue: queue)
        lock.unlock()
        return true
    }

    private let lock = NSLock()
    private var accepting = false
    private var generation: UInt64 = 0
    private var entries: [ObjectIdentifier: Entry] = [:]
    private var accepted: UInt64 = 0
    private var completed: UInt64 = 0
    private var rejectedAfterSeal: UInt64 = 0
    private var nextDrainWaiterID: UInt64 = 0
    private var drainWaiters: [UInt64: OTLPJoinDeadlineRace] = [:]

    func open() -> UInt64? {
        lock.withLock {
            guard !accepting, entries.isEmpty else { return nil }
            generation &+= 1
            accepting = true
            return generation
        }
    }

    @discardableResult
    func register(_ listener: NWListener, generation expected: UInt64) -> Bool {
        lock.withLock {
            guard accepting, generation == expected else {
                rejectedAfterSeal &+= 1
                return false
            }
            let id = ObjectIdentifier(listener)
            guard entries[id] == nil else { return false }
            entries[id] = Entry(generation: generation, listener: listener)
            accepted &+= 1
            return true
        }
    }

    /// Publish readiness and its external status callback under one ordering
    /// lock. A terminal Network.framework callback either wins first (and this
    /// returns false without publishing ready), or waits until `onReady` has
    /// completed and can then publish the terminal status after it. This closes
    /// the ready-then-immediate-failure inversion that otherwise leaves the
    /// persisted status saying `running: true` for a dead listener.
    func publishReady(
        _ listener: NWListener,
        generation expected: UInt64,
        onReady: (@Sendable () -> Void)?
    ) -> Bool {
        lock.withLock {
            let id = ObjectIdentifier(listener)
            guard accepting,
                  var entry = entries[id],
                  entry.generation == expected,
                  !entry.cancellationRequested
            else { return false }
            entry.ready = true
            entries[id] = entry
            onReady?()
            return true
        }
    }

    /// The state handler calls this synchronously, before launching or
    /// resuming any actor work. Exactly one terminal state removes the owner.
    func complete(
        _ listener: NWListener,
        beforeRelease: @Sendable (Completion) -> Void = { _ in }
    ) -> Completion? {
        let result: (Completion?, [OTLPJoinDeadlineRace]) = lock.withLock {
            let id = ObjectIdentifier(listener)
            guard let entry = entries.removeValue(forKey: id) else {
                return (nil, [])
            }
            accepting = false
            completed &+= 1
            let completion = Completion(
                wasReady: entry.ready,
                cancellationWasRequested: entry.cancellationRequested
            )
            // Run cross-plane sealing while the listener generation lock is
            // still held. A concurrent restart therefore cannot open a new
            // listener and then have this old terminal callback seal its body,
            // connection, or callback ledgers underneath it.
            beforeRelease(completion)
            guard entries.isEmpty else { return (completion, []) }
            let waiters = Array(drainWaiters.values)
            drainWaiters.removeAll(keepingCapacity: false)
            return (completion, waiters)
        }
        for waiter in result.1 { waiter.resolve(true) }
        return result.0
    }

    /// Seal before cancellation so a synchronous terminal callback can see the
    /// cancellation as expected and never report an operator-requested stop as
    /// an unexpected listener failure.
    func sealAndCancel() {
        let result: (listeners: [NWListener], waiters: [OTLPJoinDeadlineRace]) = lock.withLock {
            accepting = false
            for id in Array(entries.keys) {
                entries[id]?.cancellationRequested = true
            }
            let toCancel = entries.values.map(\.listener)
            let neverStartedIDs = entries
                .filter { !$0.value.started }
                .map(\.key)
            for id in neverStartedIDs where entries.removeValue(forKey: id) != nil {
                completed &+= 1
            }
            guard entries.isEmpty else { return (toCancel, []) }
            let waiters = Array(drainWaiters.values)
            drainWaiters.removeAll(keepingCapacity: false)
            return (toCancel, waiters)
        }
        for listener in result.listeners { listener.cancel() }
        for waiter in result.waiters { waiter.resolve(true) }
    }

    func waitForDrain(deadline: TimeInterval) async -> Bool {
        if lock.withLock({ entries.isEmpty }) { return true }
        return await withCheckedContinuation { continuation in
            let race = OTLPJoinDeadlineRace(continuation)
            let waiterID: UInt64? = lock.withLock {
                guard !entries.isEmpty else { return nil }
                nextDrainWaiterID &+= 1
                drainWaiters[nextDrainWaiterID] = race
                return nextDrainWaiterID
            }
            guard let waiterID else {
                race.resolve(true)
                return
            }
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .nanoseconds(
                    OTLPDeadline.nanoseconds(deadline)
                )
            ) { [weak self] in
                self?.timeOutDrainWaiter(waiterID)
            }
        }
    }

    private func timeOutDrainWaiter(_ id: UInt64) {
        let waiter = lock.withLock { drainWaiters.removeValue(forKey: id) }
        waiter?.resolve(false)
    }

    func snapshot() -> Snapshot {
        lock.withLock {
            Snapshot(
                accepting: accepting,
                accepted: accepted,
                completed: completed,
                rejectedAfterSeal: rejectedAfterSeal,
                active: entries.count,
                ready: entries.values.lazy.filter { $0.ready }.count
            )
        }
    }
}

/// Thread-safe bridge from Network.framework's callback-driven listener state
/// to `OTLPReceiver.start()`'s async readiness contract. Construction success
/// is not bind success: `NWListener.start(queue:)` returns before the socket is
/// ready, and address-in-use/permission failures arrive later through
/// `stateUpdateHandler`. The first terminal startup state wins exactly once.
///
/// Internal so the callback/timeout races can be tested deterministically
/// without requiring a real listener in a sandboxed test process.
final class OTLPListenerStartupGate: @unchecked Sendable {
    enum Outcome: Sendable, Equatable {
        case ready
        case failed(String)
        case cancelled
        case timedOut
    }

    private let lock = NSLock()
    private var outcome: Outcome?
    private var continuation: CheckedContinuation<Outcome, Never>?
    private var timeoutWorkItem: DispatchWorkItem?

    func wait(
        timeoutSeconds: Double,
        start: () -> Void
    ) async -> Outcome {
        await withCheckedContinuation { continuation in
            let timeout = DispatchWorkItem { [weak self] in
                self?.resolve(.timedOut)
            }

            lock.lock()
            if let outcome {
                lock.unlock()
                continuation.resume(returning: outcome)
                return
            }
            self.continuation = continuation
            timeoutWorkItem = timeout
            lock.unlock()

            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + timeoutSeconds,
                execute: timeout
            )
            start()
        }
    }

    func observe(_ state: NWListener.State) {
        switch state {
        case .ready:
            resolve(.ready)
        case .failed(let error):
            resolve(.failed(error.localizedDescription))
        case .cancelled:
            resolve(.cancelled)
        default:
            break
        }
    }

    func cancel() {
        resolve(.cancelled)
    }

    private func resolve(_ newOutcome: Outcome) {
        let continuation: CheckedContinuation<Outcome, Never>?
        let timeout: DispatchWorkItem?

        lock.lock()
        guard outcome == nil else {
            lock.unlock()
            return
        }
        outcome = newOutcome
        continuation = self.continuation
        self.continuation = nil
        timeout = timeoutWorkItem
        timeoutWorkItem = nil
        lock.unlock()

        timeout?.cancel()
        continuation?.resume(returning: newOutcome)
    }
}

public actor OTLPReceiver {

    // MARK: - Configuration

    public static let defaultPort: UInt16 = 4318
    /// Hard upper bound on a single request body. Picked to comfortably
    /// fit a typical agent batch (~1 MB observed) plus headroom; protects
    /// against denial-of-service via a single huge body.
    public static let maxBodyBytes: Int = 8 * 1024 * 1024
    /// Wall-clock deadline applied per connection. Starts when the
    /// connection is accepted; if the full request hasn't been read by
    /// the deadline, the connection is cancelled. Mitigates slow-loris
    /// (peer holding a half-sent head forever) on a feature whose only
    /// peers are local processes — but a malicious local peer could
    /// still pin many FDs without this. v1.9 PR-5 audit Sec-M2.
    public static let connectionDeadlineSeconds: Double = 10.0
    /// Hard cap on simultaneously-open connections. v1.9.0 (audit
    /// Sec-M2): without this, a local agent could hold thousands of
    /// half-open sockets — each pinning a file descriptor under the
    /// 10 s slow-loris deadline. 64 covers any plausible legitimate
    /// burst (Claude Code spans rarely exceed ~10 simultaneous) with
    /// headroom; excess connections are cancelled before they start.
    public static let maxConcurrentConnections: Int = 64
    /// Network.framework receive callbacks only enqueue tiny actor bookkeeping
    /// hops here. The connection cap makes their natural concurrency small;
    /// this larger independent ceiling keeps malformed-request bursts bounded
    /// without letting optional telemetry compete with body persistence.
    public static let maxCallbackTasks: Int = 256
    /// `NWListener.start(queue:)` is asynchronous. Refuse to advertise the
    /// receiver as running unless Network.framework reaches `.ready` within a
    /// bounded interval.
    public static let startupTimeoutSeconds: Double = 5.0
    /// Shutdown first cancels listener/connection/deadline ownership, then gives
    /// already-admitted decode/persist work this long to acknowledge
    /// cancellation or finish. A miss is returned and retained as explicitly
    /// unclean telemetry; it is never relabelled as a successful stop.
    public static let shutdownJoinTimeoutSeconds: Double = 5.0

    /// Synchronous ownership boundary between Network.framework callbacks and
    /// the receiver actor. A callback registers its connection here before it
    /// launches an actor hop. Consequently `stop()` can seal and cancel even a
    /// connection whose actor task has not started yet.
    private final class ConnectionRegistry: @unchecked Sendable {
        struct Entry: @unchecked Sendable {
            let id: UInt64
            let generation: UInt64
            let connection: NWConnection
            let buffer: ConnectionBuffer
            var started: Bool
        }

        enum Admission {
            case accepted(Entry)
            case rejectedAfterSeal
            case rejectedAtCapacity
        }

        struct Snapshot: Sendable {
            let accepting: Bool
            let accepted: UInt64
            let completed: UInt64
            let rejectedAfterSeal: UInt64
            let rejectedAtCapacity: UInt64
            let active: Int
        }

        private let lock = NSLock()
        private let maximumConnections: Int
        private var accepting = false
        private var generation: UInt64 = 0
        private var nextID: UInt64 = 0
        private var entries: [UInt64: Entry] = [:]
        private var accepted: UInt64 = 0
        private var completed: UInt64 = 0
        private var rejectedAfterSeal: UInt64 = 0
        private var rejectedAtCapacity: UInt64 = 0
        private var nextDrainWaiterID: UInt64 = 0
        private var drainWaiters: [UInt64: OTLPJoinDeadlineRace] = [:]

        init(maximumConnections: Int) {
            self.maximumConnections = max(1, maximumConnections)
        }

        func open() -> UInt64? {
            lock.withLock {
                guard !accepting, entries.isEmpty else { return nil }
                generation &+= 1
                accepting = true
                return generation
            }
        }

        func admit(
            _ connection: NWConnection,
            generation expectedGeneration: UInt64
        ) -> Admission {
            lock.withLock {
                guard accepting, generation == expectedGeneration else {
                    rejectedAfterSeal &+= 1
                    return .rejectedAfterSeal
                }
                guard entries.count < maximumConnections else {
                    rejectedAtCapacity &+= 1
                    return .rejectedAtCapacity
                }
                nextID &+= 1
                let entry = Entry(
                    id: nextID,
                    generation: generation,
                    connection: connection,
                    buffer: ConnectionBuffer(
                        connectionID: nextID,
                        connectionGeneration: generation
                    ),
                    started: false
                )
                entries[entry.id] = entry
                accepted &+= 1
                return .accepted(entry)
            }
        }

        func contains(_ id: UInt64) -> Bool {
            lock.withLock { entries[id] != nil }
        }

        func isAccepting(generation expectedGeneration: UInt64) -> Bool {
            lock.withLock { accepting && generation == expectedGeneration }
        }

        /// Called only after the terminal state handler and deadline are
        /// installed. Holding the registry lock across Network.framework's
        /// asynchronous/non-throwing start call makes the start/cancel boundary
        /// exact: shutdown either removes a never-started entry or cancels one
        /// whose callbacks are fully armed, never both.
        func start(_ id: UInt64, queue: DispatchQueue) -> Bool {
            lock.lock()
            guard accepting, var entry = entries[id] else {
                lock.unlock()
                return false
            }
            entry.started = true
            entries[id] = entry
            entry.connection.start(queue: queue)
            lock.unlock()
            return true
        }

        /// Serialize the final response registration with shutdown sealing.
        /// Once `sealAndCancel()` acquires this lock no later send can begin.
        func performIfActive(_ id: UInt64, _ operation: () -> Void) -> Bool {
            lock.withLock {
                guard accepting, entries[id] != nil else { return false }
                operation()
                return true
            }
        }

        func complete(_ id: UInt64) {
            let result: (Entry?, [OTLPJoinDeadlineRace]) = lock.withLock {
                guard let removed = entries.removeValue(forKey: id) else {
                    return (nil, [])
                }
                completed &+= 1
                guard entries.isEmpty else { return (removed, []) }
                let waiters = Array(drainWaiters.values)
                drainWaiters.removeAll(keepingCapacity: false)
                return (removed, waiters)
            }
            result.0?.buffer.seal()
            for waiter in result.1 { waiter.resolve(true) }
        }

        /// Seal first and capture the exact owned set under the same lock, then
        /// cancel timers and sockets outside it. Never-started connections are
        /// terminal at cancellation; started connections remain retained until
        /// their Network.framework terminal callback or the bounded join times
        /// out, so an in-flight socket cannot disappear from telemetry.
        func sealAndCancel() {
            let result: (cancel: [Entry], completedWaiters: [OTLPJoinDeadlineRace]) = lock.withLock {
                accepting = false
                let toCancel = Array(entries.values)
                let neverStartedIDs = entries.values
                    .filter { !$0.started }
                    .map(\.id)
                for id in neverStartedIDs where entries.removeValue(forKey: id) != nil {
                    completed &+= 1
                }
                guard entries.isEmpty else { return (toCancel, []) }
                let waiters = Array(drainWaiters.values)
                drainWaiters.removeAll(keepingCapacity: false)
                return (toCancel, waiters)
            }
            for entry in result.cancel {
                entry.buffer.seal()
                entry.connection.cancel()
            }
            for waiter in result.completedWaiters { waiter.resolve(true) }
        }

        func waitForDrain(deadline: TimeInterval) async -> Bool {
            if lock.withLock({ entries.isEmpty }) { return true }
            return await withCheckedContinuation { continuation in
                let race = OTLPJoinDeadlineRace(continuation)
                let waiterID: UInt64? = lock.withLock {
                    guard !entries.isEmpty else { return nil }
                    nextDrainWaiterID &+= 1
                    drainWaiters[nextDrainWaiterID] = race
                    return nextDrainWaiterID
                }
                guard let waiterID else {
                    race.resolve(true)
                    return
                }
                DispatchQueue.global(qos: .utility).asyncAfter(
                    deadline: .now() + .nanoseconds(
                        OTLPDeadline.nanoseconds(deadline)
                    )
                ) {
                    self.timeOutDrainWaiter(waiterID)
                }
            }
        }

        private func timeOutDrainWaiter(_ id: UInt64) {
            let waiter = lock.withLock { drainWaiters.removeValue(forKey: id) }
            waiter?.resolve(false)
        }

        func snapshot() -> Snapshot {
            lock.withLock {
                Snapshot(
                    accepting: accepting,
                    accepted: accepted,
                    completed: completed,
                    rejectedAfterSeal: rejectedAfterSeal,
                    rejectedAtCapacity: rejectedAtCapacity,
                    active: entries.count
                )
            }
        }
    }

    // MARK: - State

    private var listener: NWListener?
    /// Listener whose asynchronous bind has started but has not reached
    /// `.ready`. Kept separate so `isRunning` cannot lie during startup and so
    /// `stop()` can cancel a concurrent start while the actor is re-entrant.
    private var startingListener: NWListener?
    private var startingGate: OTLPListenerStartupGate?
    private let port: UInt16
    private var metrics = OTLPReceiverMetrics()
    private let logger = Logger(subsystem: "com.maccrab.network", category: "otlp-receiver")
    nonisolated private let listeners = OTLPListenerLifecycle()
    nonisolated private let connections = ConnectionRegistry(
        maximumConnections: OTLPReceiver.maxConcurrentConnections
    )
    nonisolated private let bodyTasks = OTLPBodyTaskLifecycle(
        maximumInFlight: OTLPReceiver.maxConcurrentConnections
    )
    nonisolated private let callbackTasks = OTLPBodyTaskLifecycle(
        maximumInFlight: OTLPReceiver.maxCallbackTasks
    )
    /// Actor re-entrancy allows start/stop joins to overlap while awaiting
    /// Network.framework or storage. A new start is forbidden until every older
    /// lifecycle operation has returned, so one generation cannot resurrect
    /// behind another caller's shutdown snapshot.
    private var lifecycleOperationsInProgress: Int = 0
    private var lastShutdownClean: Bool?
    private var shutdownTimeouts: UInt64 = 0

    /// Optional `TraceStore`. When nil (PR-3a behaviour) the receiver
    /// decodes-and-drops; when set (PR-3b) it decodes → sanitises →
    /// extracts → inserts. Nil-default keeps the type cheap to construct
    /// in tests and on hosts that haven't opted in to span persistence.
    private let traceStore: TraceStore?
    /// Called by the receiver actor immediately after it takes ownership of a
    /// listener that reached `.ready`. Keeping ready and terminal publication
    /// on this actor prevents an immediate post-ready failure from racing a
    /// caller that would otherwise persist `running: true` after the failure.
    private let onReady: (@Sendable () -> Void)?
    /// Called only when a listener that previously reached `.ready` later
    /// fails or is unexpectedly cancelled. Startup failures are returned
    /// directly from `start()` instead.
    /// AgentKit uses this to replace its persisted `running: true` snapshot;
    /// without it the dashboard can advertise a dead receiver indefinitely.
    private let onTerminalFailure: (@Sendable (String) -> Void)?

    /// v1.21.5 (audit S-04): rolling-window ingest budget. The receiver has NO
    /// caller authentication — the only admission control is "peer endpoint is
    /// loopback" (handleNewConnection) plus a connection cap — so ANY local uid
    /// that can reach 127.0.0.1:<port> can POST spans into the ROOT-owned
    /// traces.db. Without a budget an unprivileged process can push 8 MB bodies
    /// until the traces retention size cap evicts GENUINE forensic traces: an
    /// evidence-destruction primitive aimed at the engine's own audit trail.
    /// Legitimate agent tooling emits a few KB/s (observed batches ~1 MB), so
    /// 32 MB per 60 s is orders of magnitude of headroom and only ever bites a
    /// flood. This BOUNDS THE RATE — it mitigates the missing authentication, it
    /// does not replace it; the real fix is a bearer token in a 0600 root-owned
    /// file, or a unix socket in a root-owned dir authenticated with
    /// LOCAL_PEERCRED, both of which need coordinated client-config changes.
    public static let ingestWindowSeconds: Double = 60.0
    public static let ingestWindowByteBudget: Int = 32 * 1024 * 1024
    private var ingestWindowStart: Date = Date()
    private var ingestWindowBytes: Int = 0

    /// Charge `bytes` against the current window. False means the budget is
    /// spent and the caller must drop the body BEFORE the store insert. Reuses
    /// `requestsBadRequest` as the counter, exactly as the connection cap does,
    /// so no new `OTLPReceiverMetrics` field is introduced — that struct has an
    /// explicit memberwise init and synthesized Codable, and adding a key would
    /// break decoding of a metrics blob written by an older build.
    private func admitIngest(bytes: Int) -> Bool {
        let now = Date()
        if now.timeIntervalSince(ingestWindowStart) >= Self.ingestWindowSeconds {
            ingestWindowStart = now
            ingestWindowBytes = 0
        }
        guard ingestWindowBytes + bytes <= Self.ingestWindowByteBudget else {
            metrics.requestsBadRequest &+= 1
            logger.warning("OTLPReceiver: ingest budget exceeded — dropping \(bytes, privacy: .public) byte body")
            return false
        }
        ingestWindowBytes += bytes
        return true
    }

    public init(
        port: UInt16 = defaultPort,
        traceStore: TraceStore? = nil,
        onReady: (@Sendable () -> Void)? = nil,
        onTerminalFailure: (@Sendable (String) -> Void)? = nil
    ) {
        self.port = port
        self.traceStore = traceStore
        self.onReady = onReady
        self.onTerminalFailure = onTerminalFailure
    }

    public var isRunning: Bool { listeners.snapshot().ready == 1 }

    public func metricsSnapshot() -> OTLPReceiverMetrics { metrics }

    public func currentPort() -> UInt16 { port }

    /// v1.9.0 (audit Sec-M2): live count for tests and debug-overlay
    /// panels. Counts strictly the connections currently held; not a
    /// monotonic accept counter (use `metrics.requestsAccepted` for
    /// that).
    public func activeConnectionCount() -> Int { connections.snapshot().active }

    public func lifecycleSnapshot() -> OTLPReceiverLifecycleSnapshot {
        let listenerSnapshot = listeners.snapshot()
        let connectionSnapshot = connections.snapshot()
        let bodySnapshot = bodyTasks.snapshot()
        let callbackSnapshot = callbackTasks.snapshot()
        return OTLPReceiverLifecycleSnapshot(
            acceptingListeners: listenerSnapshot.accepting,
            listenersAccepted: listenerSnapshot.accepted,
            listenersCompleted: listenerSnapshot.completed,
            listenersRejectedAfterSeal: listenerSnapshot.rejectedAfterSeal,
            activeListeners: listenerSnapshot.active,
            readyListeners: listenerSnapshot.ready,
            acceptingConnections: connectionSnapshot.accepting,
            connectionsAccepted: connectionSnapshot.accepted,
            connectionsCompleted: connectionSnapshot.completed,
            connectionsRejectedAfterSeal: connectionSnapshot.rejectedAfterSeal,
            connectionsRejectedAtCapacity: connectionSnapshot.rejectedAtCapacity,
            activeConnections: connectionSnapshot.active,
            acceptingBodyTasks: bodySnapshot.accepting,
            bodyTasksAccepted: bodySnapshot.accepted,
            bodyTasksCompleted: bodySnapshot.completed,
            bodyTasksCancelled: bodySnapshot.cancelled,
            bodyTasksRejected: bodySnapshot.rejected,
            bodyTaskCancellationRequests: bodySnapshot.cancellationRequests,
            bodyTasksInFlight: bodySnapshot.inFlight,
            maximumBodyTasks: bodySnapshot.maximumInFlight,
            acceptingCallbackTasks: callbackSnapshot.accepting,
            callbackTasksAccepted: callbackSnapshot.accepted,
            callbackTasksCompleted: callbackSnapshot.completed,
            callbackTasksCancelled: callbackSnapshot.cancelled,
            callbackTasksRejected: callbackSnapshot.rejected,
            callbackTaskCancellationRequests: callbackSnapshot.cancellationRequests,
            callbackTasksInFlight: callbackSnapshot.inFlight,
            maximumCallbackTasks: callbackSnapshot.maximumInFlight,
            lifecycleOperationsInProgress: lifecycleOperationsInProgress,
            lastShutdownClean: lastShutdownClean,
            shutdownTimeouts: shutdownTimeouts
        )
    }

    // MARK: - Lifecycle

    /// Bind and start the listener. Returns only after Network.framework emits
    /// `.ready`; asynchronous bind failure/cancellation/timeout throws instead
    /// of letting DaemonSetup persist a false `running: true` status.
    public func start() async throws {
        let listenerState = listeners.snapshot()
        guard listenerState.active == 0,
              lifecycleOperationsInProgress == 0 else {
            throw OTLPReceiverError.alreadyRunning
        }
        // An unexpected terminal callback intentionally does not need an actor
        // hop to relinquish the port. Reconcile its now-stale presentation
        // references before opening the next generation.
        listener = nil
        startingListener = nil
        startingGate = nil
        lifecycleOperationsInProgress += 1
        defer { lifecycleOperationsInProgress -= 1 }
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw OTLPReceiverError.invalidPort(Int(port))
        }
        let params = NWParameters.tcp
        // AI-15: `requiredInterfaceType = .loopback` constrains which INTERFACE
        // the listener may use — it does NOT choose the local ADDRESS, so the
        // socket still bound to the wildcard. `netstat -an -p tcp` showed
        // `tcp46  *.4318  LISTEN` (compare ollama's `127.0.0.1.11434`), which
        // contradicts this file's own header invariant ("NWListener bound to
        // 127.0.0.1 explicitly") and means the port is visible to LAN scanning
        // and completes a TCP handshake from a remote peer BEFORE the
        // peer-endpoint check below cancels it. `requiredLocalEndpoint` is what
        // actually pins the bind address. The peer check in
        // handleNewConnection stays as defence in depth, unchanged.
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: nwPort)
        params.requiredInterfaceType = .loopback

        let listener: NWListener
        do {
            // MUST be `NWListener(using:)`, NOT `NWListener(using:on:)`.
            // `requiredLocalEndpoint` already carries the port, and passing `on:`
            // as well specifies it twice — Network.framework rejects the pair
            // with EINVAL ("Invalid argument") at construction. The first cut of
            // the AI-15 fix did exactly that, so the receiver threw on every
            // start and the whole Agent Traces module bound nothing on the
            // shipping engine while still advertising itself [STABLE]. The bind
            // failure was recorded only in agent_traces_status.json, which
            // nothing but one dashboard tile reads — so it looked healthy
            // everywhere an operator would actually look.
            listener = try NWListener(using: params)
        } catch {
            throw OTLPReceiverError.bindFailed("\(error)")
        }
        // Open every admission plane before Network.framework can publish a
        // connection callback. A prior unclean stop with a still-running body
        // task refuses restart rather than mixing lifecycle generations.
        guard let listenerGeneration = listeners.open() else {
            listener.cancel()
            throw OTLPReceiverError.bindFailed(
                "previous listener ownership has not terminated"
            )
        }
        guard bodyTasks.open() else {
            listeners.sealAndCancel()
            listener.cancel()
            throw OTLPReceiverError.bindFailed(
                "previous body-processing work has not terminated"
            )
        }
        guard callbackTasks.open() else {
            listeners.sealAndCancel()
            bodyTasks.sealAndCancel()
            listener.cancel()
            throw OTLPReceiverError.bindFailed(
                "previous callback work has not terminated"
            )
        }
        guard let connectionGeneration = connections.open() else {
            listeners.sealAndCancel()
            bodyTasks.sealAndCancel()
            callbackTasks.sealAndCancel()
            listener.cancel()
            throw OTLPReceiverError.bindFailed(
                "previous connection ownership has not terminated"
            )
        }
        lastShutdownClean = nil
        let connectionRegistry = connections
        listener.newConnectionHandler = { [weak self] conn in
            // Verify peer is loopback before doing any work.
            guard let self else { conn.cancel(); return }
            guard Self.isLoopback(conn.endpoint) else {
                conn.cancel()
                self.submitCallbackActorHop {
                    await self.recordNonLoopbackRejection(
                        generation: connectionGeneration
                    )
                }
                return
            }
            switch connectionRegistry.admit(
                conn,
                generation: connectionGeneration
            ) {
            case .accepted(let entry):
                self.handleNewConnection(entry)
            case .rejectedAfterSeal:
                // Stop owns the seal; never start a connection delivered after
                // it, even if Network.framework had already queued the callback.
                conn.cancel()
            case .rejectedAtCapacity:
                conn.cancel()
                self.submitCallbackActorHop {
                    await self.recordConnectionCapacityRejection(
                        generation: connectionGeneration
                    )
                }
            }
        }
        let startupGate = OTLPListenerStartupGate()
        let listenerLifecycle = listeners
        let bodyTaskLifecycle = bodyTasks
        let callbackTaskLifecycle = callbackTasks
        let terminalFailureCallback = onTerminalFailure
        listener.stateUpdateHandler = { [weak listener, weak listenerLifecycle] state in
            switch state {
            case .failed(let error):
                guard let listener,
                      let completion = listenerLifecycle?.complete(
                        listener,
                        beforeRelease: { _ in
                            callbackTaskLifecycle.sealAndCancel()
                            connectionRegistry.sealAndCancel()
                            bodyTaskLifecycle.sealAndCancel()
                        }
                      )
                else {
                    startupGate.observe(state)
                    return
                }
                // Terminal socket ownership closes every downstream admission
                // plane synchronously, before the startup continuation or any
                // status callback can run.
                startupGate.observe(state)
                if completion.wasReady, !completion.cancellationWasRequested {
                    terminalFailureCallback?(error.localizedDescription)
                }
            case .cancelled:
                guard let listener,
                      let completion = listenerLifecycle?.complete(
                        listener,
                        beforeRelease: { _ in
                            callbackTaskLifecycle.sealAndCancel()
                            connectionRegistry.sealAndCancel()
                            bodyTaskLifecycle.sealAndCancel()
                        }
                      )
                else {
                    startupGate.observe(state)
                    return
                }
                startupGate.observe(state)
                if completion.wasReady, !completion.cancellationWasRequested {
                    terminalFailureCallback?("listener cancelled after readiness")
                }
            default:
                startupGate.observe(state)
            }
        }
        guard listeners.register(listener, generation: listenerGeneration) else {
            listeners.sealAndCancel()
            connections.sealAndCancel()
            callbackTasks.sealAndCancel()
            bodyTasks.sealAndCancel()
            listener.cancel()
            throw OTLPReceiverError.bindFailed("listener admission closed before start")
        }
        startingListener = listener
        startingGate = startupGate
        let outcome = await withTaskCancellationHandler {
            await startupGate.wait(
                timeoutSeconds: Self.startupTimeoutSeconds
            ) {
                if !listenerLifecycle.start(
                    listener,
                    generation: listenerGeneration,
                    queue: .global(qos: .utility)
                ) {
                    startupGate.cancel()
                }
            }
        } onCancel: {
            // Task cancellation must be an actual ownership transition, not a
            // five-second wait that can still publish a ready listener.
            callbackTaskLifecycle.sealAndCancel()
            connectionRegistry.sealAndCancel()
            bodyTaskLifecycle.sealAndCancel()
            listenerLifecycle.sealAndCancel()
            startupGate.cancel()
        }

        switch outcome {
        case .ready:
            // `stop()` can run while this actor is suspended in `wait`.
            // Never resurrect a listener that was cancelled during startup.
            guard startingListener === listener else {
                if startingGate === startupGate { startingGate = nil }
                connections.sealAndCancel()
                bodyTasks.sealAndCancel()
                callbackTasks.sealAndCancel()
                listeners.sealAndCancel()
                listener.cancel()
                _ = await joinOwnedWork(
                    deadline: Self.shutdownJoinTimeoutSeconds
                )
                throw OTLPReceiverError.bindFailed("listener cancelled before readiness")
            }
            startingListener = nil
            if startingGate === startupGate { startingGate = nil }
            self.listener = listener
            guard listeners.publishReady(
                listener,
                generation: listenerGeneration,
                onReady: onReady
            ) else {
                self.listener = nil
                connections.sealAndCancel()
                bodyTasks.sealAndCancel()
                callbackTasks.sealAndCancel()
                listeners.sealAndCancel()
                listener.cancel()
                _ = await joinOwnedWork(
                    deadline: Self.shutdownJoinTimeoutSeconds
                )
                throw OTLPReceiverError.bindFailed(
                    "listener terminated before readiness publication"
                )
            }
        case .failed(let message):
            if startingListener === listener { startingListener = nil }
            if startingGate === startupGate { startingGate = nil }
            connections.sealAndCancel()
            bodyTasks.sealAndCancel()
            callbackTasks.sealAndCancel()
            listeners.sealAndCancel()
            _ = await joinOwnedWork(deadline: Self.shutdownJoinTimeoutSeconds)
            throw OTLPReceiverError.bindFailed(message)
        case .cancelled:
            if startingListener === listener { startingListener = nil }
            if startingGate === startupGate { startingGate = nil }
            connections.sealAndCancel()
            bodyTasks.sealAndCancel()
            callbackTasks.sealAndCancel()
            listeners.sealAndCancel()
            _ = await joinOwnedWork(deadline: Self.shutdownJoinTimeoutSeconds)
            throw OTLPReceiverError.bindFailed("listener cancelled before readiness")
        case .timedOut:
            if startingListener === listener { startingListener = nil }
            if startingGate === startupGate { startingGate = nil }
            connections.sealAndCancel()
            bodyTasks.sealAndCancel()
            callbackTasks.sealAndCancel()
            listeners.sealAndCancel()
            _ = await joinOwnedWork(deadline: Self.shutdownJoinTimeoutSeconds)
            throw OTLPReceiverError.bindFailed(
                "listener did not reach ready within \(Self.startupTimeoutSeconds) seconds"
            )
        }
        logger.notice("OTLPReceiver started on 127.0.0.1:\(self.port, privacy: .public)")
    }

    /// Seal both admission planes, cancel every retained listener, connection,
    /// and deadline timer, then bounded-join every accepted body task. The
    /// return value is the exact post-join ledger; callers must treat
    /// `cleanlyStopped == false` as an unclean shutdown rather than assuming
    /// cancellation was completion.
    @discardableResult
    public func stop(
        joinTimeoutSeconds: Double = OTLPReceiver.shutdownJoinTimeoutSeconds
    ) async -> OTLPReceiverLifecycleSnapshot {
        lifecycleOperationsInProgress += 1
        defer { lifecycleOperationsInProgress -= 1 }
        // Ordering is load-bearing: callback admission closes before any handle
        // is cancelled or detached from ownership.
        callbackTasks.sealAndCancel()
        connections.sealAndCancel()
        bodyTasks.sealAndCancel()
        listeners.sealAndCancel()
        startingGate?.cancel()
        startingGate = nil
        startingListener = nil
        listener = nil
        let joined = await joinOwnedWork(deadline: joinTimeoutSeconds)
        // Reassert this caller's result immediately before taking its return
        // snapshot. Concurrent signal/reload stop callers may be awaiting the
        // same owned prefix with a different deadline.
        lastShutdownClean = joined
        let snapshot = lifecycleSnapshot()
        if joined, snapshot.cleanlyStopped {
            logger.notice("OTLPReceiver stopped cleanly")
        } else {
            logger.error(
                "OTLPReceiver stop was unclean: \(snapshot.activeListeners, privacy: .public) listener(s), \(snapshot.activeConnections, privacy: .public) connection(s), \(snapshot.callbackTasksInFlight, privacy: .public) callback task(s), \(snapshot.bodyTasksInFlight, privacy: .public) body task(s), \(snapshot.lifecycleOperationsInProgress, privacy: .public) lifecycle operation(s) in progress"
            )
        }
        return snapshot
    }

    private func joinOwnedWork(deadline: TimeInterval) async -> Bool {
        async let listenersJoined = listeners.waitForDrain(deadline: deadline)
        async let connectionsJoined = connections.waitForDrain(deadline: deadline)
        async let callbackTasksJoined = callbackTasks.shutdown(deadline: deadline)
        async let bodyTasksJoined = bodyTasks.shutdown(deadline: deadline)
        let (listenerResult, connectionResult, callbackResult, bodyResult) = await (
            listenersJoined,
            connectionsJoined,
            callbackTasksJoined,
            bodyTasksJoined
        )
        let clean = listenerResult
            && connectionResult
            && callbackResult
            && bodyResult
        lastShutdownClean = clean
        if !clean { shutdownTimeouts &+= 1 }
        return clean
    }

    // MARK: - Connection handling

    /// The only permitted bridge from a Network.framework/dispatch callback to
    /// actor-isolated bookkeeping. Admission publishes the task handle before
    /// it can run; shutdown seals and bounded-joins this ledger.
    @discardableResult
    nonisolated private func submitCallbackActorHop(
        _ operation: @escaping @Sendable () async -> Void
    ) -> Bool {
        callbackTasks.submit(operation)
    }

    nonisolated private func handleNewConnection(_ entry: ConnectionRegistry.Entry) {
        let conn = entry.connection
        let connectionID = entry.id
        // Stop may have synchronously detached/cancelled this connection while
        // Network.framework was delivering the callback. The registry is the
        // authority for whether any network work may begin.
        guard connections.contains(connectionID) else {
            conn.cancel()
            return
        }
        let connectionRegistry = connections
        conn.stateUpdateHandler = { state in
            switch state {
            case .cancelled, .failed:
                connectionRegistry.complete(connectionID)
            default:
                break
            }
        }
        // v1.9 audit (Phase-1.1): a class-wrapped buffer keeps the
        // accumulator mutable across closure-captures so chunk appends
        // are amortized O(1) instead of the prior recursive
        // `var combined = accumulated; append; recurse` pattern that
        // copy-on-wrote the full prefix per chunk (O(N²)).
        // Buffer also carries the per-connection slow-loris deadline
        // (Phase-1.4) — a oneshot timer cancels the connection if the
        // full request hasn't been read by then.
        entry.buffer.startDeadline(
            on: conn,
            connectionID: connectionID,
            connectionGeneration: entry.generation,
            after: Self.connectionDeadlineSeconds,
            receiver: self
        )
        guard connectionRegistry.start(
            connectionID,
            queue: .global(qos: .utility)
        ) else {
            entry.buffer.seal()
            conn.cancel()
            return
        }
        Self.receiveRequestHead(on: conn, buffer: entry.buffer, receiver: self)
    }

    private func recordNonLoopbackRejection(generation: UInt64) {
        guard connections.isAccepting(generation: generation) else { return }
        metrics.requestsRejectedNonLoopback &+= 1
    }

    private func recordConnectionCapacityRejection(generation: UInt64) {
        guard connections.isAccepting(generation: generation) else { return }
        metrics.requestsBadRequest &+= 1
        logger.warning(
            "OTLPReceiver: connection cap reached (\(Self.maxConcurrentConnections, privacy: .public)) — refusing"
        )
    }

    fileprivate func connectionDeadlineDidFire(
        _ connectionID: UInt64,
        generation: UInt64
    ) {
        // A deadline callback already queued when stop cancelled its timer must
        // not mutate post-shutdown telemetry or claim a stop-induced cancel was
        // a slow-loris expiry.
        guard connections.isAccepting(generation: generation) else { return }
        metrics.connectionDeadlineExceeded &+= 1
        logger.debug("connection \(connectionID, privacy: .public) deadline exceeded")
    }

    nonisolated private func respondIfConnectionIsActive(
        _ conn: NWConnection,
        connectionID: UInt64,
        result: OTLPReceiverIngestResult
    ) {
        guard !Task.isCancelled,
              connections.performIfActive(connectionID, {
                Self.respond(conn, status: result.status, body: result.body)
              }) else {
            conn.cancel()
            return
        }
    }

    /// Reference-typed scratch buffer for one connection. Captured by
    /// reference into NWConnection callbacks so mutations are in-place.
    /// Marked `@unchecked Sendable` because NWConnection serialises its
    /// own `receive` callbacks for a given connection — there's no concurrent
    /// mutation of `data` on the main path. Deadline state is separately
    /// lock-protected because its timer fires on another queue; receive
    /// callbacks observe `timedOut` and bail without touching `data`.
    fileprivate final class ConnectionBuffer: @unchecked Sendable {
        let connectionID: UInt64
        let connectionGeneration: UInt64
        var data = Data()
        private let deadlineLock = NSLock()
        private var deadlineTimer: DispatchSourceTimer?
        private var didTimeOut = false
        private var isSealed = false

        var inactive: Bool {
            deadlineLock.withLock { didTimeOut || isSealed }
        }

        init(connectionID: UInt64, connectionGeneration: UInt64) {
            self.connectionID = connectionID
            self.connectionGeneration = connectionGeneration
        }

        /// v1.9.0 (audit Stab-M3): defensive deinit. Apple's
        /// DispatchSourceTimer requires `cancel()` before deallocating
        /// a non-suspended timer, otherwise the process aborts. Every
        /// observable exit path already calls `cancelDeadline()`, but
        /// a future code change that misses one would crash on dealloc.
        /// `cancel()` is idempotent — safe to call after a prior cancel.
        deinit {
            cancelDeadline()
        }

        func startDeadline(
            on conn: NWConnection,
            connectionID: UInt64,
            connectionGeneration: UInt64,
            after seconds: Double,
            receiver: OTLPReceiver
        ) {
            let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
            timer.schedule(deadline: .now() + seconds)
            timer.setEventHandler { [weak self, weak conn, weak receiver] in
                guard let self else { return }
                let shouldFire = self.deadlineLock.withLock {
                    guard self.deadlineTimer != nil,
                          !self.didTimeOut,
                          !self.isSealed else {
                        return false
                    }
                    self.didTimeOut = true
                    return true
                }
                guard shouldFire else { return }
                receiver?.submitCallbackActorHop { [weak receiver] in
                    guard !Task.isCancelled else { return }
                    await receiver?.connectionDeadlineDidFire(
                        connectionID,
                        generation: connectionGeneration
                    )
                }
                conn?.cancel()
            }
            deadlineLock.withLock {
                didTimeOut = false
                deadlineTimer = timer
            }
            timer.resume()
        }

        /// Cancel the timer when we hand the body off to handleBody —
        /// the work after that is decode/persist, not network-bound.
        func cancelDeadline() {
            let timer: DispatchSourceTimer? = deadlineLock.withLock {
                let result = deadlineTimer
                deadlineTimer = nil
                return result
            }
            timer?.cancel()
        }

        /// Terminal connection ownership seals the parser as well as its
        /// timer. A receive completion that was already queued when shutdown
        /// cancelled the socket can then neither recurse into another receive
        /// nor send a response after the clean-stop boundary.
        func seal() {
            let timer: DispatchSourceTimer? = deadlineLock.withLock {
                isSealed = true
                let result = deadlineTimer
                deadlineTimer = nil
                return result
            }
            timer?.cancel()
        }
    }

    /// Public accessor used by tests to assert the loopback-check
    /// implementation matches the documented contract.
    public static func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        switch endpoint {
        case let .hostPort(host, _):
            switch host {
            case .ipv4(let v4):
                return v4.isLoopback
            case .ipv6(let v6):
                return v6.isLoopback
            case .name(let name, _):
                return name == "localhost"
            @unknown default:
                return false
            }
        default:
            return false
        }
    }

    /// Recursively read until we have a full request head (terminated by
    /// `\r\n\r\n`) plus the declared Content-Length body, then dispatch.
    /// Stays off-actor so the NWConnection callbacks don't block on
    /// every chunk. Hops to `receiver` only when it needs to mutate metrics.
    /// v1.9 audit (Phase-1.1): buffer is a class so chunk appends are
    /// in-place — was recursive value-copy before, O(N²).
    nonisolated private static func receiveRequestHead(
        on conn: NWConnection,
        buffer: ConnectionBuffer,
        receiver: OTLPReceiver
    ) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
            if buffer.inactive { return }
            if let error {
                receiver.submitCallbackActorHop { [weak receiver] in
                    guard !Task.isCancelled else { return }
                    await receiver?.completeWithLog(
                        "recv head failed: \(error)",
                        generation: buffer.connectionGeneration
                    )
                }
                buffer.cancelDeadline()
                conn.cancel()
                return
            }
            guard let chunk = data, !chunk.isEmpty else {
                if isComplete {
                    buffer.cancelDeadline()
                    conn.cancel()
                }
                return
            }
            buffer.data.append(chunk)
            if buffer.data.count > 256 * 1024 {
                receiver.submitCallbackActorHop { [weak receiver] in
                    guard !Task.isCancelled else { return }
                    await receiver?.bumpBadRequest(
                        "request head too large",
                        generation: buffer.connectionGeneration
                    )
                }
                buffer.cancelDeadline()
                Self.respond(conn, status: 413, body: "head too large")
                return
            }
            if let headEnd = Self.findHeadEnd(in: buffer.data) {
                let head = buffer.data.subdata(in: 0..<headEnd)
                // Reset buffer to whatever bytes already follow the
                // CRLF CRLF — those are the start of the body.
                let bodyPrefix = buffer.data.subdata(in: (headEnd + 4)..<buffer.data.count)
                buffer.data = bodyPrefix
                Self.processRequest(conn: conn, head: head, buffer: buffer, receiver: receiver)
            } else {
                Self.receiveRequestHead(on: conn, buffer: buffer, receiver: receiver)
            }
        }
    }

    nonisolated private static func findHeadEnd(in data: Data) -> Int? {
        guard data.count >= 4 else { return nil }
        for i in 0..<(data.count - 3) {
            if data[i] == 0x0D, data[i+1] == 0x0A, data[i+2] == 0x0D, data[i+3] == 0x0A {
                return i
            }
        }
        return nil
    }

    nonisolated private static func processRequest(
        conn: NWConnection,
        head: Data,
        buffer: ConnectionBuffer,
        receiver: OTLPReceiver
    ) {
        guard let headStr = String(data: head, encoding: .utf8) else {
            receiver.submitCallbackActorHop { [weak receiver] in
                guard !Task.isCancelled else { return }
                await receiver?.bumpBadRequest(
                    "non-utf8 head",
                    generation: buffer.connectionGeneration
                )
            }
            buffer.cancelDeadline()
            Self.respond(conn, status: 400, body: "bad request")
            return
        }
        let lines = headStr.split(separator: "\r\n", omittingEmptySubsequences: false).map(String.init)
        guard let requestLine = lines.first else {
            receiver.submitCallbackActorHop { [weak receiver] in
                guard !Task.isCancelled else { return }
                await receiver?.bumpBadRequest(
                    "empty head",
                    generation: buffer.connectionGeneration
                )
            }
            buffer.cancelDeadline()
            Self.respond(conn, status: 400, body: "bad request")
            return
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else {
            receiver.submitCallbackActorHop { [weak receiver] in
                guard !Task.isCancelled else { return }
                await receiver?.bumpBadRequest(
                    "bad request line",
                    generation: buffer.connectionGeneration
                )
            }
            buffer.cancelDeadline()
            Self.respond(conn, status: 400, body: "bad request")
            return
        }
        let method = parts[0]
        let path = parts[1]
        guard method == "POST", path == "/v1/traces" else {
            buffer.cancelDeadline()
            Self.respond(conn, status: 404, body: "not found")
            return
        }

        var contentLength = 0
        var contentType = ""
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            if let colon = line.firstIndex(of: ":") {
                let name = String(line[..<colon]).lowercased()
                let value = line[line.index(after: colon)...]
                    .trimmingCharacters(in: .whitespaces)
                switch name {
                case "content-length":
                    contentLength = Int(value) ?? 0
                case "content-type":
                    contentType = value.lowercased()
                default:
                    break
                }
            }
        }

        if contentLength <= 0 {
            receiver.submitCallbackActorHop { [weak receiver] in
                guard !Task.isCancelled else { return }
                await receiver?.bumpBadRequest(
                    "no content-length",
                    generation: buffer.connectionGeneration
                )
            }
            buffer.cancelDeadline()
            Self.respond(conn, status: 411, body: "length required")
            return
        }
        if contentLength > Self.maxBodyBytes {
            receiver.submitCallbackActorHop { [weak receiver] in
                guard !Task.isCancelled else { return }
                await receiver?.bumpBadRequest(
                    "content-length too large",
                    generation: buffer.connectionGeneration
                )
            }
            buffer.cancelDeadline()
            Self.respond(conn, status: 413, body: "payload too large")
            return
        }
        if !contentType.contains("application/x-protobuf")
            && !contentType.contains("application/protobuf") {
            receiver.submitCallbackActorHop { [weak receiver] in
                guard !Task.isCancelled else { return }
                await receiver?.bumpBadRequest(
                    "unsupported content-type",
                    generation: buffer.connectionGeneration
                )
            }
            buffer.cancelDeadline()
            Self.respond(conn, status: 415, body: "unsupported media type")
            return
        }

        Self.accumulateBody(
            conn: conn,
            buffer: buffer,
            remaining: contentLength - buffer.data.count,
            receiver: receiver
        )
    }

    /// v1.9 audit (Phase-1.1, Phase-1.5): in-place chunk append into the
    /// class-wrapped buffer (avoid O(N²) value copies); strict body-cap
    /// enforcement against `maxBodyBytes` even if the peer's
    /// Content-Length header lied.
    nonisolated private static func accumulateBody(
        conn: NWConnection,
        buffer: ConnectionBuffer,
        remaining: Int,
        receiver: OTLPReceiver
    ) {
        if remaining <= 0 {
            // Body fully received — hand off to decode. Cancel the
            // slow-loris deadline so the decode/persist phase doesn't
            // race the timer.
            buffer.cancelDeadline()
            Self.handleBody(
                conn: conn,
                connectionID: buffer.connectionID,
                body: buffer.data,
                receiver: receiver
            )
            return
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, _, error in
            if buffer.inactive { return }
            if let error {
                receiver.submitCallbackActorHop { [weak receiver] in
                    guard !Task.isCancelled else { return }
                    await receiver?.completeWithLog(
                        "recv body failed: \(error)",
                        generation: buffer.connectionGeneration
                    )
                }
                buffer.cancelDeadline()
                conn.cancel()
                return
            }
            guard let chunk = data, !chunk.isEmpty else {
                buffer.cancelDeadline()
                conn.cancel()
                return
            }
            buffer.data.append(chunk)
            // v1.9 audit Phase-1.5: even if Content-Length lied, hard
            // cap the accumulator. Otherwise a peer claiming a small
            // length could keep streaming bytes that grow `data` past
            // 8 MiB.
            if buffer.data.count > Self.maxBodyBytes {
                receiver.submitCallbackActorHop { [weak receiver] in
                    guard !Task.isCancelled else { return }
                    await receiver?.bumpBadRequest(
                        "body exceeded maxBodyBytes during recv",
                        generation: buffer.connectionGeneration
                    )
                }
                buffer.cancelDeadline()
                Self.respond(conn, status: 413, body: "payload too large")
                return
            }
            Self.accumulateBody(
                conn: conn,
                buffer: buffer,
                remaining: remaining - chunk.count,
                receiver: receiver
            )
        }
    }

    nonisolated private static func handleBody(
        conn: NWConnection,
        connectionID: UInt64,
        body: Data,
        receiver: OTLPReceiver
    ) {
        receiver.submitBodyProcessing(
            conn: conn,
            connectionID: connectionID,
            body: body
        )
    }

    nonisolated private func submitBodyProcessing(
        conn: NWConnection,
        connectionID: UInt64,
        body: Data
    ) {
        guard connections.contains(connectionID) else {
            bodyTasks.recordRejected()
            conn.cancel()
            return
        }
        let accepted = bodyTasks.submit { [weak self, weak conn] in
            guard let self, let conn else { return }
            let result = await self.processBody(body)
            self.respondIfConnectionIsActive(
                conn,
                connectionID: connectionID,
                result: result
            )
        }
        guard accepted else {
            conn.cancel()
            return
        }
    }

    /// Full buffered-body pipeline shared by the live socket and deterministic
    /// tests. Storage admission runs once before protobuf decode and again with
    /// the exact decoded records before persistence; TraceStore repeats the
    /// latter centrally inside `insertSpans`.
    /// Internal test seam. Keeping this out of the public product API prevents
    /// callers from bypassing listener/body-task admission and creating work
    /// that `stop()` cannot own.
    func ingestBodyForTesting(_ body: Data) async -> OTLPReceiverIngestResult {
        await processBody(body)
    }

    private func processBody(_ body: Data) async -> OTLPReceiverIngestResult {
        guard !Task.isCancelled else {
            return OTLPReceiverIngestResult(status: 503, body: "receiver stopping")
        }
        recordBody(body)
        // v1.21.5 (audit S-04): bound unauthenticated local traffic by rate.
        guard admitIngest(bytes: body.count) else {
            return OTLPReceiverIngestResult(status: 429, body: "ingest budget exceeded")
        }

        // Ask the actor-owned store BEFORE allocating the decoded protobuf
        // graph. A pressure-blocked store rejects even malformed input as 507,
        // proving decode cannot become a pressure-side CPU/memory bypass.
        if let traceStore {
            do {
                try await traceStore.preflightStorageAdmission(
                    estimatedGrowthBytes: Int64(body.count)
                )
                guard !Task.isCancelled else {
                    return OTLPReceiverIngestResult(
                        status: 503,
                        body: "receiver stopping"
                    )
                }
            } catch is CancellationError {
                return OTLPReceiverIngestResult(
                    status: 503,
                    body: "receiver stopping"
                )
            } catch let pressure as TraceStoreStorageAdmissionError {
                recordSpanInsertError(pressure.localizedDescription)
                return OTLPReceiverIngestResult(status: 507, body: "storage pressure")
            } catch {
                recordSpanInsertError("storage preflight: \(error)")
                return OTLPReceiverIngestResult(status: 500, body: "storage unavailable")
            }
        }

        let decoded: (OTLPTracesSummary, OTLPSpanExtractionResult)
        do {
            // v1.9 audit Phase-1.3: promptly release decoder/sanitizer
            // temporaries for bursty requests.
            decoded = try autoreleasepool {
                let groups = try OTLPNestedDecoder.decodeRequest(body)
                return (
                    OTLPTracesSummary(
                        resourceSpansCount: groups.count,
                        bytesParsed: body.count
                    ),
                    OTLPSpanExtractor.extract(from: groups)
                )
            }
        } catch {
            bumpDecodeError("\(error)")
            return OTLPReceiverIngestResult(status: 400, body: "bad protobuf")
        }

        let (summary, extraction) = decoded
        recordAccept(summary)
        recordSanitisation(
            keyRedacted: extraction.totalAttributesKeyRedacted,
            valueRedacted: extraction.totalAttributesValueRedacted
        )
        guard let traceStore else {
            return OTLPReceiverIngestResult(status: 200, body: "")
        }

        let valid = extraction.spans.filter {
            $0.traceId.count == 32 && $0.spanId.count == 16
        }
        guard !Task.isCancelled else {
            return OTLPReceiverIngestResult(status: 503, body: "receiver stopping")
        }
        do {
            // Receiver-level exact decoded-batch gate, then the store repeats
            // it immediately before BEGIN so no alternate writer can bypass it.
            try await traceStore.preflightInsertSpans(valid)
            guard !Task.isCancelled else {
                return OTLPReceiverIngestResult(
                    status: 503,
                    body: "receiver stopping"
                )
            }
            let result = try await traceStore.insertSpans(valid)
            for _ in 0..<result.succeeded { recordSpanPersisted() }
            for _ in 0..<result.failed {
                recordSpanInsertError("batch insert: row failed")
            }
            return OTLPReceiverIngestResult(status: 200, body: "")
        } catch is CancellationError {
            return OTLPReceiverIngestResult(status: 503, body: "receiver stopping")
        } catch let pressure as TraceStoreStorageAdmissionError {
            for _ in 0..<max(1, valid.count) {
                recordSpanInsertError(pressure.localizedDescription)
            }
            return OTLPReceiverIngestResult(status: 507, body: "storage pressure")
        } catch {
            for _ in 0..<max(1, valid.count) {
                recordSpanInsertError("\(error)")
            }
            return OTLPReceiverIngestResult(status: 500, body: "storage unavailable")
        }
    }

    // MARK: - Metric helpers (actor-isolated counters)

    private func recordBody(_ body: Data) {
        metrics.bytesReceived &+= UInt64(body.count)
    }

    private func recordAccept(_ summary: OTLPTracesSummary) {
        metrics.requestsAccepted &+= 1
        metrics.resourceSpansSeen &+= UInt64(summary.resourceSpansCount)
    }

    private func bumpBadRequest(_ reason: String, generation: UInt64) {
        guard connections.isAccepting(generation: generation) else { return }
        metrics.requestsBadRequest &+= 1
        logger.debug("400: \(reason, privacy: .public)")
    }

    private func bumpDecodeError(_ reason: String) {
        metrics.bodyDecodeErrors &+= 1
        logger.debug("decode error: \(reason, privacy: .public)")
    }

    private func recordSanitisation(keyRedacted: Int, valueRedacted: Int) {
        metrics.attributesKeyRedacted &+= UInt64(keyRedacted)
        metrics.attributesValueRedacted &+= UInt64(valueRedacted)
    }

    private func recordSpanPersisted() {
        metrics.spansPersisted &+= 1
    }

    private func recordSpanInsertError(_ reason: String) {
        metrics.spanInsertErrors &+= 1
        logger.debug("span insert error: \(reason, privacy: .public)")
    }

    /// Accessor for the optional store. Read-only — the receiver never
    /// rebinds the store at runtime; PR-4's "Receive agent traces"
    /// toggle starts/stops the receiver wholesale.
    private func storeRef() -> TraceStore? { traceStore }

    private func completeWithLog(_ msg: String, generation: UInt64) {
        guard connections.isAccepting(generation: generation) else { return }
        logger.debug("\(msg, privacy: .public)")
    }

    // MARK: - HTTP response

    nonisolated private static func respond(_ conn: NWConnection, status: Int, body: String) {
        let reason: String
        switch status {
        case 200: reason = "OK"
        case 400: reason = "Bad Request"
        case 404: reason = "Not Found"
        case 411: reason = "Length Required"
        case 413: reason = "Payload Too Large"
        case 415: reason = "Unsupported Media Type"
        case 429: reason = "Too Many Requests"
        case 500: reason = "Internal Server Error"
        case 503: reason = "Service Unavailable"
        case 507: reason = "Insufficient Storage"
        default:  reason = "Error"
        }
        let bodyBytes = Array(body.utf8)
        let headers = """
        HTTP/1.1 \(status) \(reason)\r
        Content-Length: \(bodyBytes.count)\r
        Content-Type: text/plain; charset=utf-8\r
        Connection: close\r
        \r

        """
        var out = Data(headers.utf8)
        out.append(Data(bodyBytes))
        conn.send(content: out, completion: .contentProcessed { _ in
            conn.cancel()
        })
    }
}
