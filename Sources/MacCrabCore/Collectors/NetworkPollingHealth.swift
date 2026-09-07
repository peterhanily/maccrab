import Foundation

/// Poll completion is independent of whether a sweep discovers a new connection.
/// The collector owns all mutations; registry readers cannot manufacture progress.
public final class NetworkPollingHealth: @unchecked Sendable {
    public struct Snapshot: Sendable {
        public let started: Bool
        public let stopped: Bool
        public let lastCompletedAt: Date?
        public let completedPollCount: UInt64
        public let secondsSinceProgress: TimeInterval?
        public let errorCount: UInt64
        public let lastError: String?
        public let activeError: String?
    }

    private let lock = NSLock()
    private let now: @Sendable () -> Date
    private let monotonicNow: @Sendable () -> TimeInterval
    private var generation: UInt64 = 0
    private var started = false
    private var stopped = false
    private var progressTime: TimeInterval?
    private var lastCompletedAt: Date?
    private var completedPollCount: UInt64 = 0
    private var errorCount: UInt64 = 0
    private var lastError: String?
    private var activeError: String?

    init(now: @escaping @Sendable () -> Date = { Date() },
         monotonicNow: @escaping @Sendable () -> TimeInterval = {
             Foundation.ProcessInfo.processInfo.systemUptime
         }) {
        self.now = now
        self.monotonicNow = monotonicNow
    }

    /// A collector is one-shot. Stopping before start also seals this generation.
    func begin() -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        guard !started, !stopped else { return nil }
        generation &+= 1
        started = true
        progressTime = monotonicNow()
        return generation
    }

    func completed(generation expected: UInt64) {
        lock.lock(); defer { lock.unlock() }
        guard started, !stopped, generation == expected else { return }
        progressTime = monotonicNow()
        lastCompletedAt = now()
        completedPollCount &+= 1
        // A complete enumeration verifies recovery from an enumeration failure.
        // It does not clear independent errors held by CollectorRegistry.
        activeError = nil
    }

    func failed(generation expected: UInt64, message: String) {
        lock.lock(); defer { lock.unlock() }
        guard started, !stopped, generation == expected else { return }
        errorCount &+= 1
        lastError = String(message.prefix(200))
        activeError = lastError
    }

    func stop() {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return }
        stopped = true
        generation &+= 1
    }

    public func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(
            started: started, stopped: stopped,
            lastCompletedAt: lastCompletedAt, completedPollCount: completedPollCount,
            secondsSinceProgress: progressTime.map { max(0, monotonicNow() - $0) },
            errorCount: errorCount, lastError: lastError, activeError: activeError
        )
    }
}
