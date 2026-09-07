import Foundation

/// Shared only by the two optional registry enrichers. Bounds retained results
/// and active loads independently; at most 16 callers share each active load.
/// Charged bytes are payload-based accounting, not measured process RSS.
actor PackageEnrichmentCache<Value: Sendable> {
    struct Loaded: Sendable {
        let value: Value
        let payloadBytes: Int
    }

    struct Snapshot: Sendable {
        let entries: Int
        let chargedBytes: Int
        let activeLoads: Int
        let waitingCalls: Int
        let coalesced: UInt64
        let saturated: UInt64
        let cancelledLoads: UInt64
    }

    private struct Entry {
        let value: Value
        let expires: ContinuousClock.Instant
        let cost: Int
        var access: UInt64
    }

    /// Cancellation is recorded synchronously, before its actor cleanup task can
    /// run, so a queued completion cannot cache an already-abandoned result.
    private final class Cancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var cancelled = false
        func cancel() { lock.lock(); defer { lock.unlock() }; cancelled = true }
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    }

    private struct Waiter {
        let continuation: CheckedContinuation<Value?, Never>
        let cancellation: Cancellation
    }

    private struct Load {
        let generation: UUID
        let task: Task<Void, Never>
        var waiters: [UUID: Waiter]
        var abandoned = false
    }

    private var entries: [String: Entry] = [:]
    private var active: [String: Load] = [:]
    private var chargedBytes = 0
    private var access: UInt64 = 0
    private var coalesced: UInt64 = 0
    private var saturated: UInt64 = 0
    private var cancelledLoads: UInt64 = 0
    private let capacity: Int
    private let maximumBytes: Int
    private let maximumActive: Int
    private let maximumWaiters: Int
    private let ttl: Duration
    private let now: @Sendable () -> ContinuousClock.Instant
    private let observe: (@Sendable (Snapshot) -> Void)?

    init(ttl: TimeInterval, capacity: Int = 128, maximumBytes: Int = 8 * 1024 * 1024,
         maximumActive: Int = 4, maximumWaiters: Int = 16,
         now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
         observe: (@Sendable (Snapshot) -> Void)? = nil) {
        self.capacity = max(1, min(capacity, 1024))
        self.maximumBytes = max(0, min(maximumBytes, 64 * 1024 * 1024))
        self.maximumActive = max(1, min(maximumActive, 16))
        self.maximumWaiters = max(1, min(maximumWaiters, 64))
        self.ttl = .seconds(ttl.isFinite ? max(0, ttl) : 0)
        self.now = now
        self.observe = observe
    }

    func snapshot() -> Snapshot {
        expire()
        return currentSnapshot()
    }

    private func currentSnapshot() -> Snapshot {
        Snapshot(entries: entries.count, chargedBytes: chargedBytes, activeLoads: active.count,
                 waitingCalls: active.values.reduce(0) { $0 + $1.waiters.count },
                 coalesced: coalesced, saturated: saturated, cancelledLoads: cancelledLoads)
    }

    private func expire() {
        let instant = now()
        for (key, entry) in entries where entry.expires <= instant {
            entries.removeValue(forKey: key)
            chargedBytes -= entry.cost
        }
    }

    func value(for key: String, load: @escaping @Sendable () async -> Loaded?) async -> Value? {
        guard !Task.isCancelled else { return nil }
        expire()
        access = access == .max ? .max : access + 1
        if var entry = entries[key] {
            entry.access = access
            entries[key] = entry
            return Task.isCancelled ? nil : entry.value
        }

        let waiter = UUID()
        let cancellation = Cancellation()
        let result = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                admit(key: key, waiter: waiter, continuation: continuation,
                      cancellation: cancellation, load: load)
            }
        } onCancel: {
            cancellation.cancel()
            Task { await self.cancel(key: key, waiter: waiter) }
        }
        return Task.isCancelled ? nil : result
    }

    private func admit(key: String, waiter: UUID, continuation: CheckedContinuation<Value?, Never>,
                       cancellation: Cancellation, load: @escaping @Sendable () async -> Loaded?) {
        guard !Task.isCancelled, !cancellation.isCancelled else { continuation.resume(returning: nil); return }
        if var running = active[key] {
            // An abandoned request retains its slot until it actually settles.
            // New callers cannot revive it or start overlapping replacement IO.
            if !running.abandoned, !running.waiters.values.contains(where: { !$0.cancellation.isCancelled }) {
                running.abandoned = true
                cancelledLoads = cancelledLoads == .max ? .max : cancelledLoads + 1
                running.task.cancel()
                active[key] = running
            }
            guard !running.abandoned, !running.task.isCancelled,
                  running.waiters.count < maximumWaiters else {
                saturated = saturated == .max ? .max : saturated + 1
                observe?(currentSnapshot())
                continuation.resume(returning: nil)
                return
            }
            running.waiters[waiter] = Waiter(continuation: continuation, cancellation: cancellation)
            active[key] = running
            coalesced = coalesced == .max ? .max : coalesced + 1
            observe?(currentSnapshot())
            return
        }
        guard active.count < maximumActive else {
            saturated = saturated == .max ? .max : saturated + 1
            observe?(currentSnapshot())
            continuation.resume(returning: nil)
            return
        }

        let generation = UUID()
        let task = Task {
            let hasCaller = active[key]?.waiters.values.contains(where: { !$0.cancellation.isCancelled }) == true
            let loaded: Loaded?
            if Task.isCancelled || !hasCaller { loaded = nil }
            else { loaded = await load() }
            finish(key: key, generation: generation, result: Task.isCancelled ? nil : loaded)
        }
        active[key] = Load(generation: generation, task: task,
                           waiters: [waiter: Waiter(continuation: continuation, cancellation: cancellation)])
        observe?(currentSnapshot())
    }

    private func cancel(key: String, waiter: UUID) {
        guard var running = active[key], let removed = running.waiters.removeValue(forKey: waiter) else { return }
        if !running.abandoned, !running.waiters.values.contains(where: { !$0.cancellation.isCancelled }) {
            running.abandoned = true
            cancelledLoads = cancelledLoads == .max ? .max : cancelledLoads + 1
            running.task.cancel()
        }
        active[key] = running
        observe?(currentSnapshot())
        removed.continuation.resume(returning: nil)
    }

    private func finish(key: String, generation: UUID, result: Loaded?) {
        guard var running = active[key], running.generation == generation else { return }
        active.removeValue(forKey: key)
        expire()
        if !running.abandoned, !running.waiters.values.contains(where: { !$0.cancellation.isCancelled }) {
            running.abandoned = true
            cancelledLoads = cancelledLoads == .max ? .max : cancelledLoads + 1
        }
        let accepted = running.abandoned || running.task.isCancelled ? nil : result
        if let result = accepted, ttl > .zero {
            // Four payload bytes charged per response byte plus key/entry
            // overhead. Oversized results are returned but never retained.
            let payload = max(0, result.payloadBytes).multipliedReportingOverflow(by: 4)
            let overhead = key.utf8.count.multipliedReportingOverflow(by: 2)
            let fixed = overhead.partialValue.addingReportingOverflow(512)
            let total = payload.partialValue.addingReportingOverflow(fixed.partialValue)
            if !payload.overflow && !overhead.overflow && !fixed.overflow && !total.overflow,
               total.partialValue <= maximumBytes {
                let cost = total.partialValue
                while entries.count >= capacity || chargedBytes > maximumBytes - cost {
                    guard let victim = entries.min(by: {
                        $0.value.access == $1.value.access ? $0.key < $1.key : $0.value.access < $1.value.access
                    }) else { break }
                    chargedBytes -= victim.value.cost
                    entries.removeValue(forKey: victim.key)
                }
                access = access == .max ? .max : access + 1
                entries[key] = Entry(value: result.value, expires: now().advanced(by: ttl), cost: cost, access: access)
                chargedBytes += cost
            }
        }
        observe?(currentSnapshot())
        for waiter in running.waiters.values {
            waiter.continuation.resume(returning: waiter.cancellation.isCancelled ? nil : accepted?.value)
        }
    }
}
