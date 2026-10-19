// CollectorLifecycleSupport.swift
// MacCrabCore
//
// Shared one-shot producer lifecycle primitives. Collector shutdown must be a
// bounded join, not "cancel and forget": cancellation is only a request and a
// blocking FileHandle, framework callback, or actor hop can outlive it.

import Foundation

/// Collector streams are one-shot. Once shutdown begins their continuation is
/// finished, so allowing a later start would advertise a producer whose events
/// can never be delivered.
enum CollectorLifecyclePhase: Sendable {
    case initialized
    case running
    case stopping
    case stopped
}

/// Resolves exactly once from either the owned-work waiter or its deadline.
/// A task-group timeout is not suitable here because leaving a task group still
/// waits for cancellation-uncooperative children.
private final class CollectorJoinDeadlineRace: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var resolved = false

    init(_ continuation: CheckedContinuation<Bool, Never>) {
        self.continuation = continuation
    }

    func resolve(_ value: Bool) {
        lock.lock()
        guard !resolved else {
            lock.unlock()
            return
        }
        resolved = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}

enum CollectorBoundedTaskJoin {
    static func waitForAll(
        _ tasks: [Task<Void, Never>],
        deadline: TimeInterval
    ) async -> Bool {
        guard !tasks.isEmpty else { return true }
        return await withCheckedContinuation { continuation in
            let race = CollectorJoinDeadlineRace(continuation)
            Task.detached(priority: .utility) {
                for task in tasks { await task.value }
                race.resolve(true)
            }
            let nanoseconds = UInt64(
                min(max(0, deadline) * 1_000_000_000, Double(UInt64.max))
            )
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .nanoseconds(Int(clamping: nanoseconds))
            ) {
                race.resolve(false)
            }
        }
    }
}

/// Owns tasks launched from DispatchSource/framework callbacks. Registration
/// closes synchronously before cancellation, so a callback already queued at
/// shutdown can only be rejected; an accepted prefix remains joinable.
final class CollectorCallbackTaskLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private let maximumInFlight: Int
    private var accepting = false
    private var nextID: UInt64 = 0
    private var tasks: [UInt64: Task<Void, Never>] = [:]

    init(maximumInFlight: Int = 32) {
        self.maximumInFlight = max(1, maximumInFlight)
    }

    func open() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard tasks.isEmpty else { return false }
        accepting = true
        return true
    }

    @discardableResult
    func submit(_ operation: @escaping @Sendable () async -> Void) -> Bool {
        lock.lock()
        guard accepting, tasks.count < maximumInFlight else {
            lock.unlock()
            return false
        }
        nextID &+= 1
        let id = nextID
        let task = Task(priority: .utility) { [weak self] in
            guard !Task.isCancelled else {
                self?.finish(id)
                return
            }
            await operation()
            self?.finish(id)
        }
        // Keep the lock through publication: a very short task may call finish
        // immediately, but cannot remove an ID before its handle is installed.
        tasks[id] = task
        lock.unlock()
        return true
    }

    private func finish(_ id: UInt64) {
        lock.lock()
        tasks.removeValue(forKey: id)
        lock.unlock()
    }

    @discardableResult
    func sealAndCancel() -> [Task<Void, Never>] {
        lock.lock()
        accepting = false
        let captured = Array(tasks.values)
        lock.unlock()
        for task in captured { task.cancel() }
        return captured
    }

    func shutdown(deadline: TimeInterval) async -> Bool {
        let captured = sealAndCancel()
        let joined = await CollectorBoundedTaskJoin.waitForAll(
            captured,
            deadline: deadline
        )
        return lock.withLock { joined && tasks.isEmpty }
    }
}

enum CollectorDispatchGroupJoin {
    static func wait(_ group: DispatchGroup, deadline: TimeInterval) async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let bounded = min(max(0, deadline), Double(Int.max) / 1_000_000_000)
                let result = group.wait(
                    timeout: .now() + .nanoseconds(Int(bounded * 1_000_000_000))
                )
                continuation.resume(returning: result == .success)
            }
        }
    }
}
