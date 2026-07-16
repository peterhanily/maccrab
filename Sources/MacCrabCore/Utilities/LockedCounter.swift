// LockedCounter.swift
// MacCrabCore
//
// Tiny thread-safe monotonic counter. Used where an actor is overkill —
// e.g. inside a DispatchSourceTimer event handler where the call site is
// synchronous and must not pay actor-hop latency.

import Foundation

public final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int = 0

    public init() {}

    /// Add `n` (e.g. a whole dropped batch) atomically. No-op for n <= 0.
    @discardableResult
    public func add(_ n: Int) -> Int {
        guard n > 0 else { return get() }
        lock.lock(); defer { lock.unlock() }
        value += n
        return value
    }

    @discardableResult
    public func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }

    public func get() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
