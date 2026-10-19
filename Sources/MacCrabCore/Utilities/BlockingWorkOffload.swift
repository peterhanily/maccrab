// BlockingWorkOffload.swift
// MacCrabCore
//
// Runs blocking system calls and child-process waits outside the Swift
// cooperative thread pool while the owning task awaits them.

import Foundation

/// Cancellation request forwarded from an owning task to blocking work that
/// runs outside Swift concurrency, where `Task.isCancelled` cannot be read.
final class BlockingWorkCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

/// Blocking work off the Swift cooperative pool.
///
/// That pool has one thread per CPU and serves every actor in the engine. A
/// `read(2)`, `FileHandle.availableData` or child-process wait inside a task
/// occupies one of its threads for as long as it blocks: a live RC12 sample
/// found the DNS and unified-log readers parked there for its entire 15-second
/// window, and subprocess waits parked others. The owning task stays joinable;
/// it is merely suspended, not holding a thread, while the blocking work runs.
enum BlockingWorkOffload {
    /// Run `body` to completion on its own thread and return its result. The
    /// awaiting task's cancellation is forwarded through the flag.
    static func runOnDedicatedThread<T: Sendable>(
        name: String,
        qualityOfService: QualityOfService = .default,
        _ body: @escaping @Sendable (BlockingWorkCancellation) -> T
    ) async -> T {
        let flag = BlockingWorkCancellation()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let thread = Thread {
                    continuation.resume(returning: body(flag))
                }
                thread.name = name
                thread.qualityOfService = qualityOfService
                thread.start()
            }
        } onCancel: {
            flag.cancel()
        }
    }

    /// Run one blocking call on `queue` and resume with its result, for loops
    /// that must otherwise remain async. `qos` with `.enforceQoS` lets a
    /// caller lift the work item above the queue's own class.
    static func perform<T: Sendable>(
        on queue: DispatchQueue,
        qos: DispatchQoS = .unspecified,
        flags: DispatchWorkItemFlags = [],
        _ body: @escaping @Sendable () -> T
    ) async -> T {
        await withCheckedContinuation { continuation in
            queue.async(qos: qos, flags: flags) {
                continuation.resume(returning: body())
            }
        }
    }

    /// Dispatch class for work a task of `priority` waits on, never below
    /// `floor`. Awaiting a lower-priority Task escalated it to the waiter;
    /// a dispatch work item gets the waiter's class only when asked.
    static func dispatchQoS(
        waitedOnAt priority: TaskPriority,
        floor: DispatchQoS.QoSClass
    ) -> DispatchQoS {
        let waiter: DispatchQoS.QoSClass
        switch priority.rawValue {
        case TaskPriority.high.rawValue...: waiter = .userInitiated
        case TaskPriority.medium.rawValue...: waiter = .default
        case TaskPriority.low.rawValue...: waiter = .utility
        default: waiter = .background
        }
        return DispatchQoS(
            qosClass: rank(waiter) >= rank(floor) ? waiter : floor,
            relativePriority: 0
        )
    }

    private static func rank(_ qos: DispatchQoS.QoSClass) -> Int {
        switch qos {
        case .background: return 0
        case .utility: return 1
        case .default, .unspecified: return 2
        case .userInitiated: return 3
        case .userInteractive: return 4
        @unknown default: return 2
        }
    }
}
