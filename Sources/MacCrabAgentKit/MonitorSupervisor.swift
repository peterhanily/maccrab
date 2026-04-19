// MonitorSupervisor.swift
//
// Tracks all long-running background monitor tasks the daemon spawns so a
// clean shutdown can cancel them and wait for their unwinding before the
// process calls exit(). Without this, SIGTERM (from launchd, sysextd, or
// Sparkle's "Install Update and Relaunch" flow) hits exit(0) immediately
// and leaves collectors mid-write against SQLite / mid-flight on the XPC
// wire. Not catastrophic today, but v1.4+ ships Sparkle, which makes
// shutdown a *frequent, user-visible* operation. Clean is the bar.
//
// Design notes:
// - Named slots keep diagnostics readable ("clipboard" vs "Task-0x1234")
//   and let a future call replace a stale task with the same name.
// - `shutdown()` races the set of cancelled tasks against a wall-clock
//   deadline so a pathological task that ignores cancellation (tight CPU
//   loop, uninterruptible syscall) can't block the daemon indefinitely.
// - Callers should write monitor bodies around `for await` loops; those
//   exit naturally when the enclosing Task is cancelled, so no explicit
//   `Task.checkCancellation()` is required inside the body.

import Foundation
import os.log

public actor MonitorSupervisor {

    private var tasks: [String: Task<Void, Never>] = [:]
    private let logger = Logger(subsystem: "com.maccrab.agent", category: "MonitorSupervisor")

    public init() {}

    /// Start (or replace) a named supervised task.
    ///
    /// If a task with the same name is already running, it is cancelled
    /// first. The caller's closure runs inside the new `Task`; when that
    /// `Task` is cancelled (by `shutdown()` or another `start` with the
    /// same name), any `for await` loop inside it exits at the next
    /// iteration boundary.
    public func start(_ name: String, _ work: @escaping @Sendable () async -> Void) {
        tasks[name]?.cancel()
        tasks[name] = Task {
            await work()
        }
    }

    /// Cancel every tracked task and await their completion, bounded by
    /// `deadline` seconds. Returns when either every cancelled task has
    /// finished unwinding or the deadline fires — whichever comes first.
    ///
    /// Callers should invoke from the SIGTERM / SIGINT handler before
    /// `exit()`. After this returns, `tasks` is empty and subsequent
    /// `start` calls are silently ignored — the supervisor is one-shot
    /// with respect to shutdown.
    public func shutdown(deadline: TimeInterval = 3.0) async {
        let count = tasks.count
        guard count > 0 else { return }

        logger.info("MonitorSupervisor: cancelling \(count) supervised tasks (deadline \(deadline)s)")
        let stored = Array(tasks.values)
        for task in stored { task.cancel() }

        // Race: either every task finishes unwinding, or the deadline fires.
        // `withTaskGroup` + `group.next()` completes on the first arrival;
        // `cancelAll()` then drops the losing siblings so they don't linger.
        let deadlineNs = UInt64(max(0, deadline) * 1_000_000_000)
        await withTaskGroup(of: Void.self) { group in
            for task in stored {
                group.addTask { _ = await task.value }
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: deadlineNs)
            }
            _ = await group.next()
            group.cancelAll()
        }
        tasks.removeAll()
        logger.info("MonitorSupervisor: shutdown complete")
    }

    /// Number of currently-supervised tasks. Diagnostic only.
    public func activeCount() -> Int { tasks.count }
}
