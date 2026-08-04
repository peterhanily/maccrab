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
    private var accepting = true
    private var shutdownResult: Bool?
    private var shutdownWaiters: [CheckedContinuation<Bool, Never>] = []
    private let logger = Logger(subsystem: "com.maccrab.agent", category: "MonitorSupervisor")

    public init() {}

    /// Start (or replace) a named supervised task.
    ///
    /// If a task with the same name is already running, it is cancelled
    /// first. The caller's closure runs inside the new `Task`; when that
    /// `Task` is cancelled (by `shutdown()` or another `start` with the
    /// same name), any `for await` loop inside it exits at the next
    /// iteration boundary.
    /// v1.21.6 (RES-11): `collector` + `registry` are optional liveness wiring.
    /// When both are supplied and the body RETURNS without the task having been
    /// cancelled, the monitor's `for await` loop ended — i.e. the collector's
    /// AsyncStream finished — and the collector is recorded dead in the registry.
    /// This is the only signal that distinguishes "quiet" from "gone" for the 13
    /// collectors that are not routed through `DaemonState.driveSource`; it costs
    /// nothing while they are alive because the body never returns.
    ///
    /// The `!Task.isCancelled` gate is load-bearing: `shutdown()` cancels every
    /// task, which is a normal loop exit and must not be reported as a fault.
    @discardableResult
    public func start(
        _ name: String,
        collector: String? = nil,
        registry: CollectorRegistry? = nil,
        _ work: @escaping @Sendable () async -> Void
    ) async -> Bool {
        guard accepting else {
            logger.warning("MonitorSupervisor: refusing \(name, privacy: .public) after shutdown began")
            return false
        }
        if let previous = tasks[name] {
            previous.cancel()
            let joined = await BoundedTaskJoin.waitForAll(
                [previous],
                deadline: 0.5
            )
            guard joined else {
                logger.fault("MonitorSupervisor: refusing replacement for \(name, privacy: .public); prior task did not join")
                return false
            }
            guard accepting else {
                logger.warning("MonitorSupervisor: refusing \(name, privacy: .public); shutdown began during replacement join")
                return false
            }
        }
        tasks[name] = Task {
            await work()
            if !Task.isCancelled, let collector, let registry {
                await registry.recordStreamEnded(name: collector)
            }
        }
        return true
    }

    /// Cancel every tracked task and await their completion, bounded by
    /// `deadline` seconds. Returns when either every cancelled task has
    /// finished unwinding or the deadline fires — whichever comes first.
    ///
    /// Callers should invoke from the SIGTERM / SIGINT handler before
    /// `exit()`. After this returns, `tasks` is empty and subsequent
    /// `start` calls are silently ignored — the supervisor is one-shot
    /// with respect to shutdown.
    @discardableResult
    public func shutdown(deadline: TimeInterval = 3.0) async -> Bool {
        if let shutdownResult { return shutdownResult }
        if !accepting {
            return await withCheckedContinuation { continuation in
                shutdownWaiters.append(continuation)
            }
        }
        accepting = false
        let count = tasks.count
        guard count > 0 else {
            shutdownResult = true
            return true
        }

        logger.info("MonitorSupervisor: cancelling \(count) supervised tasks (deadline \(deadline)s)")
        let stored = Array(tasks.values)
        for task in stored { task.cancel() }

        // One completion means nothing when N-1 producers are still live. The
        // shared join races ALL stored task values against the deadline without
        // structured-task-group teardown accidentally waiting forever.
        let allStopped = await BoundedTaskJoin.waitForAll(
            stored,
            deadline: max(0, deadline)
        )
        tasks.removeAll()
        shutdownResult = allStopped
        let waiters = shutdownWaiters
        shutdownWaiters.removeAll(keepingCapacity: false)
        for waiter in waiters { waiter.resume(returning: allStopped) }
        if allStopped {
            logger.info("MonitorSupervisor: all monitored tasks stopped")
        } else {
            logger.warning("MonitorSupervisor: shutdown deadline expired with one or more monitored tasks still unwinding")
        }
        return allStopped
    }

    /// Number of currently-supervised tasks. Diagnostic only.
    public func activeCount() -> Int { tasks.count }
}
