import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

private actor DaemonLifecycleBlockingGate {
    private var entered = false
    private var released = false
    private var enterWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func runIgnoringCancellation() async {
        entered = true
        let starts = enterWaiters
        enterWaiters.removeAll(keepingCapacity: false)
        for waiter in starts { waiter.resume() }
        guard !released else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { continuation in
            enterWaiters.append(continuation)
        }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll(keepingCapacity: false)
        for waiter in waiters { waiter.resume() }
    }
}

@Suite("Daemon lifecycle joins")
struct DaemonLifecycleTests {
    private actor Probe {
        private(set) var entered: Set<String> = []
        private(set) var completed: Set<String> = []

        func markEntered(_ name: String) { entered.insert(name) }
        func markCompleted(_ name: String) { completed.insert(name) }
    }

    private func waitUntil(
        timeoutSeconds: TimeInterval = 30,
        _ predicate: @escaping @Sendable () async -> Bool
    ) async {
        let interval = UInt64(max(0, timeoutSeconds) * 1_000_000_000)
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(interval)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if await predicate() { return }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    @Test("MonitorSupervisor joins every task, not the first completion")
    func supervisorJoinsAll() async {
        let supervisor = MonitorSupervisor()
        let probe = Probe()

        await supervisor.start("fast") {
            await probe.markEntered("fast")
            while !Task.isCancelled { await Task.yield() }
            await probe.markCompleted("fast")
        }
        await supervisor.start("slow") {
            await probe.markEntered("slow")
            while !Task.isCancelled { await Task.yield() }
            // Model bounded cleanup that takes longer than the fast sibling.
            await withCheckedContinuation { continuation in
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.08) {
                    continuation.resume()
                }
            }
            await probe.markCompleted("slow")
        }
        await waitUntil { await probe.entered.count == 2 }

        let started = Date()
        // This is a semantic join test, not a production latency assertion.
        // The detached join observer can be scheduler-starved in the full
        // suite, so use a coarse test-only hang budget for its exact join.
        let clean = await supervisor.shutdown(deadline: 30.0)
        let elapsed = Date().timeIntervalSince(started)
        #expect(clean)
        #expect(elapsed >= 0.06,
                "returning with the first task would skip slow cleanup")
        #expect(await probe.completed == ["fast", "slow"])
        #expect(await supervisor.activeCount() == 0)
    }

    @Test("MonitorSupervisor reports a deadline miss without calling it clean")
    func supervisorDeadlineIsHonest() async {
        let supervisor = MonitorSupervisor()
        let probe = Probe()
        let cleanupGate = DaemonLifecycleBlockingGate()
        await supervisor.start("delayed") {
            await probe.markEntered("delayed")
            while !Task.isCancelled { await Task.yield() }
            await cleanupGate.runIgnoringCancellation()
            await probe.markCompleted("delayed")
        }
        await waitUntil { await probe.entered.contains("delayed") }

        let clean = await supervisor.shutdown(deadline: 0.02)
        #expect(!clean)
        #expect(await probe.completed.isEmpty)

        // A deadline miss removes the task from the supervised prefix but does
        // not pretend the task vanished. Release the modeled cleanup and prove
        // that its late unwind is real, while avoiding an orphan in the test.
        await cleanupGate.release()
        await waitUntil { await probe.completed.contains("delayed") }
        #expect(await probe.completed.contains("delayed"))
    }

    @Test("MonitorSupervisor seals admission even when shutdown starts empty")
    func supervisorSealsEmptyShutdown() async {
        let supervisor = MonitorSupervisor()
        let probe = Probe()
        #expect(await supervisor.shutdown(deadline: 0.0))
        await supervisor.start("late") {
            await probe.markEntered("late")
        }
        for _ in 0..<20 { await Task.yield() }
        #expect(await probe.entered.isEmpty)
        #expect(await supervisor.activeCount() == 0)
    }

    @Test("shutdown seals reload admission while the timer plane owns the active reload join")
    func reloadShutdownSerialization() async {
        let lifecycle = DaemonLifecycleCoordinator()
        #expect(await lifecycle.beginRuleReload())
        #expect(!(await lifecycle.beginRuleReload()))

        // This actor owns admission and the sole-finalizer claim. The active
        // reload Task belongs to DaemonTimerLifecycle, which provides the
        // bounded cancel/join; waiting here would create an unbounded shutdown.
        #expect(await lifecycle.beginShutdown())
        #expect(!(await lifecycle.beginRuleReload()))

        await lifecycle.endRuleReload()
        #expect(!(await lifecycle.beginShutdown()),
                "only one path may own final persistence/checkpoint teardown")
    }

    @Test("event-ingestion shutdown joins drivers and both consumers")
    func ingestionLifecycleJoins() async {
        let lifecycle = EventIngestionLifecycle()
        var priorityContinuation: AsyncStream<EventPipelineEnvelope>.Continuation!
        var fileContinuation: AsyncStream<EventPipelineEnvelope>.Continuation!
        let priority = AsyncStream<EventPipelineEnvelope> { priorityContinuation = $0 }
        let file = AsyncStream<EventPipelineEnvelope> { fileContinuation = $0 }
        await lifecycle.configure(
            priority: priorityContinuation,
            file: fileContinuation
        )

        let probe = Probe()
        await lifecycle.spawnDriver {
            await probe.markEntered("driver")
            while !Task.isCancelled { await Task.yield() }
            await probe.markCompleted("driver")
        }
        _ = await lifecycle.spawnConsumers(
            priority: {
                await probe.markEntered("priority")
                for await _ in priority {}
                await probe.markCompleted("priority")
            },
            file: {
                await probe.markEntered("file")
                for await _ in file {}
                await probe.markCompleted("file")
            }
        )
        await waitUntil { await probe.entered.count == 3 }

        // Stream completion and the exact completed set prove the lifecycle
        // semantics. Keep the wall-clock deadline as a coarse test-only hang
        // detector so full-suite scheduler contention cannot masquerade as a
        // dirty shutdown; production deadlines remain unchanged.
        #expect(await lifecycle.shutdown(deadline: 30.0))
        #expect(await probe.completed == ["driver", "priority", "file"])
        #expect(await lifecycle.shutdown(deadline: 0.0),
                "repeated shutdown returns the recorded result")
    }

    @Test("all primary source and consumer tasks are registered with lifecycle")
    func sourceWiringCannotDrift() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let state = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonState.swift"
            ), encoding: .utf8
        )
        let bootstrap = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonBootstrap.swift"
            ), encoding: .utf8
        )
        #expect(state.components(separatedBy: "spawnDriver {").count - 1 == 6)
        #expect(bootstrap.components(separatedBy: ".spawnConsumers(").count - 1 == 1)
        #expect(bootstrap.contains("DaemonShutdownCoordinator.finalize("))
    }

    @Test("ingestion task creation is atomically refused after shutdown")
    func ingestionSpawnAfterShutdown() async {
        let lifecycle = EventIngestionLifecycle()
        #expect(await lifecycle.shutdown(deadline: 0.0))
        let probe = Probe()
        let driver = await lifecycle.spawnDriver {
            await probe.markEntered("late-driver")
        }
        let consumers = await lifecycle.spawnConsumers(
            priority: { await probe.markEntered("late-priority") },
            file: { await probe.markEntered("late-file") }
        )
        #expect(driver == nil)
        #expect(consumers == nil)
        for _ in 0..<20 { await Task.yield() }
        #expect(await probe.entered.isEmpty)
    }
}
