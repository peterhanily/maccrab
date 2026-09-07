import Foundation
import Testing
@testable import MacCrabCore

@Suite("Temporary response blocks commit and expire truthfully")
struct TemporaryNetworkBlocksTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var wall = Date(timeIntervalSince1970: 1_000_000)
        private var monotonic: TimeInterval = 1000
        func date() -> Date { lock.lock(); defer { lock.unlock() }; return wall }
        func uptime() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return monotonic }
        func advance(_ seconds: TimeInterval, wallChange: TimeInterval? = nil) {
            lock.lock(); defer { lock.unlock() }
            monotonic += seconds
            wall = wall.addingTimeInterval(wallChange ?? seconds)
        }
    }

    private actor Gate {
        private var paused = false
        private var release: CheckedContinuation<Void, Never>?
        private var observers: [CheckedContinuation<Void, Never>] = []
        func pause() async {
            await withCheckedContinuation { continuation in
                release = continuation
                paused = true
                observers.forEach { $0.resume() }
                observers.removeAll()
            }
        }
        func waitUntilPaused() async {
            if paused { return }
            await withCheckedContinuation { observers.append($0) }
        }
        func open() { release?.resume(); release = nil }
    }

    private actor MemoryPF {
        private var writeResults: [Bool] = []
        private var reloadResults: [TemporaryNetworkBlocks.ReloadResult] = []
        private var nextGate: Gate?
        private(set) var writes: [String] = []
        private(set) var reloadCount = 0
        private(set) var file = ""
        private(set) var kernel = ""
        func plan(writes: [Bool] = [], reloads: [TemporaryNetworkBlocks.ReloadResult] = []) {
            writeResults = writes
            reloadResults = reloads
        }
        func holdNextReload(_ gate: Gate) { nextGate = gate }
        func write(_ content: String) -> Bool {
            writes.append(content)
            let accepted = writeResults.isEmpty ? true : writeResults.removeFirst()
            if accepted { file = content }
            return accepted
        }
        func reload() async -> TemporaryNetworkBlocks.ReloadResult {
            reloadCount += 1
            let gate = nextGate
            nextGate = nil
            let result = reloadResults.isEmpty
                ? TemporaryNetworkBlocks.ReloadResult(loaded: true, enforcing: true)
                : reloadResults.removeFirst()
            if let gate { await gate.pause() }
            if result.loaded { kernel = file }
            return result
        }
    }

    /// A manually advanced sleeper with cancellation support; no real delays.
    private actor Sleeper {
        private var waits: [UUID: CheckedContinuation<Void, Error>] = [:]
        private var latest: UUID?
        private var delays: [TimeInterval] = []
        private var observers: [(Int, CheckedContinuation<(Int, TimeInterval), Never>)] = []
        func sleep(_ delay: TimeInterval) async throws {
            let id = UUID()
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    if Task.isCancelled { continuation.resume(throwing: CancellationError()); return }
                    waits[id] = continuation
                    latest = id
                    delays.append(delay)
                    let ready = observers.filter { delays.count > $0.0 }
                    observers.removeAll { delays.count > $0.0 }
                    ready.forEach { $0.1.resume(returning: (delays.count, delay)) }
                }
            } onCancel: {
                Task { await self.cancel(id) }
            }
        }
        private func cancel(_ id: UUID) { waits.removeValue(forKey: id)?.resume(throwing: CancellationError()) }
        func next(after count: Int = 0) async -> (Int, TimeInterval) {
            if delays.count > count { return (delays.count, delays.last ?? 0) }
            return await withCheckedContinuation { observers.append((count, $0)) }
        }
        func fire() {
            guard let latest else { return }
            waits.removeValue(forKey: latest)?.resume()
        }
        func pendingCount() -> Int { waits.count }
    }

    private func controller(
        pf: MemoryPF, clock: Clock, sleeper: Sleeper? = nil,
        settled: @escaping @Sendable (TemporaryNetworkBlocks.Snapshot) -> Void = { _ in }
    ) -> TemporaryNetworkBlocks {
        TemporaryNetworkBlocks(
            io: .init(write: { await pf.write($0) }, reload: { await pf.reload() },
                      legacyStateUnverified: { false }),
            now: { clock.date() }, monotonicNow: { clock.uptime() }, didSettle: settled,
            sleep: { delay in
                guard let sleeper else { throw CancellationError() }
                try await sleeper.sleep(delay)
            }
        )
    }

    @Test("Failed expiration write retains inventory until a later complete apply")
    func failedExpirationWriteRetries() async {
        let pf = MemoryPF(), clock = Clock()
        let subject = controller(pf: pf, clock: clock)
        let added = await subject.add(ip: "203.0.113.10", durationSeconds: 10, ruleID: "fixture")
        #expect(added)
        let originalLoads = await pf.reloadCount
        clock.advance(10)
        await pf.plan(writes: [false])
        await subject.maintain()
        let pending = await subject.snapshot()
        #expect(pending.blocks.count == 1)
        #expect(pending.reconciliationPending)
        #expect(await pf.reloadCount == originalLoads)
        clock.advance(30)
        await subject.maintain()
        #expect(await subject.snapshot().blocks.isEmpty)
        #expect(!(await subject.snapshot().reconciliationPending))
        #expect(!(await pf.kernel.contains("203.0.113.10")))
    }

    @Test("Failed expiration reload cannot make an expired duplicate successful")
    func failedExpirationReloadRetainsRetry() async {
        let pf = MemoryPF(), clock = Clock()
        let subject = controller(pf: pf, clock: clock)
        let added = await subject.add(ip: "203.0.113.11", durationSeconds: 10, ruleID: "fixture")
        #expect(added)
        clock.advance(10)
        await pf.plan(reloads: [.init(loaded: false, enforcing: false)])
        await subject.maintain()
        let beforeDuplicate = await pf.reloadCount
        let duplicate = await subject.add(ip: "203.0.113.11", durationSeconds: 60, ruleID: "fixture")
        #expect(!duplicate)
        #expect(await pf.reloadCount == beforeDuplicate)
        #expect(await subject.snapshot().blocks.count == 1)
        #expect(await pf.kernel.contains("203.0.113.11"))
        clock.advance(30)
        await subject.maintain()
        #expect(await subject.snapshot().blocks.isEmpty)
    }

    @Test("Loaded but unconfirmed additions retain cleanup when rollback fails")
    func unconfirmedAddRetainsReconciliation() async {
        let pf = MemoryPF(), clock = Clock()
        let subject = controller(pf: pf, clock: clock)
        await subject.maintain()
        await pf.plan(writes: [true, false], reloads: [.init(loaded: true, enforcing: false)])
        let added = await subject.add(ip: "203.0.113.12", durationSeconds: 60, ruleID: "fixture")
        #expect(!added)
        #expect(await subject.snapshot().blocks.isEmpty)
        #expect(await subject.snapshot().reconciliationPending)
        #expect(await pf.kernel.contains("203.0.113.12"))
        clock.advance(30)
        await subject.maintain()
        #expect(!(await pf.kernel.contains("203.0.113.12")))
        #expect(!(await subject.snapshot().reconciliationPending))
    }

    @Test("Failed load and successful rollback cannot leak a rule into the next add")
    func failedAddDoesNotAppendOrphan() async {
        let pf = MemoryPF(), clock = Clock()
        let subject = controller(pf: pf, clock: clock)
        await subject.maintain()
        await pf.plan(reloads: [.init(loaded: false, enforcing: false), .init(loaded: true, enforcing: false)])
        let failed = await subject.add(ip: "203.0.113.13", durationSeconds: 60, ruleID: "first")
        #expect(!failed)
        #expect(!(await subject.snapshot().reconciliationPending))
        let applied = await subject.add(ip: "203.0.113.14", durationSeconds: 60, ruleID: "second")
        #expect(applied)
        #expect(!(await pf.kernel.contains("203.0.113.13")))
        #expect(await pf.kernel.contains("203.0.113.14"))
    }

    @Test("An awaited reload excludes concurrent mutation and starts TTL after confirmation")
    func reloadSerializesTransactionsAndTTL() async {
        let pf = MemoryPF(), clock = Clock(), gate = Gate()
        let subject = controller(pf: pf, clock: clock)
        await subject.maintain()
        await pf.holdNextReload(gate)
        let first = Task { await subject.add(ip: "203.0.113.15", durationSeconds: 60, ruleID: "first") }
        await gate.waitUntilPaused()
        let second = await subject.add(ip: "203.0.113.16", durationSeconds: 60, ruleID: "second")
        #expect(!second)
        await subject.maintain()
        #expect(await subject.snapshot().operationInFlight)
        clock.advance(120)
        await gate.open()
        #expect(await first.value)
        let snapshot = await subject.snapshot()
        #expect(snapshot.blocks.count == 1)
        #expect(snapshot.blocks.first?.ip == "203.0.113.15")
        #expect(snapshot.blocks.first?.expiryDeadline == clock.uptime() + 60)
        #expect(snapshot.blocks.first?.expiresAt == clock.date().addingTimeInterval(60))
    }

    @Test("Independent expiry retries monotonically and maintenance can be stopped")
    func independentSchedulerRetriesAndStops() async throws {
        let pf = MemoryPF(), clock = Clock(), sleeper = Sleeper()
        let events = AsyncStream<TemporaryNetworkBlocks.Snapshot>.makeStream()
        var iterator = events.stream.makeAsyncIterator()
        let subject = controller(pf: pf, clock: clock, sleeper: sleeper,
                                 settled: { events.continuation.yield($0) })
        let added = await subject.add(ip: "203.0.113.17", durationSeconds: 10, ruleID: "fixture")
        #expect(added)
        _ = await iterator.next() // Startup reconciliation.
        _ = await iterator.next() // Confirmed addition.
        await subject.startMaintenance()
        let first = await sleeper.next()
        #expect(first.1 == 10)
        await pf.plan(reloads: [.init(loaded: false, enforcing: false)])
        clock.advance(10, wallChange: -86_400)
        await sleeper.fire()
        let pendingEvent = await iterator.next()
        let pending = try #require(pendingEvent)
        #expect(pending.reconciliationPending)
        #expect(pending.blocks.count == 1)
        let retry = await sleeper.next(after: first.0)
        #expect(retry.1 == 30)
        clock.advance(30, wallChange: -86_400)
        await sleeper.fire()
        let settledEvent = await iterator.next()
        let settled = try #require(settledEvent)
        #expect(settled.blocks.isEmpty)
        #expect(!settled.reconciliationPending)
        await subject.stopMaintenance()
        #expect(await sleeper.pendingCount() == 0)
    }

    @Test("Scheduler clamps huge TTLs and cancellation releases its sleeper")
    func schedulerBoundsAndCancellation() async {
        let pf = MemoryPF(), clock = Clock(), sleeper = Sleeper()
        let subject = controller(pf: pf, clock: clock, sleeper: sleeper)
        let zero = await subject.add(ip: "203.0.113.18", durationSeconds: 0, ruleID: "fixture")
        let negative = await subject.add(ip: "203.0.113.18", durationSeconds: -1, ruleID: "fixture")
        #expect(!zero && !negative)
        #expect(await pf.reloadCount == 0)
        let large = await subject.add(ip: "203.0.113.18", durationSeconds: Int.max, ruleID: "fixture")
        #expect(large)
        await subject.startMaintenance()
        let scheduled = await sleeper.next()
        #expect(scheduled.1 == TemporaryNetworkBlocks.maximumSleepInterval)
        await subject.stopMaintenance()
        #expect(await sleeper.pendingCount() == 0)
    }

    @Test("Restart cleanup and rendering use only the dedicated anchor contract")
    func dedicatedStartupAndInterfaceIndependentRules() async {
        let pf = MemoryPF(), clock = Clock()
        _ = await pf.write("block drop out quick to 203.0.113.19\n")
        _ = await pf.reload()
        let subject = controller(pf: pf, clock: clock)
        await subject.maintain()
        #expect(!(await pf.kernel.contains("203.0.113.19")))
        #expect(TemporaryNetworkBlocks.anchorName == "com.maccrab.response")
        #expect(TemporaryNetworkBlocks.anchorFilename == "maccrab_response_blocks.conf")
        let added = await subject.add(ip: "203.0.113.20", durationSeconds: 60, ruleID: "fixture")
        #expect(added)
        let rendered = await pf.kernel
        #expect(rendered.contains("block drop out quick to 203.0.113.20\n"))
        #expect(!rendered.contains(" on en"))
    }
}
