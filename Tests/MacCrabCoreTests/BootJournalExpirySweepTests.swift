import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// Pure control-flow tests of the pre-producer expiry sweep with a synthetic
/// clock and store; no database, timer or heartbeat file is touched.
@Suite("Boot journal expiry sweep")
struct BootJournalExpirySweepTests {
    /// Scripted store: each call returns the next batch size and advances the
    /// synthetic clock; thrown errors model transient backpressure.
    private final class Script: @unchecked Sendable {
        var results: [Result<Int, EventStoreError>]
        var clock: TimeInterval = 1_000
        let secondsPerCall: TimeInterval
        var calls = 0
        var renewals: [BootJournalExpirySweep.Progress] = []
        var conserved = 0
        var slept: [Int] = []
        init(_ results: [Result<Int, EventStoreError>], secondsPerCall: TimeInterval) {
            self.results = results
            self.secondsPerCall = secondsPerCall
        }
        func next() throws -> Int {
            calls += 1
            clock += secondsPerCall
            return try results.removeFirst().get()
        }
    }

    private func run(_ script: Script, convergence: @escaping () -> Bool = { false }) async throws
        -> BootJournalExpirySweep.Outcome {
        try await BootJournalExpirySweep.run(
            expire: { try script.next() },
            backpressureBudgetSeconds: 2,
            retryMilliseconds: 250,
            uptime: { script.clock },
            storeRequiresConvergence: convergence,
            renewPhase: { script.renewals.append($0) },
            onConservedBackpressure: { script.conserved += 1 },
            sleep: { script.slept.append($0); script.clock += Double($0) / 1_000 }
        )
    }

    @Test("a backlog that drains within budget is fully expired before producers")
    func drainsWithinBudget() async throws {
        let script = Script([.success(100), .success(50), .success(0)], secondsPerCall: 1)
        let outcome = try await run(script)
        #expect(!outcome.deferredBacklogToRuntime)
        #expect(outcome.progress.expiredEvents == 150)
        #expect(outcome.progress.batches == 2)
        #expect(script.calls == 3)
        #expect(script.renewals.isEmpty)
    }

    @Test("progress renewal follows elapsed time, not batch count")
    func renewalByElapsedTime() async throws {
        // 3 s per slow batch: the old 64-batch rule would never have renewed.
        let script = Script(Array(repeating: .success(10), count: 6) + [.success(0)], secondsPerCall: 3)
        let outcome = try await run(script, convergence: { true })
        #expect(script.renewals.map(\.batches) == [4])
        #expect(script.renewals.first?.expiredEvents == 40)
        #expect(script.renewals.first?.elapsedSeconds == 12)
        #expect(!outcome.deferredBacklogToRuntime)
        #expect(outcome.progress.expiredEvents == 60)
    }

    @Test("after the work budget, remaining backlog is deferred only inside the startup boundary")
    func defersOnlyWithoutConvergenceNeed() async throws {
        let deferring = Script(Array(repeating: .success(10), count: 30) + [.success(0)], secondsPerCall: 3)
        let deferred = try await run(deferring, convergence: { false })
        #expect(deferred.deferredBacklogToRuntime)
        #expect(deferred.progress.batches == 20)  // first batch at or past 60 s of work
        #expect(deferring.calls == 20)

        let converging = Script(Array(repeating: .success(10), count: 30) + [.success(0)], secondsPerCall: 3)
        let drained = try await run(converging, convergence: { true })
        #expect(!drained.deferredBacklogToRuntime)
        #expect(drained.progress.batches == 30)
        #expect(drained.progress.expiredEvents == 300)
    }

    @Test("backpressure waits and failed calls do not spend the successful-work budget")
    func workBudgetExcludesBackpressure() async throws {
        let busy = EventStoreError.busy("writer lock")
        var results: [Result<Int, EventStoreError>] = []
        for index in 0..<70 {
            if index % 10 == 5 { results.append(.failure(busy)) }
            results.append(.success(1))
        }
        let script = Script(results, secondsPerCall: 1)
        let outcome = try await run(script, convergence: { false })
        #expect(outcome.deferredBacklogToRuntime)
        #expect(outcome.progress.batches == 60)
        #expect(outcome.progress.workSeconds == 60)
        #expect(script.conserved == 6)
        #expect(outcome.progress.elapsedSeconds == 60 + 6 * 1.25)
    }

    @Test("an unmeasurable store keeps draining; only a measured in-boundary footprint may defer")
    func convergenceRule() {
        struct Unmeasurable: Error {}
        #expect(BootJournalExpirySweep.storeRequiresConvergence(
            measureFootprint: { throw Unmeasurable() }, requiresConvergence: { _ in false }))
        #expect(!BootJournalExpirySweep.storeRequiresConvergence(
            measureFootprint: { 100 }, requiresConvergence: { $0 > 200 }))
        #expect(BootJournalExpirySweep.storeRequiresConvergence(
            measureFootprint: { 300 }, requiresConvergence: { $0 > 200 }))
    }

    @Test("the runtime timer's first pass is prompt only when boot deferred backlog")
    func runtimeFirstPass() {
        #expect(BootJournalExpirySweep.runtimeFirstPassDelaySeconds(cadenceMinutes: 5, bootBacklogDeferred: true) == 5)
        #expect(BootJournalExpirySweep.runtimeFirstPassDelaySeconds(cadenceMinutes: 5, bootBacklogDeferred: false) == 300)
        #expect(BootJournalExpirySweep.runtimeFirstPassDelaySeconds(cadenceMinutes: 1, bootBacklogDeferred: false) == 60)
    }

    @Test("transient backpressure is conserved within its own budget, then fails")
    func backpressureBudget() async throws {
        let busy = EventStoreError.memoryLeaseUnavailable("lease committed")
        let recovers = Script([.failure(busy), .failure(busy), .success(5), .success(0)], secondsPerCall: 0)
        let outcome = try await run(recovers)
        #expect(outcome.progress.expiredEvents == 5)
        #expect(recovers.conserved == 2)
        #expect(recovers.slept == [250, 250])

        let stuck = Script(Array(repeating: .failure(busy), count: 20), secondsPerCall: 0)
        await #expect(throws: EventStoreError.self) { _ = try await run(stuck) }
        #expect(stuck.conserved == 8)  // 8 x 250 ms reaches the 2 s budget

        let fatal = Script([.failure(.stepFailed("corrupt"))], secondsPerCall: 0)
        await #expect(throws: EventStoreError.self) { _ = try await run(fatal) }
        #expect(fatal.conserved == 0)
    }
}
