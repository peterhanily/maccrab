import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Delayed coverage probes reconcile only actual current FTS proof")
struct CoverageCanaryReconciliationTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var nanos: UInt64 = 1_000_000_000_000

        func now() -> UInt64 {
            lock.lock(); defer { lock.unlock() }
            return nanos
        }

        func advance(_ seconds: UInt64) {
            lock.lock(); defer { lock.unlock() }
            nanos += seconds * 1_000_000_000
        }
    }

    private enum QueryFailure: Error { case unavailable }

    private actor QueryScript {
        private var calls = 0
        let healthyOnCall: Int?
        let throwsOnMiss: Bool

        init(healthyOnCall: Int? = nil, throwsOnMiss: Bool = false) {
            self.healthyOnCall = healthyOnCall
            self.throwsOnMiss = throwsOnMiss
        }

        func next() throws -> Bool {
            calls += 1
            if healthyOnCall == calls { return true }
            if throwsOnMiss { throw QueryFailure.unavailable }
            return false
        }

        func count() -> Int { calls }
    }

    private actor Gate {
        private var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        private var observers: [CheckedContinuation<Void, Never>] = []

        func pause() async {
            await withCheckedContinuation { continuation in
                self.continuation = continuation
                entered = true
                observers.forEach { $0.resume() }
                observers.removeAll()
            }
        }

        func waitUntilEntered() async {
            if entered { return }
            await withCheckedContinuation { observers.append($0) }
        }

        func open() { continuation?.resume(); continuation = nil }
    }

    private func failedProbe(
        clock: Clock, outcome: ESDeliveryHealth.CanaryOutcome = .storeQueryUnknown
    ) throws -> (ESDeliveryHealth, UInt64) {
        let health = ESDeliveryHealth(monotonicNow: { clock.now() })
        health.started()
        let token = try #require(health.beginCanary())
        clock.advance(35)
        health.finishCanary(token, outcome: outcome)
        return (health, token)
    }

    @Test("Delay remains failed until FTS is present, preserving one failed check", arguments: [false, true])
    func latePresenceRecoversWithoutErasingFailure(throwsOnMiss: Bool) async throws {
        let clock = Clock()
        let (health, token) = try failedProbe(clock: clock)
        let script = QueryScript(healthyOnCall: 3, throwsOnMiss: throwsOnMiss)
        let original = health.snapshot(lastCallbackUptimeNanoseconds: clock.now())
        let recovered = await DaemonTimers.reconcileCoverageCanary(
            health: health, healthToken: token,
            pause: {
                #expect(health.snapshot(lastCallbackUptimeNanoseconds: clock.now()).state == .failed)
                clock.advance(5)
            },
            isPresent: { try await script.next() }
        )
        #expect(recovered)
        #expect(await script.count() == 3)
        let final = health.snapshot(lastCallbackUptimeNanoseconds: clock.now())
        #expect(final.state == .healthy)
        #expect(final.canaryOutcome == .healthy)
        #expect(final.canaryChecksTotal == 1)
        #expect(final.canaryFailuresTotal == 1)
        #expect(final.lastError == original.lastError)
        #expect(!health.canReconcileStoredCanary(token))
    }

    @Test("Permanent misses or query failures stop at the existing proof horizon", arguments: [false, true])
    func unresolvedProbeRemainsFailed(throwsOnMiss: Bool) async throws {
        let clock = Clock()
        let (health, token) = try failedProbe(clock: clock)
        let script = QueryScript(throwsOnMiss: throwsOnMiss)
        let recovered = await DaemonTimers.reconcileCoverageCanary(
            health: health, healthToken: token,
            pause: { clock.advance(5) },
            isPresent: { try await script.next() }
        )
        #expect(!recovered)
        // 35-second initial verdict; one read per five seconds through 935.
        #expect(await script.count() == 180)
        let final = health.snapshot(lastCallbackUptimeNanoseconds: clock.now())
        #expect(final.state == .failed)
        #expect(final.canaryOutcome == .storeQueryUnknown)
        #expect(final.canaryChecksTotal == 1)
        #expect(final.canaryFailuresTotal == 1)
    }

    @Test("An unchanged clock still has a finite query-work bound")
    func operationBoundIsIndependentOfClockProgress() async throws {
        let clock = Clock()
        let (health, token) = try failedProbe(clock: clock)
        let script = QueryScript()
        #expect(!(await DaemonTimers.reconcileCoverageCanary(
            health: health, healthToken: token, pause: {},
            isPresent: { try await script.next() }
        )))
        #expect(await script.count() == 187)
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: clock.now()).state == .failed)
    }

    @Test("A callback, handoff, spawn or cancellation failure is terminal", arguments: [
        ESDeliveryHealth.CanaryOutcome.kernelGap, .ingestHandoffGap, .spawnFailed, .cancelled,
    ])
    func nonStorageFailuresCannotReconcile(outcome: ESDeliveryHealth.CanaryOutcome) async throws {
        let clock = Clock()
        let (health, token) = try failedProbe(clock: clock, outcome: outcome)
        let script = QueryScript(healthyOnCall: 1)
        #expect(!(await DaemonTimers.reconcileCoverageCanary(
            health: health, healthToken: token, pause: {},
            isPresent: { try await script.next() }
        )))
        #expect(await script.count() == 0)
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: clock.now()).canaryOutcome == outcome)
    }

    @Test("A suspended positive read cannot overwrite a newer failure, stop, deadline or cancellation", arguments: [
        "new-probe", "stop", "deadline", "cancel",
    ])
    func stalePositiveCannotRecover(invalidation: String) async throws {
        let clock = Clock(), gate = Gate()
        let (health, token) = try failedProbe(clock: clock)
        let task = Task {
            await DaemonTimers.reconcileCoverageCanary(
                health: health, healthToken: token, pause: {},
                isPresent: { await gate.pause(); return true }
            )
        }
        await gate.waitUntilEntered()
        switch invalidation {
        case "new-probe":
            let next = try #require(health.beginCanary())
            health.finishCanary(next, outcome: .kernelGap)
        case "stop": health.stop()
        case "deadline": clock.advance(901)
        default: task.cancel()
        }
        await gate.open()
        #expect(!(await task.value))
        let final = health.snapshot(lastCallbackUptimeNanoseconds: clock.now())
        #expect(final.state == .failed)
        #expect(final.canaryOutcome != .healthy)
        #expect(final.canaryFailuresTotal == (invalidation == "new-probe" ? 2 : 1))
    }
}
