import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Native ES health follows callbacks and existing coverage proof")
struct ESDeliveryHealthTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var nanos: UInt64 = 1_000_000_000_000
        func now() -> UInt64 { lock.lock(); defer { lock.unlock() }; return nanos }
        func advance(_ seconds: UInt64) {
            lock.lock(); defer { lock.unlock() }; nanos += seconds * 1_000_000_000
        }
    }

    private actor Gate {
        private var entered = false
        private var release: CheckedContinuation<Void, Never>?
        private var observers: [CheckedContinuation<Void, Never>] = []
        func pause() async {
            await withCheckedContinuation { continuation in
                release = continuation; entered = true
                observers.forEach { $0.resume() }; observers.removeAll()
            }
        }
        func waitUntilEntered() async {
            if entered { return }
            await withCheckedContinuation { observers.append($0) }
        }
        func open() { release?.resume(); release = nil }
    }

    @Test("Callback progress stays healthy without normalized events, while missing canary proof expires")
    func callbacksAndProofFreshness() async throws {
        let clock = Clock(), tracker = ESSeqTracker()
        let health = ESDeliveryHealth(monotonicNow: { clock.now() })
        let registry = CollectorRegistry()
        health.started()
        await registry.register(name: "ESCollector", expectedIntervalSeconds: 935,
                                eventDriven: true, nativeESHealth: {
            health.snapshot(lastCallbackUptimeNanoseconds: tracker.lastCallbackUptimeNanoseconds())
        })
        tracker.record(eventType: 1, seqNum: 1, globalSeq: 1,
                       callbackUptimeNanoseconds: clock.now())
        clock.advance(60) // Beyond the former false 25-second polling cutoff.
        let quiet = try #require(await registry.snapshot().first)
        #expect(quiet.state == .healthy)
        #expect(quiet.eventCount == 0)
        #expect(quiet.lastTick == nil)
        #expect(quiet.nativeESHealth?.callbackAgeSeconds == 60)
        #expect(tracker.processedByType().isEmpty)
        clock.advance(875)
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: clock.now()).state == .healthy)
        clock.advance(1)
        tracker.record(eventType: 1, seqNum: 2, globalSeq: 2,
                       callbackUptimeNanoseconds: clock.now())
        let staleProof = try #require(await registry.snapshot().first)
        #expect(staleProof.state == .stalled)
        #expect(staleProof.reason.contains("canary proof"))
        let probe = try #require(health.beginCanary())
        health.finishCanary(probe, outcome: .healthy)
        #expect(await registry.snapshot().first?.state == .healthy)
        #expect(await registry.snapshot().first?.eventCount == 0)
    }

    @Test("Each failed or unknown canary stays failed until a newly verified probe", arguments: [
        ESDeliveryHealth.CanaryOutcome.kernelGap, .ingestHandoffGap, .evictionGap,
        .storeQueryUnknown, .spawnFailed, .cancelled,
    ])
    func explicitOutcomes(outcome: ESDeliveryHealth.CanaryOutcome) async throws {
        let clock = Clock()
        let native = ESDeliveryHealth(monotonicNow: { clock.now() })
        native.started()
        let registry = CollectorRegistry()
        await registry.register(name: "ESCollector", expectedIntervalSeconds: 935,
                                eventDriven: true, nativeESHealth: {
            native.snapshot(lastCallbackUptimeNanoseconds: clock.now())
        })
        let probe = try #require(native.beginCanary())
        native.finishCanary(probe, outcome: outcome)
        await registry.recordTick(name: "ESCollector")
        let failed = try #require(await registry.snapshot().first)
        #expect(failed.state == .failed)
        #expect(failed.errorCount == 1)
        #expect(failed.nativeESHealth?.canaryOutcome == outcome)
        let next = try #require(native.beginCanary())
        #expect(await registry.snapshot().first?.state == .failed)
        native.finishCanary(next, outcome: .healthy)
        let recovered = try #require(await registry.snapshot().first)
        #expect(recovered.state == .healthy)
        #expect(recovered.errorCount == 1)
        #expect(recovered.lastError == failed.lastError)
        #expect(recovered.nativeESHealth?.canaryChecksTotal == 2)
        await registry.recordStreamEnded(name: "ESCollector")
        await registry.recordRecovery(name: "ESCollector")
        #expect(await registry.snapshot().first?.state == .failed)
        #expect(await registry.snapshot().first?.errorCount == 2)
    }

    @Test("Missing callbacks, stopped instances, stale completions and fresh instances retain truthful state")
    func lifecycleAndGenerations() throws {
        let clock = Clock()
        let health = ESDeliveryHealth(monotonicNow: { clock.now() })
        health.started()
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: nil).state == .starting)
        clock.advance(936)
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: nil).state == .stalled)
        let old = try #require(health.beginCanary())
        let current = try #require(health.beginCanary())
        health.finishCanary(current, outcome: .kernelGap)
        health.finishCanary(old, outcome: .healthy)
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: clock.now()).canaryOutcome == .kernelGap)
        let stopped = try #require(health.beginCanary())
        health.stop()
        health.finishCanary(stopped, outcome: .healthy)
        health.started()
        #expect(health.snapshot(lastCallbackUptimeNanoseconds: clock.now()).state == .failed)
        #expect(health.beginCanary() == nil)

        let fresh = ESDeliveryHealth(monotonicNow: { clock.now() })
        let tracker = ESSeqTracker()
        fresh.started()
        tracker.record(eventType: 1, seqNum: 1, globalSeq: 1,
                       callbackUptimeNanoseconds: clock.now())
        #expect(fresh.snapshot(lastCallbackUptimeNanoseconds: tracker.lastCallbackUptimeNanoseconds()).state == .healthy)
        #expect(fresh.snapshot(lastCallbackUptimeNanoseconds: clock.now()).canaryFailuresTotal == 0)
        tracker.reset()
        #expect(tracker.lastCallbackUptimeNanoseconds() == nil)
        #expect(fresh.snapshot(lastCallbackUptimeNanoseconds: tracker.lastCallbackUptimeNanoseconds()).state == .starting)
        let proof = try #require(fresh.beginCanary())
        fresh.finishCanary(proof, outcome: .healthy)
        #expect(fresh.snapshot(lastCallbackUptimeNanoseconds: clock.now() + 1).state == .stalled)
        let previousCallback = clock.now()
        clock.advance(936)
        let laterProof = try #require(fresh.beginCanary())
        fresh.finishCanary(laterProof, outcome: .healthy)
        #expect(fresh.snapshot(lastCallbackUptimeNanoseconds: previousCallback).state == .stalled)
    }

    @Test("A cancelled probe task cannot publish a passing result")
    func cancelledTaskCannotPass() async throws {
        let clock = Clock(), gate = Gate()
        let health = ESDeliveryHealth(monotonicNow: { clock.now() })
        health.started()
        let token = try #require(health.beginCanary())
        let task = Task {
            await gate.pause()
            health.finishCanary(token, outcome: .healthy)
        }
        await gate.waitUntilEntered()
        task.cancel()
        await gate.open()
        await task.value
        let snapshot = health.snapshot(lastCallbackUptimeNanoseconds: clock.now())
        #expect(snapshot.state == .failed)
        #expect(snapshot.canaryOutcome == .cancelled)
        #expect(snapshot.canaryChecksTotal == 1)
        #expect(snapshot.canaryFailuresTotal == 1)
    }
}
