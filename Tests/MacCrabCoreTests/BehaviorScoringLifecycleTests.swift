import Foundation
import Testing
@testable import MacCrabCore

@Suite("Behavior scoring bounded delivery lifecycle")
struct BehaviorScoringLifecycleTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var value = Date(timeIntervalSince1970: 100_000)

        func now() -> Date { lock.withLock { value } }
        func advance(_ seconds: TimeInterval) {
            lock.withLock { value = value.addingTimeInterval(seconds) }
        }
    }

    private func scorer(cap: Int, clock: Clock) -> BehaviorScoring {
        BehaviorScoring(
            alertThreshold: 10,
            criticalThreshold: 20,
            decayHalfLife: 10,
            maxTrackedProcesses: cap,
            now: clock.now
        )
    }

    private func crossing(
        _ scorer: BehaviorScoring,
        pid: Int32,
        weight: Double
    ) async throws -> BehaviorScoring.ScoringResult {
        try #require(await scorer.addIndicator(
            .init(name: "ordinary-fixture", weight: weight),
            forProcess: pid,
            path: "/tmp/behavior-fixture-\(pid)"
        ))
    }

    private func retainStrongScores(_ scorer: BehaviorScoring) async throws {
        for pid: Int32 in [1, 2] {
            let result = try await crossing(scorer, pid: pid, weight: 100)
            let resolved = await scorer.resolveThreshold(
                deliveryToken: result.deliveryToken,
                as: .committed
            )
            #expect(resolved)
        }
    }

    @Test("at-cap arrivals still deliver and retry without retaining orphan latches")
    func detachedDeliveryChurnRemainsBounded() async throws {
        let clock = Clock()
        let scorer = scorer(cap: 2, clock: clock)
        try await retainStrongScores(scorer)

        for pid: Int32 in 3...42 {
            let result = try await crossing(scorer, pid: pid, weight: 15)
            #expect(result.totalScore == 15)
            let retained = await scorer.topProcesses(limit: 10)
            #expect(Set(retained.map { $0.pid }) == Set<Int32>([1, 2]))

            await scorer.recordThresholdDeliveryFailure(deliveryToken: result.deliveryToken)
            let retry = try await crossing(scorer, pid: pid, weight: 15)
            #expect(retry.deliveryToken == result.deliveryToken)
            let pending = await scorer.thresholdTelemetry()
            #expect(pending.pending == 1)
            #expect(pending.conservesCrossings)

            let resolved = await scorer.resolveThreshold(
                deliveryToken: result.deliveryToken,
                as: .committed
            )
            #expect(resolved)
            let duplicate = await scorer.resolveThreshold(
                deliveryToken: result.deliveryToken,
                as: .committed
            )
            #expect(!duplicate)
            let failures = await scorer.lifecycleInvariantFailures()
            #expect(failures.isEmpty)
        }

        let telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.crossings == 42)
        #expect(telemetry.committed == 42)
        #expect(telemetry.pending == 0)
        #expect(telemetry.abandoned == 0)
        #expect(telemetry.deliveryFailures == 40)
        #expect(telemetry.conservesCrossings)
    }

    @Test("pending pressure abandons the oldest delivery and conserves later outcomes")
    func pendingCapAbandonsOldestToken() async throws {
        let scorer = scorer(cap: 2, clock: Clock())
        try await retainStrongScores(scorer)
        let oldest = try await crossing(scorer, pid: 3, weight: 15)
        let second = try await crossing(scorer, pid: 4, weight: 15)
        let latest = try await crossing(scorer, pid: 5, weight: 15)

        let before = await scorer.thresholdTelemetry()
        #expect(before.pending == 2)
        #expect(before.abandoned == 1)
        #expect(before.conservesCrossings)
        let stale = await scorer.resolveThreshold(
            deliveryToken: oldest.deliveryToken,
            as: .committed
        )
        #expect(!stale)
        await scorer.recordThresholdDeliveryFailure(deliveryToken: oldest.deliveryToken)

        let secondResolved = await scorer.resolveThreshold(
            deliveryToken: second.deliveryToken,
            as: .filteredOrSuppressed
        )
        let latestResolved = await scorer.resolveThreshold(
            deliveryToken: latest.deliveryToken,
            as: .committed
        )
        #expect(secondResolved)
        #expect(latestResolved)
        let after = await scorer.thresholdTelemetry()
        #expect(after.committed == 3)
        #expect(after.filteredOrSuppressed == 1)
        #expect(after.deliveryFailures == 0)
        #expect(after.pending == 0)
        #expect(after.conservesCrossings)
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }

    @Test("score eviction abandons its old crossing and stale tokens cannot settle a reused key")
    func scoreEvictionAndKeyReuseKeepTokensDistinct() async throws {
        let scorer = scorer(cap: 1, clock: Clock())
        let first = try await crossing(scorer, pid: 1, weight: 15)
        let second = try await crossing(scorer, pid: 2, weight: 30)
        let reused = try await crossing(scorer, pid: 1, weight: 40)
        #expect(reused.deliveryToken != first.deliveryToken)
        for old in [first, second] {
            let resolved = await scorer.resolveThreshold(
                deliveryToken: old.deliveryToken,
                as: .committed
            )
            #expect(!resolved)
        }
        let resolved = await scorer.resolveThreshold(
            deliveryToken: reused.deliveryToken,
            as: .committed
        )
        #expect(resolved)
        let telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.crossings == 3)
        #expect(telemetry.abandoned == 2)
        #expect(telemetry.committed == 1)
        #expect(telemetry.conservesCrossings)
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }

    @Test("expiry preserves a fresh detached retry then abandons it at the score lifetime")
    func expiryClearsRetainedAndDetachedState() async throws {
        let clock = Clock()
        let scorer = scorer(cap: 2, clock: clock)
        try await retainStrongScores(scorer)
        let detached = try await crossing(scorer, pid: 3, weight: 15)
        await scorer.prune()
        let fresh = await scorer.thresholdTelemetry()
        #expect(fresh.pending == 1)
        #expect(fresh.abandoned == 0)

        clock.advance(100)
        await scorer.prune()
        let retained = await scorer.topProcesses()
        #expect(retained.isEmpty)
        let expired = await scorer.thresholdTelemetry()
        #expect(expired.pending == 0)
        #expect(expired.abandoned == 1)
        #expect(expired.conservesCrossings)

        let renewed = try await crossing(scorer, pid: 3, weight: 15)
        #expect(renewed.deliveryToken != detached.deliveryToken)
        let stale = await scorer.resolveThreshold(
            deliveryToken: detached.deliveryToken,
            as: .committed
        )
        #expect(!stale)
        let resolved = await scorer.resolveThreshold(
            deliveryToken: renewed.deliveryToken,
            as: .committed
        )
        #expect(resolved)
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }

    @Test("detached retry expires even when periodic prune is not called")
    func detachedRetryChecksItsOwnExpiry() async throws {
        let clock = Clock()
        let scorer = scorer(cap: 0, clock: clock)
        let first = try await crossing(scorer, pid: 1, weight: 15)
        clock.advance(100)
        let renewed = try await crossing(scorer, pid: 1, weight: 15)
        #expect(renewed.deliveryToken != first.deliveryToken)
        let telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.crossings == 2)
        #expect(telemetry.abandoned == 1)
        #expect(telemetry.pending == 1)
        #expect(telemetry.conservesCrossings)
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }

    @Test("nonpositive score retention still permits one bounded delivery", arguments: [0, -1])
    func noScoreRetentionStillDelivers(cap: Int) async throws {
        let scorer = scorer(cap: cap, clock: Clock())
        let first = try await crossing(scorer, pid: 1, weight: 15)
        let second = try await crossing(scorer, pid: 2, weight: 15)
        let retained = await scorer.topProcesses()
        #expect(retained.isEmpty)
        let stale = await scorer.resolveThreshold(
            deliveryToken: first.deliveryToken,
            as: .committed
        )
        #expect(!stale)
        let resolved = await scorer.resolveThreshold(
            deliveryToken: second.deliveryToken,
            as: .committed
        )
        #expect(resolved)
        let telemetry = await scorer.thresholdTelemetry()
        #expect(telemetry.pending == 0)
        #expect(telemetry.abandoned == 1)
        #expect(telemetry.committed == 1)
        #expect(telemetry.conservesCrossings)
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }

    @Test("a backward clock correction cannot increase retained scores or defeat capacity")
    func backwardClockPreservesScoresAndCapacity() async throws {
        let clock = Clock()
        let scorer = scorer(cap: 2, clock: clock)
        try await retainStrongScores(scorer)
        clock.advance(-10_000)
        let scores = await scorer.topProcesses()
        #expect(scores.count == 2)
        #expect(scores.allSatisfy { $0.score == 100 })
        let arrival = try await crossing(scorer, pid: 3, weight: 15)
        #expect(arrival.totalScore == 15)
        let retained = await scorer.topProcesses()
        #expect(Set(retained.map { $0.pid }) == Set<Int32>([1, 2]))
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }

    @Test("equal maximum finite scores still evict the oldest retained process")
    func maximumFiniteScoresHaveDeterministicEviction() async throws {
        let scorer = scorer(cap: 1, clock: Clock())
        let first = try await crossing(scorer, pid: 1, weight: .greatestFiniteMagnitude)
        let resolved = await scorer.resolveThreshold(
            deliveryToken: first.deliveryToken,
            as: .committed
        )
        #expect(resolved)
        let latest = try await crossing(scorer, pid: 2, weight: .greatestFiniteMagnitude)
        #expect(latest.totalScore.isFinite)
        let retained = await scorer.topProcesses()
        #expect(retained.count == 1)
        #expect(retained.first?.pid == 2)
        let failures = await scorer.lifecycleInvariantFailures()
        #expect(failures.isEmpty)
    }
}
