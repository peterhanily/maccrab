import Testing
import Foundation
@testable import MacCrabCore

@Suite("Journal expiry backpressure policy")
struct JournalExpiryBackpressureTests {
    private let consecutiveBudget: TimeInterval = 30
    private let cumulativeBudget: TimeInterval = 120

    private func decide(
        _ error: EventStoreError,
        consecutive: TimeInterval = 0,
        cumulative: TimeInterval = 0
    ) -> JournalExpiryTickDecision {
        JournalExpiryBackpressurePolicy.decide(
            error: error,
            consecutiveWaitSeconds: consecutive,
            cumulativeWaitSeconds: cumulative,
            maximumConsecutiveWaitSeconds: consecutiveBudget,
            maximumCumulativeWaitSeconds: cumulativeBudget
        )
    }

    @Test("A committed memory lease conserves the pass instead of ending it")
    func leaseConservesThePass() {
        // The original regression: this reached a catch-all that logged `fault`
        // and returned, abandoning the rest of the expired backlog until the
        // next cadence -- which met the same contention.
        #expect(
            decide(.memoryLeaseUnavailable("block 1 decode is waiting"))
                == .conserveAndRetry
        )
    }

    @Test("A busy database conserves the pass — it documents itself transient")
    func busyConservesThePass() {
        #expect(decide(.busy("locked")) == .conserveAndRetry)
    }

    @Test("Time spent making progress does not consume the budget")
    func progressDoesNotSpendTheBudget() {
        // Measured on the reference host: anchoring the budget to the pass's
        // START meant a pass that spent minutes draining quanta had already
        // exhausted it before its first refusal, so it abandoned immediately --
        // reproducing the very behaviour the policy removes. 8 abandoned passes
        // were recorded against a single deferral. The budget therefore counts
        // WAITING, and a caller resets `consecutive` on every quantum that
        // makes progress; elapsed pass time is not an input at all.
        #expect(
            decide(
                .memoryLeaseUnavailable("first refusal, 9 minutes into the pass"),
                consecutive: 0,
                cumulative: 0
            ) == .conserveAndRetry
        )
    }

    @Test("Consecutive waiting past its budget gives the cadence back")
    func consecutiveWaitingIsBounded() {
        #expect(
            decide(.memoryLeaseUnavailable("still committed"),
                   consecutive: consecutiveBudget) == .abandonPass
        )
        #expect(
            decide(.memoryLeaseUnavailable("still committed"),
                   consecutive: consecutiveBudget + 1) == .abandonPass
        )
        #expect(
            decide(.memoryLeaseUnavailable("still committed"),
                   consecutive: consecutiveBudget - 0.25) == .conserveAndRetry
        )
    }

    @Test("Cumulative waiting bounds a pass that alternates with progress")
    func cumulativeWaitingIsBounded() {
        // Progress resets `consecutive`, so without this bound a pass that
        // alternated between draining and waiting could run without limit and
        // carry its cutoff outside the sweep's documented overhang.
        #expect(
            decide(.memoryLeaseUnavailable("committed again"),
                   consecutive: 0, cumulative: cumulativeBudget) == .abandonPass
        )
        #expect(
            decide(.memoryLeaseUnavailable("committed again"),
                   consecutive: 0, cumulative: cumulativeBudget - 0.25)
                == .conserveAndRetry
        )
    }

    @Test("Real failures still end the pass immediately")
    func realFailuresAbandon() {
        let failures: [EventStoreError] = [
            .decodingFailed("corrupt frame"),
            .encodingFailed("bad rollup"),
            .prepareFailed("syntax"),
            .stepFailed("constraint"),
            .diskFull("no space"),
        ]
        for failure in failures {
            #expect(decide(failure) == .abandonPass, "\(failure) must not be waited out")
        }
    }

    @Test("Only the self-described transient errors are backpressure")
    func classificationIsNarrow() {
        #expect(EventStoreError.memoryLeaseUnavailable("x").isTransientBackpressure)
        #expect(EventStoreError.busy("x").isTransientBackpressure)
        #expect(!EventStoreError.decodingFailed("x").isTransientBackpressure)
        #expect(!EventStoreError.diskFull("x").isTransientBackpressure)
    }
}
