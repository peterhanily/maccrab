import Testing
import Foundation
@testable import MacCrabCore

@Suite("Journal expiry backpressure policy")
struct JournalExpiryBackpressureTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test("A committed memory lease conserves the pass instead of ending it")
    func leaseConservesThePass() {
        // The regression: this reached a catch-all that logged `fault` and
        // returned, abandoning the rest of the expired backlog until the next
        // cadence -- which met the same contention. Measured on the reference
        // host, 36,774 of 43,133 blocks sat past `retained_until`.
        let decision = JournalExpiryBackpressurePolicy.decide(
            error: .memoryLeaseUnavailable("block 1 decode is waiting"),
            now: now,
            backpressureDeadline: now.addingTimeInterval(30)
        )
        #expect(decision == .conserveAndRetry)
    }

    @Test("A busy database conserves the pass — it documents itself transient")
    func busyConservesThePass() {
        let decision = JournalExpiryBackpressurePolicy.decide(
            error: .busy("locked"),
            now: now,
            backpressureDeadline: now.addingTimeInterval(30)
        )
        #expect(decision == .conserveAndRetry)
    }

    @Test("Backpressure past its budget gives the cadence back, never spins")
    func backpressureIsBounded() {
        let deadline = now.addingTimeInterval(30)
        #expect(JournalExpiryBackpressurePolicy.decide(
            error: .memoryLeaseUnavailable("still committed"),
            now: deadline,
            backpressureDeadline: deadline
        ) == .abandonPass)
        #expect(JournalExpiryBackpressurePolicy.decide(
            error: .memoryLeaseUnavailable("still committed"),
            now: deadline.addingTimeInterval(1),
            backpressureDeadline: deadline
        ) == .abandonPass)
    }

    @Test("Real failures still end the pass immediately")
    func realFailuresAbandon() {
        let deadline = now.addingTimeInterval(30)
        let failures: [EventStoreError] = [
            .decodingFailed("corrupt frame"),
            .encodingFailed("bad rollup"),
            .prepareFailed("syntax"),
            .stepFailed("constraint"),
            .diskFull("no space"),
        ]
        for failure in failures {
            #expect(
                JournalExpiryBackpressurePolicy.decide(
                    error: failure, now: now, backpressureDeadline: deadline
                ) == .abandonPass,
                "\(failure) must not be waited out"
            )
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
