import Foundation

/// What an expiry pass should do after `expireJournalBlocks` throws.
public enum JournalExpiryTickDecision: Equatable, Sendable {
    /// Transient backpressure: release the maintenance exclusion, wait, and
    /// resume the same pass against the same cutoff.
    case conserveAndRetry
    /// A real failure, or backpressure that outlasted its budget. Give the
    /// cadence back.
    case abandonPass
}

/// Classifies an expiry-pass throw as backpressure or failure.
///
/// Journal expiry is the only thing that removes journal blocks, and every
/// exact read pays for each block that survives, so a pass that abandons its
/// remaining backlog does not merely delay cleanup -- it compounds read cost
/// until the next cadence, which meets the same contention. Both of the store's
/// self-described transient errors were reaching a catch-all that logged
/// `fault` and returned the cadence.
///
/// `memoryLeaseUnavailable` exists precisely because a blind retry is wrong for
/// the per-event write path: there, the retrying task is itself holding the
/// credit it waits for, so retrying burns the deadline and can never succeed,
/// and that case's contract is a BOUNDED, ACCOUNTED exit. This is the other
/// situation. A maintenance sweep holds no record ownership when its
/// acquisition fails -- the credit belongs to live ingest and enrichment, which
/// release it independently -- and it releases the maintenance exclusion before
/// waiting, so it blocks no one. The exit here stays bounded by
/// `backpressureDeadline` and accounted by a published deferral counter, which
/// is what that contract asks for; it is not an unbounded retry.
public enum JournalExpiryBackpressurePolicy {
    public static func decide(
        error: EventStoreError,
        now: Date,
        backpressureDeadline: Date
    ) -> JournalExpiryTickDecision {
        guard error.isTransientBackpressure else { return .abandonPass }
        // Bounded: a permanently starved budget gives the cadence back instead
        // of spinning, and can never push this cutoff past the sweep's
        // documented overhang.
        return now < backpressureDeadline ? .conserveAndRetry : .abandonPass
    }
}

extension EventStoreError {
    /// Whether this is a momentary condition a maintenance sweep should wait
    /// out, rather than a failure that should end the pass.
    public var isTransientBackpressure: Bool {
        switch self {
        case .memoryLeaseUnavailable, .busy:
            return true
        default:
            return false
        }
    }
}
