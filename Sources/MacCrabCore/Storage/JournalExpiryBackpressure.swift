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
    /// - Parameters:
    ///   - consecutiveWaitSeconds: time spent waiting since the last quantum
    ///     that made progress. Resets to zero whenever one succeeds.
    ///   - cumulativeWaitSeconds: total time this pass has spent waiting.
    ///
    /// Two bounds, because one is not enough. The consecutive bound is the one
    /// that decides whether the budget is still worth spending: a pass runs for
    /// minutes draining quanta, so anchoring the budget to the pass's start
    /// means that by the time backpressure first appears the budget is already
    /// spent and the pass abandons on its first refusal -- the exact behaviour
    /// this policy exists to remove. Measured on the reference host, that
    /// anchoring produced 8 abandoned passes against a single recorded
    /// deferral. The cumulative bound then keeps a pass that alternates between
    /// progress and waiting from running unboundedly, so a pass still cannot
    /// outlive the sweep's documented five-minute overhang.
    public static func decide(
        error: EventStoreError,
        consecutiveWaitSeconds: TimeInterval,
        cumulativeWaitSeconds: TimeInterval,
        maximumConsecutiveWaitSeconds: TimeInterval,
        maximumCumulativeWaitSeconds: TimeInterval
    ) -> JournalExpiryTickDecision {
        guard error.isTransientBackpressure else { return .abandonPass }
        guard consecutiveWaitSeconds < maximumConsecutiveWaitSeconds,
              cumulativeWaitSeconds < maximumCumulativeWaitSeconds else {
            return .abandonPass
        }
        return .conserveAndRetry
    }

    /// What a pass does once `decide` abandons it.
    public enum AbandonedPassOutcome: Sendable, Equatable {
        /// Wait `continuationDelaySeconds`, then continue with fresh budgets.
        case continueAfterDelay
        /// Backpressure, not failure: the next cadence resumes the backlog.
        case deferToNextPass
        /// A non-transient error.
        case fail
    }

    /// A pass that spent its backpressure budget used to end as a failure,
    /// leaving its backlog to the next cadence, which label coalescing pushes
    /// up to ten minutes out when the pass overlaps a tick. A continuation is
    /// a new pass with a fresh cutoff and budgets, so each keeps the bound
    /// above.
    public static let continuationDelaySeconds: TimeInterval = 30
    public static let maximumContinuationsPerPass = 8

    /// Where a continuation starts: a cutoff taken now and unspent budgets.
    /// Keeping the abandoned pass's cutoff would only chase the backlog it
    /// already failed to drain, with the budgets it already spent.
    public struct PassStart: Sendable, Equatable {
        public let retainedThrough: Date
        public let consecutiveWaitSeconds: TimeInterval
        public let cumulativeWaitSeconds: TimeInterval
    }

    public static func continuation(at now: Date) -> PassStart {
        PassStart(retainedThrough: now, consecutiveWaitSeconds: 0, cumulativeWaitSeconds: 0)
    }

    public static func afterAbandon(
        error: EventStoreError,
        continuations: Int,
        backlogRemains: Bool
    ) -> AbandonedPassOutcome {
        guard error.isTransientBackpressure else { return .fail }
        guard backlogRemains, continuations < maximumContinuationsPerPass else {
            return .deferToNextPass
        }
        return .continueAfterDelay
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
