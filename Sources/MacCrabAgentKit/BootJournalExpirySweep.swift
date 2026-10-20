import Foundation
import MacCrabCore

/// Pre-producer journal expiry with time-based progress renewal and a bounded
/// hand-off of remaining backlog to the runtime expiry timer.
///
/// The former loop drained every eligible block before producers started and
/// renewed the boot heartbeat every 64 batches. RC12 spent 77.6 seconds there
/// on its first boot, with nothing written between renewals when batches were
/// slow. This keeps every batch the same authenticated, aggregate-rolling
/// expiry call. Once its successful-work budget is spent it stops early only
/// if the store no longer needs startup convergence, so the pre-producer
/// writable-admission recovery that follows sees the same or better headroom.
/// The runtime timer then continues the remaining backlog in its usual
/// bounded quanta, contending with live ingestion.
enum BootJournalExpirySweep {
    struct Progress: Equatable, Sendable {
        var expiredEvents = 0
        var batches = 0
        /// Wall time since the sweep began, including backpressure waits.
        var elapsedSeconds: TimeInterval = 0
        /// Time spent inside successful expiry calls only.
        var workSeconds: TimeInterval = 0
    }

    struct Outcome: Equatable, Sendable {
        enum Ending: Equatable, Sendable {
            /// No eligible block remains.
            case drained
            /// The work budget ran out with the store inside its startup boundary.
            case workBudgetSpent
            /// A pass expired nothing while eligible blocks remain, e.g. a
            /// reader pinned the WAL at a checkpoint boundary.
            case stoppedWithBacklog
        }

        let progress: Progress
        let ending: Ending
        /// Eligible backlog remained and is left to the runtime expiry timer.
        var deferredBacklogToRuntime: Bool { ending != .drained }
    }

    /// Boot-phase renewal cadence; well inside the app's 120 s freshness window.
    static let phaseRenewalSeconds: TimeInterval = 10
    /// Successful expiry work allowed before producers when no convergence is
    /// needed; backpressure waiting keeps its own separate budget. Generous on
    /// purpose: an ordinary backlog still drains completely before producers,
    /// and only a pathological one moves into the live window, where it
    /// contends with ingestion.
    static let workBudgetSeconds: TimeInterval = 60

    /// The runtime expiry timer's first pass: prompt when boot deferred
    /// backlog to it, otherwise one ordinary cadence.
    static func runtimeFirstPassDelaySeconds(
        cadenceMinutes: Int,
        bootBacklogDeferred: Bool
    ) -> Int {
        bootBacklogDeferred ? 5 : cadenceMinutes * 60
    }

    /// Whether boot must keep draining. Only a measured footprint inside the
    /// startup boundary permits a hand-off; an unmeasurable store keeps draining.
    static func storeRequiresConvergence(
        measureFootprint: () throws -> Int64,
        requiresConvergence: (Int64) -> Bool
    ) -> Bool {
        guard let footprint = try? measureFootprint() else { return true }
        return requiresConvergence(footprint)
    }

    static func run(
        expire: () async throws -> Int,
        backpressureBudgetSeconds: TimeInterval,
        retryMilliseconds: Int,
        uptime: () -> TimeInterval,
        storeRequiresConvergence: () -> Bool,
        backlogRemains: () async -> Bool,
        renewPhase: (Progress) -> Void,
        onConservedBackpressure: () -> Void,
        sleep: (Int) async throws -> Void
    ) async throws -> Outcome {
        let startedAt = uptime()
        var lastRenewal = startedAt
        var progress = Progress()
        // Consecutive resets whenever a quantum makes progress; cumulative
        // never does. Both use the boot-specific backpressure budget.
        var consecutiveWaitSeconds: TimeInterval = 0
        var cumulativeWaitSeconds: TimeInterval = 0
        while true {
            let callStartedAt = uptime()
            let batch: Int
            do {
                batch = try await expire()
            } catch let error as EventStoreError {
                guard JournalExpiryBackpressurePolicy.decide(
                    error: error,
                    consecutiveWaitSeconds: consecutiveWaitSeconds,
                    cumulativeWaitSeconds: cumulativeWaitSeconds,
                    maximumConsecutiveWaitSeconds: backpressureBudgetSeconds,
                    maximumCumulativeWaitSeconds: backpressureBudgetSeconds
                ) == .conserveAndRetry else {
                    throw error
                }
                onConservedBackpressure()
                try await sleep(retryMilliseconds)
                let waited = Double(retryMilliseconds) / 1000.0
                consecutiveWaitSeconds += waited
                cumulativeWaitSeconds += waited
                continue
            }
            consecutiveWaitSeconds = 0
            progress.expiredEvents += batch
            let now = uptime()
            progress.elapsedSeconds = now - startedAt
            progress.workSeconds += now - callStartedAt
            if batch == 0 {
                // Zero is also what a pass stopped by a reader pin returns.
                return Outcome(
                    progress: progress,
                    ending: await backlogRemains() ? .stoppedWithBacklog : .drained
                )
            }
            progress.batches += 1
            if now - lastRenewal >= phaseRenewalSeconds {
                renewPhase(progress)
                lastRenewal = now
            }
            if progress.workSeconds >= workBudgetSeconds, !storeRequiresConvergence() {
                return Outcome(progress: progress, ending: .workBudgetSpent)
            }
            await Task.yield()
        }
    }
}
