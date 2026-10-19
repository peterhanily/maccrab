import Foundation
import MacCrabCore

/// Pre-producer journal expiry with time-based progress renewal and a bounded
/// hand-off of remaining backlog to the runtime expiry timer.
///
/// The former loop drained every eligible block before producers started and
/// renewed the boot heartbeat every 64 batches. RC12 spent 77.6 seconds there
/// on its first boot, with nothing written between renewals when batches were
/// slow. This keeps every batch the same authenticated, aggregate-rolling
/// expiry call. Once its work budget is spent it stops early only if the store
/// no longer needs startup convergence, so the pre-producer writable-admission
/// recovery that follows sees the same or better headroom. The runtime timer
/// then continues the remaining backlog in its usual bounded quanta.
enum BootJournalExpirySweep {
    struct Progress: Equatable, Sendable {
        var expiredEvents = 0
        var batches = 0
        var elapsedSeconds: TimeInterval = 0
    }

    struct Outcome: Equatable, Sendable {
        let progress: Progress
        /// Eligible backlog remained and is left to the runtime expiry timer.
        let deferredBacklogToRuntime: Bool
    }

    /// Boot-phase renewal cadence; well inside the app's 120 s freshness window.
    static let phaseRenewalSeconds: TimeInterval = 10
    /// Successful expiry work allowed before producers when no convergence is
    /// needed. Backpressure waiting keeps its own separate budget.
    static let workBudgetSeconds: TimeInterval = 20

    static func run(
        expire: () async throws -> Int,
        backpressureBudgetSeconds: TimeInterval,
        retryMilliseconds: Int,
        uptime: () -> TimeInterval,
        storeRequiresConvergence: () -> Bool,
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
            if batch == 0 {
                return Outcome(progress: progress, deferredBacklogToRuntime: false)
            }
            progress.batches += 1
            if now - lastRenewal >= phaseRenewalSeconds {
                renewPhase(progress)
                lastRenewal = now
            }
            if now - startedAt >= workBudgetSeconds, !storeRequiresConvergence() {
                return Outcome(progress: progress, deferredBacklogToRuntime: true)
            }
            await Task.yield()
        }
    }
}
