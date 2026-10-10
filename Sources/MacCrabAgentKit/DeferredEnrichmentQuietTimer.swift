import Foundation

/// The callback installed on the production quiet-period timer. Keeping this
/// tiny boundary separate lets tests deliver explicit ticks through the same
/// lifecycle admission path without depending on DispatchSource scheduling.
enum DeferredEnrichmentQuietTimer {
    static func makeEventHandler(
        lifecycle: DaemonTimerLifecycle,
        drain: @escaping @Sendable () async -> Void
    ) -> @Sendable () -> Void {
        {
            // Never gate this callback on an ingestion event's earlier hint:
            // a worker may have completed after the last event was processed.
            _ = lifecycle.submit(label: "deferred-enrichment-drain", operation: drain)
        }
    }
}
