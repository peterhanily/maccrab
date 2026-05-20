// CollectorOutput — the narrow write-only handle a Collector
// receives, so plugins can commit artifacts mid-run without
// reaching for the full ArtifactStore surface.
//
// Plan reference: §3.5 — "batched commit: every N artifacts
// (default 1000), COMMIT and continue".

import Foundation

/// Write-only artifact-commit interface. The runtime constructs
/// one of these per invocation, wrapping the case's ArtifactStore.
/// Plugins call `commit(_:)` as they discover artifacts; the
/// runtime tallies and surfaces the count back via
/// `CollectionResult.artifactsCommitted`.
///
/// Read APIs (query, list cases) are intentionally absent — a
/// Collector that needs to read its own prior committed output
/// is doing something wrong; that's Analyzer territory.
public protocol CollectorOutput: Sendable {

    /// Commit a single artifact. Mirrors `ArtifactStore.commit(_:)`
    /// and surfaces the same errors — notably
    /// `plaintextCaseRejectsNonMetadata` (Pass 2026-D), which the
    /// plugin should treat as fatal for that artifact (but not
    /// necessarily for the whole run).
    @discardableResult
    func commit(_ record: ArtifactRecord) async throws -> Int64
}

/// Production CollectorOutput backed by an ArtifactStore. The
/// PluginRunner constructs one per invocation; the plugin sees
/// it as the abstract protocol only.
public struct StoreCollectorOutput: CollectorOutput {
    private let store: ArtifactStore

    public init(store: ArtifactStore) {
        self.store = store
    }

    @discardableResult
    public func commit(_ record: ArtifactRecord) async throws -> Int64 {
        try await store.commit(record)
    }
}
