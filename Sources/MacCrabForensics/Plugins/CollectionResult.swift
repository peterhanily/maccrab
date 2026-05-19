// CollectionResult — what a Collector returns after `collect(...)`.
// The ArtifactStore actually owns commit; CollectionResult is the
// summary the runtime writes into `plugin_invocations`.
//
// Plan reference: §3.5 plugin lifecycle.

import Foundation

public struct CollectionResult: Sendable, Codable {

    /// Number of artifacts the Collector handed to the ArtifactStore
    /// for commit. Matches what `plugin_invocations.artifacts_committed`
    /// holds in SQLite.
    public let artifactsCommitted: Int

    /// Number of items the Collector saw at the source but rejected
    /// from commit — malformed, schema-version mismatched, or
    /// privacy-class-rejected at the store layer.
    public let artifactsRejected: Int

    /// Optional structured findings the Collector wants to surface
    /// to its invocation log. Distinct from `Finding` (which is the
    /// Analyzer output type); these are operational notes like
    /// "coverage gap: REG.db not parsed" or "snapshot used:
    /// /tmp/TCC.db.snapshot.<sha>".
    public let notes: [String]

    /// Overall exit status. The runtime maps this to
    /// `plugin_invocations.exit_status`.
    public let status: ExitStatus

    public init(
        artifactsCommitted: Int,
        artifactsRejected: Int = 0,
        notes: [String] = [],
        status: ExitStatus = .ok
    ) {
        self.artifactsCommitted = artifactsCommitted
        self.artifactsRejected = artifactsRejected
        self.notes = notes
        self.status = status
    }

    public enum ExitStatus: String, Codable, Sendable {
        /// All declared sources read; all artifacts committed.
        case ok

        /// Some sources read; some not. Stored alongside a `notes`
        /// entry naming the gap. Caller may choose to retry.
        case partial

        /// Hard fail — no artifacts committed (or commit rolled
        /// back). The runtime records `error_message` separately.
        case error

        /// Operator hit `^C` (CLI) or "Cancel" (dashboard) mid-run.
        /// Already-committed artifacts are retained.
        case cancelled
    }
}
