// Plugin invocation record — one row per call into
// Collector/Enricher/Fingerprinter/Analyzer.
//
// Plan reference: §3.4 schema, §3.5 lifecycle.

import Foundation

public struct PluginInvocationRecord: Sendable {

    /// Server-assigned id (set after `recordInvocationStart`).
    public let id: Int64

    /// Owning case.
    public let caseID: String

    /// Which plugin ran.
    public let pluginID: String
    public let pluginVersion: String

    /// JSON-encoded inputs as the runtime saw them. Includes the
    /// operator-supplied values + any defaults the manifest applied.
    /// Stored verbatim so a later operator can rerun an identical
    /// invocation by replaying this column.
    public let inputsJSON: String

    /// Start / end timestamps.
    public let startedAt: Date
    public let completedAt: Date?

    /// Mapped from `CollectionResult.ExitStatus` (for Collectors) or
    /// equivalent enums for the other plugin kinds.
    public let exitStatus: String

    /// What `CollectionResult` reported.
    public let artifactsCommitted: Int64
    public let artifactsRejected: Int64

    /// Populated when `exitStatus == "error"`. Surfaced in
    /// dashboard + invocation log.
    public let errorMessage: String?

    /// For collectors that snapshot a live application database
    /// (TCC.db, BAM): the sha256 of the snapshot copy. Lets the
    /// audit trail link a specific artifact back to the exact
    /// snapshot it was parsed from.
    public let snapshotHash: String?

    public init(
        id: Int64,
        caseID: String,
        pluginID: String,
        pluginVersion: String,
        inputsJSON: String,
        startedAt: Date,
        completedAt: Date? = nil,
        exitStatus: String,
        artifactsCommitted: Int64 = 0,
        artifactsRejected: Int64 = 0,
        errorMessage: String? = nil,
        snapshotHash: String? = nil
    ) {
        self.id = id
        self.caseID = caseID
        self.pluginID = pluginID
        self.pluginVersion = pluginVersion
        self.inputsJSON = inputsJSON
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.exitStatus = exitStatus
        self.artifactsCommitted = artifactsCommitted
        self.artifactsRejected = artifactsRejected
        self.errorMessage = errorMessage
        self.snapshotHash = snapshotHash
    }
}
