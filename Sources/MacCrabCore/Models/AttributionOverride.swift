// AttributionOverride.swift
// MacCrabCore
//
// v1.9 PR-4 — operator-recorded verdict overlay on top of an event's
// machine-emitted agent attribution.
//
// Design contract from Plan v3 review #4 + #10:
//   * Machine attribution is IMMUTABLE on the events row (the
//     `machine_agent_confidence` column never changes after write).
//   * Operator verdicts live in their own `attribution_overrides` table
//     keyed by event id. A second verdict for the same event REPLACES the
//     first (single source of truth per event); we bump `updated_at` so
//     the UI can show "last reviewed at".
//   * Retention coupling: when an event row is purged from `events.db`,
//     the corresponding override row is purged in the same transaction.
//     Pass 12 invariant: every override has a matching event.
//   * `verdict` is a versioned enum (Plan v3 review #12) so a future
//     write that adds a case doesn't make legacy readers crash.

import Foundation

/// One operator verdict on a machine attribution.
public struct AttributionOverride: Sendable, Codable, Equatable {

    /// Schema version for the verdict enum + struct shape. PR-4 ships v1;
    /// future field additions/renames bump this and update the decoder.
    public static let currentSchemaVersion: Int = 1

    /// Operator-supplied verdict. Treated as a versioned enum: a future
    /// writer may emit a value the v1.9 reader doesn't know — that
    /// decodes as `.unknown` rather than failing the row.
    public enum Verdict: String, Sendable, Codable, CaseIterable {
        /// Operator agrees with the machine attribution.
        case confirmed
        /// Machine attributed to the wrong agent tool — UI shows the
        /// operator-provided verdict alongside the machine-emitted one.
        case wrongTool = "wrong_tool"
        /// Machine attributed to an agent at all; operator says no agent
        /// was responsible (e.g. a script run independently, mistakenly
        /// flagged via lineage fallback).
        case noAgent = "no_agent"
        /// Operator wants to record they reviewed the row but neither
        /// confirms nor disconfirms — useful for triage workflow.
        case unknown
    }

    public let eventId: String                 // matches Event.id (UUID)
    public let machineConfidence: String?      // snapshot of machine_agent_confidence at verdict time
    public let verdict: Verdict
    public let userNote: String?
    public let schemaVersion: Int
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        eventId: String,
        machineConfidence: String?,
        verdict: Verdict,
        userNote: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        schemaVersion: Int = AttributionOverride.currentSchemaVersion
    ) {
        self.eventId = eventId
        self.machineConfidence = machineConfidence
        self.verdict = verdict
        self.userNote = userNote
        self.schemaVersion = schemaVersion
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// Aggregate counts surfaced by `EventStore.attributionOverrideStats()`.
///
/// Plan v3 review #11 bound the label format: any place that prints accuracy
/// must clearly note "among rated" so readers don't misinterpret a
/// self-selected sample as a population statistic.
public struct AttributionOverrideStats: Sendable, Codable, Equatable {
    public let ratedCount: Int                 // # events with an override
    public let confirmedCount: Int             // verdict == .confirmed
    public let wrongToolCount: Int             // verdict == .wrongTool
    public let noAgentCount: Int               // verdict == .noAgent
    public let unknownVerdictCount: Int        // verdict == .unknown
    public let totalEventsWithMachineAttribution: Int

    public init(
        ratedCount: Int,
        confirmedCount: Int,
        wrongToolCount: Int,
        noAgentCount: Int,
        unknownVerdictCount: Int,
        totalEventsWithMachineAttribution: Int
    ) {
        self.ratedCount = ratedCount
        self.confirmedCount = confirmedCount
        self.wrongToolCount = wrongToolCount
        self.noAgentCount = noAgentCount
        self.unknownVerdictCount = unknownVerdictCount
        self.totalEventsWithMachineAttribution = totalEventsWithMachineAttribution
    }

    /// Accuracy among rated rows = confirmed / max(rated, 1). Returns nil
    /// when no rows have been rated (UI prints "—" in that case).
    public var accuracyAmongRated: Double? {
        guard ratedCount > 0 else { return nil }
        return Double(confirmedCount) / Double(ratedCount)
    }

    /// Plan v3 review #11 fixed label format. ANY caller that prints the
    /// accuracy must use this string; raw 0.94/n=1247 is forbidden because
    /// it reads as "94% of all 1247 attributions are correct" rather than
    /// "94% of the 1247 attributions a user has rated."
    public var formattedAccuracyLine: String {
        guard let acc = accuracyAmongRated else {
            return "attribution_accuracy_among_rated: — (rated=0, total=\(totalEventsWithMachineAttribution))"
        }
        return String(
            format: "attribution_accuracy_among_rated: %.2f (rated=%d, total=%d)",
            acc, ratedCount, totalEventsWithMachineAttribution
        )
    }
}
