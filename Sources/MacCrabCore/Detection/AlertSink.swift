// AlertSink.swift
// MacCrabCore
//
// Single chokepoint through which every alert reaches AlertStore. Closes the
// v1.6.9 NoiseFilter-layering bug class architecturally: direct
// AlertStore.insert calls scattered across EventLoop, MonitorTasks,
// DaemonSetup, and SignalHandlers bypassed both NoiseFilter and the
// AlertDeduplicator. Routing every emission through AlertSink means dedup
// is mandatory by construction.
//
// The rule-engine batch path (EventLoop line ~925 NoiseFilter.apply followed
// by line ~1265 batch insert) calls `insertEngineBatch(alerts:)` after it has
// already applied NoiseFilter + per-match dedup. Direct emissions (AI-Guard,
// supply chain, threat intel, monitor tasks, self-defense) call `submit(alert:
// event:)` which applies dedup before inserting.
//
// NoiseFilter is intentionally NOT applied to direct emissions — its gates
// were tuned for RuleMatch context and applying them blanket to AI-Guard
// or threat-intel alerts would suppress legitimate signal. Dedup is the
// universal guard.

import Foundation
import os.log

public actor AlertSink {

    private let alertStore: AlertStore
    private let eventStore: EventStore?
    private let deduplicator: AlertDeduplicator
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "AlertSink")

    /// Counter of suppressed alerts since the sink was created. Useful for
    /// the metrics file and diagnostic surfaces.
    private(set) public var suppressedCount: Int = 0
    private(set) public var insertedCount: Int = 0

    public init(
        alertStore: AlertStore,
        deduplicator: AlertDeduplicator,
        eventStore: EventStore? = nil
    ) {
        self.alertStore = alertStore
        self.eventStore = eventStore
        self.deduplicator = deduplicator
    }

    // v1.8.0: when an alert is committed, snapshot the surrounding ±60s of
    // events into `alert_evidence` so the dashboard's alert detail can show
    // "what was happening when this fired?" even after the 24h hot tier
    // drops the originating events. Best-effort — failure is logged but
    // does not back out the alert insert.
    private func captureEvidenceIfPossible(alertId: String, timestamp: Date) async {
        guard let eventStore else { return }
        do {
            try await eventStore.recordAlertEvidence(
                alertId: alertId,
                alertTimestamp: timestamp
            )
        } catch {
            logger.warning("Evidence capture failed for alert \(alertId, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Single alert with event context

    /// Submit a single alert produced outside the rule-engine batch path.
    /// Applies dedup keyed on `(alert.ruleId, event.process.executable)`,
    /// then inserts into the store. Returns `true` if the alert was inserted,
    /// `false` if it was suppressed as a duplicate. Throws on storage error
    /// so the caller can route to StorageErrorTracker (which lives in the
    /// agent-kit layer, not MacCrabCore).
    ///
    /// v1.12.6 Wave 2B: before insertion, the alert is enriched with
    /// attribution fields lifted from the triggering Event (user, CWD,
    /// AI tool, parent exec, exec sha256). Doing this in the sink — the
    /// single chokepoint — means every call site automatically picks up
    /// the new schema v5 columns without changes, and no second
    /// insertion path is introduced (preserves Pass 2 of
    /// pre-release-audit.sh: only one place writes to alerts.db).
    @discardableResult
    public func submit(alert: Alert, event: Event) async throws -> Bool {
        let dedupKey = event.process.executable
        // Atomic check+record closes the TOCTOU window where two concurrent
        // submits with the same key could both pass shouldSuppress between
        // each other's recordAlert. AlertDeduplicator is an actor so a
        // single method invocation is serialized.
        if await deduplicator.shouldSuppressAndRecord(ruleId: alert.ruleId, processPath: dedupKey) {
            suppressedCount += 1
            return false
        }
        let enriched = Self.enrichWithAttribution(alert: alert, event: event)
        try await alertStore.insert(alert: enriched)
        insertedCount += 1
        await captureEvidenceIfPossible(alertId: enriched.id, timestamp: enriched.timestamp)
        return true
    }

    // MARK: - Single alert without event context

    /// Submit a single alert that has no associated event (self-defense,
    /// ES-health, or other infrastructure alerts). Uses `alert.processPath`
    /// (when present) or `alert.ruleId` as the dedup key.
    ///
    /// v1.12.6 Wave 2B: even without an Event we set `hostName` so the
    /// alert row carries the originating machine — useful for fleet
    /// dashboards consolidating multiple hosts' alerts.
    @discardableResult
    public func submit(alert: Alert) async throws -> Bool {
        let dedupKey = alert.processPath ?? alert.ruleId
        // Atomic check+record closes the TOCTOU window where two concurrent
        // submits with the same key could both pass shouldSuppress between
        // each other's recordAlert. AlertDeduplicator is an actor so a
        // single method invocation is serialized.
        if await deduplicator.shouldSuppressAndRecord(ruleId: alert.ruleId, processPath: dedupKey) {
            suppressedCount += 1
            return false
        }
        let enriched = Self.enrichWithHostOnly(alert: alert)
        try await alertStore.insert(alert: enriched)
        insertedCount += 1
        await captureEvidenceIfPossible(alertId: enriched.id, timestamp: enriched.timestamp)
        return true
    }

    // MARK: - Engine batch (already filtered + deduped)

    /// Insert a batch of alerts produced by the rule-engine path that has
    /// already applied NoiseFilter + per-match dedup. The sink does not
    /// re-filter; this exists so the engine path uses the same chokepoint
    /// as direct emissions and the architectural invariant holds.
    ///
    /// v1.12.6 Wave 2B: optional `event` parameter so the engine path
    /// (which generates N alerts from one Event) can supply the
    /// triggering Event once and have every alert enriched. Callers that
    /// already pre-populated attribution on the alert (or have no Event
    /// context, like test harnesses) pass nil and the alerts go through
    /// unchanged.
    public func insertEngineBatch(alerts: [Alert], event: Event? = nil) async throws {
        guard !alerts.isEmpty else { return }
        let toInsert: [Alert]
        if let event {
            toInsert = alerts.map { Self.enrichWithAttribution(alert: $0, event: event) }
        } else {
            toInsert = alerts.map { Self.enrichWithHostOnly(alert: $0) }
        }
        try await alertStore.insert(alerts: toInsert)
        insertedCount += toInsert.count
        // Evidence capture is per-alert because each alert's window center
        // is its own timestamp. The PRIMARY KEY (alert_id, id) on
        // alert_evidence dedupes overlapping windows automatically.
        for alert in toInsert {
            await captureEvidenceIfPossible(alertId: alert.id, timestamp: alert.timestamp)
        }
    }

    // MARK: - Stats

    public func stats() -> (inserted: Int, suppressed: Int) {
        (insertedCount, suppressedCount)
    }

    // MARK: - Attribution enrichment (schema v5)

    /// Return a copy of `alert` with the schema-v5 attribution fields
    /// populated from the triggering Event. Existing values on the
    /// alert are preserved — i.e. a caller that already filled in
    /// `aiTool` (say, from a richer enrichment source) keeps that value;
    /// nil-fields fall through to the Event-derived defaults.
    ///
    /// Empty strings on the Event side are converted to nil here so the
    /// "" → NULL contract is enforced at the chokepoint rather than
    /// scattered through every Alert constructor.
    nonisolated static func enrichWithAttribution(alert: Alert, event: Event) -> Alert {
        let aiTool = event.enrichments["ai_tool"] ?? event.enrichments["agent_tool"]
        let parentExec = event.process.ancestors.first?.executable
        let sha256 = event.process.hashes?.sha256
        return Alert(
            id: alert.id,
            timestamp: alert.timestamp,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: alert.severity,
            eventId: alert.eventId,
            processPath: alert.processPath,
            processName: alert.processName,
            description: alert.description,
            mitreTactics: alert.mitreTactics,
            mitreTechniques: alert.mitreTechniques,
            suppressed: alert.suppressed,
            campaignId: alert.campaignId,
            hostContext: alert.hostContext,
            analyst: alert.analyst,
            d3fendTechniques: alert.d3fendTechniques,
            remediationHint: alert.remediationHint,
            llmInvestigation: alert.llmInvestigation,
            userId: alert.userId ?? event.process.userId,
            userName: alert.userName ?? Self.nilIfEmpty(event.process.userName),
            workingDirectory: alert.workingDirectory ?? Self.nilIfEmpty(event.process.workingDirectory),
            aiTool: alert.aiTool ?? Self.nilIfEmpty(aiTool),
            parentExecutable: alert.parentExecutable ?? Self.nilIfEmpty(parentExec),
            processSha256: alert.processSha256 ?? Self.nilIfEmpty(sha256),
            hostName: alert.hostName ?? Self.defaultHostName()
        )
    }

    /// Variant for alerts that have no triggering Event (self-defense,
    /// ES health, scheduled-report stubs). Only sets `hostName` — the
    /// other attribution fields stay nil since there's no source.
    nonisolated static func enrichWithHostOnly(alert: Alert) -> Alert {
        guard alert.hostName == nil else { return alert }
        return Alert(
            id: alert.id,
            timestamp: alert.timestamp,
            ruleId: alert.ruleId,
            ruleTitle: alert.ruleTitle,
            severity: alert.severity,
            eventId: alert.eventId,
            processPath: alert.processPath,
            processName: alert.processName,
            description: alert.description,
            mitreTactics: alert.mitreTactics,
            mitreTechniques: alert.mitreTechniques,
            suppressed: alert.suppressed,
            campaignId: alert.campaignId,
            hostContext: alert.hostContext,
            analyst: alert.analyst,
            d3fendTechniques: alert.d3fendTechniques,
            remediationHint: alert.remediationHint,
            llmInvestigation: alert.llmInvestigation,
            userId: alert.userId,
            userName: alert.userName,
            workingDirectory: alert.workingDirectory,
            aiTool: alert.aiTool,
            parentExecutable: alert.parentExecutable,
            processSha256: alert.processSha256,
            hostName: Self.defaultHostName()
        )
    }

    /// Resolve the host name for local alert storage. Uses
    /// `Foundation.ProcessInfo.processInfo.hostName` — same convention
    /// as FleetClient.hostId and BundleRedactor.systemDefault. Falls
    /// back to the v1.12.5 webhook/syslog default `"maccrab-host"` if
    /// the lookup returns an empty string (rare; defensive).
    nonisolated static func defaultHostName() -> String {
        let raw = Foundation.ProcessInfo.processInfo.hostName
        return raw.isEmpty ? "maccrab-host" : raw
    }

    nonisolated private static func nilIfEmpty(_ s: String?) -> String? {
        guard let s, !s.isEmpty else { return nil }
        return s
    }
}
