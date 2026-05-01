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
        try await alertStore.insert(alert: alert)
        insertedCount += 1
        await captureEvidenceIfPossible(alertId: alert.id, timestamp: alert.timestamp)
        return true
    }

    // MARK: - Single alert without event context

    /// Submit a single alert that has no associated event (self-defense,
    /// ES-health, or other infrastructure alerts). Uses `alert.processPath`
    /// (when present) or `alert.ruleId` as the dedup key.
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
        try await alertStore.insert(alert: alert)
        insertedCount += 1
        await captureEvidenceIfPossible(alertId: alert.id, timestamp: alert.timestamp)
        return true
    }

    // MARK: - Engine batch (already filtered + deduped)

    /// Insert a batch of alerts produced by the rule-engine path that has
    /// already applied NoiseFilter + per-match dedup. The sink does not
    /// re-filter; this exists so the engine path uses the same chokepoint
    /// as direct emissions and the architectural invariant holds.
    public func insertEngineBatch(alerts: [Alert]) async throws {
        guard !alerts.isEmpty else { return }
        try await alertStore.insert(alerts: alerts)
        insertedCount += alerts.count
        // Evidence capture is per-alert because each alert's window center
        // is its own timestamp. The PRIMARY KEY (alert_id, id) on
        // alert_evidence dedupes overlapping windows automatically.
        for alert in alerts {
            await captureEvidenceIfPossible(alertId: alert.id, timestamp: alert.timestamp)
        }
    }

    // MARK: - Stats

    public func stats() -> (inserted: Int, suppressed: Int) {
        (insertedCount, suppressedCount)
    }
}
