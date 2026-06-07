// AlertStoreFileRoutingTests.swift
//
// Regression for the cluster_alerts bug: handleClusterAlerts opened the
// AlertStore via `init(path: <dir>/events.db)` while every other alert
// handler used `init(directory:)` — which appends the canonical
// `alerts.db`. events.db carries a dormant/empty `alerts` table, so the
// query succeeded and silently returned zero rows ("0 alerts → 0
// clusters") no matter the real alert volume.
//
// These pin the file-routing invariant: a directory-initialized store
// reads/writes <dir>/alerts.db, and a store pointed at <dir>/events.db
// does NOT observe those alerts.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore file routing")
struct AlertStoreFileRoutingTests {

    private func tempDir() throws -> URL {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-alert-routing-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }

    private func alert() -> Alert {
        Alert(
            id: UUID().uuidString,
            timestamp: Date(),
            ruleId: "test.routing",
            ruleTitle: "routing probe",
            severity: .high,
            eventId: UUID().uuidString,
            processPath: "/usr/bin/true",
            processName: "true",
            description: "routing probe",
            mitreTactics: nil,
            mitreTechniques: nil,
            suppressed: false,
            llmInvestigation: nil
        )
    }

    @Test("directory init writes alerts.db; an events.db-path store can't see them")
    func directoryRoutingIsolatesEventsDb() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        // The path every alert handler (incl. the fixed cluster_alerts) uses.
        let dirStore = try AlertStore(directory: dir.path)
        try await dirStore.insert(alert: alert())

        // It lands in <dir>/alerts.db and is visible via the directory store.
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("alerts.db").path))
        let viaDir = try await dirStore.alerts(since: .distantPast, severity: nil, suppressed: false, limit: 5000)
        #expect(viaDir.count == 1)

        // The pre-fix cluster_alerts path: a store bound to <dir>/events.db
        // is a different file and must NOT observe the alert.
        let eventsPathStore = try AlertStore(path: dir.appendingPathComponent("events.db").path)
        let viaEventsPath = try await eventsPathStore.alerts(since: .distantPast, severity: nil, suppressed: false, limit: 5000)
        #expect(viaEventsPath.isEmpty)
    }

    @Test("two directory-init stores observe the same alerts (cluster ≡ get path)")
    func directoryInitParity() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let writer = try AlertStore(directory: dir.path)
        try await writer.insert(alert: alert())

        // cluster_alerts and get_alerts each open AlertStore(directory: dataDir)
        // separately; both must see the same rows.
        let reader = try AlertStore(directory: dir.path)
        let rows = try await reader.alerts(since: .distantPast, severity: nil, suppressed: false, limit: 5000)
        #expect(rows.count == 1)
    }
}
