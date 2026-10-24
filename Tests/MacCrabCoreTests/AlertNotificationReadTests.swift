import Foundation
import Testing
@testable import MacCrabCore

/// The notification channel reads forward from its cursor in commit (rowid)
/// order, at or above its severity floor, in bounded batches.
@Suite("Alert store forward read for notifications")
struct AlertNotificationReadTests {
    private func alert(_ id: String, at seconds: TimeInterval, severity: Severity = .high,
                       suppressed: Bool = false) -> Alert {
        Alert(id: id, timestamp: Date(timeIntervalSince1970: seconds), ruleId: "rule.fixture",
              ruleTitle: "Fixture", severity: severity, eventId: UUID().uuidString,
              processPath: "/tmp/fixture", processName: "fixture", description: "d",
              mitreTactics: nil, mitreTechniques: nil, suppressed: suppressed,
              triggeringEventsJson: String(repeating: "x", count: 4_096))
    }

    private func store() throws -> (AlertStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-notify-read-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return (try AlertStore(directory: directory.path), directory)
    }

    @Test("commit order after the cursor, unsuppressed and at the floor only, bounded, without trigger evidence")
    func forwardRead() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        for index in 0..<10 {
            try await store.insert(alert: alert("a\(index)", at: 1_000 + Double(index),
                                                severity: index == 7 ? .low : .high, suppressed: index == 4))
        }
        // Stamped before everything else, committed last.
        try await store.insert(alert: alert("late", at: 500))
        let newest = try #require(try await store.newestAlertRow())
        #expect(newest.id == "late")
        let all = try await store.alertsForNotification(afterRowID: 0, throughRowID: newest.rowID,
                                                         severities: [.high, .critical], limit: 100)
        #expect(all.map(\.alert.id) == ["a0", "a1", "a2", "a3", "a5", "a6", "a8", "a9", "late"])
        #expect(all.map(\.rowID) == all.map(\.rowID).sorted())
        let third = all[2].rowID
        #expect(try await store.alertID(atRowID: third) == "a2")

        let batch = try await store.alertsForNotification(afterRowID: third, throughRowID: newest.rowID,
                                                           severities: [.high, .critical], limit: 3)
        #expect(batch.map(\.alert.id) == ["a3", "a5", "a6"])
        #expect(batch.allSatisfy { $0.alert.triggeringEventsJson == nil && $0.alert.llmInvestigation == nil })
        #expect(batch.allSatisfy { $0.alert.ruleTitle == "Fixture" && $0.alert.processName == "fixture" })
        #expect(try await store.notificationBacklogCount(afterRowID: third, severities: [.high, .critical]) == 6)
        #expect(try await store.notificationBacklogCount(afterRowID: third, severities: Severity.allCases) == 7)
        #expect(try await store.alertsForNotification(afterRowID: newest.rowID, throughRowID: newest.rowID,
                                                      severities: Severity.allCases, limit: 3).isEmpty)
        #expect(try await store.alertsForNotification(afterRowID: 0, throughRowID: third,
                                                      severities: [.high], limit: 100).count == 3,
                "nothing past the upper bound")
    }

    @Test("a reader resumes on the row just below the oldest alert stamped after its watermark")
    func resumeAfterWatermark() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(try await store.notificationResumeRow(after: Date(timeIntervalSince1970: 0)) == nil)
        #expect(try await store.newestAlertRow() == nil)
        try await store.insert(alert: alert("b0", at: 2_000))
        try await store.insert(alert: alert("b1", at: 2_010))
        try await store.insert(alert: alert("b2", at: 1_990))   // late commit, stamped before b1
        let rows = try await store.alertsForNotification(afterRowID: 0, throughRowID: Int64.max,
                                                          severities: Severity.allCases, limit: 10)
        let resume = try await store.notificationResumeRow(after: Date(timeIntervalSince1970: 2_005))
        #expect(resume == AlertStore.AlertRowReference(rowID: rows[0].rowID, id: "b0"),
                "b1 and everything committed after it are read again")
        #expect(try await store.notificationResumeRow(after: Date(timeIntervalSince1970: 3_000))
                == AlertStore.AlertRowReference(rowID: rows[2].rowID, id: "b2"))
        #expect(try await store.notificationResumeRow(after: Date(timeIntervalSince1970: 1_000)) == nil,
                "every row is stamped after it: nothing precedes them")
        #expect(try await store.newestTimestamp(throughRowID: rows[0].rowID) == Date(timeIntervalSince1970: 2_000))
        #expect(try await store.newestTimestamp(throughRowID: rows[2].rowID) == Date(timeIntervalSince1970: 2_010))
    }

    @Test("the resume and rewrite reads stay on the timestamp index")
    func readsStayOnTheTimestampIndex() throws {
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabCore/Storage/AlertStore.swift"), encoding: .utf8)
        // MIN(rowid) and a bare rowid or severity term let the planner walk the
        // table in rowid order, or every alert of a severity, on every tick.
        #expect(source.contains("SELECT MIN(+rowid) FROM alerts WHERE timestamp > ?1"))
        #expect(source.contains("FROM alerts WHERE +rowid <= ?1 AND timestamp > ?2 AND suppressed = 0"))
        #expect(source.contains("AND +severity IN (\\(placeholders))"))
    }

    @Test("a cursor read whose step fails throws instead of reading as an empty table")
    func failedStepThrows() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        try await store.insert(alert: alert("c0", at: 2_000))
        let newest = try #require(try await store.newestAlertRow())
        await store.interruptReadsForTesting(true)
        await #expect(throws: (any Error).self) { _ = try await store.newestAlertRow() }
        await #expect(throws: (any Error).self) { _ = try await store.alertID(atRowID: newest.rowID) }
        await #expect(throws: (any Error).self) {
            _ = try await store.notificationResumeRow(after: Date(timeIntervalSince1970: 0))
        }
        await #expect(throws: (any Error).self) { _ = try await store.newestTimestamp(throughRowID: newest.rowID) }
        await store.interruptReadsForTesting(false)
        #expect(try await store.newestAlertRow() == newest)
    }

    @Test("a row rewritten in place behind the cursor is read once its stamp moves past the watermark")
    func rewrittenRows() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        try await store.insert(alert: alert("vuln-CVE-1", at: 3_000, severity: .high))
        try await store.insert(alert: alert("other", at: 3_001, severity: .critical))
        let through = try #require(try await store.newestAlertRow()).rowID
        let watermark = Date(timeIntervalSince1970: 3_001)
        #expect(try await store.alertsRewrittenForNotification(throughRowID: through, after: watermark,
                                                               severities: [.critical], limit: 10).isEmpty)
        // Re-scored as critical on its own row, stamped again.
        try await store.insert(alert: alert("vuln-CVE-1", at: 3_600, severity: .critical))
        #expect(try await store.newestAlertRow()?.rowID == through, "rewritten in place, not a new row")
        let rewritten = try await store.alertsRewrittenForNotification(throughRowID: through, after: watermark,
                                                                       severities: [.critical], limit: 10)
        #expect(rewritten.map(\.alert.id) == ["vuln-CVE-1"])
        #expect(try await store.alertsRewrittenForNotification(throughRowID: through, after: watermark,
                                                               severities: [.critical], limit: 10)
                .count == 1, "a read does not consume it; the reader's watermark does")
        #expect(try await store.alertsRewrittenForNotification(throughRowID: through,
                                                               after: Date(timeIntervalSince1970: 3_600),
                                                               severities: [.critical], limit: 10).isEmpty)
    }
}
