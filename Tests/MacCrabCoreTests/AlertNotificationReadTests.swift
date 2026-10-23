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

    @Test("a reader resumes just below the oldest alert stamped after its watermark")
    func resumeAfterWatermark() async throws {
        let (store, directory) = try store()
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(try await store.notificationResumeRowID(after: Date(timeIntervalSince1970: 0)) == 0)
        #expect(try await store.newestAlertRow() == nil)
        try await store.insert(alert: alert("b0", at: 2_000))
        try await store.insert(alert: alert("b1", at: 2_010))
        try await store.insert(alert: alert("b2", at: 1_990))   // late commit, stamped before b1
        let rows = try await store.alertsForNotification(afterRowID: 0, throughRowID: Int64.max,
                                                          severities: Severity.allCases, limit: 10)
        let resume = try await store.notificationResumeRowID(after: Date(timeIntervalSince1970: 2_005))
        #expect(resume == rows[1].rowID - 1, "b1 and everything committed after it are read again")
        #expect(try await store.notificationResumeRowID(after: Date(timeIntervalSince1970: 3_000)) == rows[2].rowID)
    }
}
