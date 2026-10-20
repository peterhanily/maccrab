import Foundation
import Testing
@testable import MacCrabCore

/// The notification channel reads forward from its cursor in bounded
/// batches instead of re-reading the newest rows.
@Suite("Alert store forward read for notifications")
struct AlertNotificationReadTests {
    private func alert(_ id: String, at seconds: TimeInterval, suppressed: Bool = false) -> Alert {
        Alert(id: id, timestamp: Date(timeIntervalSince1970: seconds), ruleId: "rule.fixture",
              ruleTitle: "Fixture", severity: .high, eventId: UUID().uuidString,
              processPath: "/tmp/fixture", processName: "fixture", description: "d",
              mitreTactics: nil, mitreTechniques: nil, suppressed: suppressed,
              triggeringEventsJson: String(repeating: "x", count: 4_096))
    }

    @Test("oldest first after the cursor, unsuppressed only, bounded, without trigger evidence")
    func forwardRead() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-notify-read-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        for index in 0..<10 {
            try await store.insert(alert: alert("a\(index)", at: 1_000 + Double(index), suppressed: index == 4))
        }
        let batch = try await store.alertsForNotification(after: Date(timeIntervalSince1970: 1_002), limit: 3)
        #expect(batch.map(\.id) == ["a3", "a5", "a6"])
        #expect(batch.allSatisfy { $0.triggeringEventsJson == nil && $0.llmInvestigation == nil })
        #expect(batch.allSatisfy { $0.ruleTitle == "Fixture" && $0.processName == "fixture" })
        #expect(try await store.notificationBacklogCount(after: Date(timeIntervalSince1970: 1_002)) == 6)
        #expect(try await store.alertsForNotification(after: Date(timeIntervalSince1970: 1_009), limit: 3).isEmpty)
    }
}
