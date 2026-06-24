// AlertStoreAggregateTests.swift
// PERF-3/5: openAlertCount is an exact whole-window COUNT(*) (no 5000-row
// undercount); severityHistogram buckets per (bucket, severity) SQL-side.
// Pin both, and the histogram's parity with manual row-based bucketing.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore aggregates (PERF-3/5)")
struct AlertStoreAggregateTests {

    private func store() throws -> (AlertStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-agg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return (try AlertStore(directory: tmp.path), tmp)
    }

    private func alert(_ sev: Severity, ago: TimeInterval, from now: Date, suppressed: Bool = false) -> Alert {
        Alert(id: UUID().uuidString, timestamp: now.addingTimeInterval(-ago),
              ruleId: "r", ruleTitle: "t", severity: sev,
              eventId: UUID().uuidString, processPath: nil, processName: nil, description: nil,
              mitreTactics: nil, mitreTechniques: nil, suppressed: suppressed, llmInvestigation: nil)
    }

    @Test("openAlertCount: exact whole-window count, excludes suppressed by default")
    func openAlertCount() async throws {
        let (s, tmp) = try store(); defer { try? FileManager.default.removeItem(at: tmp) }
        let now = Date()
        for _ in 0..<10 { try await s.insert(alert: alert(.high, ago: 100, from: now)) }
        try await s.insert(alert: alert(.high, ago: 100, from: now, suppressed: true))   // excluded
        try await s.insert(alert: alert(.high, ago: 100_000, from: now))                  // outside 1h window
        #expect(try await s.openAlertCount(since: now.addingTimeInterval(-3600)) == 10)
        #expect(try await s.openAlertCount(since: now.addingTimeInterval(-3600), includeSuppressed: true) == 11)
    }

    @Test("severityHistogram matches manual steps-ago bucketing; excludes suppressed")
    func histogramParity() async throws {
        let (s, tmp) = try store(); defer { try? FileManager.default.removeItem(at: tmp) }
        let now = Date()
        let span: TimeInterval = 3600, step: TimeInterval = 300   // 12 buckets
        let seeds: [(Severity, TimeInterval)] = [
            (.critical, 30), (.critical, 90), (.high, 350), (.medium, 650),
            (.low, 1000), (.high, 1000), (.critical, 3500),
        ]
        for (sev, ago) in seeds { try await s.insert(alert: alert(sev, ago: ago, from: now)) }
        try await s.insert(alert: alert(.high, ago: 200, from: now, suppressed: true))   // must not appear

        let cells = try await s.severityHistogram(spanSeconds: span, stepSeconds: step, endingAt: now)
        var agg: [String: Int] = [:]
        for c in cells { agg["\(c.bucketsAgo)|\(c.severity)", default: 0] += c.count }
        var manual: [String: Int] = [:]
        for (sev, ago) in seeds {
            let bucketsAgo = Int(ago / step)
            manual["\(bucketsAgo)|\(sev.rawValue)", default: 0] += 1
        }
        #expect(agg == manual)
        #expect(cells.reduce(0) { $0 + $1.count } == seeds.count)   // 7 unsuppressed, all within 1h
    }
}
