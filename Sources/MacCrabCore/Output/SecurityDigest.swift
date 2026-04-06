import Foundation
import os.log

/// Generates daily security digest summaries.
public actor SecurityDigest {
    private let logger = Logger(subsystem: "com.maccrab.output", category: "security-digest")

    public struct Digest: Sendable {
        public let date: Date
        public let period: String  // "24 hours", "7 days"
        public let totalEvents: Int
        public let totalAlerts: Int
        public let criticalAlerts: Int
        public let highAlerts: Int
        public let mediumAlerts: Int
        public let lowAlerts: Int
        public let topRules: [(name: String, count: Int)]
        public let topProcesses: [(name: String, count: Int)]
        public let preventionActions: Int
        public let securityScore: Int?
        public let recommendations: [String]
        public let summary: String
    }

    public init() {}

    /// Generate a digest from alert data.
    public func generate(
        alerts: [(ruleTitle: String, severity: String, processName: String, timestamp: Date)],
        eventCount: Int,
        securityScore: Int? = nil,
        period: String = "24 hours"
    ) -> Digest {
        let critical = alerts.filter { $0.severity == "critical" }.count
        let high = alerts.filter { $0.severity == "high" }.count
        let medium = alerts.filter { $0.severity == "medium" }.count
        let low = alerts.filter { $0.severity == "low" }.count

        // Top rules
        var ruleCounts: [String: Int] = [:]
        for alert in alerts { ruleCounts[alert.ruleTitle, default: 0] += 1 }
        let topRules = ruleCounts.sorted { $0.value > $1.value }.prefix(5).map { ($0.key, $0.value) }

        // Top processes
        var processCounts: [String: Int] = [:]
        for alert in alerts { processCounts[alert.processName, default: 0] += 1 }
        let topProcesses = processCounts.sorted { $0.value > $1.value }.prefix(5).map { ($0.key, $0.value) }

        // Recommendations
        var recommendations: [String] = []
        if critical > 0 { recommendations.append("Review \(critical) critical alert(s) immediately") }
        if high > 5 { recommendations.append("High alert volume (\(high)) — consider tuning rules or investigating root cause") }
        if let score = securityScore, score < 80 { recommendations.append("Security score is \(score)/100 — check recommendations in the dashboard") }
        if alerts.isEmpty { recommendations.append("No alerts in the last \(period) — detection is running clean") }

        // Summary text
        let summary: String
        if critical > 0 {
            summary = "⚠️ \(critical) critical alert(s) detected in the last \(period). Immediate review recommended."
        } else if high > 0 {
            summary = "\(high) high-severity alert(s) in the last \(period). \(eventCount) events processed."
        } else if alerts.isEmpty {
            summary = "✅ Clean — no alerts in the last \(period). \(eventCount) events processed."
        } else {
            summary = "\(alerts.count) alert(s) in the last \(period), none critical. \(eventCount) events processed."
        }

        return Digest(
            date: Date(), period: period,
            totalEvents: eventCount, totalAlerts: alerts.count,
            criticalAlerts: critical, highAlerts: high,
            mediumAlerts: medium, lowAlerts: low,
            topRules: topRules, topProcesses: topProcesses,
            preventionActions: 0,
            securityScore: securityScore,
            recommendations: recommendations,
            summary: summary
        )
    }

    /// Format digest as plain text (for email/log).
    public func formatText(_ digest: Digest) -> String {
        var text = """
        ═══════════════════════════════════════════════
        🦀 MacCrab Security Digest — \(digest.period)
        Generated: \(ISO8601DateFormatter().string(from: digest.date))
        ═══════════════════════════════════════════════

        \(digest.summary)

        Events processed: \(digest.totalEvents)
        Total alerts: \(digest.totalAlerts)
          Critical: \(digest.criticalAlerts)
          High: \(digest.highAlerts)
          Medium: \(digest.mediumAlerts)
          Low: \(digest.lowAlerts)

        """

        if let score = digest.securityScore {
            text += "Security Score: \(score)/100\n\n"
        }

        if !digest.topRules.isEmpty {
            text += "Top Rules:\n"
            for (name, count) in digest.topRules {
                text += "  \(count)× \(name)\n"
            }
            text += "\n"
        }

        if !digest.recommendations.isEmpty {
            text += "Recommendations:\n"
            for rec in digest.recommendations {
                text += "  • \(rec)\n"
            }
        }

        text += "\n═══════════════════════════════════════════════\n"
        return text
    }
}
