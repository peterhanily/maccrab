// ReportGenerator.swift
// MacCrabCore
//
// Generates self-contained HTML incident reports from alert data.

import Foundation
import os.log

/// Generates HTML incident reports from alert data.
public actor ReportGenerator {

    private let logger = Logger(subsystem: "com.maccrab.output", category: "report-generator")

    // MARK: - Report Data

    public struct ReportData: Sendable {
        public let title: String
        public let generatedAt: Date
        public let timeRangeStart: Date
        public let timeRangeEnd: Date
        public let alerts: [AlertData]
        public let summary: Summary

        public init(
            title: String,
            generatedAt: Date,
            timeRangeStart: Date,
            timeRangeEnd: Date,
            alerts: [AlertData],
            summary: Summary
        ) {
            self.title = title
            self.generatedAt = generatedAt
            self.timeRangeStart = timeRangeStart
            self.timeRangeEnd = timeRangeEnd
            self.alerts = alerts
            self.summary = summary
        }

        public struct AlertData: Sendable {
            public let id: String
            public let timestamp: Date
            public let ruleTitle: String
            public let severity: String
            public let processName: String
            public let processPath: String
            public let description: String
            public let mitreTactics: String
            public let mitreTechniques: String

            public init(
                id: String,
                timestamp: Date,
                ruleTitle: String,
                severity: String,
                processName: String,
                processPath: String,
                description: String,
                mitreTactics: String,
                mitreTechniques: String
            ) {
                self.id = id
                self.timestamp = timestamp
                self.ruleTitle = ruleTitle
                self.severity = severity
                self.processName = processName
                self.processPath = processPath
                self.description = description
                self.mitreTactics = mitreTactics
                self.mitreTechniques = mitreTechniques
            }
        }

        public struct Summary: Sendable {
            public let totalAlerts: Int
            public let criticalCount: Int
            public let highCount: Int
            public let mediumCount: Int
            public let lowCount: Int
            public let topRules: [(name: String, count: Int)]
            public let topProcesses: [(name: String, count: Int)]
            public let tacticsDistribution: [(tactic: String, count: Int)]

            public init(
                totalAlerts: Int,
                criticalCount: Int,
                highCount: Int,
                mediumCount: Int,
                lowCount: Int,
                topRules: [(name: String, count: Int)],
                topProcesses: [(name: String, count: Int)],
                tacticsDistribution: [(tactic: String, count: Int)]
            ) {
                self.totalAlerts = totalAlerts
                self.criticalCount = criticalCount
                self.highCount = highCount
                self.mediumCount = mediumCount
                self.lowCount = lowCount
                self.topRules = topRules
                self.topProcesses = topProcesses
                self.tacticsDistribution = tacticsDistribution
            }
        }
    }

    // MARK: - Initialization

    public init() {}

    // MARK: - Report Generation

    /// Generate an HTML report from alert data.
    public func generateHTML(from data: ReportData) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .medium

        let timestampFormatter = DateFormatter()
        timestampFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"

        var html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>\(escapeHTML(data.title))</title>
        <style>
        \(Self.cssTheme)
        </style>
        </head>
        <body>
        """

        // Header
        html += """
        <header>
            <div class="logo-area">
                <span class="logo-icon">&#x1F980;</span>
                <div>
                    <h1>\(escapeHTML(data.title))</h1>
                    <p class="subtitle">Generated: \(dateFormatter.string(from: data.generatedAt))</p>
                    <p class="subtitle">Time Range: \(dateFormatter.string(from: data.timeRangeStart)) &mdash; \(dateFormatter.string(from: data.timeRangeEnd))</p>
                </div>
            </div>
        </header>
        """

        // Executive Summary
        html += """
        <section class="card">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-stat">
                    <span class="stat-value">\(data.summary.totalAlerts)</span>
                    <span class="stat-label">Total Alerts</span>
                </div>
                <div class="summary-stat">
                    <span class="badge badge-critical">\(data.summary.criticalCount)</span>
                    <span class="stat-label">Critical</span>
                </div>
                <div class="summary-stat">
                    <span class="badge badge-high">\(data.summary.highCount)</span>
                    <span class="stat-label">High</span>
                </div>
                <div class="summary-stat">
                    <span class="badge badge-medium">\(data.summary.mediumCount)</span>
                    <span class="stat-label">Medium</span>
                </div>
                <div class="summary-stat">
                    <span class="badge badge-low">\(data.summary.lowCount)</span>
                    <span class="stat-label">Low</span>
                </div>
            </div>
        """

        if !data.summary.topRules.isEmpty {
            html += "<h3>Top Detection Rules</h3><ol>"
            for rule in data.summary.topRules.prefix(3) {
                html += "<li><strong>\(escapeHTML(rule.name))</strong> &mdash; \(rule.count) alert\(rule.count == 1 ? "" : "s")</li>"
            }
            html += "</ol>"
        }
        html += "</section>"

        // Severity Distribution (CSS-only bar chart)
        html += """
        <section class="card">
            <h2>Severity Distribution</h2>
            <div class="bar-chart">
        """

        let maxCount = max(
            data.summary.criticalCount,
            data.summary.highCount,
            data.summary.mediumCount,
            data.summary.lowCount,
            1
        )

        html += barChartRow(label: "Critical", count: data.summary.criticalCount, max: maxCount, cssClass: "bar-critical")
        html += barChartRow(label: "High", count: data.summary.highCount, max: maxCount, cssClass: "bar-high")
        html += barChartRow(label: "Medium", count: data.summary.mediumCount, max: maxCount, cssClass: "bar-medium")
        html += barChartRow(label: "Low", count: data.summary.lowCount, max: maxCount, cssClass: "bar-low")

        html += """
            </div>
        </section>
        """

        // Alert Timeline
        html += """
        <section class="card">
            <h2>Alert Timeline</h2>
        """
        if data.alerts.isEmpty {
            html += "<p class=\"muted\">No alerts in this time range.</p>"
        } else {
            html += """
            <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Timestamp</th>
                        <th>Rule</th>
                        <th>Process</th>
                        <th>MITRE Techniques</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
            """
            for alert in data.alerts {
                let sevClass = severityCSSClass(alert.severity)
                html += """
                <tr>
                    <td><span class="badge \(sevClass)">\(escapeHTML(alert.severity))</span></td>
                    <td class="mono">\(timestampFormatter.string(from: alert.timestamp))</td>
                    <td>\(escapeHTML(alert.ruleTitle))</td>
                    <td class="mono">\(escapeHTML(alert.processName))</td>
                    <td class="mono">\(escapeHTML(alert.mitreTechniques))</td>
                    <td>\(escapeHTML(alert.description))</td>
                </tr>
                """
            }
            html += """
                </tbody>
            </table>
            </div>
            """
        }
        html += "</section>"

        // MITRE ATT&CK Coverage
        if !data.summary.tacticsDistribution.isEmpty {
            html += """
            <section class="card">
                <h2>MITRE ATT&amp;CK Coverage</h2>
                <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Tactic</th>
                            <th>Alert Count</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for entry in data.summary.tacticsDistribution {
                html += """
                    <tr>
                        <td>\(escapeHTML(entry.tactic))</td>
                        <td>\(entry.count)</td>
                    </tr>
                """
            }
            html += """
                    </tbody>
                </table>
                </div>
            </section>
            """
        }

        // Top Processes
        if !data.summary.topProcesses.isEmpty {
            html += """
            <section class="card">
                <h2>Top Processes</h2>
                <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Process</th>
                            <th>Alert Count</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for proc in data.summary.topProcesses {
                html += """
                    <tr>
                        <td class="mono">\(escapeHTML(proc.name))</td>
                        <td>\(proc.count)</td>
                    </tr>
                """
            }
            html += """
                    </tbody>
                </table>
                </div>
            </section>
            """
        }

        // Recommendations
        html += """
        <section class="card">
            <h2>Recommendations</h2>
            <ul>
        """
        html += generateRecommendations(from: data.summary)
        html += """
            </ul>
        </section>
        """

        // Footer
        html += """
        <footer>
            <p>MacCrab Incident Report &mdash; Generated \(dateFormatter.string(from: data.generatedAt))</p>
        </footer>
        </body>
        </html>
        """

        logger.info("Generated HTML report: \(data.summary.totalAlerts) alerts, \(data.alerts.count) rows")
        return html
    }

    /// Generate report data from an array of alerts.
    public func buildReportData(
        alerts: [Alert],
        title: String = "MacCrab Incident Report",
        timeRange: (start: Date, end: Date)? = nil
    ) -> ReportData {
        let now = Date()
        let resolvedStart: Date
        let resolvedEnd: Date

        if let timeRange {
            resolvedStart = timeRange.start
            resolvedEnd = timeRange.end
        } else if let earliest = alerts.map(\.timestamp).min(),
                  let latest = alerts.map(\.timestamp).max() {
            resolvedStart = earliest
            resolvedEnd = latest
        } else {
            resolvedStart = now
            resolvedEnd = now
        }

        // Severity counts
        var criticalCount = 0
        var highCount = 0
        var mediumCount = 0
        var lowCount = 0

        // Aggregation
        var ruleCounts: [String: Int] = [:]
        var processCounts: [String: Int] = [:]
        var tacticCounts: [String: Int] = [:]

        for alert in alerts {
            switch alert.severity {
            case .critical: criticalCount += 1
            case .high: highCount += 1
            case .medium: mediumCount += 1
            case .low: lowCount += 1
            case .informational: break
            }

            ruleCounts[alert.ruleTitle, default: 0] += 1

            let procName = alert.processName ?? "unknown"
            processCounts[procName, default: 0] += 1

            if let tactics = alert.mitreTactics {
                for tactic in tactics.split(separator: ",") {
                    let trimmed = tactic.trimmingCharacters(in: .whitespaces)
                    if !trimmed.isEmpty {
                        tacticCounts[trimmed, default: 0] += 1
                    }
                }
            }
        }

        let topRules = ruleCounts
            .sorted { $0.value > $1.value }
            .prefix(10)
            .map { (name: $0.key, count: $0.value) }

        let topProcesses = processCounts
            .sorted { $0.value > $1.value }
            .prefix(10)
            .map { (name: $0.key, count: $0.value) }

        let tacticsDistribution = tacticCounts
            .sorted { $0.value > $1.value }
            .map { (tactic: $0.key, count: $0.value) }

        let summary = ReportData.Summary(
            totalAlerts: alerts.count,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount,
            topRules: topRules,
            topProcesses: topProcesses,
            tacticsDistribution: tacticsDistribution
        )

        let alertData = alerts.map { alert in
            ReportData.AlertData(
                id: alert.id,
                timestamp: alert.timestamp,
                ruleTitle: alert.ruleTitle,
                severity: alert.severity.rawValue,
                processName: alert.processName ?? "unknown",
                processPath: alert.processPath ?? "unknown",
                description: alert.description ?? "",
                mitreTactics: alert.mitreTactics ?? "",
                mitreTechniques: alert.mitreTechniques ?? ""
            )
        }

        return ReportData(
            title: title,
            generatedAt: now,
            timeRangeStart: resolvedStart,
            timeRangeEnd: resolvedEnd,
            alerts: alertData,
            summary: summary
        )
    }

    /// Write report HTML to file.
    public func writeReport(html: String, to path: String) throws {
        try html.write(toFile: path, atomically: true, encoding: .utf8)
        logger.info("Wrote report to \(path)")
    }

    // MARK: - Private Helpers

    private func escapeHTML(_ string: String) -> String {
        string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    private func severityCSSClass(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return "badge-critical"
        case "high": return "badge-high"
        case "medium": return "badge-medium"
        case "low": return "badge-low"
        default: return "badge-info"
        }
    }

    private func barChartRow(label: String, count: Int, max: Int, cssClass: String) -> String {
        let pct = max > 0 ? Int((Double(count) / Double(max)) * 100) : 0
        return """
        <div class="bar-row">
            <span class="bar-label">\(label)</span>
            <div class="bar-track">
                <div class="bar-fill \(cssClass)" style="width: \(pct)%;"></div>
            </div>
            <span class="bar-count">\(count)</span>
        </div>
        """
    }

    private func generateRecommendations(from summary: ReportData.Summary) -> String {
        var items = ""

        if summary.criticalCount > 0 {
            items += "<li><strong>Immediate Action Required:</strong> \(summary.criticalCount) critical alert\(summary.criticalCount == 1 ? "" : "s") detected. Investigate and remediate these immediately. Consider isolating affected hosts.</li>"
        }

        if summary.highCount > 5 {
            items += "<li><strong>High Alert Volume:</strong> \(summary.highCount) high-severity alerts suggest an active or persistent threat. Review the top detection rules and assess whether they indicate a coordinated attack.</li>"
        } else if summary.highCount > 0 {
            items += "<li><strong>High-Severity Alerts:</strong> \(summary.highCount) high-severity alert\(summary.highCount == 1 ? "" : "s") should be triaged promptly to rule out active compromise.</li>"
        }

        if summary.mediumCount > 20 {
            items += "<li><strong>Rule Tuning Recommended:</strong> \(summary.mediumCount) medium-severity alerts may indicate noisy detection rules. Review the top firing rules and consider tuning thresholds or adding suppressions.</li>"
        }

        if !summary.topRules.isEmpty, let topRule = summary.topRules.first, topRule.count > summary.totalAlerts / 3 {
            items += "<li><strong>Dominant Rule:</strong> \"\(escapeHTML(topRule.name))\" accounts for \(topRule.count) of \(summary.totalAlerts) alerts. Verify this rule is not generating excessive noise and refine its conditions.</li>"
        }

        if !summary.tacticsDistribution.isEmpty && summary.tacticsDistribution.count >= 3 {
            items += "<li><strong>Multi-Tactic Activity:</strong> Alerts span \(summary.tacticsDistribution.count) MITRE ATT&amp;CK tactics, which may indicate a multi-stage attack. Correlate these tactics to assess kill-chain coverage.</li>"
        }

        if summary.totalAlerts == 0 {
            items += "<li><strong>Clean Period:</strong> No alerts detected in this time range. Continue monitoring and ensure detection rules remain up to date.</li>"
        }

        return items
    }

    // MARK: - CSS Theme

    private static let cssTheme = """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', Roboto, sans-serif;
        background: #1a1a2e;
        color: #e0e0e0;
        padding: 24px;
        line-height: 1.6;
    }
    header {
        margin-bottom: 32px;
        padding-bottom: 20px;
        border-bottom: 2px solid #2a2a4a;
    }
    .logo-area {
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .logo-icon {
        font-size: 48px;
    }
    header h1 {
        font-size: 24px;
        font-weight: 700;
        color: #ffffff;
    }
    .subtitle {
        font-size: 13px;
        color: #8888aa;
        margin-top: 2px;
    }
    h2 {
        font-size: 18px;
        font-weight: 600;
        color: #ffffff;
        margin-bottom: 16px;
        padding-bottom: 8px;
        border-bottom: 1px solid #2a2a4a;
    }
    h3 {
        font-size: 15px;
        font-weight: 600;
        color: #ccccdd;
        margin-top: 16px;
        margin-bottom: 8px;
    }
    .card {
        background: #16213e;
        border: 1px solid #2a2a4a;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
    }
    .summary-grid {
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
    }
    .summary-stat {
        display: flex;
        flex-direction: column;
        align-items: center;
        background: #1a1a2e;
        border-radius: 8px;
        padding: 16px 24px;
        min-width: 90px;
    }
    .stat-value {
        font-size: 28px;
        font-weight: 700;
        color: #ffffff;
    }
    .stat-label {
        font-size: 12px;
        color: #8888aa;
        margin-top: 4px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-critical { background: #dc2626; color: #fff; }
    .badge-high { background: #ea580c; color: #fff; }
    .badge-medium { background: #ca8a04; color: #fff; }
    .badge-low { background: #2563eb; color: #fff; }
    .badge-info { background: #4b5563; color: #fff; }
    .bar-chart { margin-top: 8px; }
    .bar-row {
        display: flex;
        align-items: center;
        margin-bottom: 10px;
        gap: 12px;
    }
    .bar-label {
        width: 70px;
        font-size: 13px;
        font-weight: 500;
        text-align: right;
        color: #ccccdd;
    }
    .bar-track {
        flex: 1;
        height: 22px;
        background: #1a1a2e;
        border-radius: 6px;
        overflow: hidden;
    }
    .bar-fill {
        height: 100%;
        border-radius: 6px;
        transition: width 0.3s ease;
        min-width: 2px;
    }
    .bar-critical { background: #dc2626; }
    .bar-high { background: #ea580c; }
    .bar-medium { background: #ca8a04; }
    .bar-low { background: #2563eb; }
    .bar-count {
        width: 40px;
        font-size: 13px;
        font-weight: 600;
        color: #ffffff;
        font-family: 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
    }
    .table-wrapper {
        overflow-x: auto;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }
    thead th {
        text-align: left;
        padding: 10px 12px;
        background: #1a1a2e;
        color: #8888aa;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 0.5px;
        border-bottom: 2px solid #2a2a4a;
    }
    tbody td {
        padding: 8px 12px;
        border-bottom: 1px solid #2a2a4a;
        vertical-align: top;
    }
    tbody tr:hover {
        background: rgba(255, 255, 255, 0.03);
    }
    .mono {
        font-family: 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 12px;
    }
    .muted { color: #8888aa; font-style: italic; }
    ol, ul { padding-left: 24px; }
    li { margin-bottom: 8px; }
    footer {
        margin-top: 32px;
        padding-top: 16px;
        border-top: 1px solid #2a2a4a;
        text-align: center;
        font-size: 12px;
        color: #6666888;
    }
    @media print {
        body { background: #fff; color: #111; padding: 12px; }
        .card { border-color: #ccc; background: #fff; }
        header { border-bottom-color: #ccc; }
        h2 { border-bottom-color: #ccc; color: #111; }
        .summary-stat { background: #f5f5f5; }
        .bar-track { background: #eee; }
        thead th { background: #f5f5f5; color: #333; border-bottom-color: #ccc; }
        tbody td { border-bottom-color: #eee; }
        footer { border-top-color: #ccc; color: #666; }
    }
    """
}
