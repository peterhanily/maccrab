// ReplayBatchReport.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-11 batch replay) — types + HTML renderer for
// `replay-batch` runs per §17.5 of the v1.10.0 spec.
//
// Use case: a directory of regression bundles is replayed against a
// ruleset; the report shows per-bundle outcomes, fail-closed counts,
// difference summaries, and aggregate statistics.

import Foundation

public struct ReplayBatchReport: Sendable {

    public let runStartedAt: Date
    public let runCompletedAt: Date
    public let directoryPath: String
    public let entries: [Entry]

    public init(
        runStartedAt: Date,
        runCompletedAt: Date,
        directoryPath: String,
        entries: [Entry]
    ) {
        self.runStartedAt = runStartedAt
        self.runCompletedAt = runCompletedAt
        self.directoryPath = directoryPath
        self.entries = entries.sorted { $0.bundlePath < $1.bundlePath }
    }

    public struct Entry: Sendable {
        public let bundlePath: String
        public let result: ReplayResult

        public init(bundlePath: String, result: ReplayResult) {
            self.bundlePath = bundlePath
            self.result = result
        }
    }

    // MARK: - Aggregates

    public var totalCount: Int { entries.count }
    public var okCount: Int { entries.filter { $0.result.result == .ok }.count }
    public var failClosedCount: Int { entries.filter { $0.result.result == .unsupportedStatefulReplay }.count }
    public var schemaInvalidCount: Int { entries.filter { $0.result.result == .schemaInvalid }.count }
    public var incompatibleCount: Int { entries.filter { $0.result.result == .incompatibleNormalizationVersion }.count }
    public var withDifferencesCount: Int { entries.filter { !$0.result.differencesVsOriginal.isEmpty }.count }

    public var durationSeconds: TimeInterval {
        runCompletedAt.timeIntervalSince(runStartedAt)
    }
}

public enum ReplayBatchReportRenderer {

    public static func renderHTML(_ report: ReplayBatchReport) -> String {
        let dateFormatter = ISO8601DateFormatter()
        let started = dateFormatter.string(from: report.runStartedAt)
        let completed = dateFormatter.string(from: report.runCompletedAt)
        var html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8" />
        <title>MacCrab TraceGraph Replay Batch Report</title>
        <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif; margin: 24px; color: #1d1d1f; }
        h1 { font-size: 24px; }
        h2 { font-size: 18px; margin-top: 32px; }
        .summary { background: #f5f5f7; padding: 16px; border-radius: 8px; margin: 16px 0; }
        .summary span { display: inline-block; margin-right: 24px; }
        .summary .ok { color: #1f9c4f; font-weight: 600; }
        .summary .fail-closed { color: #b85c00; font-weight: 600; }
        .summary .schema-invalid { color: #c00000; font-weight: 600; }
        table { border-collapse: collapse; width: 100%; margin-top: 16px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #ddd; vertical-align: top; }
        th { background: #f5f5f7; font-weight: 600; }
        tr.ok td.outcome { color: #1f9c4f; }
        tr.fail-closed td.outcome { color: #b85c00; }
        tr.schema-invalid td.outcome { color: #c00000; }
        tr.incompatible td.outcome { color: #6e6e73; }
        code { font-family: 'SF Mono', Menlo, monospace; font-size: 13px; background: #f5f5f7; padding: 1px 4px; border-radius: 3px; }
        .diffs { font-size: 12px; color: #6e6e73; }
        .diffs li { margin: 2px 0; }
        footer { margin-top: 48px; font-size: 12px; color: #6e6e73; }
        </style>
        </head>
        <body>
        <h1>MacCrab TraceGraph Replay Batch Report</h1>
        <p><strong>Directory:</strong> <code>\(escapeHTML(report.directoryPath))</code></p>
        <p><strong>Started:</strong> \(started) &nbsp; <strong>Completed:</strong> \(completed) &nbsp; <strong>Duration:</strong> \(String(format: "%.2f", report.durationSeconds))s</p>

        <div class="summary">
        <span class="ok">✓ OK: \(report.okCount)</span>
        <span class="fail-closed">⚠ Fail-closed (out-of-scope state): \(report.failClosedCount)</span>
        <span class="schema-invalid">✗ Schema invalid: \(report.schemaInvalidCount)</span>
        <span>↺ Incompatible normalization: \(report.incompatibleCount)</span>
        <span>↦ With differences: \(report.withDifferencesCount)</span>
        <span><strong>Total: \(report.totalCount)</strong></span>
        </div>

        <h2>Per-bundle results</h2>
        <table>
        <thead><tr>
          <th>Bundle</th>
          <th>Outcome</th>
          <th>Exit</th>
          <th>Trace</th>
          <th>Alerts</th>
          <th>Differences</th>
          <th>Notes</th>
        </tr></thead>
        <tbody>
        """

        for entry in report.entries {
            let r = entry.result
            let cssClass: String = {
                switch r.result {
                case .ok: return "ok"
                case .unsupportedStatefulReplay: return "fail-closed"
                case .schemaInvalid: return "schema-invalid"
                case .incompatibleNormalizationVersion: return "incompatible"
                }
            }()
            let bundleName = (entry.bundlePath as NSString).lastPathComponent
            let differencesNote: String = {
                if r.differencesVsOriginal.isEmpty { return "" }
                let items = r.differencesVsOriginal.prefix(5).map { d -> String in
                    var s = "<li>\(escapeHTML(d.type)): <code>\(escapeHTML(d.ruleId))</code>"
                    if let from = d.from, let to = d.to {
                        s += " (\(escapeHTML(from)) → \(escapeHTML(to)))"
                    }
                    s += "</li>"
                    return s
                }
                return "<ul class=\"diffs\">" + items.joined() + "</ul>"
            }()
            let notes: String = {
                if !r.unsupportedEngines.isEmpty {
                    return "engines: " + r.unsupportedEngines.joined(separator: ", ")
                }
                return ""
            }()
            html += """
            <tr class="\(cssClass)">
              <td><code>\(escapeHTML(bundleName))</code></td>
              <td class="outcome">\(escapeHTML(r.result.rawValue))</td>
              <td>\(r.exitCode)</td>
              <td><code>\(escapeHTML(r.traceId))</code></td>
              <td>\(r.alerts.count)</td>
              <td>\(differencesNote)</td>
              <td><span class="diffs">\(escapeHTML(notes))</span></td>
            </tr>

            """
        }
        html += """
        </tbody>
        </table>
        <footer>
        Generated by MacCrab TraceGraph ReplayEngine. Exit codes per §18.9: 0 ok · 1 schema · 6 normalization · 11 fail-closed.
        </footer>
        </body>
        </html>
        """
        return html
    }

    private static func escapeHTML(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
