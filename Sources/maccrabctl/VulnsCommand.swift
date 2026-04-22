import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listVulns(hours: Double? = nil, severityFilter: Severity? = nil) async {
        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let since = hours.map { Date().addingTimeInterval(-$0 * 3600) } ?? Date.distantPast
            let all = try await store.alerts(since: since, severity: severityFilter, limit: 500)
            let vulns = all.filter { $0.ruleId.hasPrefix("maccrab.vuln.") }

            if vulns.isEmpty {
                let timeDesc = hours.map { "last \(Int($0))h" } ?? "all time"
                print("No vulnerability alerts recorded (\(timeDesc)).")
                print("The scanner runs hourly and only surfaces critical/high CVEs.")
                return
            }

            let timeLabel = hours.map { "last \(Int($0))h" } ?? "all time"
            let sevLabel = severityFilter.map { " [\($0.rawValue)+]" } ?? ""
            print("\(vulns.count) vulnerability alert(s) — \(timeLabel)\(sevLabel)")
            print("══════════════════════════════════════════════════════════════")

            for vuln in vulns {
                let time = formatDate(vuln.timestamp)
                // Extract CVE ID from ruleId: "maccrab.vuln.CVE-YYYY-NNNNNN"
                let cveId = String(vuln.ruleId.dropFirst("maccrab.vuln.".count))
                print("\(vuln.severity.coloredLabel) \(time)  \(cveId)")
                print("   App:     \(vuln.processName ?? "?")  (\(vuln.processPath ?? "?"))")
                if let desc = vuln.description, !desc.isEmpty {
                    print("   Detail:  \(desc)")
                }
                print()
            }

            print("Run 'maccrabctl alerts --severity critical' to see all alerts including vulns.")
        } catch {
            print("Error reading alerts: \(error)")
        }
    }
}
