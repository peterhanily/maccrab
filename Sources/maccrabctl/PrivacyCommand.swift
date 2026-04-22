import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listPrivacyAlerts(hours: Double? = nil) async {
        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let since = hours.map { Date().addingTimeInterval(-$0 * 3600) } ?? Date.distantPast
            let all = try await store.alerts(since: since, limit: 500)
            let privAlerts = all.filter { $0.ruleId.hasPrefix("maccrab.privacy.") }

            if privAlerts.isEmpty {
                let timeDesc = hours.map { "last \(Int($0))h" } ?? "all time"
                print("No privacy anomaly alerts recorded (\(timeDesc)).")
                print("The auditor runs hourly and surfaces bulk egress, domain spikes,")
                print("and high-frequency tracker contacts.")
                return
            }

            let timeLabel = hours.map { "last \(Int($0))h" } ?? "all time"
            print("\(privAlerts.count) privacy anomaly alert(s) — \(timeLabel)")
            print("══════════════════════════════════════════════════════════════")

            for alert in privAlerts {
                let time = formatDate(alert.timestamp)
                // Extract kind from ruleId: "maccrab.privacy.<kind>"
                let kind = String(alert.ruleId.dropFirst("maccrab.privacy.".count))
                let kindLabel: String
                switch kind {
                case "bulkEgress":       kindLabel = "Bulk Egress"
                case "singleDomainSpike": kindLabel = "Domain Spike"
                case "trackingContact":  kindLabel = "Tracker Contact"
                default:                 kindLabel = kind
                }
                print("\(alert.severity.coloredLabel) \(time)  \(kindLabel)")
                print("   Process: \(alert.processName ?? "?")  (\(alert.processPath ?? "?"))")
                if let desc = alert.description, !desc.isEmpty {
                    print("   Detail:  \(desc)")
                }
                print()
            }

            print("Run 'maccrabctl alerts' to see all alerts including privacy anomalies.")
        } catch {
            print("Error reading alerts: \(error)")
        }
    }
}
