import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listAlerts(limit: Int) async {
        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let alerts = try await store.alerts(since: Date.distantPast, limit: limit)

            if alerts.isEmpty {
                print("No alerts recorded.")
                return
            }

            print("Last \(alerts.count) alerts:")
            print("══════════════════════════════════════════════════════════════")

            for alert in alerts {
                let time = formatDate(alert.timestamp)
                // Severity prefix provides a text fallback for screen readers and
                // copy-paste contexts where emoji may be rendered as descriptions
                // (e.g., "Heavy Red Circle") or stripped entirely.
                let severityIcon: String
                switch alert.severity {
                case .critical:      severityIcon = "[CRITICAL] 🔴"
                case .high:          severityIcon = "[HIGH]     🟠"
                case .medium:        severityIcon = "[MEDIUM]   🟡"
                case .low:           severityIcon = "[LOW]      🔵"
                case .informational: severityIcon = "[INFO]     ⚪"
                }

                print("\(severityIcon) \(time) \(alert.ruleTitle)")
                print("   Process: \(alert.processName ?? "?") (\(alert.processPath ?? "?"))")
                if let techniques = alert.mitreTechniques, !techniques.isEmpty {
                    print("   MITRE: \(techniques)")
                }
                print()
            }
        } catch {
            print("Error reading alerts: \(error)")
        }
    }

    static func exportAlerts(format: String, limit: Int) async {
        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let alerts = try await store.alerts(since: Date.distantPast, limit: limit)

            if alerts.isEmpty {
                print("No alerts to export.")
                return
            }

            switch format.lowercased() {
            case "csv":
                print("timestamp,severity,rule_id,rule_title,process_name,process_path,mitre_techniques")
                let iso = ISO8601DateFormatter()
                for a in alerts {
                    let ts = iso.string(from: a.timestamp)
                    let fields = [ts, a.severity.rawValue, a.ruleId, a.ruleTitle,
                                  a.processName ?? "", a.processPath ?? "", a.mitreTechniques ?? ""]
                    let escaped = fields.map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }
                    print(escaped.joined(separator: ","))
                }

            case "json":
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                encoder.dateEncodingStrategy = .iso8601
                let data = try encoder.encode(alerts)
                print(String(data: data, encoding: .utf8) ?? "{}")

            default:
                print("Unknown format: \(format). Use 'json' or 'csv'.")
            }
        } catch {
            print("Error exporting alerts: \(error)")
        }
    }

    static func suppressRule(ruleId: String, processPath: String) async {
        let configDir = maccrabDataDir()
        let suppressFile = (configDir as NSString).appendingPathComponent("suppressions.json")

        // Load existing suppressions
        var suppressions: [String: [String]] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: suppressFile)) {
            suppressions = (try? JSONDecoder().decode([String: [String]].self, from: data)) ?? [:]
        }

        // Add suppression
        var paths = suppressions[ruleId] ?? []
        if paths.contains(processPath) {
            print("Process '\(processPath)' is already suppressed for rule '\(ruleId)'.")
            return
        }
        paths.append(processPath)
        suppressions[ruleId] = paths

        // Save
        do {
            let data = try JSONEncoder().encode(suppressions)
            try data.write(to: URL(fileURLWithPath: suppressFile))
            print("✔ Suppressed '\(processPath)' for rule '\(ruleId)'")
            print("  Stored in: \(suppressFile)")
            print("  Restart daemon (SIGHUP) to apply.")
        } catch {
            print("Error saving suppression: \(error)")
        }
    }

    static func watchAlerts() async {
        // LOCALIZE: "Watching for new alerts... (Ctrl+C to stop)"
        print("Watching for new alerts... (Ctrl+C to stop)")
        print("══════════════════════════════════════════════════════════════")

        var lastSeen = Date()
        // IDs of alerts at the exact lastSeen frontier — prevents silent drops when
        // two alerts share the same timestamp within a single poll batch.
        var lastSeenIDs = Set<String>()
        let store: AlertStore
        do {
            store = try AlertStore(directory: maccrabDataDir())
        } catch {
            print("Error opening alert store: \(error)")
            return
        }

        while true {
            do {
                let alerts = try await store.alerts(since: lastSeen, limit: 100)
                var frontierTime = lastSeen
                var frontierIDs = Set<String>()
                for alert in alerts {
                    // Skip alerts already emitted at the frontier timestamp
                    if alert.timestamp == lastSeen && lastSeenIDs.contains(alert.id) { continue }
                    if alert.timestamp < lastSeen { continue }

                    let time = formatDate(alert.timestamp)
                    let icon: String
                    switch alert.severity {
                    case .critical:      icon = "[CRITICAL] 🔴"
                    case .high:          icon = "[HIGH]     🟠"
                    case .medium:        icon = "[MEDIUM]   🟡"
                    case .low:           icon = "[LOW]      🔵"
                    case .informational: icon = "[INFO]     ⚪"
                    }
                    print("\(icon) \(time) \(alert.ruleTitle)")
                    print("   Process: \(alert.processName ?? "?") (\(alert.processPath ?? "?"))")
                    if let tech = alert.mitreTechniques, !tech.isEmpty {
                        print("   MITRE: \(tech)")
                    }
                    print()

                    if alert.timestamp > frontierTime {
                        frontierTime = alert.timestamp
                        frontierIDs = [alert.id]
                    } else if alert.timestamp == frontierTime {
                        frontierIDs.insert(alert.id)
                    }
                }
                if frontierTime > lastSeen {
                    lastSeen = frontierTime
                    lastSeenIDs = frontierIDs
                } else if !frontierIDs.isEmpty {
                    lastSeenIDs.formUnion(frontierIDs)
                }
            } catch {
                // DB may not exist yet; wait silently
            }
            try? await Task.sleep(nanoseconds: 2_000_000_000) // Poll every 2 seconds
        }
    }
}
