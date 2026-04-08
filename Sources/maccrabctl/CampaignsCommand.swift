import Foundation
import MacCrabCore

extension MacCrabCtl {

    /// Lists recent campaigns detected by the campaign correlator.
    /// Campaigns are stored as regular alerts with rule IDs prefixed "maccrab.campaign.".
    static func listCampaigns(limit: Int) async {
        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let allRecent = try await store.alerts(since: Date.distantPast, limit: 500)
            let campaigns = allRecent
                .filter { $0.ruleId.hasPrefix("maccrab.campaign.") }
                .prefix(limit)

            if campaigns.isEmpty {
                print("No campaigns recorded.")
                print("Campaigns require ≥3 MITRE tactics within the detection window (600s).")
                print("Run 'make test-campaign' to simulate multi-tactic adversary activity.")
                return
            }

            print("Last \(campaigns.count) campaign\(campaigns.count == 1 ? "" : "s"):")
            print("══════════════════════════════════════════════════════════════")

            for c in campaigns {
                let time = formatDate(c.timestamp)
                let severityLabel: String
                switch c.severity {
                case .critical:      severityLabel = "[CRITICAL]"
                case .high:          severityLabel = "[HIGH]    "
                case .medium:        severityLabel = "[MEDIUM]  "
                case .low:           severityLabel = "[LOW]     "
                case .informational: severityLabel = "[INFO]    "
                }

                let typeLabel = c.ruleId
                    .replacingOccurrences(of: "maccrab.campaign.", with: "")
                    .replacingOccurrences(of: "_", with: " ")
                    .capitalized

                print("\(severityLabel) \(time)")
                print("   Type:    \(typeLabel)")
                print("   Title:   \(c.ruleTitle)")
                if let desc = c.description, !desc.isEmpty {
                    // Trim to one line for the summary view
                    let firstLine = desc.components(separatedBy: "\n").first ?? desc
                    print("   Detail:  \(firstLine)")
                }
                if let tactics = c.mitreTactics, !tactics.isEmpty {
                    print("   Tactics: \(tactics)")
                }
                print("   ID:      \(c.id)")
                print()
            }
        } catch {
            print("Error reading campaigns: \(error)")
        }
    }

    /// Streams new campaigns live (polls every 5 seconds).
    static func watchCampaigns() async {
        print("Watching for new campaigns... (Ctrl+C to stop)")
        print("══════════════════════════════════════════════════════════════")

        var lastSeen = Date()
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
                let recent = try await store.alerts(since: lastSeen, limit: 100)
                let campaigns = recent.filter { $0.ruleId.hasPrefix("maccrab.campaign.") }

                var frontierTime = lastSeen
                var frontierIDs = Set<String>()

                for c in campaigns {
                    if c.timestamp == lastSeen && lastSeenIDs.contains(c.id) { continue }
                    if c.timestamp < lastSeen { continue }

                    let time = formatDate(c.timestamp)
                    let typeLabel = c.ruleId
                        .replacingOccurrences(of: "maccrab.campaign.", with: "")
                        .replacingOccurrences(of: "_", with: " ")
                        .capitalized

                    print("🚨 CAMPAIGN  \(time)")
                    print("   [\(c.severity.rawValue.uppercased())] \(typeLabel)")
                    print("   \(c.ruleTitle)")
                    if let tactics = c.mitreTactics, !tactics.isEmpty {
                        print("   Tactics: \(tactics)")
                    }
                    print()

                    if c.timestamp > frontierTime {
                        frontierTime = c.timestamp
                        frontierIDs = [c.id]
                    } else if c.timestamp == frontierTime {
                        frontierIDs.insert(c.id)
                    }
                }

                if frontierTime > lastSeen {
                    lastSeen = frontierTime
                    lastSeenIDs = frontierIDs
                } else if !frontierIDs.isEmpty {
                    lastSeenIDs.formUnion(frontierIDs)
                }
            } catch {
                // DB may not exist yet
            }
            try? await Task.sleep(nanoseconds: 5_000_000_000) // Poll every 5s
        }
    }
}
