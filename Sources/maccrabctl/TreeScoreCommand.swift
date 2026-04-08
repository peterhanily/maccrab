// TreeScoreCommand.swift
// maccrabctl
//
// Shows process tree Markov chain model statistics and the top behaviorally
// suspicious processes (by alert count and pattern spread).

import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func showTreeScore(limit: Int) async {
        print("MacCrab Process Tree & Behavioral Scoring")
        print("══════════════════════════════════════════")

        // ── 1. Markov chain model stats ────────────────────────────────────
        let analyzer = ProcessTreeAnalyzer()
        do {
            try await analyzer.load()
        } catch {
            // No model persisted yet — that's fine, show zero stats
        }

        let modelStats = await analyzer.stats()
        print("\nMarkov Chain Model")
        print("  Mode:             \(modelStats.mode.rawValue)")
        print("  Transitions:      \(modelStats.transitions)")
        print("  Unique parents:   \(modelStats.uniqueParents)")
        print("  Unique edges:     \(modelStats.uniqueEdges)")

        if modelStats.mode == .learning {
            print("  ⚠️  Still learning — scoring begins after \(ProcessTreeAnalyzer.defaultMinTransitions) transitions")
        }

        // ── 2. Behavioral scoring ─────────────────────────────────────────
        // Derive from alert store: aggregate by process path, count distinct rule IDs,
        // and flag processes that appear in multiple MITRE tactic categories.
        print("\nTop Suspicious Processes (last 24h)")
        print("──────────────────────────────────────────")

        do {
            let store = try AlertStore(directory: maccrabDataDir())
            let since = Date().addingTimeInterval(-86400)
            let alerts = try await store.alerts(since: since, limit: 5000)

            guard !alerts.isEmpty else {
                print("  No alerts in the last 24 hours.")
                return
            }

            // Group by process path, counting distinct rules and tactics
            struct ProcessStats {
                var path: String
                var name: String
                var alertCount: Int = 0
                var rules: Set<String> = []
                var tactics: Set<String> = []
                var severities: [String: Int] = [:]
            }

            var byPath: [String: ProcessStats] = [:]
            for alert in alerts {
                let path = alert.processPath ?? alert.processName ?? "unknown"
                var stats = byPath[path] ?? ProcessStats(path: path, name: alert.processName ?? "unknown")
                stats.alertCount += 1
                stats.rules.insert(alert.ruleId)
                if let tactics = alert.mitreTactics {
                    for tactic in tactics.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) {
                        stats.tactics.insert(tactic)
                    }
                }
                stats.severities[alert.severity.rawValue, default: 0] += 1
                byPath[path] = stats
            }

            // Score: weight by alert count + tactic spread + rule variety
            let scored = byPath.values
                .filter { $0.alertCount >= 1 }
                .map { stats -> (stats: ProcessStats, score: Double) in
                    let score = Double(stats.alertCount) * 1.0
                        + Double(stats.rules.count) * 2.0
                        + Double(stats.tactics.count) * 5.0
                        + Double(stats.severities["critical"] ?? 0) * 10.0
                        + Double(stats.severities["high"] ?? 0) * 4.0
                    return (stats, score)
                }
                .sorted { $0.score > $1.score }
                .prefix(limit)

            if scored.isEmpty {
                print("  No processes with significant behavioral signal.")
            } else {
                print(String(format: "  %-35s %5s %5s %5s  %s",
                    "Process", "Alrts", "Rules", "Tctcs", "Top Severity"))
                print("  " + String(repeating: "─", count: 72))
                for (stats, _) in scored {
                    let name = String(((stats.path as NSString).lastPathComponent.isEmpty
                        ? stats.name : (stats.path as NSString).lastPathComponent)
                        .prefix(34))
                    let topSeverity: String
                    if (stats.severities["critical"] ?? 0) > 0 { topSeverity = "CRITICAL" }
                    else if (stats.severities["high"] ?? 0) > 0 { topSeverity = "HIGH" }
                    else if (stats.severities["medium"] ?? 0) > 0 { topSeverity = "MEDIUM" }
                    else { topSeverity = "LOW" }

                    print(String(format: "  %-35s %5d %5d %5d  %s",
                        name, stats.alertCount, stats.rules.count, stats.tactics.count, topSeverity))
                }
            }
        } catch {
            print("  Error reading alert store: \(error)")
        }

        print("\nTip: maccrabctl hunt \"show anomalous process trees\" for NL analysis")
    }
}

// Default minimum transitions before scoring (same as ProcessTreeAnalyzer.init default).
extension ProcessTreeAnalyzer {
    static let defaultMinTransitions = 500
}
