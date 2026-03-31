import Foundation
import HawkEyeCore

@main
struct HawkCtl {
    static func main() async {
        let args = CommandLine.arguments

        guard args.count >= 2 else {
            printUsage()
            exit(0)
        }

        let command = args[1]

        switch command {
        case "status":
            await showStatus()
        case "rules":
            if args.count >= 3 && args[2] == "list" {
                await listRules()
            } else if args.count >= 3 && args[2] == "count" {
                await countRules()
            } else {
                print("Usage: hawkctl rules [list|count]")
            }
        case "events":
            if args.count >= 3 && args[2] == "tail" {
                let limit = args.count >= 4 ? Int(args[3]) ?? 20 : 20
                await tailEvents(limit: limit)
            } else if args.count >= 3 && args[2] == "search" && args.count >= 4 {
                let query = args[3...].joined(separator: " ")
                await searchEvents(query: query)
            } else if args.count >= 3 && args[2] == "stats" {
                await eventStats()
            } else {
                print("Usage: hawkctl events [tail [N]|search <query>|stats]")
            }
        case "alerts":
            let limit = args.count >= 3 ? Int(args[2]) ?? 20 : 20
            await listAlerts(limit: limit)
        case "compile":
            if args.count >= 4 {
                compileRules(inputDir: args[2], outputDir: args[3])
            } else {
                print("Usage: hawkctl compile <input-rules-dir> <output-compiled-dir>")
            }
        case "version":
            printVersion()
        case "help", "-h", "--help":
            printUsage()
        default:
            print("Unknown command: \(command)")
            printUsage()
            exit(1)
        }
    }

    static func printUsage() {
        print("""
        hawkctl - HawkEye Detection Engine CLI

        Usage: hawkctl <command> [options]

        Commands:
          status              Show daemon status and statistics
          rules list          List all loaded detection rules
          rules count         Count rules by category
          events tail [N]     Show last N events (default: 20)
          events search <q>   Full-text search over events
          events stats        Show event statistics
          alerts [N]          Show last N alerts (default: 20)
          compile <in> <out>  Compile Sigma YAML rules to JSON
          version             Show version information
          help                Show this help message

        Environment:
          HAWKEYE_DB_PATH     Path to events database
                              (default: ~/Library/Application Support/HawkEye/events.db)

        Examples:
          hawkctl status
          hawkctl events tail 50
          hawkctl events search "curl Downloads"
          hawkctl alerts 10
          hawkctl rules list
          hawkctl compile ./Rules ./compiled_rules
        """)
    }

    static func printVersion() {
        print("HawkEye Detection Engine v0.1.0")
        print("License: Apache 2.0 (code), DRL 1.1 (rules)")
        print("https://github.com/hawkeye-detection/hawkeye")
    }

    static func showStatus() async {
        let supportDir = NSHomeDirectory() + "/Library/Application Support/HawkEye"
        let dbPath = supportDir + "/events.db"
        let alertsPath = supportDir + "/alerts.jsonl"

        print("HawkEye Status")
        print("══════════════════════════════════════")

        // Check if daemon is running
        let daemonRunning = isDaemonRunning()
        print("Daemon:     \(daemonRunning ? "Running ✓" : "Not running ✗")")

        // Database info
        if FileManager.default.fileExists(atPath: dbPath) {
            let attrs = try? FileManager.default.attributesOfItem(atPath: dbPath)
            let size = attrs?[.size] as? UInt64 ?? 0
            let modified = attrs?[.modificationDate] as? Date
            print("Database:   \(dbPath)")
            print("DB Size:    \(formatBytes(size))")
            if let modified = modified {
                print("Last Event: \(formatDate(modified))")
            }
        } else {
            print("Database:   Not found (daemon has not run yet)")
        }

        // Alerts info
        if FileManager.default.fileExists(atPath: alertsPath) {
            let attrs = try? FileManager.default.attributesOfItem(atPath: alertsPath)
            let size = attrs?[.size] as? UInt64 ?? 0
            print("Alerts Log: \(formatBytes(size))")
        }

        // Rules info
        let compiledDir = supportDir + "/compiled_rules"
        if FileManager.default.fileExists(atPath: compiledDir) {
            let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir)
            let ruleCount = files?.filter { $0.hasSuffix(".json") }.count ?? 0
            print("Rules:      \(ruleCount) compiled rules loaded")
        } else {
            print("Rules:      No compiled rules found")
        }

        print("══════════════════════════════════════")
    }

    static func listRules() async {
        let supportDir = NSHomeDirectory() + "/Library/Application Support/HawkEye"
        let compiledDir = supportDir + "/compiled_rules"

        guard FileManager.default.fileExists(atPath: compiledDir) else {
            print("No compiled rules found. Run: hawkctl compile <rules-dir> <output-dir>")
            return
        }

        guard let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir) else {
            print("Failed to read compiled rules directory")
            return
        }

        let jsonFiles = files.filter { $0.hasSuffix(".json") }.sorted()

        print("Detection Rules (\(jsonFiles.count) total)")
        print("══════════════════════════════════════════════════════════════")
        print(String(format: "%-8s %-50s %s", "Level", "Title", "Tags"))
        print(String(repeating: "─", count: 80))

        for file in jsonFiles {
            let path = compiledDir + "/" + file
            guard let data = FileManager.default.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
            }

            let title = json["title"] as? String ?? "Unknown"
            let level = json["level"] as? String ?? "?"
            let tags = (json["tags"] as? [String])?.prefix(3).joined(separator: ", ") ?? ""

            let levelStr: String
            switch level {
            case "critical": levelStr = "[CRIT]"
            case "high":     levelStr = "[HIGH]"
            case "medium":   levelStr = "[MED] "
            case "low":      levelStr = "[LOW] "
            default:         levelStr = "[INFO]"
            }

            print(String(format: "%-8s %-50s %s", levelStr, String(title.prefix(48)), String(tags.prefix(30))))
        }
    }

    static func countRules() async {
        let supportDir = NSHomeDirectory() + "/Library/Application Support/HawkEye"
        let compiledDir = supportDir + "/compiled_rules"

        guard let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir) else {
            print("No compiled rules found.")
            return
        }

        var bySeverity: [String: Int] = [:]
        var byCategory: [String: Int] = [:]

        for file in files where file.hasSuffix(".json") {
            let path = compiledDir + "/" + file
            guard let data = FileManager.default.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            let level = json["level"] as? String ?? "unknown"
            bySeverity[level, default: 0] += 1

            if let logsource = json["logsource"] as? [String: String],
               let category = logsource["category"] {
                byCategory[category, default: 0] += 1
            }
        }

        print("Rules by Severity:")
        for (level, count) in bySeverity.sorted(by: { $0.value > $1.value }) {
            print("  \(level): \(count)")
        }
        print("\nRules by Log Source:")
        for (cat, count) in byCategory.sorted(by: { $0.value > $1.value }) {
            print("  \(cat): \(count)")
        }
    }

    static func tailEvents(limit: Int) async {
        do {
            let store = try EventStore()
            let events = await store.events(since: Date.distantPast, category: nil, limit: limit)

            print("Last \(events.count) events:")
            print(String(repeating: "─", count: 100))

            for event in events {
                let time = formatDate(event.timestamp)
                let action = event.eventAction
                let proc = "\(event.process.name)(\(event.process.pid))"
                let detail: String
                if let file = event.file {
                    detail = file.path
                } else if let net = event.network {
                    detail = "\(net.destinationIp ?? "?"):\(net.destinationPort ?? 0)"
                } else {
                    detail = event.process.executable
                }

                print("\(time) [\(action)] \(proc) → \(detail)")
            }
        } catch {
            print("Error reading events: \(error)")
        }
    }

    static func searchEvents(query: String) async {
        do {
            let store = try EventStore()
            let events = await store.search(text: query, limit: 50)

            print("Search results for '\(query)' (\(events.count) matches):")
            print(String(repeating: "─", count: 100))

            for event in events {
                let time = formatDate(event.timestamp)
                let proc = "\(event.process.name)(\(event.process.pid))"
                print("\(time) [\(event.eventAction)] \(proc) | \(event.process.executable)")
            }
        } catch {
            print("Error searching events: \(error)")
        }
    }

    static func eventStats() async {
        do {
            let store = try EventStore()
            let stats = await store.statistics()
            print("Event Statistics (last 24h):")
            print("══════════════════════════════════════")
            for (key, value) in stats.sorted(by: { $0.key < $1.key }) {
                print("  \(key): \(value)")
            }
        } catch {
            print("Error reading stats: \(error)")
        }
    }

    static func listAlerts(limit: Int) async {
        do {
            let store = try AlertStore()
            let alerts = await store.alerts(since: Date.distantPast, limit: limit)

            if alerts.isEmpty {
                print("No alerts recorded.")
                return
            }

            print("Last \(alerts.count) alerts:")
            print("══════════════════════════════════════════════════════════════")

            for alert in alerts {
                let time = formatDate(alert.timestamp)
                let severityIcon: String
                switch alert.severity {
                case .critical: severityIcon = "🔴"
                case .high:     severityIcon = "🟠"
                case .medium:   severityIcon = "🟡"
                case .low:      severityIcon = "🔵"
                case .informational: severityIcon = "⚪"
                }

                print("\(severityIcon) \(time) \(alert.ruleTitle)")
                print("   Process: \(alert.processName ?? "?") (\(alert.processPath ?? "?"))")
                if !alert.mitreTechniques.isEmpty {
                    print("   MITRE: \(alert.mitreTechniques)")
                }
                print()
            }
        } catch {
            print("Error reading alerts: \(error)")
        }
    }

    static func compileRules(inputDir: String, outputDir: String) {
        print("Compiling rules from \(inputDir) to \(outputDir)...")
        print("Note: Use the Python compiler for full Sigma YAML support:")
        print("  python3 Compiler/compile_rules.py --input-dir \(inputDir) --output-dir \(outputDir)")
    }

    // MARK: - Helpers

    static func isDaemonRunning() -> Bool {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", "hawkeyed"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes) / 1024) }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(bytes) / (1024 * 1024)) }
        return String(format: "%.1f GB", Double(bytes) / (1024 * 1024 * 1024))
    }

    static func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }
}
