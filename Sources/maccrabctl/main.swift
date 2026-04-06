import Foundation
import MacCrabCore

/// Resolve the MacCrab data directory.
/// Prefers the system dir (root daemon) when its DB is newer, since the
/// user dir may contain stale data from a previous non-root run.
private func maccrabDataDir() -> String {
    let fm = FileManager.default
    let userDir = fm.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
    ).first.map { $0.appendingPathComponent("MacCrab").path }
        ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
    let systemDir = "/Library/Application Support/MacCrab"

    let userDB = userDir + "/events.db"
    let systemDB = systemDir + "/events.db"
    let userExists = fm.fileExists(atPath: userDB)
    let systemReadable = fm.isReadableFile(atPath: systemDB)

    if userExists && systemReadable {
        let userMod = (try? fm.attributesOfItem(atPath: userDB))?[.modificationDate] as? Date
        let sysMod = (try? fm.attributesOfItem(atPath: systemDB))?[.modificationDate] as? Date
        if let s = sysMod, let u = userMod, s >= u {
            return systemDir
        }
        return userDir
    }
    if systemReadable { return systemDir }
    if userExists { return userDir }
    return systemDir
}

@main
struct MacCrabCtl {
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
                print("Usage: maccrabctl rules [list|count]")
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
                print("Usage: maccrabctl events [tail [N]|search <query>|stats]")
            }
        case "alerts":
            let limit = args.count >= 3 ? Int(args[2]) ?? 20 : 20
            await listAlerts(limit: limit)
        case "compile":
            if args.count >= 4 {
                compileRules(inputDir: args[2], outputDir: args[3])
            } else {
                print("Usage: maccrabctl compile <input-rules-dir> <output-compiled-dir>")
            }
        case "export":
            let format = args.count >= 3 ? args[2] : "json"
            let limit = args.count >= 4 ? Int(args[3]) ?? 1000 : 1000
            await exportAlerts(format: format, limit: limit)
        case "rule":
            if args.count >= 3 && args[2] == "create" {
                let category = args.count >= 4 ? args[3] : "process_creation"
                createRuleTemplate(category: category)
            } else {
                print("Usage: maccrabctl rule create [category]")
                print("  Categories: process_creation, file_event, network_connection, tcc_event")
            }
        case "suppress":
            if args.count >= 4 {
                await suppressRule(ruleId: args[2], processPath: args[3])
            } else {
                print("Usage: maccrabctl suppress <rule-id> <process-path>")
                print("  Adds a process to the allowlist for a specific rule.")
            }
        case "watch":
            await watchAlerts()
        case "hunt":
            if args.count >= 3 {
                let query = args[2...].joined(separator: " ")
                await huntThreats(query: query)
            } else {
                print("Usage: maccrabctl hunt <natural language query>")
                print("Examples:")
                print("  maccrabctl hunt \"show critical alerts from last hour\"")
                print("  maccrabctl hunt \"find unsigned processes with network connections\"")
            }
        case "report":
            await generateReport(args: Array(args.dropFirst(2)))
        case "cdhash":
            if args.count >= 3 {
                if args[2] == "--all" {
                    await extractAllCDHashes()
                } else if let pid = Int32(args[2]) {
                    await extractCDHash(pid: pid)
                } else {
                    print("Usage: maccrabctl cdhash <PID> | --all")
                }
            } else {
                print("Usage: maccrabctl cdhash <PID> | --all")
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
        // LOCALIZE: All CLI usage/help strings below are candidates for future localization.
        // In a CLI context without a resource bundle, NSLocalizedString is not practical.
        // Mark strings with LOCALIZE comments for extraction tooling.
        print("""
        maccrabctl - MacCrab Detection Engine CLI

        Usage: maccrabctl <command> [options]

        Monitoring:
          status              Show daemon status and statistics
          events tail [N]     Show last N events (default: 20)
          events search <q>   Full-text search over events
          events stats        Show event statistics
          alerts [N]          Show last N alerts (default: 20)
          watch               Live stream alerts as they happen

        Rules:
          rules list          List all loaded detection rules
          rules count         Count rules by category
          rule create [cat]   Generate a rule YAML template
          compile <in> <out>  Compile Sigma YAML rules to JSON

        Response:
          suppress <rule> <path>  Allowlist a process for a rule
          export [format] [N]     Export alerts (json|csv, default: json)

        Forensics:
          hunt <query>            Natural language threat hunting
          report [--hours N] [--output file]  Generate HTML incident report
          cdhash <PID>            Extract CDHash for a process
          cdhash --all            Extract CDHashes for all processes

        Other:
          version             Show version information
          help                Show this help message

        Examples:
          maccrabctl status
          maccrabctl watch
          maccrabctl events search "curl Downloads"
          maccrabctl export csv 500
          maccrabctl rule create network_connection
          maccrabctl suppress my-rule-id /usr/bin/safe-process
          maccrabctl hunt "show critical alerts from last hour"
          maccrabctl report --hours 48 --output incident.html
          maccrabctl cdhash 1234
        """)
    }

    static func printVersion() {
        // LOCALIZE: "MacCrab Detection Engine v0.5.0"
        print("MacCrab Detection Engine v0.5.0")
        // LOCALIZE: "License: Apache 2.0 (code), DRL 1.1 (rules)"
        print("License: Apache 2.0 (code), DRL 1.1 (rules)")
        print("https://github.com/maccrab-detection/maccrab")
    }

    static func showStatus() async {
        let supportDir = maccrabDataDir()
        let dbPath = supportDir + "/events.db"
        let alertsPath = supportDir + "/alerts.jsonl"

        // LOCALIZE: "MacCrab Status"
        print("MacCrab Status")
        print("══════════════════════════════════════")

        // Check if daemon is running
        let daemonRunning = isDaemonRunning()
        // LOCALIZE: "Running", "Not running"
        print("Daemon:     \(daemonRunning ? "Running \u{2713}" : "Not running \u{2717}")")

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
        let supportDir = maccrabDataDir()
        let compiledDir = supportDir + "/compiled_rules"

        guard FileManager.default.fileExists(atPath: compiledDir) else {
            print("No compiled rules found. Run: maccrabctl compile <rules-dir> <output-dir>")
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
        let supportDir = maccrabDataDir()
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
            let store = try EventStore(directory: maccrabDataDir())
            let events = try await store.events(since: Date.distantPast, category: nil, limit: limit)

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
                    detail = "\(net.destinationIp):\(net.destinationPort)"
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
            let store = try EventStore(directory: maccrabDataDir())
            let events = try await store.search(text: query, limit: 50)

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
            let store = try EventStore(directory: maccrabDataDir())
            let totalCount = try await store.count()
            let last24h = try await store.events(since: Date().addingTimeInterval(-86400), limit: 1_000_000)
            print("Event Statistics:")
            print("══════════════════════════════════════")
            print("  Total events:     \(totalCount)")
            print("  Events (last 24h): \(last24h.count)")
        } catch {
            print("Error reading stats: \(error)")
        }
    }

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
                if let techniques = alert.mitreTechniques, !techniques.isEmpty {
                    print("   MITRE: \(techniques)")
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

    // MARK: - Export

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

    // MARK: - Rule Creation

    static func createRuleTemplate(category: String) {
        let id = UUID().uuidString.lowercased()
        let date = {
            let f = DateFormatter()
            f.dateFormat = "yyyy/MM/dd"
            return f.string(from: Date())
        }()

        let template: String
        switch category {
        case "process_creation":
            template = """
            title: <Rule Title — what does it detect?>
            id: \(id)
            status: experimental
            description: >
                <Describe the threat behavior this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.execution
                - attack.tXXXX
            logsource:
                category: process_creation
                product: macos
            detection:
                selection:
                    Image|endswith:
                        - '/suspicious-binary'
                    CommandLine|contains:
                        - '--malicious-flag'
                filter_signed:
                    SignerType:
                        - 'apple'
                        - 'devId'
                condition: selection and not filter_signed
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "file_event":
            template = """
            title: <Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe suspicious file activity this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.persistence
                - attack.tXXXX
            logsource:
                category: file_event
                product: macos
            detection:
                selection:
                    TargetFilename|contains:
                        - '/Library/LaunchAgents/'
                    TargetFilename|endswith:
                        - '.plist'
                filter_system:
                    SignerType:
                        - 'apple'
                condition: selection and not filter_system
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "network_connection":
            template = """
            title: <Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe suspicious network behavior this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.command_and_control
                - attack.tXXXX
            logsource:
                category: network_connection
                product: macos
            detection:
                selection:
                    DestinationPort:
                        - 4444
                        - 5555
                    DestinationIsPrivate: 'false'
                condition: selection
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "tcc_event":
            template = """
            title: <Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe suspicious TCC permission access this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.collection
                - attack.tXXXX
            logsource:
                category: tcc_event
                product: macos
            detection:
                selection:
                    TCCService: 'kTCCServiceCamera'
                    TCCAllowed: 'true'
                filter_signed:
                    SignerType:
                        - 'apple'
                        - 'appStore'
                        - 'devId'
                condition: selection and not filter_signed
            falsepositives:
                - <Known legitimate use cases>
            level: high
            """

        case "sequence":
            template = """
            title: <Sequence Rule Title>
            id: \(id)
            status: experimental
            description: >
                <Describe the multi-step attack chain this rule detects.>
            author: <Your name>
            date: \(date)
            references:
                - https://attack.mitre.org/techniques/TXXXX/
            tags:
                - attack.execution
                - attack.tXXXX

            type: sequence
            window: 60s
            correlation: process.lineage
            ordered: true

            steps:
                - id: step1
                  logsource:
                      category: process_creation
                      product: macos
                  detection:
                      selection:
                          Image|endswith:
                              - '/suspicious-tool'
                      condition: selection

                - id: step2
                  logsource:
                      category: network_connection
                      product: macos
                  detection:
                      selection:
                          DestinationIsPrivate: 'false'
                      condition: selection
                  process: step1.descendant

            trigger: all
            level: critical
            """

        default:
            template = "Unknown category: \(category). Use: process_creation, file_event, network_connection, tcc_event, sequence"
        }

        print(template)
        print("")
        print("# Save this to Rules/<tactic>/<rule_name>.yml")
        print("# Then compile: python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir compiled_rules/")
    }

    // MARK: - Watch (Live Alert Tail)

    static func watchAlerts() async {
        // LOCALIZE: "Watching for new alerts... (Ctrl+C to stop)"
        print("Watching for new alerts... (Ctrl+C to stop)")
        print("══════════════════════════════════════════════════════════════")

        var lastSeen = Date()
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
                for alert in alerts {
                    if alert.timestamp > lastSeen {
                        let time = formatDate(alert.timestamp)
                        let icon: String
                        switch alert.severity {
                        case .critical: icon = "🔴"
                        case .high:     icon = "🟠"
                        case .medium:   icon = "🟡"
                        case .low:      icon = "🔵"
                        case .informational: icon = "⚪"
                        }
                        print("\(icon) \(time) \(alert.ruleTitle)")
                        print("   Process: \(alert.processName ?? "?") (\(alert.processPath ?? "?"))")
                        if let tech = alert.mitreTechniques, !tech.isEmpty {
                            print("   MITRE: \(tech)")
                        }
                        print()
                        lastSeen = alert.timestamp
                    }
                }
            } catch {
                // DB may not exist yet; wait silently
            }
            try? await Task.sleep(nanoseconds: 2_000_000_000) // Poll every 2 seconds
        }
    }

    // MARK: - Suppress (Allowlist)

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

    // MARK: - Hunt (Natural Language Threat Hunting)

    static func huntThreats(query: String) async {
        let supportDir = maccrabDataDir()
        let dbPath = supportDir + "/events.db"

        guard FileManager.default.fileExists(atPath: dbPath) else {
            print("No event database found at \(dbPath)")
            print("The daemon must run first to collect events.")
            return
        }

        let hunter = ThreatHunter(databasePath: dbPath)
        guard let result = await hunter.hunt(query) else {
            print("Hunt returned no result.")
            return
        }

        print("Threat Hunt Results")
        print("══════════════════════════════════════════════════════════════")
        print("Query:          \(result.query)")
        print("Interpretation: \(result.interpretation)")
        print("Results:        \(result.resultCount)")
        print("Execution:      \(String(format: "%.3f", result.executionTime))s")

        if !result.sqlQuery.isEmpty {
            print("SQL:            \(result.sqlQuery)")
        }
        print(String(repeating: "─", count: 80))

        if result.results.isEmpty {
            print("No matching results found.")
            print("\nSuggested queries:")
            let suggestions = await hunter.suggestions()
            for suggestion in suggestions {
                print("  - \(suggestion)")
            }
        } else {
            for (i, row) in result.results.enumerated() {
                print("\n[\(i + 1)]")
                for (key, value) in row.sorted(by: { $0.key < $1.key }) {
                    if !value.isEmpty {
                        print("  \(key): \(value)")
                    }
                }
            }
        }
    }

    // MARK: - Report (HTML Incident Report)

    static func generateReport(args: [String]) async {
        // Parse arguments
        var hours: Double = 24
        var outputPath: String? = nil

        var i = 0
        while i < args.count {
            if args[i] == "--hours" && i + 1 < args.count {
                hours = Double(args[i + 1]) ?? 24
                i += 2
            } else if args[i] == "--output" && i + 1 < args.count {
                outputPath = args[i + 1]
                i += 2
            } else {
                i += 1
            }
        }

        let supportDir = maccrabDataDir()
        let store: AlertStore
        do {
            store = try AlertStore(directory: supportDir)
        } catch {
            print("Error opening alert store: \(error)")
            return
        }

        let since = Date().addingTimeInterval(-hours * 3600)
        let alerts: [Alert]
        do {
            alerts = try await store.alerts(since: since)
        } catch {
            print("Error reading alerts: \(error)")
            return
        }

        let generator = ReportGenerator()
        let reportData = await generator.buildReportData(
            alerts: alerts,
            title: "MacCrab Incident Report",
            timeRange: (start: since, end: Date())
        )
        let html = await generator.generateHTML(from: reportData)

        if let outputPath = outputPath {
            do {
                try await generator.writeReport(html: html, to: outputPath)
                print("Report written to \(outputPath)")
                print("  Time range: last \(Int(hours)) hours")
                print("  Alerts:     \(alerts.count)")
            } catch {
                print("Error writing report: \(error)")
            }
        } else {
            // Write to stdout
            print(html)
        }
    }

    // MARK: - CDHash Extraction

    static func extractCDHash(pid: Int32) async {
        let extractor = CDHashExtractor()
        if let hash = await extractor.extractCDHash(pid: pid) {
            print("PID \(pid): \(hash)")
        } else {
            print("PID \(pid): no CDHash available (process may not exist or may be unsigned)")
        }
    }

    static func extractAllCDHashes() async {
        print("Extracting CDHashes for all running processes...")
        print("══════════════════════════════════════════════════════════════")
        print(String(format: "%-8s %s", "PID", "CDHash"))
        print(String(repeating: "─", count: 60))

        // Get all PIDs using proc_listallpids
        let count = proc_listallpids(nil, 0)
        guard count > 0 else {
            print("Failed to enumerate processes.")
            return
        }
        var pids = [Int32](repeating: 0, count: Int(count) + 100)
        let actual = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard actual > 0 else {
            print("Failed to enumerate processes.")
            return
        }

        let validPids = pids.prefix(Int(actual)).filter { $0 > 0 }.sorted()
        let extractor = CDHashExtractor()
        let results = await extractor.extractBatch(pids: Array(validPids))

        for pid in validPids {
            if let hash = results[pid] {
                print(String(format: "%-8d %@", pid, hash))
            }
        }

        print(String(repeating: "─", count: 60))
        print("\(results.count) of \(validPids.count) processes have CDHashes")
    }

    // MARK: - Helpers

    static func isDaemonRunning() -> Bool {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", "maccrabd"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    static func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale.current
        formatter.dateStyle = .short
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }
}
