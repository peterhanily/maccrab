import Foundation
import HawkEyeCore
import os.log

let logger = Logger(subsystem: "com.hawkeye.daemon", category: "main")

@main
struct HawkEyeDaemon {
    static func main() async {
        logger.info("HawkEye daemon starting...")

        // Verify running as root (required for ES framework)
        guard getuid() == 0 else {
            logger.error("hawkeyed must run as root (required for Endpoint Security framework)")
            fputs("Error: hawkeyed must run as root. Use: sudo hawkeyed\n", stderr)
            exit(1)
        }

        // Paths
        let supportDir = NSHomeDirectory() + "/Library/Application Support/HawkEye"
        let rulesDir: String
        let compiledRulesDir = supportDir + "/compiled_rules"

        // Determine rules directory: check bundled first, then user-specified
        if let envRules = ProcessInfo.processInfo.environment["HAWKEYE_RULES_DIR"] {
            rulesDir = envRules
        } else {
            // Default: look for Rules/ next to the executable
            let execDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
            let bundledRules = execDir + "/Rules"
            if FileManager.default.fileExists(atPath: bundledRules) {
                rulesDir = bundledRules
            } else {
                rulesDir = supportDir + "/rules"
            }
        }

        logger.info("Rules directory: \(rulesDir)")
        logger.info("Support directory: \(supportDir)")

        // Create support directories
        try? FileManager.default.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true
        )
        try? FileManager.default.createDirectory(
            atPath: compiledRulesDir,
            withIntermediateDirectories: true
        )

        // Initialize components
        let eventStore: EventStore
        let alertStore: AlertStore
        let enricher: EventEnricher
        let ruleEngine: RuleEngine
        let collector: ESCollector

        do {
            eventStore = try EventStore()
            alertStore = try AlertStore()
        } catch {
            logger.error("Failed to initialize storage: \(error.localizedDescription)")
            fputs("Error: Failed to initialize database: \(error)\n", stderr)
            exit(1)
        }

        enricher = EventEnricher()
        ruleEngine = RuleEngine()

        // Initialize sequence engine (Phase 2: temporal-causal detection)
        let sequenceEngine = await SequenceEngine(lineage: enricher.lineage)

        // Initialize baseline anomaly engine (Phase 3: learned detection)
        let baselineEngine = BaselineEngine()
        do {
            try await baselineEngine.load()
            let status = await baselineEngine.status()
            logger.info("Baseline engine: \(status.state.rawValue), \(status.totalEdges) edges")
            print("Baseline engine: \(status.state.rawValue) (\(status.totalEdges) edges learned)")
        } catch {
            logger.info("Baseline engine: starting fresh learning period")
            print("Baseline engine: starting 7-day learning period")
        }

        // Initialize alert deduplicator (Phase 3)
        let deduplicator = AlertDeduplicator()

        // Initialize optional outputs (Phase 3)
        var webhookOutput: WebhookOutput? = nil
        if let webhookURLStr = ProcessInfo.processInfo.environment["HAWKEYE_WEBHOOK_URL"],
           let webhookURL = URL(string: webhookURLStr) {
            webhookOutput = WebhookOutput(url: webhookURL)
            logger.info("Webhook output enabled: \(webhookURLStr)")
            print("Webhook output: \(webhookURLStr)")
        }

        var syslogOutput: SyslogOutput? = nil
        if let syslogHost = ProcessInfo.processInfo.environment["HAWKEYE_SYSLOG_HOST"] {
            let syslogPort = UInt16(ProcessInfo.processInfo.environment["HAWKEYE_SYSLOG_PORT"] ?? "514") ?? 514
            syslogOutput = SyslogOutput(host: syslogHost, port: syslogPort)
            do {
                try await syslogOutput!.connect()
                logger.info("Syslog output enabled: \(syslogHost):\(syslogPort)")
                print("Syslog output: \(syslogHost):\(syslogPort)")
            } catch {
                logger.error("Failed to connect syslog: \(error.localizedDescription)")
                syslogOutput = nil
            }
        }

        // Initialize optional YARA enrichment (Phase 3)
        let yaraRulesPath = supportDir + "/yara_rules"
        let yaraEnricher = YARAEnricher(rulesPath: yaraRulesPath)
        if await yaraEnricher.isAvailable() {
            logger.info("YARA enrichment enabled")
            print("YARA enrichment: active (\(yaraRulesPath))")
        }

        // Initialize network collector (Phase 3)
        let networkCollector = NetworkCollector()
        Task { await networkCollector.start() }
        print("Network connection collector active (5s poll)")

        // Load compiled rules (single-event)
        let rulesURL = URL(fileURLWithPath: compiledRulesDir)
        do {
            let count = try await ruleEngine.loadRules(from: rulesURL)
            logger.info("Loaded \(count) single-event detection rules")
            print("Loaded \(count) single-event detection rules")
        } catch {
            logger.warning("No compiled rules found at \(compiledRulesDir). Run compile_rules.py first.")
            print("Warning: No compiled rules found. Run: python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir '\(compiledRulesDir)'")
        }

        // Load sequence rules
        let sequenceRulesDir = compiledRulesDir + "/sequences"
        try? FileManager.default.createDirectory(atPath: sequenceRulesDir, withIntermediateDirectories: true)
        do {
            let seqCount = try await sequenceEngine.loadRules(from: URL(fileURLWithPath: sequenceRulesDir))
            logger.info("Loaded \(seqCount) sequence detection rules")
            print("Loaded \(seqCount) sequence detection rules")
        } catch {
            logger.info("No sequence rules loaded (this is fine for initial setup)")
        }

        // Start TCC monitor (Phase 2: permission change detection)
        let tccMonitor = TCCMonitor()
        Task { await tccMonitor.start() }
        logger.info("TCC permission monitor active")

        // Start Unified Log collector (Phase 2: system log events)
        var ulCollector: UnifiedLogCollector? = nil
        do {
            ulCollector = try UnifiedLogCollector()
            logger.info("Unified Log collector active")
            print("Unified Log collector active (12 subsystems)")
        } catch {
            logger.warning("Failed to start Unified Log collector: \(error.localizedDescription)")
            print("Warning: Unified Log collector unavailable")
        }

        // Merge all event sources into a single stream
        let eventStream = AsyncStream<Event> { continuation in
            // Source 1: Endpoint Security events
            do {
                collector = try ESCollector { event in
                    continuation.yield(event)
                }
                logger.info("ES collector started successfully")
                print("Endpoint Security collector active")
            } catch {
                logger.error("Failed to start ES collector: \(error.localizedDescription)")
                fputs("Error: Failed to start ES collector: \(error)\n", stderr)
                fputs("Ensure:\n", stderr)
                fputs("  1. Running as root (sudo)\n", stderr)
                fputs("  2. com.apple.developer.endpoint-security.client entitlement is present\n", stderr)
                fputs("  3. Terminal has Full Disk Access\n", stderr)
                continuation.finish()
                return
            }

            // Source 2: Unified Log events
            if let ul = ulCollector {
                Task {
                    for await event in ul.events {
                        continuation.yield(event)
                    }
                }
            }

            // Source 3: TCC permission change events
            Task {
                for await event in tccMonitor.events {
                    continuation.yield(event)
                }
            }

            // Source 4: Network connection events (Phase 3)
            Task {
                for await event in networkCollector.events {
                    continuation.yield(event)
                }
            }
        }

        // Print startup banner
        print("""

        ╔══════════════════════════════════════════╗
        ║         HawkEye Detection Engine         ║
        ║       Local-First macOS Security         ║
        ║              v0.3.0 (Phase 3)            ║
        ╚══════════════════════════════════════════╝

        Status: Active
        PID: \(ProcessInfo.processInfo.processIdentifier)

        Event Sources:
          - Endpoint Security (ES) framework
          - Unified Log (12 subsystems)
          - TCC permission monitor
          - Network connection collector

        Detection Layers:
          - Single-event Sigma rules
          - Temporal sequence rules
          - Baseline anomaly detection (learned)

        Enrichment:
          - Process lineage graph
          - Code signing cache
          - YARA file scanning (if available)

        Storage: \(supportDir)/events.db
        Rules:   \(compiledRulesDir)

        Press Ctrl+C to stop.
        """)

        // Handle SIGHUP for rule reload
        let sigHupSource = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .main)
        signal(SIGHUP, SIG_IGN) // Ignore default handler
        sigHupSource.setEventHandler {
            Task {
                do {
                    let singleCount = try await ruleEngine.reloadRules(from: rulesURL)
                    let seqCount = try await sequenceEngine.loadRules(from: URL(fileURLWithPath: sequenceRulesDir))
                    logger.info("Reloaded \(singleCount) single + \(seqCount) sequence rules after SIGHUP")
                    print("[SIGHUP] Reloaded \(singleCount) single + \(seqCount) sequence rules")
                } catch {
                    logger.error("Failed to reload rules: \(error.localizedDescription)")
                }
            }
        }
        sigHupSource.resume()

        // Handle SIGTERM/SIGINT for graceful shutdown
        let shutdownHandler = {
            logger.info("HawkEye daemon shutting down...")
            print("\nShutting down HawkEye daemon...")
            exit(0)
        }

        let sigTermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        signal(SIGTERM, SIG_IGN)
        sigTermSource.setEventHandler { shutdownHandler() }
        sigTermSource.resume()

        let sigIntSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        signal(SIGINT, SIG_IGN)
        sigIntSource.setEventHandler { shutdownHandler() }
        sigIntSource.resume()

        // Stats tracking
        var eventCount: UInt64 = 0
        var alertCount: UInt64 = 0
        let startTime = Date()

        // Periodic stats logging
        let statsTimer = DispatchSource.makeTimerSource(queue: .global())
        statsTimer.schedule(deadline: .now() + 60, repeating: 60)
        statsTimer.setEventHandler {
            let uptime = Int(Date().timeIntervalSince(startTime))
            let hours = uptime / 3600
            let minutes = (uptime % 3600) / 60
            logger.info("Stats: \(eventCount) events processed, \(alertCount) alerts, uptime \(hours)h\(minutes)m")
        }
        statsTimer.resume()

        // Retention pruning (daily)
        let pruneTimer = DispatchSource.makeTimerSource(queue: .global())
        pruneTimer.schedule(deadline: .now() + 3600, repeating: 86400) // First at 1h, then daily
        pruneTimer.setEventHandler {
            Task {
                let cutoff = Date().addingTimeInterval(-30 * 86400) // 30 days
                await eventStore.prune(olderThan: cutoff)
                await alertStore.prune(olderThan: cutoff)
                logger.info("Pruned events older than 30 days")
            }
        }
        pruneTimer.resume()

        // Periodic baseline save + dedup sweep (every 5 minutes)
        let maintenanceTimer = DispatchSource.makeTimerSource(queue: .global())
        maintenanceTimer.schedule(deadline: .now() + 300, repeating: 300)
        maintenanceTimer.setEventHandler {
            Task {
                try? await baselineEngine.save()
                await deduplicator.sweep()
            }
        }
        maintenanceTimer.resume()

        // Main event processing loop
        for await event in eventStream {
            eventCount += 1

            // Enrich the event (lineage, code signing)
            var enrichedEvent = await enricher.enrich(event)

            // YARA enrichment for file events (Phase 3)
            if enrichedEvent.eventCategory == .file {
                enrichedEvent = await yaraEnricher.enrich(enrichedEvent)
            }

            // Store event
            await eventStore.insert(event: enrichedEvent)

            // === Detection: 3 layers ===

            // Layer 1: Single-event Sigma rules
            var matches = await ruleEngine.evaluate(enrichedEvent)

            // Layer 2: Temporal sequence rules (Phase 2)
            let sequenceMatches = await sequenceEngine.evaluate(enrichedEvent)
            matches.append(contentsOf: sequenceMatches)

            // Layer 3: Baseline anomaly detection (Phase 3)
            if let baselineMatch = await baselineEngine.evaluate(enrichedEvent) {
                matches.append(baselineMatch)
            }

            if !matches.isEmpty {
                for match in matches {
                    // Deduplication check (Phase 3)
                    if await deduplicator.shouldSuppress(ruleId: match.ruleId, processPath: enrichedEvent.process.executable) {
                        continue
                    }
                    await deduplicator.recordAlert(ruleId: match.ruleId, processPath: enrichedEvent.process.executable)

                    alertCount += 1

                    let alert = Alert(
                        id: UUID().uuidString,
                        timestamp: Date(),
                        ruleId: match.ruleId,
                        ruleTitle: match.ruleTitle,
                        severity: match.severity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: match.description,
                        mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                        mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                        suppressed: false
                    )

                    await alertStore.insert(alert: alert)

                    // Log alert to stdout
                    let severityIcon: String
                    switch match.severity {
                    case .critical: severityIcon = "[CRIT]"
                    case .high: severityIcon = "[HIGH]"
                    case .medium: severityIcon = "[MED] "
                    case .low: severityIcon = "[LOW] "
                    case .informational: severityIcon = "[INFO]"
                    }

                    print("\(severityIcon) \(match.ruleTitle) | \(enrichedEvent.process.name) (\(enrichedEvent.process.pid)) | \(enrichedEvent.process.executable)")

                    // Write JSON alert to log file
                    if let jsonData = try? JSONEncoder().encode(alert),
                       let jsonString = String(data: jsonData, encoding: .utf8) {
                        let logPath = supportDir + "/alerts.jsonl"
                        if let handle = FileHandle(forWritingAtPath: logPath) {
                            handle.seekToEndOfFile()
                            handle.write((jsonString + "\n").data(using: .utf8)!)
                            handle.closeFile()
                        } else {
                            FileManager.default.createFile(atPath: logPath, contents: (jsonString + "\n").data(using: .utf8))
                        }
                    }

                    // Webhook output (Phase 3)
                    if let webhook = webhookOutput {
                        Task { await webhook.send(alert: alert, event: enrichedEvent) }
                    }

                    // Syslog output (Phase 3)
                    if let syslog = syslogOutput {
                        Task { await syslog.send(alert: alert) }
                    }
                }
            }
        }

        logger.info("Event stream ended. Daemon exiting.")
    }
}
