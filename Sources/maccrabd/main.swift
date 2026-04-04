import Foundation
import Darwin
import MacCrabCore
import os.log

let logger = Logger(subsystem: "com.maccrab.daemon", category: "main")

@main
struct MacCrabDaemon {
    static func main() async {
        logger.info("MacCrab daemon starting...")

        // Check if running as root (required for ES framework, optional for other sources)
        let isRoot = getuid() == 0
        if !isRoot {
            print("Note: Running without root. Endpoint Security events unavailable.")
            print("      Other sources (Unified Log, TCC, Network) will still work.")
            print("      For full coverage: sudo maccrabd")
        }

        // Paths — root uses system location (shared with app), non-root uses user directory
        let supportDir: String
        if isRoot {
            supportDir = "/Library/Application Support/MacCrab"
        } else {
            let userAppSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first.map { $0.appendingPathComponent("MacCrab").path }
                ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
            supportDir = userAppSupport
        }
        let compiledRulesDir = supportDir + "/compiled_rules"

        // Determine rules directory using a fixed, secure search order.
        // Environment variables are NOT used because a non-root user could
        // influence what the root daemon loads.
        let rulesDir: String
        let fm = FileManager.default

        /// Validate that a directory is safe to load rules from:
        /// it must be owned by root (or the current user) and not world-writable.
        func isSecureDirectory(_ path: String) -> Bool {
            guard let attrs = try? fm.attributesOfItem(atPath: path) else {
                return false
            }
            let ownerUID = (attrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
            let currentUID = getuid()
            guard ownerUID == 0 || ownerUID == currentUID else {
                logger.warning("Rules directory \(path) is owned by uid \(ownerUID), expected 0 or \(currentUID). Skipping.")
                return false
            }
            if let posix = (attrs[.posixPermissions] as? NSNumber)?.intValue {
                // Check world-writable bit (o+w = 0o002)
                if posix & 0o002 != 0 {
                    logger.warning("Rules directory \(path) is world-writable (mode \(String(posix, radix: 8))). Skipping.")
                    return false
                }
            }
            return true
        }

        // Fixed search order:
        // 1. /Library/MacCrab/rules/ (system-wide, root-owned)
        // 2. <executable_dir>/Rules/ (bundled with binary)
        // 3. ~/Library/Application Support/MacCrab/rules/ (user rules, only if not root)
        let systemRulesDir = "/Library/MacCrab/rules"
        let execDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
        let bundledRulesDir = execDir + "/Rules"
        let userRulesDir = supportDir + "/rules"

        if fm.fileExists(atPath: systemRulesDir) && isSecureDirectory(systemRulesDir) {
            rulesDir = systemRulesDir
        } else if fm.fileExists(atPath: bundledRulesDir) && isSecureDirectory(bundledRulesDir) {
            rulesDir = bundledRulesDir
        } else if getuid() != 0 && fm.fileExists(atPath: userRulesDir) && isSecureDirectory(userRulesDir) {
            rulesDir = userRulesDir
        } else {
            // Fallback: use the system rules path even if it doesn't exist yet,
            // so the daemon can start and rules can be added later.
            rulesDir = systemRulesDir
        }

        logger.info("Rules directory: \(rulesDir)")
        logger.info("Support directory: \(supportDir)")

        // Create support directories with restrictive permissions
        try? fm.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true
        )
        // Restrict support directory: owner-only access (rwx------).
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: supportDir)

        try? fm.createDirectory(
            atPath: compiledRulesDir,
            withIntermediateDirectories: true
        )
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: compiledRulesDir)

        // Initialize components
        let eventStore: EventStore
        let alertStore: AlertStore
        let enricher: EventEnricher
        let ruleEngine: RuleEngine
        var collector: ESCollector? = nil

        do {
            eventStore = try EventStore(directory: supportDir)
            alertStore = try AlertStore(directory: supportDir)
        } catch {
            logger.error("Failed to initialize storage: \(error.localizedDescription)")
            fputs("Error: Failed to initialize database: \(error)\n", stderr)
            exit(1)
        }

        enricher = EventEnricher()
        ruleEngine = RuleEngine()
        let notifier = NotificationOutput(minimumSeverity: .high)
        let responseEngine = ResponseEngine()

        // Self-defense: tamper detection
        let selfDefense = SelfDefense(dataDir: supportDir, rulesDir: compiledRulesDir)
        await selfDefense.start { event in
            logger.critical("SELF-DEFENSE: [\(event.type.rawValue)] \(event.description)")
            print("[TAMPER] \(event.type.rawValue): \(event.description)")

            // Create an alert for tamper events
            let alert = Alert(
                ruleId: "maccrab.self-defense.\(event.type.rawValue)",
                ruleTitle: "MacCrab Tamper Detection: \(event.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                severity: event.severity,
                eventId: UUID().uuidString,
                processPath: event.path,
                processName: "maccrabd",
                description: event.description,
                mitreTactics: "attack.defense_evasion",
                mitreTechniques: "attack.t1562.001",
                suppressed: false
            )
            Task {
                try? await alertStore.insert(alert: alert)
                await notifier.notify(alert: alert)
            }
        }
        print("Self-defense active (binary integrity, file monitoring, anti-debug)")

        // Threat intelligence feed
        let threatIntel = ThreatIntelFeed(cacheDir: supportDir + "/threat_intel")
        await threatIntel.start()
        print("Threat intel feed active (abuse.ch Feodo, URLhaus, MalwareBazaar)")

        // Behavioral scoring engine
        let behaviorScoring = BehaviorScoring(alertThreshold: 10.0, criticalThreshold: 20.0)

        // Certificate Transparency monitor
        let ctMonitor = CertTransparency()

        // Incident grouper — clusters related alerts into attack timelines
        let incidentGrouper = IncidentGrouper(correlationWindow: 300, staleWindow: 600)

        // Load response action config if it exists
        let actionConfigPath = supportDir + "/actions.json"
        if FileManager.default.fileExists(atPath: actionConfigPath) {
            do {
                try await responseEngine.loadConfig(from: actionConfigPath)
                logger.info("Loaded response action config from \(actionConfigPath)")
                print("Response actions configured from: \(actionConfigPath)")
            } catch {
                logger.warning("Failed to load action config: \(error.localizedDescription)")
            }
        }

        // AI Guard: tool registry + process tracker
        let aiRegistry = AIToolRegistry()
        let lineageRef = await enricher.lineage
        let aiTracker = AIProcessTracker(lineage: lineageRef, registry: aiRegistry)
        let credentialFence = CredentialFence()
        let projectBoundary = ProjectBoundary()
        let injectionScanner = PromptInjectionScanner(confidenceThreshold: 40)
        let scannerStatus = await injectionScanner.isAvailable ? "active" : "unavailable (pip install forensicate)"
        print("AI Guard active (monitoring Claude Code, Codex, OpenClaw, Cursor)")
        print("  Credential fence: \(CredentialFence.defaultPaths.count) sensitive paths")
        print("  Prompt injection scanner: \(scannerStatus)")

        // Statistical anomaly detector
        let statisticalDetector = StatisticalAnomalyDetector(zThreshold: 3.0, minSamples: 50)

        // Fleet telemetry (optional — configure via MACCRAB_FLEET_URL env var)
        let fleetClient = FleetClient()
        if let fleet = fleetClient {
            await fleet.start { aggregation in
                // Feed fleet IOCs into local threat intel
                for ioc in aggregation.iocs where ioc.hostCount >= 2 {
                    if ioc.type == "ip" {
                        await threatIntel.addCustomIOCs(ips: [ioc.value])
                    } else if ioc.type == "domain" {
                        await threatIntel.addCustomIOCs(domains: [ioc.value])
                    } else if ioc.type == "hash" {
                        await threatIntel.addCustomIOCs(hashes: [ioc.value])
                    }
                }
            }
            print("Fleet client active: \(ProcessInfo.processInfo.environment["MACCRAB_FLEET_URL"] ?? "")")
        }

        // DNS collector (BPF capture or passive mode)
        let dnsCollector = DNSCollector()
        await dnsCollector.start()
        print("DNS collector active")

        // Event tap monitor (keylogger detection)
        let eventTapMonitor = EventTapMonitor(pollInterval: 30)
        await eventTapMonitor.start()
        print("Event tap monitor active (keylogger detection)")

        // System policy monitor (SIP, auth plugins, quarantine, XProtect)
        let systemPolicyMonitor = SystemPolicyMonitor(pollInterval: 300)
        await systemPolicyMonitor.start()
        print("System policy monitor active (SIP, plugins, quarantine, XProtect, XPC, MDM)")

        // FSEvents fallback file monitor (works without root)
        let fsEventsCollector = FSEventsCollector()
        if !isRoot {
            await fsEventsCollector.start()
            print("FSEvents file monitor active (non-root fallback for ES)")
        }

        // Quarantine provenance enricher
        let quarantineEnricher = QuarantineEnricher()

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
        if let webhookURLStr = Foundation.ProcessInfo.processInfo.environment["MACCRAB_WEBHOOK_URL"],
           let webhookURL = URL(string: webhookURLStr) {
            webhookOutput = WebhookOutput(url: webhookURL)
            logger.info("Webhook output enabled: \(webhookURLStr)")
            print("Webhook output: \(webhookURLStr)")
        }

        var syslogOutput: SyslogOutput? = nil
        if let syslogHost = Foundation.ProcessInfo.processInfo.environment["MACCRAB_SYSLOG_HOST"] {
            let syslogPort = UInt16(Foundation.ProcessInfo.processInfo.environment["MACCRAB_SYSLOG_PORT"] ?? "514") ?? 514
            syslogOutput = SyslogOutput(host: syslogHost, port: syslogPort)
            do {
                try await syslogOutput?.connect()
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
        // Also check for rules next to the binary (development convenience)
        let binaryDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
        let localCompiledRules = binaryDir + "/compiled_rules"
        let effectiveRulesDir: String
        if FileManager.default.fileExists(atPath: localCompiledRules) {
            let localFiles = (try? FileManager.default.contentsOfDirectory(atPath: localCompiledRules))?.filter { $0.hasSuffix(".json") } ?? []
            if !localFiles.isEmpty {
                effectiveRulesDir = localCompiledRules
                print("Using local compiled rules: \(localCompiledRules) (\(localFiles.count) files)")
            } else {
                effectiveRulesDir = compiledRulesDir
            }
        } else {
            effectiveRulesDir = compiledRulesDir
        }
        let rulesURL = URL(fileURLWithPath: effectiveRulesDir)
        do {
            let count = try await ruleEngine.loadRules(from: rulesURL)
            logger.info("Loaded \(count) single-event detection rules")
            print("Loaded \(count) single-event detection rules")
        } catch {
            logger.warning("No compiled rules found at \(compiledRulesDir). Run compile_rules.py first.")
            print("Warning: No compiled rules found. Run: python3 Compiler/compile_rules.py --input-dir Rules/ --output-dir '\(compiledRulesDir)'")
        }

        // Load sequence rules (use same effective dir as single-event rules)
        let sequenceRulesDir = effectiveRulesDir + "/sequences"
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

        // Start ES collector (optional — requires root + ES entitlement)
        if isRoot {
            do {
                collector = try ESCollector()
                logger.info("ES collector started successfully")
                print("Endpoint Security collector active")
            } catch {
                logger.warning("ES collector unavailable: \(error)")
                print("Warning: Endpoint Security unavailable (\(error))")
                print("  To enable: sign binary with com.apple.developer.endpoint-security.client entitlement")
            }
        } else {
            print("Endpoint Security: skipped (requires root)")
        }

        // Merge all event sources into a single stream
        let eventStream = AsyncStream<Event> { continuation in
            // Source 1: Endpoint Security events (if available)
            if let es = collector {
                Task {
                    for await event in es.events {
                        continuation.yield(event)
                    }
                }
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
        ║         MacCrab Detection Engine         ║
        ║       Local-First macOS Security         ║
        ║                  v0.4.0                   ║
        ╚══════════════════════════════════════════╝

        Status: Active
        PID: \(Foundation.ProcessInfo.processInfo.processIdentifier)

        Event Sources:
          - Endpoint Security (ES): \(collector != nil ? "active" : "unavailable")
          - Unified Log (12 subsystems): \(ulCollector != nil ? "active" : "unavailable")
          - TCC permission monitor: active
          - Network connection collector: active

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
                    print("[SIGHUP] Reloading rules from: \(rulesURL.path)")
                    let singleCount = try await ruleEngine.reloadRules(from: rulesURL)
                    print("[SIGHUP] Single-event rules: \(singleCount)")
                    let seqCount = try await sequenceEngine.loadRules(from: URL(fileURLWithPath: sequenceRulesDir))
                    print("[SIGHUP] Reloaded \(singleCount) single + \(seqCount) sequence rules")
                } catch {
                    print("[SIGHUP] ERROR: \(error)")
                }
            }
        }
        sigHupSource.resume()

        // Handle SIGTERM/SIGINT for graceful shutdown
        let shutdownHandler = {
            logger.info("MacCrab daemon shutting down...")
            print("\nShutting down MacCrab daemon...")
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

        // FSEvents file monitor task (non-root fallback)
        if !isRoot {
            Task {
                for await event in fsEventsCollector.events {
                    // Route FSEvents through the enrichment + detection pipeline
                    let enriched = await enricher.enrich(event)
                    try? await eventStore.insert(event: enriched)
                    let matches = await ruleEngine.evaluate(enriched)
                    for match in matches {
                        if await deduplicator.shouldSuppress(ruleId: match.ruleId, processPath: enriched.process.executable) { continue }
                        await deduplicator.recordAlert(ruleId: match.ruleId, processPath: enriched.process.executable)
                        let alert = Alert(
                            ruleId: match.ruleId, ruleTitle: match.ruleName, severity: match.severity,
                            eventId: enriched.id.uuidString, processPath: enriched.process.executable,
                            processName: enriched.process.name, description: match.description,
                            mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                            mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                            suppressed: false
                        )
                        try? await alertStore.insert(alert: alert)
                        await notifier.notify(alert: alert)
                        print("[FS] \(match.ruleName) | \(enriched.file?.path ?? "?")")
                    }
                }
            }
        }

        // Event tap monitoring task (keylogger detection)
        Task {
            for await tapInfo in eventTapMonitor.events {
                let alert = Alert(
                    ruleId: "maccrab.deep.event-tap-keylogger",
                    ruleTitle: "Suspicious Event Tap: \(tapInfo.processName) Monitoring Keyboard",
                    severity: tapInfo.isActive ? .critical : .high,
                    eventId: UUID().uuidString,
                    processPath: tapInfo.processPath,
                    processName: tapInfo.processName,
                    description: "Process \(tapInfo.processName) (PID \(tapInfo.tappingPID)) has an active CGEventTap monitoring keyboard events. Mask: 0x\(String(tapInfo.eventMask, radix: 16)). Mode: \(tapInfo.isActive ? "ACTIVE (can modify input)" : "passive (listen-only)"). This is a strong indicator of keylogging.",
                    mitreTactics: "attack.collection",
                    mitreTechniques: "attack.t1056.001",
                    suppressed: false
                )
                try? await alertStore.insert(alert: alert)
                await notifier.notify(alert: alert)
                await behaviorScoring.addIndicator(
                    named: "event_tap_keylogger",
                    detail: "PID \(tapInfo.tappingPID) taps keyboard",
                    forProcess: tapInfo.tappingPID,
                    path: tapInfo.processPath
                )
                print("[CRIT] Event tap keylogger: \(tapInfo.processName) (PID \(tapInfo.tappingPID))")
            }
        }

        // System policy monitoring task
        Task {
            for await policyEvent in systemPolicyMonitor.events {
                let alert = Alert(
                    ruleId: "maccrab.deep.\(policyEvent.type.rawValue)",
                    ruleTitle: "System Policy: \(policyEvent.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                    severity: policyEvent.severity,
                    eventId: UUID().uuidString,
                    processPath: policyEvent.path,
                    processName: nil,
                    description: policyEvent.description,
                    mitreTactics: policyEvent.mitreTactic,
                    mitreTechniques: policyEvent.mitreTechnique,
                    suppressed: false
                )
                try? await alertStore.insert(alert: alert)
                await notifier.notify(alert: alert)

                // Behavioral scoring for relevant events
                let indicatorName: String? = switch policyEvent.type {
                case .sipDisabled: "sip_disabled"
                case .authPluginFound: "non_apple_auth_plugin"
                case .xprotectOutdated: "xprotect_outdated"
                case .quarantineStripped: "removes_quarantine"
                case .gatekeeperOverride: "gatekeeper_override"
                default: nil
                }
                if let name = indicatorName {
                    // Use PID 0 for system-level events
                    await behaviorScoring.addIndicator(
                        named: name,
                        detail: policyEvent.description,
                        forProcess: 0,
                        path: policyEvent.path ?? "system"
                    )
                }

                let severityIcon = policyEvent.severity == .critical ? "[CRIT]" : "[HIGH]"
                print("\(severityIcon) System policy: \(policyEvent.type.rawValue) — \(policyEvent.description.prefix(100))")
            }
        }

        // DNS event processing task
        Task {
            for await dnsQuery in dnsCollector.events {
                // Record resolution for IP-to-domain correlation
                if dnsQuery.isResponse && !dnsQuery.resolvedIPs.isEmpty {
                    await dnsCollector.recordResolution(domain: dnsQuery.queryName, ips: dnsQuery.resolvedIPs)
                }

                // Check for DGA domains
                let (_, isDGA, dgaReason) = EntropyAnalysis.analyzeDomain(dnsQuery.queryName)
                if isDGA {
                    let alert = Alert(
                        ruleId: "maccrab.dns.dga-detection",
                        ruleTitle: "Possible DGA Domain Queried",
                        severity: .high,
                        eventId: UUID().uuidString,
                        processPath: nil,
                        processName: "mDNSResponder",
                        description: "DNS query for suspected DGA domain: \(dnsQuery.queryName). \(dgaReason ?? "")",
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1568.002",
                        suppressed: false
                    )
                    try? await alertStore.insert(alert: alert)
                    await notifier.notify(alert: alert)
                }

                // Check for DNS tunneling
                let (isTunneling, tunnelingReason) = EntropyAnalysis.isDNSTunneling(
                    queryName: dnsQuery.queryName, queryType: dnsQuery.queryType
                )
                if isTunneling {
                    let alert = Alert(
                        ruleId: "maccrab.dns.tunneling-detection",
                        ruleTitle: "Possible DNS Tunneling Detected",
                        severity: .high,
                        eventId: UUID().uuidString,
                        processPath: nil,
                        processName: "mDNSResponder",
                        description: "DNS tunneling indicators: \(dnsQuery.queryName). \(tunnelingReason ?? "")",
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1071.004",
                        suppressed: false
                    )
                    try? await alertStore.insert(alert: alert)
                    await notifier.notify(alert: alert)
                }

                // Check against threat intel
                if await threatIntel.isDomainMalicious(dnsQuery.queryName) {
                    let alert = Alert(
                        ruleId: "maccrab.dns.threat-intel-match",
                        ruleTitle: "DNS Query to Known Malicious Domain",
                        severity: .critical,
                        eventId: UUID().uuidString,
                        processPath: nil,
                        processName: "mDNSResponder",
                        description: "DNS query for known-malicious domain: \(dnsQuery.queryName)",
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1071.004",
                        suppressed: false
                    )
                    try? await alertStore.insert(alert: alert)
                    await notifier.notify(alert: alert)
                }
            }
        }

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
                _ = try? await eventStore.prune(olderThan: cutoff)
                _ = try? await alertStore.prune(olderThan: cutoff)
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

            // === AI Tool Detection ===
            let aiProc = enrichedEvent.process
            if let aiType = aiRegistry.isAITool(executablePath: aiProc.executable) {
                await aiTracker.registerAIProcess(pid: aiProc.pid, type: aiType, projectDir: aiProc.workingDirectory)
                await projectBoundary.registerBoundary(aiPid: aiProc.pid, projectDir: aiProc.workingDirectory)
                enrichedEvent.enrichments["ai_tool"] = aiType.rawValue
                enrichedEvent.enrichments["ai_tool_name"] = aiType.displayName
            } else {
                let (isChild, aiType, projectDir) = await aiTracker.isAIChild(pid: aiProc.pid, ancestors: aiProc.ancestors)
                if isChild {
                    enrichedEvent.enrichments["ai_tool"] = aiType?.rawValue ?? "unknown"
                    enrichedEvent.enrichments["ai_tool_child"] = "true"
                    if let dir = projectDir { enrichedEvent.enrichments["ai_project_dir"] = dir }

                    // AI child spawning a shell — track it
                    let shellNames = ["/bash", "/zsh", "/sh", "/dash", "/fish"]
                    if shellNames.contains(where: { aiProc.executable.hasSuffix($0) }) {
                        await behaviorScoring.addIndicator(
                            named: "ai_tool_spawns_shell",
                            detail: "\(aiType?.displayName ?? "AI tool") spawned \(aiProc.name)",
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child running sudo
                    if aiProc.executable.hasSuffix("/sudo") || aiProc.commandLine.hasPrefix("sudo ") {
                        await behaviorScoring.addIndicator(
                            named: "ai_tool_runs_sudo",
                            detail: "\(aiType?.displayName ?? "AI tool") child running sudo: \(aiProc.commandLine.prefix(100))",
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child installing packages
                    let pkgCmds = ["npm install", "npm i ", "pip install", "pip3 install", "cargo add", "brew install"]
                    if pkgCmds.contains(where: { aiProc.commandLine.lowercased().contains($0) }) {
                        await behaviorScoring.addIndicator(
                            named: "ai_tool_installs_unknown_pkg",
                            detail: aiProc.commandLine.prefix(200).description,
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child downloading and executing
                    let dlExec = ["curl", "wget"]
                    let execPipe = ["| sh", "| bash", "| zsh", "-o /tmp", "-O /tmp"]
                    if dlExec.contains(where: { aiProc.commandLine.contains($0) })
                        && execPipe.contains(where: { aiProc.commandLine.contains($0) }) {
                        await behaviorScoring.addIndicator(
                            named: "ai_tool_downloads_and_exec",
                            detail: aiProc.commandLine.prefix(200).description,
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child writing to persistence locations
                    if let file = enrichedEvent.file {
                        let persistPaths = ["/LaunchAgents/", "/LaunchDaemons/", "/StartupItems/", ".zshrc", ".bashrc", ".bash_profile"]
                        if persistPaths.contains(where: { file.path.contains($0) }) {
                            await behaviorScoring.addIndicator(
                                named: "ai_tool_persistence_write",
                                detail: "AI tool writing to \(file.path)",
                                forProcess: aiProc.pid, path: aiProc.executable
                            )
                        }
                    }

                    // === Credential Fence: check file access against sensitive paths ===
                    if let filePath = enrichedEvent.file?.path {
                        if let (credType, credDesc) = credentialFence.checkAccessDetailed(
                            filePath: filePath,
                            aiToolName: aiType?.displayName ?? "AI tool"
                        ) {
                            let alert = Alert(
                                ruleId: "maccrab.ai-guard.credential-access",
                                ruleTitle: "🦀 AI Tool Accessed \(credType.rawValue)",
                                severity: .critical,
                                eventId: enrichedEvent.id.uuidString,
                                processPath: aiProc.executable,
                                processName: aiProc.name,
                                description: credDesc,
                                mitreTactics: "attack.credential_access",
                                mitreTechniques: "attack.t1552.001",
                                suppressed: false
                            )
                            try? await alertStore.insert(alert: alert)
                            await notifier.notify(alert: alert)
                            await behaviorScoring.addIndicator(
                                named: "ai_tool_credential_access",
                                detail: "\(credType.rawValue): \(filePath)",
                                forProcess: aiProc.pid, path: aiProc.executable
                            )
                            print("[CRIT] AI credential access: \(aiType?.displayName ?? "AI") → \(credType.rawValue)")
                        }

                        // === Project Boundary: check writes outside project dir ===
                        // Check via the child-to-session mapping
                        let sessions = await aiTracker.activeSessions()
                        for session in sessions where session.childPids.contains(aiProc.pid) || session.aiPid == aiProc.pid {
                            if let violation = await projectBoundary.checkWrite(
                                filePath: filePath,
                                aiSessionPid: session.aiPid,
                                aiToolName: aiType?.displayName ?? "AI tool"
                            ) {
                                let alert = Alert(
                                    ruleId: "maccrab.ai-guard.boundary-violation",
                                    ruleTitle: "🦀 AI Tool Wrote Outside Project Directory",
                                    severity: .high,
                                    eventId: enrichedEvent.id.uuidString,
                                    processPath: aiProc.executable,
                                    processName: aiProc.name,
                                    description: violation.description,
                                    mitreTactics: "attack.defense_evasion",
                                    mitreTechniques: "attack.t1036",
                                    suppressed: false
                                )
                                try? await alertStore.insert(alert: alert)
                                await notifier.notify(alert: alert)
                                await behaviorScoring.addIndicator(
                                    named: "ai_tool_boundary_violation",
                                    detail: "Wrote to \(filePath) outside \(session.projectDir)",
                                    forProcess: aiProc.pid, path: aiProc.executable
                                )
                                print("[HIGH] AI boundary violation: \(filePath) outside \(session.projectDir)")
                            }
                            break
                        }
                    }
                    // === Prompt Injection Scanning (Forensicate.ai) ===
                    if await injectionScanner.isAvailable {
                        let textToScan = aiProc.commandLine
                        if !textToScan.isEmpty, textToScan.count > 20 {
                            if let (indicator, detail) = await injectionScanner.scanForSeverity(textToScan) {
                                let alert = Alert(
                                    ruleId: "maccrab.ai-guard.prompt-injection",
                                    ruleTitle: "🦀 Prompt Injection Detected in AI Tool Command",
                                    severity: indicator.contains("critical") || indicator.contains("compound") ? .critical : .high,
                                    eventId: enrichedEvent.id.uuidString,
                                    processPath: aiProc.executable,
                                    processName: aiProc.name,
                                    description: "Prompt injection detected in command executed by \(aiType?.displayName ?? "AI tool"). \(detail)",
                                    mitreTactics: "attack.initial_access",
                                    mitreTechniques: "attack.t1195.001",
                                    suppressed: false
                                )
                                try? await alertStore.insert(alert: alert)
                                await notifier.notify(alert: alert)
                                await behaviorScoring.addIndicator(
                                    named: indicator, detail: detail,
                                    forProcess: aiProc.pid, path: aiProc.executable
                                )
                                print("[CRIT] Prompt injection in AI context: \(detail.prefix(100))")
                            }
                        }
                    }
                }
            }

            // === Quarantine provenance enrichment for file events ===
            if let filePath = enrichedEvent.file?.path {
                await quarantineEnricher.enrich(&enrichedEvent.enrichments, forFile: filePath)
            }

            // === DYLD injection detection ===
            let cmdline = enrichedEvent.process.commandLine.lowercased()
            let args = enrichedEvent.process.args.joined(separator: " ").lowercased()
            if cmdline.contains("dyld_insert_libraries") || args.contains("dyld_insert_libraries") {
                await behaviorScoring.addIndicator(
                    named: "library_injection",
                    detail: "DYLD_INSERT_LIBRARIES in command/env",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
            }

            // === Statistical anomaly detection ===
            let anomalies = await statisticalDetector.processEvent(
                processPath: enrichedEvent.process.executable,
                argCount: enrichedEvent.process.args.count,
                commandLine: enrichedEvent.process.commandLine,
                category: enrichedEvent.eventCategory.rawValue,
                timestamp: enrichedEvent.timestamp
            )
            for anomaly in anomalies {
                await behaviorScoring.addIndicator(
                    named: "statistical_frequency_anomaly",
                    detail: "\(anomaly.feature) z=\(String(format: "%.1f", anomaly.zScore))",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
            }

            // === Entropy analysis on command lines ===
            if !enrichedEvent.process.commandLine.isEmpty {
                let (entropy, suspicious, _) = EntropyAnalysis.analyzeCommandLine(enrichedEvent.process.commandLine)
                if suspicious {
                    await behaviorScoring.addIndicator(
                        named: "high_entropy_commandline",
                        detail: "entropy=\(String(format: "%.2f", entropy))",
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === DNS enrichment: resolve IP → domain from DNS cache ===
            if let net = enrichedEvent.network, enrichedEvent.network?.destinationHostname == nil {
                if let domain = await dnsCollector.domainForIP(net.destinationIp) {
                    enrichedEvent.enrichments["dns.resolved_domain"] = domain
                }
            }

            // === Threat Intel + CT enrichment ===
            if let net = enrichedEvent.network {
                // Certificate Transparency check on destination domains
                if let host = net.destinationHostname {
                    if let ctResult = await ctMonitor.checkDomain(host), ctResult.isSuspicious {
                        await behaviorScoring.addIndicator(
                            BehaviorScoring.Indicator(name: "suspicious_certificate", weight: 4.0, detail: ctResult.reason ?? host),
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                    // Typosquatting check
                    let (isTypo, typoReason) = await ctMonitor.isTyposquat(host)
                    if isTypo {
                        await behaviorScoring.addIndicator(
                            BehaviorScoring.Indicator(name: "typosquat_domain", weight: 6.0, detail: typoReason ?? host),
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                }
            }

            // Check process hash, network IPs, and domains against known-bad IOCs
            if let net = enrichedEvent.network {
                if await threatIntel.isIPMalicious(net.destinationIp) {
                    await behaviorScoring.addIndicator(
                        named: "known_malicious_ip",
                        detail: net.destinationIp,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
                if let host = net.destinationHostname, await threatIntel.isDomainMalicious(host) {
                    await behaviorScoring.addIndicator(
                        named: "known_malicious_domain",
                        detail: host,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === Behavioral scoring: process-level indicators ===
            let proc = enrichedEvent.process
            if proc.codeSignature == nil || proc.codeSignature?.signerType == .unsigned {
                await behaviorScoring.addIndicator(
                    named: "unsigned_binary", detail: proc.executable,
                    forProcess: proc.pid, path: proc.executable
                )
            }
            if proc.executable.contains("/tmp/") || proc.executable.contains("/private/tmp/") {
                await behaviorScoring.addIndicator(
                    named: "executed_from_tmp", detail: proc.executable,
                    forProcess: proc.pid, path: proc.executable
                )
            }
            if let file = enrichedEvent.file {
                if file.path.contains("/LaunchAgents/") {
                    await behaviorScoring.addIndicator(
                        named: "writes_launch_agent", detail: file.path,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
                if file.path.contains("/LaunchDaemons/") {
                    await behaviorScoring.addIndicator(
                        named: "writes_launch_daemon", detail: file.path,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
            }

            // Store event
            try? await eventStore.insert(event: enrichedEvent)

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

            // Layer 4: Behavioral scoring — escalate score on rule matches
            for match in matches {
                if let scoringResult = await behaviorScoring.addRuleMatch(
                    severity: match.severity,
                    ruleTitle: match.ruleName,
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                ) {
                    // Behavioral threshold crossed — generate composite alert
                    let indicatorSummary = scoringResult.indicators.prefix(5)
                        .map { "\($0.name)(\($0.weight))" }.joined(separator: ", ")
                    let behaviorMatch = RuleMatch(
                        ruleId: "maccrab.behavior.composite",
                        ruleName: "Behavioral Score Threshold: \(enrichedEvent.process.name)",
                        severity: scoringResult.severity,
                        description: "Process accumulated suspicious behavior score of \(String(format: "%.1f", scoringResult.totalScore)). Top indicators: \(indicatorSummary)",
                        mitreTechniques: [],
                        tags: ["attack.execution", "attack.defense_evasion"]
                    )
                    matches.append(behaviorMatch)
                }
            }

            if !matches.isEmpty {
                for match in matches {
                    // Deduplication check
                    if await deduplicator.shouldSuppress(ruleId: match.ruleId, processPath: enrichedEvent.process.executable) {
                        continue
                    }
                    await deduplicator.recordAlert(ruleId: match.ruleId, processPath: enrichedEvent.process.executable)

                    alertCount += 1

                    let alert = Alert(
                        id: UUID().uuidString,
                        timestamp: Date(),
                        ruleId: match.ruleId,
                        ruleTitle: match.ruleName,
                        severity: match.severity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: match.description,
                        mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                        mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                        suppressed: false
                    )

                    try? await alertStore.insert(alert: alert)
                    await notifier.notify(alert: alert)
                    await responseEngine.execute(alert: alert, event: enrichedEvent)

                    // Buffer for fleet telemetry
                    if let fleet = fleetClient {
                        await fleet.bufferAlert(FleetAlertSummary(
                            ruleId: alert.ruleId,
                            ruleTitle: alert.ruleTitle,
                            severity: alert.severity.rawValue,
                            processPath: alert.processPath ?? "",
                            mitreTechniques: alert.mitreTechniques ?? "",
                            timestamp: alert.timestamp
                        ))
                    }

                    // Group into incident
                    let tactics = match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }
                    await incidentGrouper.processAlert(
                        alertId: alert.id,
                        timestamp: alert.timestamp,
                        ruleTitle: match.ruleName,
                        severity: match.severity,
                        processPath: enrichedEvent.process.executable,
                        parentPath: enrichedEvent.process.ancestors.first?.executable,
                        tactics: tactics
                    )

                    // Log alert to stdout
                    let severityIcon: String
                    switch match.severity {
                    case .critical: severityIcon = "[CRIT]"
                    case .high: severityIcon = "[HIGH]"
                    case .medium: severityIcon = "[MED] "
                    case .low: severityIcon = "[LOW] "
                    case .informational: severityIcon = "[INFO]"
                    }

                    print("\(severityIcon) \(match.ruleName) | \(enrichedEvent.process.name) (\(enrichedEvent.process.pid)) | \(enrichedEvent.process.executable)")

                    // Write JSON alert to log file (with rotation at 50MB)
                    if let jsonData = try? JSONEncoder().encode(alert),
                       let jsonString = String(data: jsonData, encoding: .utf8) {
                        let logPath = supportDir + "/alerts.jsonl"
                        // Rotate if over 50MB
                        if let attrs = try? FileManager.default.attributesOfItem(atPath: logPath),
                           let size = attrs[.size] as? UInt64, size > 50_000_000 {
                            let rotatedPath = logPath + ".\(Int(Date().timeIntervalSince1970))"
                            try? FileManager.default.moveItem(atPath: logPath, toPath: rotatedPath)
                            // Keep only last 5 rotated files
                            let dir = (logPath as NSString).deletingLastPathComponent
                            if let files = try? FileManager.default.contentsOfDirectory(atPath: dir) {
                                let rotated = files.filter { $0.hasPrefix("alerts.jsonl.") }.sorted().reversed()
                                for old in rotated.dropFirst(5) {
                                    try? FileManager.default.removeItem(atPath: dir + "/" + old)
                                }
                            }
                        }
                        // Atomic append — use O_APPEND to avoid seek+write race
                        let lineData = (jsonString + "\n").data(using: .utf8)!
                        let fd = open(logPath, O_WRONLY | O_CREAT | O_APPEND, 0o600)
                        if fd >= 0 {
                            lineData.withUnsafeBytes { ptr in
                                _ = write(fd, ptr.baseAddress!, ptr.count)
                            }
                            close(fd)
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
