import Foundation
import Darwin
import HawkEyeCore
import os.log

let logger = Logger(subsystem: "com.hawkeye.daemon", category: "main")

@main
struct HawkEyeDaemon {
    static func main() async {
        logger.info("HawkEye daemon starting...")

        // Check if running as root (required for ES framework, optional for other sources)
        let isRoot = getuid() == 0
        if !isRoot {
            print("Note: Running without root. Endpoint Security events unavailable.")
            print("      Other sources (Unified Log, TCC, Network) will still work.")
            print("      For full coverage: sudo hawkeyed")
        }

        // Paths — root uses system location (shared with app), non-root uses user directory
        let supportDir: String
        if isRoot {
            supportDir = "/Library/Application Support/HawkEye"
        } else {
            let userAppSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first!.appendingPathComponent("HawkEye").path
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
        // 1. /Library/HawkEye/rules/ (system-wide, root-owned)
        // 2. <executable_dir>/Rules/ (bundled with binary)
        // 3. ~/Library/Application Support/HawkEye/rules/ (user rules, only if not root)
        let systemRulesDir = "/Library/HawkEye/rules"
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
                ruleId: "hawkeye.self-defense.\(event.type.rawValue)",
                ruleTitle: "HawkEye Tamper Detection: \(event.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                severity: event.severity,
                eventId: UUID().uuidString,
                processPath: event.path,
                processName: "hawkeyed",
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

        // Statistical anomaly detector
        let statisticalDetector = StatisticalAnomalyDetector(zThreshold: 3.0, minSamples: 50)

        // Fleet telemetry (optional — configure via HAWKEYE_FLEET_URL env var)
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
            print("Fleet client active: \(ProcessInfo.processInfo.environment["HAWKEYE_FLEET_URL"] ?? "")")
        }

        // DNS collector (BPF capture or passive mode)
        let dnsCollector = DNSCollector()
        await dnsCollector.start()
        print("DNS collector active")

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
        if let webhookURLStr = Foundation.ProcessInfo.processInfo.environment["HAWKEYE_WEBHOOK_URL"],
           let webhookURL = URL(string: webhookURLStr) {
            webhookOutput = WebhookOutput(url: webhookURL)
            logger.info("Webhook output enabled: \(webhookURLStr)")
            print("Webhook output: \(webhookURLStr)")
        }

        var syslogOutput: SyslogOutput? = nil
        if let syslogHost = Foundation.ProcessInfo.processInfo.environment["HAWKEYE_SYSLOG_HOST"] {
            let syslogPort = UInt16(Foundation.ProcessInfo.processInfo.environment["HAWKEYE_SYSLOG_PORT"] ?? "514") ?? 514
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
        ║         HawkEye Detection Engine         ║
        ║       Local-First macOS Security         ║
        ║              v0.3.0 (Phase 3)            ║
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
                        ruleId: "hawkeye.dns.dga-detection",
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
                        ruleId: "hawkeye.dns.tunneling-detection",
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
                        ruleId: "hawkeye.dns.threat-intel-match",
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
                try? await eventStore.prune(olderThan: cutoff)
                try? await alertStore.prune(olderThan: cutoff)
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
                        ruleId: "hawkeye.behavior.composite",
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
