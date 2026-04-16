import Foundation
import Darwin
import MacCrabCore
import os.log

/// Creates and initializes all daemon components, returning a fully configured DaemonState.
enum DaemonSetup {
    static func initialize() async -> DaemonState {
        let startupBegin = DispatchTime.now()

        // Check if running as root (required for ES framework, optional for other sources)
        let isRoot = getuid() == 0
        if !isRoot {
            print("Note: Running without root. Endpoint Security events unavailable.")
            print("      Other sources (Unified Log, TCC, Network) will still work.")
            print("      For full coverage: sudo maccrabd")
        }

        // Check Full Disk Access by probing a TCC-protected path.
        // Without FDA, ES events for protected file paths are silently dropped.
        if isRoot {
            let tccDB = "/Library/Application Support/com.apple.TCC/TCC.db"
            if FileManager.default.isReadableFile(atPath: tccDB) {
                print("Full Disk Access: granted (complete ES coverage)")
            } else {
                print("WARNING: Full Disk Access not granted — detection at ~70% coverage.")
                print("         Grant FDA to maccrabd in System Settings > Privacy & Security")
                print("         > Full Disk Access, then restart the daemon.")
            }
        }

        // Paths -- root uses system location (shared with app), non-root uses user directory
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
        /// it must not be a symlink, must be owned by root (or the current user),
        /// and must not be world-writable.
        func isSecureDirectory(_ path: String) -> Bool {
            // Reject symlinks: an attacker could point /Library/MacCrab/rules at
            // a world-writable directory they control. Use URL resource values
            // which operate on the path itself (lstat semantics) rather than
            // following the symlink (stat semantics).
            let url = URL(fileURLWithPath: path)
            if let resourceValues = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]),
               resourceValues.isSymbolicLink == true {
                logger.warning("Rules directory \(path) is a symlink. Refusing to load rules to prevent symlink injection attacks.")
                return false
            }

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

        // Load daemon configuration (optional JSON file with tuning overrides)
        let config = DaemonConfig.load(from: supportDir)

        // Create support directories with restrictive permissions
        try? fm.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true
        )
        // Allow non-root GUI app to read the DB: rwxr-xr-x.
        // The DB file itself is 0o644 so the app can read it; the directory
        // needs at least r-x for traversal.
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: supportDir)

        try? fm.createDirectory(
            atPath: compiledRulesDir,
            withIntermediateDirectories: true
        )
        // Compiled rules are only read by the daemon — restrict to owner-only
        // to prevent attackers from reading detection logic for evasion.
        // rwxr-xr-x: non-root MacCrab.app needs to read rules for display
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: compiledRulesDir)

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

        // ProcessHasher populates SHA-256 + CDHash on exec/fork events so
        // downstream rules and exports can match against threat-intel hashes.
        // Shared state across the daemon lifetime for cache reuse.
        let processHasher = ProcessHasher()

        // Deception tier (opt-in via MACCRAB_DECEPTION=1). Plants canary
        // credential files and exposes an isHoneyfile() lookup the enricher
        // uses to tag file events touching a canary.
        let honeyfileManager: HoneyfileManager?
        if ProcessInfo.processInfo.environment["MACCRAB_DECEPTION"] == "1" {
            let mgr = HoneyfileManager()
            honeyfileManager = mgr
            Task {
                do {
                    let deployed = try await mgr.deploy()
                    logger.info("Deployed \(deployed.count) honeyfiles (deception tier enabled)")
                } catch {
                    logger.warning("Honeyfile deploy failed: \(error.localizedDescription)")
                }
            }
        } else {
            honeyfileManager = nil
        }

        // Env-var capture (opt-in). Reads DYLD_*, SSH_*, SUDO_*, AWS_PROFILE,
        // and a small set of context keys via sysctl on exec/fork. Secret-
        // bearing keys (AWS_SECRET_*, *_TOKEN, *_PASSWORD) are denied by
        // EnvCapture before allowlist resolution.
        let captureEnv = ProcessInfo.processInfo.environment["MACCRAB_CAPTURE_ENV"] == "1"
        if captureEnv {
            logger.info("Env var capture enabled (MACCRAB_CAPTURE_ENV=1)")
        }

        enricher = EventEnricher(
            processHasher: processHasher,
            honeyfileManager: honeyfileManager,
            captureEnv: captureEnv
        )
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

        // ES infrastructure health monitor
        let esHealthMonitor = ESClientMonitor(pollInterval: config.esHealthPollInterval)
        await esHealthMonitor.start()
        let esHealth = await esHealthMonitor.currentStatus()
        if esHealth.isHealthy {
            print("ES infrastructure: healthy (xprotectd, syspolicyd, endpointsecurityd running)")
        } else {
            print("ES infrastructure: DEGRADED -- \(esHealth.issues.joined(separator: ", "))")
        }

        // ES health monitoring task
        Task {
            for await healthEvent in esHealthMonitor.events {
                let alert = Alert(
                    ruleId: "maccrab.self-defense.\(healthEvent.type.rawValue)",
                    ruleTitle: "ES Infrastructure: \(healthEvent.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                    severity: healthEvent.severity,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "maccrabd",
                    description: healthEvent.description,
                    mitreTactics: "attack.defense_evasion",
                    mitreTechniques: "attack.t1562.001",
                    suppressed: false
                )
                try? await alertStore.insert(alert: alert)
                await notifier.notify(alert: alert)
                print("[ES-HEALTH] \(healthEvent.type.rawValue): \(healthEvent.description)")
            }
        }

        // Threat intelligence feed
        let threatIntel = ThreatIntelFeed(cacheDir: supportDir + "/threat_intel")
        await threatIntel.start()

        // Load bundled threat intel for immediate protection (before any event collection)
        await BundledThreatIntel.loadInto(threatIntel)
        let bundledStats = BundledThreatIntel.stats
        print("Bundled threat intel loaded: \(bundledStats.hashes) hashes, \(bundledStats.ips) IPs, \(bundledStats.domains) domains")
        print("Threat intel feed active (abuse.ch Feodo, URLhaus, MalwareBazaar)")

        // Behavioral scoring engine
        let behaviorScoring = BehaviorScoring(alertThreshold: config.behaviorAlertThreshold, criticalThreshold: config.behaviorCriticalThreshold)

        // Certificate Transparency monitor
        let ctMonitor = CertTransparency()

        // Incident grouper -- clusters related alerts into attack timelines
        let incidentGrouper = IncidentGrouper(correlationWindow: config.incidentCorrelationWindow, staleWindow: config.incidentStaleWindow)

        // Campaign detector -- meta-alert engine: chains alerts into kill chains,
        // alert storms, AI compromise patterns, and coordinated attacks
        let campaignDetector = CampaignDetector()

        // Persistent campaign store. Non-fatal if it fails to open — the
        // detector stays in-memory-only in that case and the daemon logs
        // the error rather than crashing.
        let campaignStore: CampaignStore?
        do {
            campaignStore = try CampaignStore(directory: supportDir)
        } catch {
            logger.warning("CampaignStore failed to open: \(error.localizedDescription) — campaigns will not persist across restarts")
            campaignStore = nil
        }

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
        let injectionScanner = PromptInjectionScanner(confidenceThreshold: config.promptInjectionConfidence)
        let scannerStatus = await injectionScanner.isAvailable ? "active" : "unavailable (pip install forensicate)"
        print("AI Guard active (monitoring Claude Code, Codex, OpenClaw, Cursor)")
        print("  Credential fence: \(CredentialFence.defaultPaths.count) sensitive paths")
        print("  Prompt injection scanner: \(scannerStatus)")

        // Statistical anomaly detector
        let statisticalDetector = StatisticalAnomalyDetector(zThreshold: config.statisticalZThreshold, minSamples: config.statisticalMinSamples)

        // MCP server monitor -- watches AI tool configs for suspicious MCP server registrations
        let mcpMonitor = MCPMonitor()
        await mcpMonitor.start()
        print("MCP server monitor active (watching Claude, Cursor, Continue, VS Code, Windsurf configs)")

        // USB device monitor -- detects mass storage, HID keyboard emulation
        let usbMonitor = USBMonitor(pollInterval: config.usbPollInterval)
        await usbMonitor.start()
        print("USB device monitor active")

        // Database encryption -- AES-256 field encryption, key in Keychain
        let dbEncryption = DatabaseEncryption(
            enabled: Foundation.ProcessInfo.processInfo.environment["MACCRAB_ENCRYPT_DB"] == "1"
        )
        if dbEncryption.isEnabled {
            print("Database encryption: active (AES-256, key in Keychain)")
        }

        // Report generator -- HTML incident reports
        let reportGenerator = ReportGenerator()

        // Clipboard monitor -- detects sensitive data and injection on clipboard
        let clipboardMonitor = ClipboardMonitor(pollInterval: config.clipboardPollInterval)
        await clipboardMonitor.start()
        let clipboardInjectionDetector = ClipboardInjectionDetector()
        print("Clipboard monitor active (sensitive data + injection detection)")

        // Browser extension monitor -- scans Chrome/Firefox/Brave/Edge/Arc
        let browserExtMonitor = BrowserExtensionMonitor(pollInterval: config.browserExtensionPollInterval)
        await browserExtMonitor.start()
        print("Browser extension monitor active")

        // Ultrasonic attack monitor -- FFT mic sampling for DolphinAttack/NUIT
        // Opt-in: requires microphone access which triggers a TCC permission popup.
        // Enable with "ultrasonicEnabled": true in daemon_config.json or MACCRAB_ULTRASONIC=1.
        let ultrasonicEnabled = config.ultrasonicEnabled || ProcessInfo.processInfo.environment["MACCRAB_ULTRASONIC"] == "1"
        let ultrasonicMonitor = UltrasonicMonitor(pollInterval: config.ultrasonicPollInterval)
        if ultrasonicEnabled {
            await ultrasonicMonitor.start()
            print("Ultrasonic attack monitor active (DolphinAttack, NUIT, SurfingAttack)")
        } else {
            print("Ultrasonic attack monitor: disabled (set MACCRAB_ULTRASONIC=1 to enable)")
        }

        // DoH evasion detector -- flags non-browser DoH usage
        let dohDetector = DoHDetector()

        // TLS fingerprinter -- C2 beacon detection via connection interval analysis
        let tlsFingerprinter = TLSFingerprinter()

        // Git security monitor -- credential theft, SSH agent hijack, malicious hooks
        let gitSecurityMonitor = GitSecurityMonitor()

        // File injection scanner -- scans files AI tools access for hidden prompt injection
        let fileInjectionScanner = FileInjectionScanner()
        if await fileInjectionScanner.isAvailable {
            print("File injection scanner active (forensicate + inline detection)")
        }

        // Natural language threat hunter
        let threatHunter = ThreatHunter(databasePath: supportDir + "/events.db")

        // Auto rule generator -- creates Sigma rules from observed campaigns
        let ruleGenerator = RuleGenerator(outputDir: supportDir + "/compiled_rules")

        // Rootkit detector -- cross-references proc_listallpids vs sysctl for hidden processes
        let rootkitDetector = RootkitDetector(pollInterval: config.rootkitPollInterval)
        await rootkitDetector.start()
        print("Rootkit detector active (dual-API cross-reference)")

        // EDR/RMM tool monitor — scans for EDR, insider threat, MDM, and remote access tools
        let edrMonitor = EDRMonitor(pollInterval: 120)
        await edrMonitor.start()
        print("EDR/RMM monitor active (CrowdStrike, SentinelOne, ForcePoint, Jamf, TeamViewer + 25 more)")

        // TEMPEST / Van Eck phreaking monitor — SDR device detection + display anomalies
        let tempestMonitor = TEMPESTMonitor(pollInterval: 60)
        await tempestMonitor.start()
        print("TEMPEST monitor active (SDR device detection, display anomaly monitoring)")

        // Library inventory -- scans for injected dylibs
        let libraryInventory = LibraryInventory()

        // CDHash extractor -- binary identity via undocumented flavor 17
        let cdhashExtractor = CDHashExtractor()

        // Crash report miner -- exploitation indicators in crash logs
        let crashReportMiner = CrashReportMiner()

        // Power anomaly detector -- crypto miners, C2 beacons via sleep prevention
        let powerAnomalyDetector = PowerAnomalyDetector()

        // === PREVENTION LAYER ===
        let preventionEnabled: Bool = {
            // Check env var first (backward compat)
            if Foundation.ProcessInfo.processInfo.environment["MACCRAB_PREVENTION"] == "1" { return true }
            // Check config file written by the dashboard app
            let configPath = supportDir + "/prevention_config.json"
            if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let enabled = json["enabled"] as? Bool {
                return enabled
            }
            return false
        }()

        // DNS Sinkhole -- redirect malicious domains to localhost
        let dnsSinkhole = DNSSinkhole()

        // Network Blocker -- PF table-based IP blocking
        let networkBlocker = NetworkBlocker()

        // Persistence Guard -- chflags on LaunchAgent/LaunchDaemon dirs
        let persistenceGuard = PersistenceGuard()

        // Sandbox Analyzer -- sandbox-exec suspicious binaries
        let sandboxAnalyzer = SandboxAnalyzer()

        // AI Containment -- lock credential files from AI tools
        let aiContainment = AIContainment()

        // Supply Chain Gate -- kill installers of fresh packages
        let supplyChainGate = SupplyChainGate()

        // TCC Revocation -- auto-revoke permissions for unsigned apps
        let tccRevocation = TCCRevocation()

        if preventionEnabled {
            // Register threat intel update callback to populate prevention modules
            await threatIntel.onUpdate { [dnsSinkhole, networkBlocker] ips, domains in
                await dnsSinkhole.enable(domains: domains)
                await networkBlocker.enable(ips: ips)
            }

            // Initial population from any cached threat intel
            let cachedIPs = await threatIntel.maliciousIPSet()
            let cachedDomains = await threatIntel.maliciousDomainSet()
            if !cachedDomains.isEmpty {
                await dnsSinkhole.enable(domains: cachedDomains)
            }
            if !cachedIPs.isEmpty {
                await networkBlocker.enable(ips: cachedIPs)
            }

            // Lock persistence directories
            await persistenceGuard.enable()

            // Lock credential files from AI tools
            await aiContainment.enable()

            // Enable supply chain gate
            await supplyChainGate.enable()

            // Enable TCC auto-revocation
            await tccRevocation.enable()

            print("Prevention layer: ACTIVE (DNS sinkhole, PF blocker, persistence guard, AI containment, supply chain gate, TCC revocation)")
        } else {
            print("Prevention layer: STANDBY (set MACCRAB_PREVENTION=1 to enable)")
        }

        // === USER SECURITY FEATURES ===

        // Security scorer -- 0-100 system security posture score
        let securityScorer = SecurityScorer()
        let initialScore = await securityScorer.calculate()
        print("Security score: \(initialScore.totalScore)/100 (\(initialScore.grade))\(initialScore.recommendations.isEmpty ? "" : " -- \(initialScore.recommendations.first ?? "")")")

        // App privacy auditor -- tracks which apps phone home
        let appPrivacyAuditor = AppPrivacyAuditor()

        // Vulnerability scanner -- checks installed apps against CVE database
        let vulnScanner = VulnerabilityScanner()

        // Panic button -- one-click emergency containment
        let panicButton = PanicButton()

        // Travel mode -- heightened security for untrusted networks
        let travelMode = TravelMode()

        // Daily security digest generator
        let securityDigest = SecurityDigest()

        // Notification integrations (Slack, Teams, Discord, PagerDuty)
        let notificationIntegrations = NotificationIntegrations(configPath: supportDir + "/notifications.json")
        let configuredNotifs = await notificationIntegrations.configuredServices()
        if !configuredNotifs.isEmpty {
            print("Notification integrations: \(configuredNotifs.joined(separator: ", "))")
        }

        // Alert exporter -- multi-format export (SARIF, CEF, CSV, JSON, STIX)
        let alertExporter = AlertExporter()

        // Scheduled reports -- daily digest + weekly HTML report
        let scheduledReports = ScheduledReports(supportDir: supportDir)
        let reportSchedule = await scheduledReports.getSchedule()
        if reportSchedule.dailyDigestEnabled || reportSchedule.weeklyReportEnabled {
            print("Scheduled reports: daily=\(reportSchedule.dailyDigestEnabled), weekly=\(reportSchedule.weeklyReportEnabled)")
        }

        // MISP threat intel integration
        let mispClient = MISPClient()
        if await mispClient.isConfigured {
            print("MISP integration: configured")
            // Fetch IOCs from MISP and feed into threat intel
            let mispIOCs = await mispClient.fetchCategorized(lastDays: 7)
            if !mispIOCs.ips.isEmpty || !mispIOCs.domains.isEmpty || !mispIOCs.hashes.isEmpty {
                await threatIntel.addCustomIOCs(hashes: mispIOCs.hashes, ips: mispIOCs.ips, domains: mispIOCs.domains)
                print("  MISP import: \(mispIOCs.ips.count) IPs, \(mispIOCs.domains.count) domains, \(mispIOCs.hashes.count) hashes")
            }
        }

        // Security tool integrations (read-only detection of other tools)
        let toolIntegrations = SecurityToolIntegrations()
        let installedTools = await toolIntegrations.detectInstalledTools()
        if !installedTools.isEmpty {
            let running = installedTools.filter(\.isRunning).map(\.name)
            print("Security tools detected: \(installedTools.map(\.name).joined(separator: ", "))\(running.isEmpty ? "" : " (running: \(running.joined(separator: ", ")))")")
        }

        // Notarization checker -- verifies notarization status of executed binaries
        let notarizationChecker = NotarizationChecker()

        // AI network sandbox -- monitors AI tool network connections against allowlist
        let aiNetworkSandbox = AINetworkSandbox(customConfigPath: supportDir + "/ai_network_allowlist.json")

        // Package freshness checker -- queries registries for package age
        let packageChecker = PackageFreshnessChecker()
        print("Package freshness checker active (npm, PyPI, Homebrew, Cargo)")

        // Cross-process correlator -- links events across unrelated process trees
        let crossProcessCorrelator = CrossProcessCorrelator()

        // Process tree ML -- Markov chain anomaly detection on parent-child transitions
        let processTreeAnalyzer = ProcessTreeAnalyzer(modelPath: supportDir + "/process_tree_model.json")
        do {
            try await processTreeAnalyzer.load()
            let treeStats = await processTreeAnalyzer.stats()
            print("Process tree ML: \(treeStats.mode.rawValue) (\(treeStats.transitions) transitions, \(treeStats.uniqueParents) parents)")
        } catch {
            print("Process tree ML: starting fresh learning period")
        }

        // Fleet telemetry (optional -- configure via MACCRAB_FLEET_URL env var)
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
            print("Fleet client active")
        }

        // === LLM REASONING BACKEND (optional) ===
        // Config sources (in priority order): env vars > llm_config.json > daemon_config.json
        let llmService: LLMService? = await {
            var llmConfig = config.llm

            // Read dashboard-written llm_config.json (written by Settings > AI Backend)
            let llmConfigPath = supportDir + "/llm_config.json"
            if let data = try? Data(contentsOf: URL(fileURLWithPath: llmConfigPath)),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                if let enabled = json["enabled"] as? Bool { llmConfig.enabled = enabled }
                if let provider = json["provider"] as? String {
                    llmConfig.provider = LLMProvider(rawValue: provider) ?? llmConfig.provider
                }
                if let v = json["ollama_url"] as? String { llmConfig.ollamaURL = v }
                if let v = json["ollama_model"] as? String { llmConfig.ollamaModel = v }
                if let v = json["ollama_api_key"] as? String { llmConfig.ollamaAPIKey = v }
                if let v = json["claude_api_key"] as? String { llmConfig.claudeAPIKey = v }
                if let v = json["claude_model"] as? String { llmConfig.claudeModel = v }
                if let v = json["openai_url"] as? String { llmConfig.openaiURL = v }
                if let v = json["openai_api_key"] as? String { llmConfig.openaiAPIKey = v }
                if let v = json["openai_model"] as? String { llmConfig.openaiModel = v }
                if let v = json["mistral_api_key"] as? String { llmConfig.mistralAPIKey = v }
                if let v = json["mistral_model"] as? String { llmConfig.mistralModel = v }
                if let v = json["gemini_api_key"] as? String { llmConfig.geminiAPIKey = v }
                if let v = json["gemini_model"] as? String { llmConfig.geminiModel = v }
            }

            // Env vars override everything (backward compat)
            let env = ProcessInfo.processInfo.environment
            if let p = env["MACCRAB_LLM_PROVIDER"] { llmConfig.provider = LLMProvider(rawValue: p) ?? llmConfig.provider }
            if let v = env["MACCRAB_LLM_OLLAMA_URL"] { llmConfig.ollamaURL = v }
            if let v = env["MACCRAB_LLM_OLLAMA_MODEL"] { llmConfig.ollamaModel = v }
            if let v = env["MACCRAB_LLM_CLAUDE_KEY"] { llmConfig.claudeAPIKey = v }
            if let v = env["MACCRAB_LLM_CLAUDE_MODEL"] { llmConfig.claudeModel = v }
            if let v = env["MACCRAB_LLM_OPENAI_URL"] { llmConfig.openaiURL = v }
            if let v = env["MACCRAB_LLM_OPENAI_KEY"] { llmConfig.openaiAPIKey = v }
            if let v = env["MACCRAB_LLM_OPENAI_MODEL"] { llmConfig.openaiModel = v }

            guard llmConfig.enabled else { return nil }

            let backend: any LLMBackend
            switch llmConfig.provider {
            case .ollama:
                backend = OllamaBackend(baseURL: llmConfig.ollamaURL, model: llmConfig.ollamaModel, apiKey: llmConfig.ollamaAPIKey)
            case .claude:
                guard let key = llmConfig.claudeAPIKey, !key.isEmpty else {
                    print("LLM backend: Claude requires API key")
                    return nil
                }
                backend = ClaudeBackend(apiKey: key, model: llmConfig.claudeModel)
            case .openai:
                guard let key = llmConfig.openaiAPIKey, !key.isEmpty else {
                    print("LLM backend: OpenAI requires API key")
                    return nil
                }
                backend = OpenAIBackend(baseURL: llmConfig.openaiURL, apiKey: key, model: llmConfig.openaiModel)
            case .mistral:
                guard let key = llmConfig.mistralAPIKey, !key.isEmpty else {
                    print("LLM backend: Mistral requires API key")
                    return nil
                }
                backend = MistralBackend(apiKey: key, model: llmConfig.mistralModel)
            case .gemini:
                guard let key = llmConfig.geminiAPIKey, !key.isEmpty else {
                    print("LLM backend: Gemini requires API key")
                    return nil
                }
                backend = GeminiBackend(apiKey: key, model: llmConfig.geminiModel)
            }

            let service = LLMService(backend: backend, config: llmConfig)
            if await service.isAvailable() {
                let model: String
                switch llmConfig.provider {
                case .ollama:  model = llmConfig.ollamaModel
                case .claude:  model = llmConfig.claudeModel
                case .openai:  model = llmConfig.openaiModel
                case .mistral: model = llmConfig.mistralModel
                case .gemini:  model = llmConfig.geminiModel
                }
                print("LLM backend: \(llmConfig.provider.rawValue) (\(model))")
                return service
            } else {
                print("LLM backend: \(llmConfig.provider.rawValue) configured but not reachable")
                return nil
            }
        }()

        // DNS collector (BPF capture or passive mode)
        let dnsCollector = DNSCollector()
        await dnsCollector.start()
        print("DNS collector active")

        // Event tap monitor (keylogger detection)
        let eventTapMonitor = EventTapMonitor(pollInterval: config.eventTapPollInterval)
        await eventTapMonitor.start()
        print("Event tap monitor active (keylogger detection)")

        // System policy monitor (SIP, auth plugins, quarantine, XProtect)
        let systemPolicyMonitor = SystemPolicyMonitor(pollInterval: config.systemPolicyPollInterval)
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

        // Load per-rule process suppressions (from maccrabctl suppress)
        let suppressionManager = SuppressionManager(dataDir: supportDir)
        await suppressionManager.load()
        let suppressionStats = await suppressionManager.stats()
        if suppressionStats.ruleCount > 0 {
            print("Suppressions loaded: \(suppressionStats.pathCount) paths across \(suppressionStats.ruleCount) rules")
        }

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

        // Phase 7 outputs: FileOutput and StreamOutput (Splunk HEC /
        // Elastic Bulk / Datadog Logs) built from daemon_config.json.outputs[].
        var additionalOutputs: [any Output] = []
        for spec in config.outputs {
            if let out = Self.buildOutput(spec: spec, logger: logger) {
                additionalOutputs.append(out)
            }
        }
        if !additionalOutputs.isEmpty {
            logger.info("Configured \(additionalOutputs.count) additional output(s)")
            print("Additional outputs: \(additionalOutputs.map { $0.name }.joined(separator: ", "))")
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
        // Check both the system dir and the binary-local dir; prefer whichever has more
        // JSON files (the one with more rules is fresher from a recent build or install).
        let binaryDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
        let localCompiledRules = binaryDir + "/compiled_rules"
        let effectiveRulesDir: String
        do {
            let systemFiles = (try? fm.contentsOfDirectory(atPath: compiledRulesDir))?.filter { $0.hasSuffix(".json") } ?? []
            let localFiles: [String]
            if fm.fileExists(atPath: localCompiledRules) {
                localFiles = (try? fm.contentsOfDirectory(atPath: localCompiledRules))?.filter { $0.hasSuffix(".json") } ?? []
            } else {
                localFiles = []
            }
            if !localFiles.isEmpty && localFiles.count >= systemFiles.count {
                effectiveRulesDir = localCompiledRules
                print("Using local compiled rules: \(localCompiledRules) (\(localFiles.count) files, system has \(systemFiles.count))")
            } else if !systemFiles.isEmpty {
                effectiveRulesDir = compiledRulesDir
                print("Using system compiled rules: \(compiledRulesDir) (\(systemFiles.count) files)")
            } else if !localFiles.isEmpty {
                effectiveRulesDir = localCompiledRules
                print("Using local compiled rules: \(localCompiledRules) (\(localFiles.count) files)")
            } else {
                effectiveRulesDir = compiledRulesDir
            }
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

        // Start ES collector (optional -- requires root + ES entitlement)
        // Falls back to eslogger proxy if entitlement is missing.
        var esloggerCollector: EsloggerCollector? = nil
        var kdebugCollector: KdebugCollector? = nil
        var esMode = "unavailable"

        if isRoot {
            do {
                collector = try ESCollector()
                logger.info("ES collector started successfully (native client)")
                esMode = "native client"
            } catch {
                logger.warning("ES entitlement unavailable: \(error)")
                // Fallback: use eslogger proxy (same kernel events, no entitlement)
                if let preflightError = EsloggerCollector.preflightCheck() {
                    logger.warning("eslogger preflight failed: \(preflightError)")
                    print("  eslogger: \(preflightError)")
                } else if EsloggerCollector.isAvailable() {
                    esloggerCollector = EsloggerCollector()
                    await esloggerCollector!.start()
                    logger.info("eslogger proxy collector started")
                    esMode = "eslogger proxy"
                } else if KdebugCollector.isAvailable() {
                    // Third fallback: kdebug via fs_usage (root only, no entitlement, no FDA)
                    let kdebug = KdebugCollector()
                    await kdebug.start()
                    kdebugCollector = kdebug
                    logger.info("kdebug collector started via fs_usage")
                    esMode = "kdebug (fs_usage)"
                } else {
                    logger.warning("No kernel event source available")
                    print("  To enable: sign binary with ES entitlement, or install macOS 13+ for eslogger")
                }
            }
        } else {
            // Non-root: try eslogger (needs root but fail gracefully)
            if EsloggerCollector.isAvailable() {
                esloggerCollector = EsloggerCollector()
                await esloggerCollector!.start()
                esMode = "eslogger proxy (may need root)"
            }
        }
        print("Endpoint Security: \(esMode)")

        let startupMs = Double(DispatchTime.now().uptimeNanoseconds - startupBegin.uptimeNanoseconds) / 1_000_000
        print(String(format: "Startup complete in %.0fms", startupMs))

        return DaemonState(
            isRoot: isRoot,
            supportDir: supportDir,
            compiledRulesDir: compiledRulesDir,
            rulesDir: rulesDir,
            rulesURL: rulesURL,
            sequenceRulesDir: sequenceRulesDir,
            effectiveRulesDir: effectiveRulesDir,
            eventStore: eventStore,
            alertStore: alertStore,
            enricher: enricher,
            ruleEngine: ruleEngine,
            sequenceEngine: sequenceEngine,
            baselineEngine: baselineEngine,
            behaviorScoring: behaviorScoring,
            deduplicator: deduplicator,
            suppressionManager: suppressionManager,
            statisticalDetector: statisticalDetector,
            crossProcessCorrelator: crossProcessCorrelator,
            processTreeAnalyzer: processTreeAnalyzer,
            notifier: notifier,
            responseEngine: responseEngine,
            webhookOutput: webhookOutput,
            syslogOutput: syslogOutput,
            additionalOutputs: additionalOutputs,
            notificationIntegrations: notificationIntegrations,
            selfDefense: selfDefense,
            esHealthMonitor: esHealthMonitor,
            threatIntel: threatIntel,
            ctMonitor: ctMonitor,
            mispClient: mispClient,
            aiRegistry: aiRegistry,
            aiTracker: aiTracker,
            credentialFence: credentialFence,
            projectBoundary: projectBoundary,
            injectionScanner: injectionScanner,
            aiNetworkSandbox: aiNetworkSandbox,
            fileInjectionScanner: fileInjectionScanner,
            mcpMonitor: mcpMonitor,
            usbMonitor: usbMonitor,
            clipboardMonitor: clipboardMonitor,
            clipboardInjectionDetector: clipboardInjectionDetector,
            browserExtMonitor: browserExtMonitor,
            ultrasonicMonitor: ultrasonicMonitor,
            eventTapMonitor: eventTapMonitor,
            systemPolicyMonitor: systemPolicyMonitor,
            rootkitDetector: rootkitDetector,
            tccMonitor: tccMonitor,
            edrMonitor: edrMonitor,
            tempestMonitor: tempestMonitor,
            fsEventsCollector: fsEventsCollector,
            collector: collector,
            esloggerCollector: esloggerCollector,
            kdebugCollector: kdebugCollector,
            ulCollector: ulCollector,
            networkCollector: networkCollector,
            dnsCollector: dnsCollector,
            esMode: esMode,
            dohDetector: dohDetector,
            tlsFingerprinter: tlsFingerprinter,
            crashReportMiner: crashReportMiner,
            powerAnomalyDetector: powerAnomalyDetector,
            libraryInventory: libraryInventory,
            cdhashExtractor: cdhashExtractor,
            quarantineEnricher: quarantineEnricher,
            yaraEnricher: yaraEnricher,
            dbEncryption: dbEncryption,
            preventionEnabled: preventionEnabled,
            dnsSinkhole: dnsSinkhole,
            networkBlocker: networkBlocker,
            persistenceGuard: persistenceGuard,
            sandboxAnalyzer: sandboxAnalyzer,
            aiContainment: aiContainment,
            supplyChainGate: supplyChainGate,
            tccRevocation: tccRevocation,
            securityScorer: securityScorer,
            appPrivacyAuditor: appPrivacyAuditor,
            vulnScanner: vulnScanner,
            panicButton: panicButton,
            travelMode: travelMode,
            securityDigest: securityDigest,
            alertExporter: alertExporter,
            scheduledReports: scheduledReports,
            incidentGrouper: incidentGrouper,
            campaignDetector: campaignDetector,
            campaignStore: campaignStore,
            ruleGenerator: ruleGenerator,
            packageChecker: packageChecker,
            notarizationChecker: notarizationChecker,
            gitSecurityMonitor: gitSecurityMonitor,
            reportGenerator: reportGenerator,
            threatHunter: threatHunter,
            toolIntegrations: toolIntegrations,
            fleetClient: fleetClient,
            llmService: llmService
        )
    }

    // MARK: - Phase 7 output factory

    /// Convert a `DaemonConfig.OutputSpec` into a concrete `any Output`.
    /// Returns nil for malformed specs; each failure is logged.
    static func buildOutput(spec: DaemonConfig.OutputSpec, logger: os.Logger) -> (any Output)? {
        switch spec.type {
        case "file":
            guard let path = spec.path else {
                logger.warning("FileOutput spec missing 'path'")
                return nil
            }
            let format = FileOutput.Format(rawValue: spec.format ?? "ocsf") ?? .ocsf
            let maxBytes = Int64((spec.maxMb ?? 100) * 1024 * 1024)
            let maxAge = (spec.maxAgeHours ?? 24) * 3600
            let maxArch = spec.maxArchives ?? 10
            return FileOutput(
                path: path,
                format: format,
                maxBytes: maxBytes,
                maxAgeSeconds: maxAge,
                maxArchives: maxArch
            )

        case "splunk_hec", "elastic_bulk", "datadog_logs":
            guard let urlStr = spec.url, let url = URL(string: urlStr) else {
                logger.warning("StreamOutput spec missing valid 'url'")
                return nil
            }
            guard let kind = StreamOutput.Kind(rawValue: spec.type) else {
                return nil
            }
            let token = resolveToken(spec: spec)
            return StreamOutput(
                kind: kind,
                url: url,
                token: token,
                indexName: spec.indexName,
                retryCount: spec.retryCount ?? 2,
                timeout: spec.timeoutSeconds ?? 10
            )

        default:
            logger.warning("Unknown output type '\(spec.type)'")
            return nil
        }
    }

    /// Prefer tokenEnv lookup over a literal token — keeps secrets out
    /// of the on-disk config file.
    private static func resolveToken(spec: DaemonConfig.OutputSpec) -> String? {
        if let envVar = spec.tokenEnv,
           let value = Foundation.ProcessInfo.processInfo.environment[envVar],
           !value.isEmpty {
            return value
        }
        return spec.token
    }
}
