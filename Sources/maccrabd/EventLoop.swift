import Foundation
import MacCrabCore
import os.log

/// The main event processing loop. Processes each event through
/// enrichment, AI guard, detection layers, and alert output.
enum EventLoop {
    static func run(state: DaemonState, eventStream: AsyncStream<Event>, eventCount: inout UInt64, alertCount: inout UInt64) async {
        for await event in eventStream {
            eventCount += 1

            // Enrich the event (lineage, code signing)
            var enrichedEvent = await state.enricher.enrich(event)

            // YARA enrichment for file events (Phase 3)
            if enrichedEvent.eventCategory == .file {
                enrichedEvent = await state.yaraEnricher.enrich(enrichedEvent)
            }

            // === AI Tool Detection ===
            let aiProc = enrichedEvent.process
            if let aiType = state.aiRegistry.isAITool(executablePath: aiProc.executable) {
                await state.aiTracker.registerAIProcess(pid: aiProc.pid, type: aiType, projectDir: aiProc.workingDirectory)
                await state.projectBoundary.registerBoundary(aiPid: aiProc.pid, projectDir: aiProc.workingDirectory)
                enrichedEvent.enrichments["ai_tool"] = aiType.rawValue
                enrichedEvent.enrichments["ai_tool_name"] = aiType.displayName
            } else {
                let (isChild, aiType, projectDir) = await state.aiTracker.isAIChild(pid: aiProc.pid, ancestors: aiProc.ancestors)
                if isChild {
                    enrichedEvent.enrichments["ai_tool"] = aiType?.rawValue ?? "unknown"
                    enrichedEvent.enrichments["ai_tool_child"] = "true"
                    if let dir = projectDir { enrichedEvent.enrichments["ai_project_dir"] = dir }

                    // AI child spawning a shell -- track it
                    let shellNames = ["/bash", "/zsh", "/sh", "/dash", "/fish"]
                    if shellNames.contains(where: { aiProc.executable.hasSuffix($0) }) {
                        await state.behaviorScoring.addIndicator(
                            named: "ai_tool_spawns_shell",
                            detail: "\(aiType?.displayName ?? "AI tool") spawned \(aiProc.name)",
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child running sudo
                    if aiProc.executable.hasSuffix("/sudo") || aiProc.commandLine.hasPrefix("sudo ") {
                        await state.behaviorScoring.addIndicator(
                            named: "ai_tool_runs_sudo",
                            detail: "\(aiType?.displayName ?? "AI tool") child running sudo: \(aiProc.commandLine.prefix(100))",
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child installing packages
                    let pkgCmds = ["npm install", "npm i ", "pip install", "pip3 install", "cargo add", "brew install"]
                    if pkgCmds.contains(where: { aiProc.commandLine.lowercased().contains($0) }) {
                        await state.behaviorScoring.addIndicator(
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
                        await state.behaviorScoring.addIndicator(
                            named: "ai_tool_downloads_and_exec",
                            detail: aiProc.commandLine.prefix(200).description,
                            forProcess: aiProc.pid, path: aiProc.executable
                        )
                    }

                    // AI child writing to persistence locations
                    if let file = enrichedEvent.file {
                        let persistPaths = ["/LaunchAgents/", "/LaunchDaemons/", "/StartupItems/", ".zshrc", ".bashrc", ".bash_profile"]
                        if persistPaths.contains(where: { file.path.contains($0) }) {
                            await state.behaviorScoring.addIndicator(
                                named: "ai_tool_persistence_write",
                                detail: "AI tool writing to \(file.path)",
                                forProcess: aiProc.pid, path: aiProc.executable
                            )
                        }
                    }

                    // === Credential Fence: check file access against sensitive paths ===
                    if let filePath = enrichedEvent.file?.path {
                        if let (credType, credDesc) = state.credentialFence.checkAccessDetailed(
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
                            do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            await state.notifier.notify(alert: alert)
                            await state.behaviorScoring.addIndicator(
                                named: "ai_tool_credential_access",
                                detail: "\(credType.rawValue): \(filePath)",
                                forProcess: aiProc.pid, path: aiProc.executable
                            )
                            print("[CRIT] AI credential access: \(aiType?.displayName ?? "AI") -> \(credType.rawValue)")
                        }

                        // === Project Boundary: check writes outside project dir ===
                        // Check via the child-to-session mapping
                        let sessions = await state.aiTracker.activeSessions()
                        for session in sessions where session.childPids.contains(aiProc.pid) || session.aiPid == aiProc.pid {
                            if let violation = await state.projectBoundary.checkWrite(
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
                                do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                await state.notifier.notify(alert: alert)
                                await state.behaviorScoring.addIndicator(
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
                    if await state.injectionScanner.isAvailable {
                        let textToScan = aiProc.commandLine
                        if !textToScan.isEmpty, textToScan.count > 20 {
                            if let (indicator, detail) = await state.injectionScanner.scanForSeverity(textToScan) {
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
                                do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                await state.notifier.notify(alert: alert)
                                await state.behaviorScoring.addIndicator(
                                    named: indicator, detail: detail,
                                    forProcess: aiProc.pid, path: aiProc.executable
                                )
                                print("[CRIT] Prompt injection in AI context: \(detail.prefix(100))")
                            }
                        }
                    }
                }
            }

            // === Package freshness check for install commands ===
            if enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                let packages = PackageFreshnessChecker.parseInstallCommand(enrichedEvent.process.commandLine)
                if !packages.isEmpty {
                    let results = await state.packageChecker.checkPackages(packages)
                    for result in results where result.riskLevel >= .medium {
                        let severity: Severity = result.riskLevel == .critical ? .critical : result.riskLevel == .high ? .high : .medium
                        let alert = Alert(
                            ruleId: "maccrab.supply-chain.fresh-package",
                            ruleTitle: "Fresh Package Installed: \(result.name) (\(result.registry.rawValue))",
                            severity: severity,
                            eventId: enrichedEvent.id.uuidString,
                            processPath: enrichedEvent.process.executable,
                            processName: enrichedEvent.process.name,
                            description: result.description,
                            mitreTactics: "attack.initial_access",
                            mitreTechniques: "attack.t1195.002",
                            suppressed: false
                        )
                        do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        await state.notifier.notify(alert: alert)
                        await state.behaviorScoring.addIndicator(
                            named: "fresh_package_install",
                            detail: "\(result.name) (\(result.registry.rawValue)) age: \(result.ageInDays.map { String(format: "%.1f", $0) } ?? "unknown") days",
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                        let riskIcon = result.riskLevel == .critical ? "[CRIT]" : result.riskLevel == .high ? "[HIGH]" : "[MED] "
                        print("\(riskIcon) Fresh package: \(result.name) (\(result.registry.rawValue)) -- \(result.description)")

                        // === Supply Chain Gate: block critical-risk packages ===
                        if state.preventionEnabled && result.riskLevel >= .high {
                            if let blocked = await state.supplyChainGate.gate(
                                packageName: result.name,
                                registry: result.registry.rawValue,
                                ageInDays: result.ageInDays,
                                riskLevel: result.riskLevel.rawValue,
                                installerPid: enrichedEvent.process.pid
                            ) {
                                let blockAlert = Alert(
                                    ruleId: "maccrab.prevention.supply-chain-blocked",
                                    ruleTitle: "BLOCKED: Package Install Killed -- \(blocked.packageName)",
                                    severity: .critical,
                                    eventId: UUID().uuidString,
                                    processPath: enrichedEvent.process.executable,
                                    processName: enrichedEvent.process.name,
                                    description: "Supply chain gate killed installer (PID \(blocked.installerPid)): \(blocked.reason)",
                                    mitreTactics: "attack.initial_access",
                                    mitreTechniques: "attack.t1195.002",
                                    suppressed: false
                                )
                                do { try await state.alertStore.insert(alert: blockAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                await state.notifier.notify(alert: blockAlert)
                                print("[BLOCKED] Supply chain gate killed PID \(blocked.installerPid): \(blocked.packageName)")
                            }
                        }
                    }
                }
            }

            // === Notarization check for executed binaries ===
            if enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                let notarResult = await state.notarizationChecker.check(binaryPath: enrichedEvent.process.executable)
                enrichedEvent.enrichments["notarization.status"] = notarResult.status.rawValue
                if let source = notarResult.source {
                    enrichedEvent.enrichments["notarization.source"] = source
                }
                if notarResult.status == .notNotarized && enrichedEvent.process.codeSignature?.signerType != .apple {
                    await state.behaviorScoring.addIndicator(
                        named: "not_notarized",
                        detail: enrichedEvent.process.executable,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )

                    // === Prevention: sandbox-analyze unnotarized binaries from Downloads/tmp ===
                    if state.preventionEnabled {
                        let execPath = enrichedEvent.process.executable
                        if execPath.contains("/Downloads/") || execPath.contains("/tmp/") || execPath.contains("/Users/Shared/") {
                            if let analysis = await state.sandboxAnalyzer.analyze(binaryPath: execPath) {
                                if analysis.isSuspicious {
                                    let alert = Alert(
                                        ruleId: "maccrab.prevention.sandbox-suspicious",
                                        ruleTitle: "Sandbox Analysis: Suspicious Behavior Detected",
                                        severity: .critical,
                                        eventId: enrichedEvent.id.uuidString,
                                        processPath: execPath,
                                        processName: enrichedEvent.process.name,
                                        description: "Unnotarized binary from \(execPath) attempted blocked operations in sandbox: \(analysis.blockedOperations.prefix(3).joined(separator: "; "))",
                                        mitreTactics: "attack.execution",
                                        mitreTechniques: "attack.t1204",
                                        suppressed: false
                                    )
                                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                    await state.notifier.notify(alert: alert)
                                    print("[SANDBOX] Suspicious: \(execPath) -- \(analysis.blockedOperations.count) blocked ops")
                                }
                            }
                        }
                    }
                }
            }

            // === AI Network Sandbox: check outbound connections from AI tools ===
            if enrichedEvent.eventCategory == .network,
               let aiTool = enrichedEvent.enrichments["ai_tool"],
               let net = enrichedEvent.network {
                if let violation = await state.aiNetworkSandbox.checkConnection(
                    aiToolName: aiTool,
                    processPid: enrichedEvent.process.pid,
                    processPath: enrichedEvent.process.executable,
                    destinationIP: net.destinationIp,
                    destinationPort: net.destinationPort,
                    destinationDomain: net.destinationHostname
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.ai-guard.network-sandbox",
                        ruleTitle: "AI Tool Connected to Unapproved Destination",
                        severity: .high,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: violation.reason,
                        mitreTactics: "attack.exfiltration",
                        mitreTechniques: "attack.t1041",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.notifier.notify(alert: alert)
                    await state.behaviorScoring.addIndicator(
                        named: "ai_tool_unapproved_network",
                        detail: "\(violation.destinationDomain ?? violation.destinationIP):\(violation.destinationPort)",
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === Cross-process correlation ===
            if let file = enrichedEvent.file {
                let action = enrichedEvent.eventAction == "exec" ? "execute" : enrichedEvent.eventAction
                if let chain = await state.crossProcessCorrelator.recordFileEvent(
                    path: file.path, action: action,
                    pid: enrichedEvent.process.pid,
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    timestamp: enrichedEvent.timestamp
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.correlator.cross-process",
                        ruleTitle: "Cross-Process Attack Chain: \(chain.description.prefix(60))",
                        severity: chain.severity,
                        eventId: UUID().uuidString,
                        processPath: chain.events.last?.processPath,
                        processName: chain.events.last?.processName,
                        description: "Cross-process chain (\(chain.processCount) processes, \(chain.events.count) events, \(Int(chain.timeSpanSeconds))s): \(chain.description)",
                        mitreTactics: "attack.execution",
                        mitreTechniques: "attack.t1204",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.notifier.notify(alert: alert)
                    print("[XPROC] \(chain.description)")
                }
            }
            if let net = enrichedEvent.network {
                if let chain = await state.crossProcessCorrelator.recordNetworkEvent(
                    destinationIP: net.destinationIp,
                    destinationPort: net.destinationPort,
                    destinationDomain: net.destinationHostname,
                    pid: enrichedEvent.process.pid,
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    timestamp: enrichedEvent.timestamp
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.correlator.network-convergence",
                        ruleTitle: "Multiple Processes Contacting Same Destination",
                        severity: chain.severity,
                        eventId: UUID().uuidString,
                        processPath: chain.events.last?.processPath,
                        processName: chain.events.last?.processName,
                        description: chain.description,
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1071",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.notifier.notify(alert: alert)
                }
            }

            // === Process Tree ML: record transition and check for anomalies ===
            if enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                let parentName = enrichedEvent.process.ancestors.first?.name ?? "unknown"
                let childName = enrichedEvent.process.name
                if let logProb = await state.processTreeAnalyzer.recordTransition(
                    parentName: parentName, childName: childName
                ) {
                    if logProb < -8.0 {
                        enrichedEvent.enrichments["tree.anomaly_score"] = String(format: "%.2f", logProb)
                        await state.behaviorScoring.addIndicator(
                            named: "anomalous_process_tree",
                            detail: "\(parentName) -> \(childName) (logP=\(String(format: "%.1f", logProb)))",
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                }
            }

            // === Quarantine provenance enrichment for file events ===
            if let filePath = enrichedEvent.file?.path {
                await state.quarantineEnricher.enrich(&enrichedEvent.enrichments, forFile: filePath)
            }

            // === DYLD injection detection ===
            let cmdline = enrichedEvent.process.commandLine.lowercased()
            let args = enrichedEvent.process.args.joined(separator: " ").lowercased()
            if cmdline.contains("dyld_insert_libraries") || args.contains("dyld_insert_libraries") {
                await state.behaviorScoring.addIndicator(
                    named: "library_injection",
                    detail: "DYLD_INSERT_LIBRARIES in command/env",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
            }

            // === Statistical anomaly detection ===
            let anomalies = await state.statisticalDetector.processEvent(
                processPath: enrichedEvent.process.executable,
                argCount: enrichedEvent.process.args.count,
                commandLine: enrichedEvent.process.commandLine,
                category: enrichedEvent.eventCategory.rawValue,
                timestamp: enrichedEvent.timestamp
            )
            for anomaly in anomalies {
                await state.behaviorScoring.addIndicator(
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
                    await state.behaviorScoring.addIndicator(
                        named: "high_entropy_commandline",
                        detail: "entropy=\(String(format: "%.2f", entropy))",
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === DNS enrichment: resolve IP -> domain from DNS cache ===
            if let net = enrichedEvent.network, enrichedEvent.network?.destinationHostname == nil {
                if let domain = await state.dnsCollector.domainForIP(net.destinationIp) {
                    enrichedEvent.enrichments["dns.resolved_domain"] = domain
                }
            }

            // === Threat Intel + CT enrichment ===
            if let net = enrichedEvent.network {
                // Certificate Transparency check on destination domains
                if let host = net.destinationHostname {
                    if let ctResult = await state.ctMonitor.checkDomain(host), ctResult.isSuspicious {
                        await state.behaviorScoring.addIndicator(
                            BehaviorScoring.Indicator(name: "suspicious_certificate", weight: 4.0, detail: ctResult.reason ?? host),
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                    // Typosquatting check
                    let (isTypo, typoReason) = await state.ctMonitor.isTyposquat(host)
                    if isTypo {
                        await state.behaviorScoring.addIndicator(
                            BehaviorScoring.Indicator(name: "typosquat_domain", weight: 6.0, detail: typoReason ?? host),
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                }
            }

            // === App privacy audit: track network connections per process ===
            if let net = enrichedEvent.network {
                await state.appPrivacyAuditor.recordConnection(
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    domain: net.destinationHostname,
                    ip: net.destinationIp,
                    port: net.destinationPort
                )
            }

            // Check process hash, network IPs, and domains against known-bad IOCs
            if let net = enrichedEvent.network {
                if await state.threatIntel.isIPMalicious(net.destinationIp) {
                    await state.behaviorScoring.addIndicator(
                        named: "known_malicious_ip",
                        detail: net.destinationIp,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
                if let host = net.destinationHostname, await state.threatIntel.isDomainMalicious(host) {
                    await state.behaviorScoring.addIndicator(
                        named: "known_malicious_domain",
                        detail: host,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === CDHash threat intel matching (from eslogger) ===
            if let cdhash = enrichedEvent.enrichments["process.cdhash"],
               await state.threatIntel.isHashMalicious(cdhash) {
                let alert = Alert(
                    ruleId: "maccrab.threat-intel.hash-match",
                    ruleTitle: "Known Malicious Binary (CDHash Match)",
                    severity: .critical,
                    eventId: enrichedEvent.id.uuidString,
                    processPath: enrichedEvent.process.executable,
                    processName: enrichedEvent.process.name,
                    description: "Process binary CDHash \(cdhash) matches known-malicious hash from threat intelligence feed",
                    mitreTactics: "attack.execution",
                    mitreTechniques: "attack.t1204",
                    suppressed: false
                )
                do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                await state.notifier.notify(alert: alert)
                await state.behaviorScoring.addIndicator(
                    named: "known_malicious_hash",
                    detail: "CDHash: \(cdhash)",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
                print("[CRIT] Threat intel hash match: \(enrichedEvent.process.name) CDHash=\(cdhash)")
            }

            // === DYLD injection via environment variables (from eslogger) ===
            if let dyldEnv = enrichedEvent.enrichments["exec.dyld_env"] {
                await state.behaviorScoring.addIndicator(
                    named: "library_injection",
                    detail: "DYLD env var: \(dyldEnv.prefix(100))",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
            }

            // === DoH evasion detection ===
            if let net = enrichedEvent.network {
                if let dohViolation = await state.dohDetector.check(
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    pid: enrichedEvent.process.pid,
                    destinationIP: net.destinationIp,
                    destinationPort: net.destinationPort
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.network.doh-evasion",
                        ruleTitle: "DNS-over-HTTPS Evasion: \(dohViolation.processName) -> \(dohViolation.resolverName)",
                        severity: .high,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: dohViolation.processPath, processName: dohViolation.processName,
                        description: "Non-browser process using DoH resolver \(dohViolation.resolverName) (\(dohViolation.destinationIP):443)",
                        mitreTactics: "attack.command_and_control", mitreTechniques: "attack.t1071.004",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.notifier.notify(alert: alert)
                }

                // === TLS fingerprinting / C2 beacon detection ===
                if let tlsAlert = await state.tlsFingerprinter.analyze(
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    destinationIP: net.destinationIp,
                    destinationPort: net.destinationPort,
                    timestamp: enrichedEvent.timestamp
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.network.\(tlsAlert.alertType.rawValue)",
                        ruleTitle: tlsAlert.detail.prefix(80).description,
                        severity: tlsAlert.severity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: tlsAlert.processPath, processName: tlsAlert.processName,
                        description: tlsAlert.detail,
                        mitreTactics: "attack.command_and_control", mitreTechniques: "attack.t1071.001",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    if tlsAlert.severity >= .high { await state.notifier.notify(alert: alert) }
                }
            }

            // === Git security monitoring ===
            if enrichedEvent.eventCategory == .process || enrichedEvent.eventCategory == .file {
                if let gitEvent = await state.gitSecurityMonitor.checkProcess(
                    name: enrichedEvent.process.name,
                    path: enrichedEvent.process.executable,
                    pid: enrichedEvent.process.pid,
                    commandLine: enrichedEvent.process.commandLine,
                    filePath: enrichedEvent.file?.path,
                    envVars: nil
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.git.\(gitEvent.type.rawValue)",
                        ruleTitle: "Git Security: \(gitEvent.type.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                        severity: gitEvent.severity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: gitEvent.processPath, processName: gitEvent.processName,
                        description: gitEvent.detail,
                        mitreTactics: "attack.credential_access", mitreTechniques: "attack.t1555",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    if gitEvent.severity >= .high { await state.notifier.notify(alert: alert) }
                }
            }

            // === File injection scanning (AI tool file access) ===
            if enrichedEvent.enrichments["ai_tool"] != nil || enrichedEvent.enrichments["ai_tool_child"] != nil,
               let filePath = enrichedEvent.file?.path {
                if let scanResult = await state.fileInjectionScanner.scanFile(path: filePath) {
                    let alert = Alert(
                        ruleId: "maccrab.ai-guard.file-injection",
                        ruleTitle: "Prompt Injection in File: \((filePath as NSString).lastPathComponent)",
                        severity: scanResult.severity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: "Hidden prompt injection detected in \(filePath) (\(scanResult.confidence)% confidence). Threats: \(scanResult.threats.joined(separator: "; "))",
                        mitreTactics: "attack.initial_access", mitreTechniques: "attack.t1195.002",
                        suppressed: false
                    )
                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.notifier.notify(alert: alert)
                    print("[FILE-INJECT] \(filePath): \(scanResult.threats.first ?? "injection detected")")
                }
            }

            // === Behavioral scoring: process-level indicators ===
            let proc = enrichedEvent.process
            if proc.codeSignature == nil || proc.codeSignature?.signerType == .unsigned {
                await state.behaviorScoring.addIndicator(
                    named: "unsigned_binary", detail: proc.executable,
                    forProcess: proc.pid, path: proc.executable
                )
            }
            if proc.executable.contains("/tmp/") || proc.executable.contains("/private/tmp/") {
                await state.behaviorScoring.addIndicator(
                    named: "executed_from_tmp", detail: proc.executable,
                    forProcess: proc.pid, path: proc.executable
                )
            }
            if let file = enrichedEvent.file {
                if file.path.contains("/LaunchAgents/") {
                    await state.behaviorScoring.addIndicator(
                        named: "writes_launch_agent", detail: file.path,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
                if file.path.contains("/LaunchDaemons/") {
                    await state.behaviorScoring.addIndicator(
                        named: "writes_launch_daemon", detail: file.path,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
            }

            // Store event
            do { try await state.eventStore.insert(event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordEventError(error) }

            // === Detection: 3 layers ===

            // Layer 1: Single-event Sigma rules
            var matches = await state.ruleEngine.evaluate(enrichedEvent)

            // Layer 2: Temporal sequence rules (Phase 2)
            let sequenceMatches = await state.sequenceEngine.evaluate(enrichedEvent)
            matches.append(contentsOf: sequenceMatches)

            // Layer 3: Baseline anomaly detection (Phase 3)
            if let baselineMatch = await state.baselineEngine.evaluate(enrichedEvent) {
                matches.append(baselineMatch)
            }

            // Layer 4: Behavioral scoring -- escalate score on rule matches
            for match in matches {
                if let scoringResult = await state.behaviorScoring.addRuleMatch(
                    severity: match.severity,
                    ruleTitle: match.ruleName,
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                ) {
                    // Behavioral threshold crossed -- generate composite alert
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
                    // Suppression + deduplication checks
                    if await state.suppressionManager.isSuppressed(ruleId: match.ruleId, processPath: enrichedEvent.process.executable) {
                        continue
                    }
                    if await state.deduplicator.shouldSuppress(ruleId: match.ruleId, processPath: enrichedEvent.process.executable) {
                        continue
                    }
                    await state.deduplicator.recordAlert(ruleId: match.ruleId, processPath: enrichedEvent.process.executable)

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

                    do { try await state.alertStore.insert(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await state.notifier.notify(alert: alert)
                    await state.responseEngine.execute(alert: alert, event: enrichedEvent)

                    // Send to external notification integrations (Slack, Teams, etc.)
                    await state.notificationIntegrations.sendAlert(
                        ruleTitle: alert.ruleTitle,
                        severity: match.severity.rawValue,
                        processName: alert.processName,
                        processPath: alert.processPath,
                        description: alert.description ?? "",
                        mitreTechniques: alert.mitreTechniques
                    )

                    // Buffer for fleet telemetry
                    if let fleet = state.fleetClient {
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
                    await state.incidentGrouper.processAlert(
                        alertId: alert.id,
                        timestamp: alert.timestamp,
                        ruleTitle: match.ruleName,
                        severity: match.severity,
                        processPath: enrichedEvent.process.executable,
                        parentPath: enrichedEvent.process.ancestors.first?.executable,
                        tactics: tactics
                    )

                    // Campaign detection: chain alerts into higher-level patterns
                    let alertSummary = CampaignDetector.AlertSummary(
                        ruleId: alert.ruleId,
                        ruleTitle: alert.ruleTitle,
                        severity: match.severity,
                        processPath: alert.processPath,
                        timestamp: alert.timestamp,
                        tactics: Set(tactics)
                    )
                    let campaigns = await state.campaignDetector.processAlert(alertSummary)
                    for campaign in campaigns {
                        let campaignAlert = Alert(
                            id: campaign.id,
                            timestamp: campaign.detectedAt,
                            ruleId: "maccrab.campaign.\(campaign.type.rawValue)",
                            ruleTitle: campaign.title,
                            severity: campaign.severity,
                            eventId: alert.id,
                            processPath: campaign.alerts.last?.processPath,
                            processName: nil,
                            description: campaign.description,
                            mitreTactics: campaign.tactics.joined(separator: ","),
                            mitreTechniques: "",
                            suppressed: false
                        )
                        do { try await state.alertStore.insert(alert: campaignAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        await state.notifier.notify(alert: campaignAlert)
                        print("[CAMPAIGN] \(campaign.type.rawValue): \(campaign.title)")

                        // Auto-generate a Sigma rule from the campaign
                        let campaignAlerts = campaign.alerts.map { a in
                            (ruleId: a.ruleId, ruleTitle: a.ruleTitle, processPath: a.processPath, tactics: a.tactics, timestamp: a.timestamp)
                        }
                        let rule: RuleGenerator.GeneratedRule?
                        if state.llmService != nil {
                            rule = await state.ruleGenerator.generateFromCampaignEnhanced(
                                campaignType: campaign.type.rawValue,
                                alerts: campaignAlerts
                            )
                        } else {
                            rule = await state.ruleGenerator.generateFromCampaign(
                                campaignType: campaign.type.rawValue,
                                alerts: campaignAlerts
                            )
                        }
                        if let rule {
                            print("[RULE-GEN] Auto-generated: \(rule.filename)")
                        }

                        // LLM investigation summary + defense recommendation (non-blocking)
                        if let llm = state.llmService {
                            let campaignTitle = campaign.title
                            let campaignType = campaign.type.rawValue
                            let campaignSeverity = campaign.severity
                            let campaignId = campaign.id
                            let campaignTactics = Array(campaign.tactics)
                            let alertSummaries = campaign.alerts.prefix(10).map { a in
                                (title: a.ruleTitle, process: a.processPath, severity: a.severity.rawValue)
                            }

                            Task {
                                // Investigation summary
                                if let enhancement = await llm.query(
                                    systemPrompt: LLMPrompts.investigationSystem,
                                    userPrompt: LLMPrompts.investigationUser(
                                        campaignType: campaignType, title: campaignTitle,
                                        severity: campaignSeverity.rawValue,
                                        tactics: campaignTactics,
                                        alerts: alertSummaries
                                    ),
                                    maxTokens: 1024, temperature: 0.3
                                ) {
                                    let summaryAlert = Alert(
                                        ruleId: "maccrab.llm.investigation-summary",
                                        ruleTitle: "Investigation Summary: \(campaignTitle)",
                                        severity: .informational,
                                        eventId: campaignId,
                                        processPath: nil, processName: nil,
                                        description: enhancement.response,
                                        mitreTactics: nil, mitreTechniques: nil,
                                        suppressed: false
                                    )
                                    do { try await state.alertStore.insert(alert: summaryAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                    print("[LLM] Investigation summary generated for: \(campaignTitle)")
                                }

                                // Active defense recommendation (high/critical only)
                                // NOTE: Advisory only — recommendations are stored as informational
                                // alerts for human review. Actions are NEVER auto-executed.
                                if campaignSeverity == .critical || campaignSeverity == .high {
                                    let context = "Campaign: \(campaignType) — \(campaignTitle)\nSeverity: \(campaignSeverity.rawValue)\nAlerts: \(alertSummaries.map { "[\($0.severity)] \($0.title) (\($0.process ?? "?"))" }.joined(separator: "; "))"
                                    if let rec = await llm.query(
                                        systemPrompt: LLMPrompts.activeDefenseSystem,
                                        userPrompt: LLMPrompts.activeDefenseUser(alertContext: context),
                                        maxTokens: 512, temperature: 0.1
                                    ) {
                                        let recAlert = Alert(
                                            ruleId: "maccrab.llm.defense-recommendation",
                                            ruleTitle: "Defense Recommendation: \(campaignTitle)",
                                            severity: .informational,
                                            eventId: campaignId,
                                            processPath: nil, processName: nil,
                                            description: rec.response,
                                            mitreTactics: nil, mitreTechniques: nil,
                                            suppressed: false
                                        )
                                        do { try await state.alertStore.insert(alert: recAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                        print("[LLM] Defense recommendation generated for: \(campaignTitle)")
                                    }
                                }
                            }
                        }
                    }

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
                        let logPath = state.supportDir + "/alerts.jsonl"
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
                        // Atomic append -- use O_APPEND to avoid seek+write race
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
                    if let webhook = state.webhookOutput {
                        Task { await webhook.send(alert: alert, event: enrichedEvent) }
                    }

                    // Syslog output (Phase 3)
                    if let syslog = state.syslogOutput {
                        Task { await syslog.send(alert: alert) }
                    }
                }
            }
        }

        logger.info("Event stream ended. Daemon exiting.")
    }
}
