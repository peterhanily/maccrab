import Foundation
import MacCrabCore
import os.log

/// Spawns all background monitor tasks (clipboard, browser extension, ultrasonic,
/// USB, MCP, system policy, event tap, DNS, rootkit, FSEvents).
///
/// Each task is registered with `supervisor` under a stable name. On SIGTERM
/// the daemon calls `supervisor.shutdown()` which cancels every supervised
/// task and awaits its unwinding with a bounded deadline. The inner
/// `for await` loops exit automatically when the enclosing Task is cancelled;
/// no explicit `Task.checkCancellation()` is needed inside the bodies.
enum MonitorTasks {
    static func start(state: DaemonState, supervisor: MonitorSupervisor) async {
        // FSEvents file monitor task (non-root fallback)
        if !state.isRoot {
            await supervisor.start("fsevents") {
                for await event in state.fsEventsCollector.events {
                    // Route FSEvents through the enrichment + detection pipeline
                    let enriched = await state.enricher.enrich(event)
                    try? await state.eventStore.insert(event: enriched)
                    var matches = await state.ruleEngine.evaluate(enriched)
                    // Apply the same noise filters the main EventLoop uses
                    // so FSEvents-triggered rule hits don't bypass
                    // unknown-process / warm-up / trusted-browser gates.
                    NoiseFilter.apply(&matches, event: enriched, isWarmingUp: state.isWarmingUp)
                    for match in matches {
                        if await state.suppressionManager.isSuppressed(ruleId: match.ruleId, processPath: enriched.process.executable) { continue }
                        if await state.deduplicator.shouldSuppress(ruleId: match.ruleId, processPath: enriched.process.executable) { continue }
                        await state.deduplicator.recordAlert(ruleId: match.ruleId, processPath: enriched.process.executable)
                        let effective = await state.deduplicator.effectiveSeverity(
                            ruleId: match.ruleId, original: match.severity)
                        let alert = Alert(
                            ruleId: match.ruleId, ruleTitle: match.ruleName, severity: effective,
                            eventId: enriched.id.uuidString, processPath: enriched.process.executable,
                            processName: enriched.process.name, description: match.description,
                            mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                            mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                            suppressed: false
                        )
                        try? await state.alertStore.insert(alert: alert)
                        if effective >= .high {
                            await state.notifier.notify(alert: alert)
                        }
                        print("[FS] \(match.ruleName) | \(enriched.file?.path ?? "?")")
                    }
                }
            }
        }

        // Event tap monitoring task (keylogger detection)
        await supervisor.start("event-tap") {
            for await tapInfo in state.eventTapMonitor.events {
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
                try? await state.alertStore.insert(alert: alert)
                await state.notifier.notify(alert: alert)
                await state.behaviorScoring.addIndicator(
                    named: "event_tap_keylogger",
                    detail: "PID \(tapInfo.tappingPID) taps keyboard",
                    forProcess: tapInfo.tappingPID,
                    path: tapInfo.processPath
                )
                print("[CRIT] Event tap keylogger: \(tapInfo.processName) (PID \(tapInfo.tappingPID))")
            }
        }

        // System policy monitoring task
        await supervisor.start("system-policy") {
            for await policyEvent in state.systemPolicyMonitor.events {
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
                try? await state.alertStore.insert(alert: alert)
                await state.notifier.notify(alert: alert)

                // Behavioral scoring for relevant events
                let indicatorName: String? = switch policyEvent.type {
                case .sipDisabled: "sip_disabled"
                case .authPluginFound: "non_apple_auth_plugin"
                case .xprotectOutdated: "xprotect_outdated"
                case .quarantineStripped: "removes_quarantine"
                case .gatekeeperOverride: "gatekeeper_override"
                case .mdmProfileInstalled: "mdm_profile_installed"
                case .mdmProfileRemoved: "mdm_profile_removed"
                default: nil
                }
                if let name = indicatorName {
                    // Use PID 0 for system-level events
                    await state.behaviorScoring.addIndicator(
                        named: name,
                        detail: policyEvent.description,
                        forProcess: 0,
                        path: policyEvent.path ?? "system"
                    )
                }

                let severityIcon = policyEvent.severity == .critical ? "[CRIT]" : "[HIGH]"
                print("\(severityIcon) System policy: \(policyEvent.type.rawValue) -- \(policyEvent.description.prefix(100))")
            }
        }

        // MCP server monitoring task
        await supervisor.start("mcp") {
            for await mcpEvent in state.mcpMonitor.events {
                let severity: Severity = mcpEvent.eventType == .suspicious ? .critical : .high
                let alert = Alert(
                    ruleId: "maccrab.ai-guard.mcp-\(mcpEvent.eventType.rawValue)",
                    ruleTitle: "MCP Server \(mcpEvent.eventType.rawValue.replacingOccurrences(of: "_", with: " ").capitalized): \(mcpEvent.serverName)",
                    severity: severity,
                    eventId: UUID().uuidString,
                    processPath: mcpEvent.command,
                    processName: mcpEvent.serverName,
                    description: "\(mcpEvent.reason). Config: \(mcpEvent.configFile). Command: \(mcpEvent.command) \(mcpEvent.args.joined(separator: " "))",
                    mitreTactics: "attack.initial_access",
                    mitreTechniques: "attack.t1195.002",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)
                await state.notifier.notify(alert: alert)
                if mcpEvent.eventType == .suspicious {
                    await state.behaviorScoring.addIndicator(
                        named: "mcp_server_suspicious",
                        detail: "\(mcpEvent.serverName): \(mcpEvent.reason)",
                        forProcess: 0, path: mcpEvent.command
                    )
                }
                print("[MCP] \(mcpEvent.eventType.rawValue): \(mcpEvent.serverName) -- \(mcpEvent.reason)")
            }
        }

        // USB device monitoring task
        await supervisor.start("usb") {
            for await usbEvent in state.usbMonitor.events {
                // Hubs and non-storage HID are benign — the vast majority
                // of a user's USB chatter is keyboards, mice, hubs, audio
                // devices. Only mass-storage events are worth drawing
                // attention to; everything else is Informational.
                let severity: Severity
                if usbEvent.isMassStorage {
                    severity = .high
                } else {
                    severity = .informational
                }
                let alert = Alert(
                    ruleId: "maccrab.usb.\(usbEvent.isConnected ? "connected" : "disconnected")",
                    ruleTitle: "USB Device \(usbEvent.isConnected ? "Connected" : "Disconnected"): \(usbEvent.productName)",
                    severity: severity,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "kernel",
                    description: "\(usbEvent.vendorName) \(usbEvent.productName) (VID:0x\(String(usbEvent.vendorId, radix: 16)) PID:0x\(String(usbEvent.productId, radix: 16)))\(usbEvent.isMassStorage ? " [MASS STORAGE]" : "")\(usbEvent.serialNumber.isEmpty ? "" : " SN:\(usbEvent.serialNumber)")",
                    mitreTactics: "attack.initial_access",
                    mitreTechniques: "attack.t1200",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)
                if usbEvent.isMassStorage {
                    await state.notifier.notify(alert: alert)
                }
                print("[USB] \(usbEvent.isConnected ? "+" : "-") \(usbEvent.vendorName) \(usbEvent.productName)\(usbEvent.isMassStorage ? " [MASS STORAGE]" : "")")
            }
        }

        // Clipboard monitoring task
        _ = state.clipboardInjectionDetector  // Available for dashboard/CLI on-demand scanning
        await supervisor.start("clipboard") {
            for await clipEvent in state.clipboardMonitor.events {
                if clipEvent.containsSensitiveData {
                    let alert = Alert(
                        ruleId: "maccrab.clipboard.sensitive-data",
                        ruleTitle: "Sensitive Data on Clipboard",
                        severity: .medium,
                        eventId: UUID().uuidString,
                        processPath: nil, processName: "pasteboard",
                        description: "Sensitive data detected on clipboard (API key, token, SSH key, or credential). Types: \(clipEvent.contentTypes.prefix(3).joined(separator: ", "))",
                        mitreTactics: "attack.collection", mitreTechniques: "attack.t1115",
                        suppressed: false
                    )
                    try? await state.alertStore.insert(alert: alert)
                    print("[CLIP] Sensitive data detected on clipboard")
                }
            }
        }

        // Browser extension monitoring task
        await supervisor.start("browser-extensions") {
            for await extEvent in state.browserExtMonitor.events {
                // Browser extension monitor fires an initial inventory scan
                // on startup — those aren't installs we just watched happen.
                // During the warm-up window, only surface genuinely suspicious
                // extensions.
                if state.isWarmingUp && !extEvent.isSuspicious { continue }
                let severity: Severity = extEvent.isSuspicious ? .high : .medium
                let alert = Alert(
                    ruleId: "maccrab.browser.\(extEvent.isNew ? "extension-installed" : "extension-modified")",
                    ruleTitle: "\(extEvent.browser.capitalized) Extension \(extEvent.isNew ? "Installed" : "Modified"): \(extEvent.extensionName)",
                    severity: severity,
                    eventId: UUID().uuidString,
                    processPath: extEvent.extensionPath, processName: extEvent.browser,
                    description: "\(extEvent.extensionName) (ID: \(extEvent.extensionId))\(extEvent.isSuspicious ? " -- SUSPICIOUS: \(extEvent.suspicionReason ?? "dangerous permissions")" : "")\nPermissions: \(extEvent.permissions.prefix(5).joined(separator: ", "))",
                    mitreTactics: "attack.persistence", mitreTechniques: "attack.t1176",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)
                if extEvent.isSuspicious { await state.notifier.notify(alert: alert) }
                print("[EXT] \(extEvent.browser): \(extEvent.extensionName)\(extEvent.isSuspicious ? " [SUSPICIOUS]" : "")")
            }
        }

        // Ultrasonic attack monitoring task
        await supervisor.start("ultrasonic") {
            for await usEvent in state.ultrasonicMonitor.events {
                let alert = Alert(
                    ruleId: "maccrab.ultrasonic.\(usEvent.attackType.rawValue)",
                    ruleTitle: "Ultrasonic Attack Detected: \(usEvent.attackType.rawValue.replacingOccurrences(of: "_", with: " ").capitalized)",
                    severity: .critical,
                    eventId: UUID().uuidString,
                    processPath: nil, processName: "microphone",
                    description: "Ultrasonic voice injection detected at \(String(format: "%.0f", usEvent.peakFrequencyHz)) Hz. Energy ratio: \(String(format: "%.1f", usEvent.energyRatio)) dB. Confidence: \(String(format: "%.0f", usEvent.confidence * 100))%.",
                    mitreTactics: "attack.initial_access", mitreTechniques: "attack.t1200",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)
                await state.notifier.notify(alert: alert)
                print("[ULTRASONIC] \(usEvent.attackType.rawValue) at \(String(format: "%.0f", usEvent.peakFrequencyHz)) Hz!")
            }
        }

        // Rootkit detection task
        await supervisor.start("rootkit") {
            for await hidden in state.rootkitDetector.events {
                let alert = Alert(
                    ruleId: "maccrab.forensic.hidden-process",
                    ruleTitle: "Hidden Process Detected (Possible Rootkit)",
                    severity: .critical,
                    eventId: UUID().uuidString,
                    processPath: nil, processName: "PID \(hidden.pid)",
                    description: "Process PID \(hidden.pid) visible to \(hidden.source) but not the other enumeration API. This discrepancy indicates a userland rootkit hiding the process.",
                    mitreTactics: "attack.defense_evasion", mitreTechniques: "attack.t1014",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)
                await state.notifier.notify(alert: alert)
                print("[ROOTKIT] Hidden process: PID \(hidden.pid) (\(hidden.source))")
            }
        }

        // TEMPEST / Van Eck phreaking monitoring task
        await supervisor.start("tempest") {
            for await tempestEvent in state.tempestMonitor.events {
                let alert = Alert(
                    ruleId: "maccrab.tempest.\(tempestEvent.type.rawValue)",
                    ruleTitle: tempestEvent.title,
                    severity: tempestEvent.severity,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "TEMPESTMonitor",
                    description: "\(tempestEvent.description)\n\n\(tempestEvent.detail)",
                    mitreTactics: "attack.collection",
                    mitreTechniques: "attack.t1040",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)
                await state.notifier.notify(alert: alert)
                print("[TEMPEST] \(tempestEvent.type.rawValue): \(tempestEvent.title)")

                // LLM analysis for TEMPEST events (non-blocking)
                if let llm = state.llmService {
                    let title = tempestEvent.title
                    let desc = tempestEvent.description
                    let detail = tempestEvent.detail
                    let alertId = alert.id
                    Task {
                        if let analysis = await llm.query(
                            systemPrompt: """
                                You are a TEMPEST/EMSEC (electromagnetic security) specialist. \
                                A potential Van Eck phreaking indicator has been detected. Explain \
                                the threat, what an attacker could see or capture, and specific \
                                countermeasures. Keep under 200 words. Include both the risk \
                                assessment and practical steps the user can take RIGHT NOW.
                                """,
                            userPrompt: "Detection: \(title)\nDetail: \(desc)\nTechnical: \(detail)",
                            maxTokens: 512, temperature: 0.2
                        ) {
                            let analysisAlert = Alert(
                                ruleId: "maccrab.llm.tempest-analysis",
                                ruleTitle: "AI TEMPEST Analysis: \(title)",
                                severity: .informational,
                                eventId: alertId,
                                processPath: nil, processName: "TEMPESTMonitor",
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { try await state.alertStore.insert(alert: analysisAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            print("[LLM] TEMPEST analysis generated for: \(title)")
                        }
                    }
                }
            }
        }

        // EDR/RMM tool monitoring task
        await supervisor.start("edr-rmm") {
            for await discovery in state.edrMonitor.events {
                let capList = discovery.capabilities.prefix(4).joined(separator: ", ")
                let processInfo = discovery.processName.map { " (process: \($0), PID: \(discovery.pid ?? 0))" } ?? ""
                let installedInfo = discovery.installedPath.map { " (installed: \($0))" } ?? ""

                let severity: Severity = discovery.category == .insiderThreat ? .high : .medium
                let alert = Alert(
                    ruleId: "maccrab.edr.\(discovery.category.rawValue.lowercased().replacingOccurrences(of: " ", with: "-").replacingOccurrences(of: "/", with: "-"))",
                    ruleTitle: "\(discovery.category.rawValue) Tool Active: \(discovery.toolName)",
                    severity: severity,
                    eventId: UUID().uuidString,
                    processPath: discovery.processPath ?? discovery.installedPath,
                    processName: discovery.processName ?? discovery.toolName,
                    description: "\(discovery.toolName) by \(discovery.vendor) is \(discovery.processName != nil ? "running" : "installed") on this machine.\(processInfo)\(installedInfo)\nCapabilities: \(capList)",
                    mitreTactics: "attack.discovery",
                    mitreTechniques: "attack.t1518.001",
                    suppressed: false
                )
                try? await state.alertStore.insert(alert: alert)

                // Only push notifications for insider threat tools (high privacy impact)
                if discovery.category == .insiderThreat {
                    await state.notifier.notify(alert: alert)
                }

                print("[EDR] \(discovery.category.rawValue): \(discovery.toolName) by \(discovery.vendor)\(processInfo)")

                // LLM contextual analysis for EDR/RMM discoveries (non-blocking)
                if let llm = state.llmService {
                    let toolName = discovery.toolName
                    let vendor = discovery.vendor
                    let category = discovery.category.rawValue
                    let capabilities = discovery.capabilities
                    let procName = discovery.processName
                    let procPath = discovery.processPath
                    let instPath = discovery.installedPath
                    let alertId = alert.id

                    Task {
                        if let analysis = await llm.query(
                            systemPrompt: LLMPrompts.edrContextSystem,
                            userPrompt: LLMPrompts.edrContextUser(
                                toolName: toolName, vendor: vendor, category: category,
                                capabilities: capabilities, processName: procName,
                                processPath: procPath, installedPath: instPath
                            ),
                            maxTokens: 512, temperature: 0.2
                        ) {
                            let contextAlert = Alert(
                                ruleId: "maccrab.llm.edr-context",
                                ruleTitle: "AI Context: \(toolName) (\(category))",
                                severity: .informational,
                                eventId: alertId,
                                processPath: procPath ?? instPath,
                                processName: procName ?? toolName,
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { try await state.alertStore.insert(alert: contextAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            print("[LLM] EDR context generated for: \(toolName)")
                        }
                    }
                }
            }
        }

        // DNS event processing task
        await supervisor.start("dns") {
            for await dnsQuery in state.dnsCollector.events {
                // Record resolution for IP-to-domain correlation
                if dnsQuery.isResponse && !dnsQuery.resolvedIPs.isEmpty {
                    await state.dnsCollector.recordResolution(domain: dnsQuery.queryName, ips: dnsQuery.resolvedIPs)
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
                    try? await state.alertStore.insert(alert: alert)
                    await state.notifier.notify(alert: alert)
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
                    try? await state.alertStore.insert(alert: alert)
                    await state.notifier.notify(alert: alert)
                }

                // Check against threat intel
                if await state.threatIntel.isDomainMalicious(dnsQuery.queryName) {
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
                    try? await state.alertStore.insert(alert: alert)
                    await state.notifier.notify(alert: alert)
                }
            }
        }
    }
}
