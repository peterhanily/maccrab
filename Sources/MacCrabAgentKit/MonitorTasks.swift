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
                    await state.collectorRegistry.recordTick(name: "FSEventsCollector")
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
                        // AlertSink applies dedup + insert in one call.
                        let inserted: Bool
                        do {
                            inserted = try await state.alertSink.submit(alert: alert, event: enriched)
                        } catch {
                            await StorageErrorTracker.shared.recordAlertError(error)
                            continue
                        }
                        guard inserted else { continue }
                        if effective >= .high {
                            await state.notifier.notify(alert: alert)
                        }
                        print("[FS] \(match.ruleName) | \(enriched.file?.path ?? "?")")
                    }
                }
                // v1.11.1 (audit BLOCKER 2 secondary): cooperative
                // yield drains the autorelease pool per iteration —
                // same EventLoop fix shape, lower volume.
                await Task.yield()
            }
        }

        // Event tap monitoring task (keylogger detection)
        await supervisor.start("event-tap") {
            for await tapInfo in state.eventTapMonitor.events {
                await state.collectorRegistry.recordTick(name: "EventTapMonitor")
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                await state.behaviorScoring.addIndicator(
                    named: "event_tap_keylogger",
                    detail: "PID \(tapInfo.tappingPID) taps keyboard",
                    forProcess: tapInfo.tappingPID,
                    path: tapInfo.processPath
                )
                print("[CRIT] Event tap keylogger: \(tapInfo.processName) (PID \(tapInfo.tappingPID))")
                await Task.yield()
            }
        }

        // System policy monitoring task
        await supervisor.start("system-policy") {
            for await policyEvent in state.systemPolicyMonitor.events {
                await state.collectorRegistry.recordTick(name: "SystemPolicyMonitor")
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }

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
                await Task.yield()
            }
        }

        // MCP server monitoring task
        await supervisor.start("mcp") {
            for await mcpEvent in state.mcpMonitor.events {
                await state.collectorRegistry.recordTick(name: "MCPMonitor")
                let severity: Severity = mcpEvent.eventType == .suspicious ? .critical : .high
                let alert = Alert(
                    // v1.18: dotted suffix (was `mcp-…`) so the
                    // `maccrab.ai-guard.mcp` catalog/settings base governs the
                    // whole family via AlertSink's longest-prefix match.
                    ruleId: "maccrab.ai-guard.mcp.\(mcpEvent.eventType.rawValue)",
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                if mcpEvent.eventType == .suspicious {
                    await state.behaviorScoring.addIndicator(
                        named: "mcp_server_suspicious",
                        detail: "\(mcpEvent.serverName): \(mcpEvent.reason)",
                        forProcess: 0, path: mcpEvent.command
                    )
                }
                print("[MCP] \(mcpEvent.eventType.rawValue): \(mcpEvent.serverName) -- \(mcpEvent.reason)")
                await Task.yield()
            }
        }

        // v1.7.0: MCP behavioral baseline deviation listener.
        // MCPBaselineService.observe() is called from EventLoop on each
        // attributed event; the service learns per-(tool, server)
        // fingerprints (file basenames, domains, child process names)
        // for `defaultLearningObservations` (20) events, then enforces.
        // Deviations stream here and become alerts via AlertSink so
        // they participate in the same dedup + notification pipeline as
        // any other rule.
        await supervisor.start("mcp-baseline") {
            for await dev in state.mcpBaseline.deviations {
                let detailKind: String
                switch dev.kind {
                case .newFileBasename:  detailKind = "file basename"
                case .newDomain:        detailKind = "domain"
                case .newChildBasename: detailKind = "child process"
                }
                let alert = Alert(
                    ruleId: "maccrab.mcp.baseline-anomaly.\(dev.tool).\(dev.serverName).\(dev.kind.rawValue)",
                    ruleTitle: "MCP Baseline Drift: \(dev.serverName) (\(dev.tool)) — new \(detailKind)",
                    severity: .medium,
                    eventId: UUID().uuidString,
                    processPath: dev.serverKey,
                    processName: dev.serverName,
                    description: "MCP server '\(dev.serverName)' under \(dev.tool) observed a previously-unseen \(detailKind): \(dev.observedValue). Baseline learned over \(MCPBaselineService.defaultLearningObservations) prior observations.",
                    mitreTactics: "attack.initial_access,attack.command_and_control",
                    mitreTechniques: "attack.t1195.002,attack.t1059",
                    suppressed: false
                )
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                await Task.yield()
            }
        }

        // USB device monitoring task. v1.4.5: per-device rate limiting.
        // Before, every hub replug produced an informational alert. A
        // user with a dock, YubiKey, and a USB-C hub hit 10+ USB alerts
        // every time they reconnected. Track (vid, pid) tuples in-
        // process and skip non-mass-storage events we've already
        // surfaced in the last 24 hours. Mass-storage events always
        // fire — those are exfil-class and the user needs to see every
        // one. Rate limit cache is in-memory only; resets on restart.
        let usbRateLimiter = USBRateLimiter()
        await supervisor.start("usb") {
            for await usbEvent in state.usbMonitor.events {
                await state.collectorRegistry.recordTick(name: "USBMonitor")
                let severity: Severity
                if usbEvent.isMassStorage {
                    severity = .high
                } else {
                    // Apple VID 0x5ac = built-in keyboard, trackpad, camera,
                    // touchbar, T2 chip, FaceTime HD. These churn on every
                    // sleep/wake and are never exfil signal — suppress
                    // entirely rather than surfacing the first event per day.
                    if usbEvent.vendorId == 0x5ac { continue }
                    // Yubico VID 0x1050 = YubiKey security tokens. Frequent
                    // connect/disconnect is expected with 2FA workflows and
                    // YubiKeys cannot exfil data or execute code — skip.
                    if usbEvent.vendorId == 0x1050 { continue }
                    // Nitrokey VID 0x20a0 and SoloKeys VID 0x0483 — same rationale.
                    if usbEvent.vendorId == 0x20a0 || usbEvent.vendorId == 0x0483 { continue }
                    // USB device class 0x09 = hub. Third-party USB-C docks,
                    // 4-port splitters, monitor-integrated hubs (Realtek,
                    // VIA, Intel) churn connect/disconnect on every replug
                    // or USB-C mode renegotiation. A malicious USB hub is
                    // not a plausible attack vector on macOS (can't exfil
                    // data, can't execute code, can't grant permissions).
                    // Skip entirely for informational.
                    if usbEvent.deviceClass == 9 { continue }
                    severity = .informational
                    // Only rate-limit non-mass-storage. Mass-storage
                    // connect/disconnect always surfaces — every event
                    // matters.
                    let key = "\(usbEvent.vendorId):\(usbEvent.productId):\(usbEvent.isConnected ? "c" : "d")"
                    if await usbRateLimiter.shouldSuppress(key: key) {
                        continue
                    }
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
                do { _ = try await state.alertSink.submit(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                if usbEvent.isMassStorage {
                    await state.notifier.notify(alert: alert)
                }
                print("[USB] \(usbEvent.isConnected ? "+" : "-") \(usbEvent.vendorName) \(usbEvent.productName)\(usbEvent.isMassStorage ? " [MASS STORAGE]" : "")")
                await Task.yield()
            }
        }

        // Clipboard monitoring task
        _ = state.clipboardInjectionDetector  // Available for dashboard/CLI on-demand scanning
        await supervisor.start("clipboard") {
            for await clipEvent in state.clipboardMonitor.events {
                await state.collectorRegistry.recordTick(name: "ClipboardMonitor")
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
                    do { _ = try await state.alertSink.submit(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    print("[CLIP] Sensitive data detected on clipboard")
                }
                await Task.yield()
            }
        }

        // Browser extension monitoring task
        await supervisor.start("browser-extensions") {
            for await extEvent in state.browserExtMonitor.events {
                await state.collectorRegistry.recordTick(name: "BrowserExtensionMonitor")
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        if extEvent.isSuspicious { await state.notifier.notify(alert: alert) }
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                print("[EXT] \(extEvent.browser): \(extEvent.extensionName)\(extEvent.isSuspicious ? " [SUSPICIOUS]" : "")")
                await Task.yield()
            }
        }

        // Ultrasonic attack monitoring task
        await supervisor.start("ultrasonic") {
            for await usEvent in state.ultrasonicMonitor.events {
                await state.collectorRegistry.recordTick(name: "UltrasonicMonitor")
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                print("[ULTRASONIC] \(usEvent.attackType.rawValue) at \(String(format: "%.0f", usEvent.peakFrequencyHz)) Hz!")
                await Task.yield()
            }
        }

        // Rootkit detection task
        await supervisor.start("rootkit") {
            for await hidden in state.rootkitDetector.events {
                await state.collectorRegistry.recordTick(name: "RootkitDetector")
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                print("[ROOTKIT] Hidden process: PID \(hidden.pid) (\(hidden.source))")
                await Task.yield()
            }
        }

        // TEMPEST / Van Eck phreaking monitoring task
        await supervisor.start("tempest") {
            for await tempestEvent in state.tempestMonitor.events {
                await state.collectorRegistry.recordTick(name: "TEMPESTMonitor")
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
                do {
                    if try await state.alertSink.submit(alert: alert) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                            do { _ = try await state.alertSink.submit(alert: analysisAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            print("[LLM] TEMPEST analysis generated for: \(title)")
                        }
                    }
                }
                await Task.yield()
            }
        }

        // EDR/RMM tool monitoring task
        await supervisor.start("edr-rmm") {
            for await discovery in state.edrMonitor.events {
                await state.collectorRegistry.recordTick(name: "EDRMonitor")
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
                do { _ = try await state.alertSink.submit(alert: alert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }

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
                            do { _ = try await state.alertSink.submit(alert: contextAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            print("[LLM] EDR context generated for: \(toolName)")
                        }
                    }
                }
                await Task.yield()
            }
        }

        // DNS event processing task
        await supervisor.start("dns") {
            for await dnsQuery in state.dnsCollector.events {
                await state.collectorRegistry.recordTick(name: "DNSCollector")
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
                    do {
                        if try await state.alertSink.submit(alert: alert) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do {
                        if try await state.alertSink.submit(alert: alert) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // Check against threat intel
                if await state.threatIntel.isDomainMalicious(dnsQuery.queryName) {
                    // v1.17: carry the matched IOC's source/family/first-seen.
                    let record = await state.threatIntel.recordForDomain(dnsQuery.queryName)
                    let (desc, hint) = EventLoop.iocMatchStrings(
                        record: record,
                        value: dnsQuery.queryName,
                        type: "domain",
                        hit: "DNS query for"
                    )
                    let alert = Alert(
                        ruleId: "maccrab.dns.threat-intel-match",
                        ruleTitle: "DNS Query to Known Malicious Domain",
                        severity: .critical,
                        eventId: UUID().uuidString,
                        processPath: nil,
                        processName: "mDNSResponder",
                        description: desc,
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1071.004",
                        suppressed: false,
                        remediationHint: hint
                    )
                    do {
                        if try await state.alertSink.submit(alert: alert) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }
                await Task.yield()
            }
        }
    }
}
