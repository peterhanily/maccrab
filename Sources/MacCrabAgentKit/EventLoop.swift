import Foundation
import MacCrabCore
import os.log

/// The main event processing loop. Processes each event through
/// enrichment, AI guard, detection layers, and alert output.
enum EventLoop {
    static func run(state: DaemonState, eventStream: AsyncStream<Event>, eventCount: inout UInt64, alertCount: inout UInt64) async {
        for await event in eventStream {
            eventCount += 1

            // v1.7.9: per-collector counter increment.
            //
            // Pre-fix, only secondary collectors with their own MonitorTask
            // for-await loop (TCC, USB, Clipboard, BrowserExt, etc.) called
            // recordTick — primary collectors (ESCollector, NetworkCollector,
            // DNSCollector, UnifiedLogCollector, EsloggerCollector) feed the
            // merged stream consumed here, but the merged stream lacks source
            // attribution. Result: heartbeat showed event_count=0 for every
            // primary collector while the global events_processed climbed
            // into the millions — operators couldn't trust the per-collector
            // health flag. Field reproduction during v1.7.6 memory diagnosis.
            //
            // Pragmatic attribution by event category. Imperfect (a file event
            // could come from ESCollector OR FSEventsCollector fallback) but
            // gives operators non-zero, semantically meaningful counts. The
            // exact source mapping isn't critical — what matters is "we know
            // events are flowing through these subsystems".
            let attributedCollector: String
            switch event.eventCategory {
            case .process, .file:
                // ES is primary; FSEvents only fires on non-root dev builds.
                // The dashboard's collector_health row labelled ESCollector
                // is the right place to surface volume.
                attributedCollector = "ESCollector"
            case .network:
                attributedCollector = "NetworkCollector"
            case .authentication, .registry:
                attributedCollector = "UnifiedLogCollector"
            case .tcc:
                // TCCMonitor has its own MonitorTasks loop that already
                // records ticks — skip to avoid double-counting.
                attributedCollector = ""
            }
            if !attributedCollector.isEmpty {
                await state.collectorRegistry.recordTick(name: attributedCollector)
            }

            // v1.10.0 perf: notify MCPAttributor of process exits so its
            // pid→server cache evicts proactively rather than waiting for
            // its 5K-entry LRU cap to overflow (audit P-W3.8). Cheap —
            // no-op for events that aren't NOTIFY_EXIT.
            if event.eventAction == "exit" {
                await state.mcpAttributor.processExited(pid: event.process.pid)
            }

            // Enrich the event (lineage, code signing)
            var enrichedEvent = await state.enricher.enrich(event)

            // YARA enrichment for file events (Phase 3)
            if enrichedEvent.eventCategory == .file {
                enrichedEvent = await state.yaraEnricher.enrich(enrichedEvent)
            }

            // === AI Tool Detection ===
            //
            // v1.6.9 fast path: if the subject isn't itself an AI
            // tool AND no AI tool is currently registered,
            // short-circuit out of the whole AI-child block. On
            // idle machines this skips ~4 actor hops per event.
            // `hasActiveSessionsHint` is a nonisolated lock-protected
            // mirror of `sessions.isEmpty` — a stale read is
            // harmless (one event's lineage missed; next event
            // heals). Using `isAITool` twice below is fine;
            // `aiRegistry.isAITool` is nonisolated and O(1).
            let aiProc = enrichedEvent.process
            if let aiType = state.aiRegistry.isAITool(executablePath: aiProc.executable) {
                await state.aiTracker.registerAIProcess(pid: aiProc.pid, type: aiType, projectDir: aiProc.workingDirectory)
                await state.projectBoundary.registerBoundary(aiPid: aiProc.pid, projectDir: aiProc.workingDirectory)
                // v1.6.7: start a lineage session so subsequent events
                // (file, network, alert) under this AI tool populate a
                // chronological timeline.
                await state.agentLineageService.startSession(
                    aiPid: aiProc.pid,
                    toolType: aiType,
                    projectDir: aiProc.workingDirectory,
                    startTime: enrichedEvent.timestamp
                )
                enrichedEvent.enrichments["ai_tool"] = aiType.rawValue
                enrichedEvent.enrichments["ai_tool_name"] = aiType.displayName
            } else if state.aiTracker.hasActiveSessionsHint {
                // Only pay the isAIChild actor hop when there are
                // actually AI sessions running that this event could
                // belong to.
                let (isChild, aiType, projectDir) = await state.aiTracker.isAIChild(pid: aiProc.pid, ancestors: aiProc.ancestors)
                if isChild {
                    enrichedEvent.enrichments["ai_tool"] = aiType?.rawValue ?? "unknown"
                    enrichedEvent.enrichments["ai_tool_child"] = "true"
                    if let dir = projectDir { enrichedEvent.enrichments["ai_project_dir"] = dir }

                    // v1.9 Agent Traces (PR-2): correlate kernel event back
                    // to its originating agent interaction. Two-pass:
                    // direct TRACEPARENT (high confidence) then lineage
                    // fallback (medium confidence). No-op when the
                    // feature flag is off (traceRegistry == nil).
                    //
                    // Runs alongside MCP attribution rather than instead
                    // of — both attribution lenses are independent and a
                    // single event can carry both sets of enrichments.
                    if let traceRegistry = state.traceRegistry {
                        // Build a ProcessIdentity from the enriched ProcessInfo
                        // shape we already have. PR-2 uses a best-effort
                        // identity here — pidversion/audit_token live in the
                        // ESCollector bind path, so the lookup matches by pid
                        // and pathHash. Confirmed by the PID-recycle pin test:
                        // a recycled pid with a different pathHash will be
                        // treated as a miss.
                        let lookupIdentity = ProcessIdentity(
                            auditIdentity: AuditIdentity(
                                auid: 0, euid: aiProc.userId, egid: 0,
                                ruid: aiProc.userId, rgid: 0,
                                pid: aiProc.pid, pidversion: 0, asid: 0
                            ),
                            pathHash: ProcessIdentity.fnv1a64(aiProc.executable),
                            pid: aiProc.pid,
                            startTime: UInt64(aiProc.startTime.timeIntervalSince1970)
                        )
                        if let correlation = await TraceCorrelator.correlate(
                            identity: lookupIdentity,
                            ancestors: aiProc.ancestors,
                            registry: traceRegistry,
                            ancestorIdentityResolver: { ancestor in
                                ProcessIdentity(
                                    auditIdentity: AuditIdentity(
                                        auid: 0, euid: 0, egid: 0,
                                        ruid: 0, rgid: 0,
                                        pid: ancestor.pid, pidversion: 0, asid: 0
                                    ),
                                    pathHash: ProcessIdentity.fnv1a64(ancestor.executable),
                                    pid: ancestor.pid,
                                    startTime: 0
                                )
                            },
                            aiToolForPath: { path in state.aiRegistry.isAITool(executablePath: path) }
                        ) {
                            TraceCorrelator.apply(correlation, to: &enrichedEvent)
                        }
                    }

                    // v1.7.0: MCP attribution. Walk ancestry to identify
                    // whether one of them is a configured MCP server for
                    // this AI tool; tag the event and feed the baseline.
                    if let aiType {
                        if let attr = await state.mcpAttributor.attribute(
                            pid: aiProc.pid,
                            ancestors: aiProc.ancestors,
                            aiTool: aiType
                        ) {
                            enrichedEvent.enrichments["mcp_server_name"] = attr.serverName
                            enrichedEvent.enrichments["mcp_server_category"] = attr.serverCategory
                            enrichedEvent.enrichments["mcp_attribution_confidence"] = attr.confidence.rawValue
                            // Only feed high/medium-confidence attributions
                            // into the baseline; low-confidence noise
                            // would dilute the fingerprint.
                            if attr.confidence != .low {
                                let observation = MCPBaselineObservation(
                                    tool: attr.tool,
                                    serverName: attr.serverName,
                                    filePath: enrichedEvent.file?.path,
                                    domain: enrichedEvent.network?.destinationHostname,
                                    childProcessBasename: aiProc.name,
                                    timestamp: enrichedEvent.timestamp
                                )
                                await state.mcpBaseline.observe(observation)
                            }
                        }
                    }

                    // v1.6.7: record lineage events for this AI child.
                    // The session's root PID is the nearest AI-tool
                    // ancestor; walk the provided ancestry list to
                    // find it rather than re-querying the tracker.
                    if let aiAncestor = aiProc.ancestors.first(where: {
                        state.aiRegistry.isAITool(executablePath: $0.executable) != nil
                    }) {
                        let rootPid = aiAncestor.pid
                        // Always record the spawn for any AI-child exec.
                        await state.agentLineageService.record(
                            aiPid: rootPid,
                            kind: .processSpawn(
                                basename: aiProc.name,
                                pid: aiProc.pid
                            ),
                            timestamp: enrichedEvent.timestamp
                        )
                        // For file events, record the read/write. Our
                        // FileAction enum has no "read"; reads come
                        // through as `.close` in most ES subtypes.
                        //
                        // v1.12.0 RC3 fix (Sec-H2): filter credential-
                        // shaped paths out of the lineage record. The
                        // snapshot persists to disk (under root) and is
                        // readable by the dashboard (admin user). A
                        // path like `~/.aws/credentials` recorded here
                        // would surface to any tool that reads the
                        // snapshot or any LLM call that ingests it.
                        // Filtering at record time keeps the deception/
                        // intent-bridge signal (which only needs the
                        // shape of the agent's activity, not specific
                        // credential paths) while keeping the file
                        // path off disk.
                        if let file = enrichedEvent.file,
                           !isCredentialShapedPath(file.path) {
                            let kind: AgentEvent.Kind
                            switch file.action {
                            case .write, .create, .rename, .link:
                                kind = .fileWrite(path: file.path)
                            case .delete:
                                kind = .fileWrite(path: file.path)
                            case .close:
                                kind = .fileRead(path: file.path)
                            }
                            await state.agentLineageService.record(
                                aiPid: rootPid, kind: kind,
                                timestamp: enrichedEvent.timestamp
                            )
                        }
                        // For network events, record the destination.
                        // `destinationIp` is non-optional but can be
                        // empty when the collector only resolved a
                        // hostname; fall through on empty ip so we
                        // don't create synthetic "0.0.0.0" rows.
                        if let net = enrichedEvent.network, !net.destinationIp.isEmpty {
                            let host = net.destinationHostname ?? net.destinationIp
                            await state.agentLineageService.record(
                                aiPid: rootPid,
                                kind: .network(host: host, port: net.destinationPort),
                                timestamp: enrichedEvent.timestamp
                            )
                        }
                    }

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
                            do {
                                if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                                    await state.notifier.notify(alert: alert)
                                }
                            } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            await state.behaviorScoring.addIndicator(
                                named: "ai_tool_credential_access",
                                detail: "\(credType.rawValue): \(filePath)",
                                forProcess: aiProc.pid, path: aiProc.executable
                            )
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
                                do {
                                    if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                                        await state.notifier.notify(alert: alert)
                                    }
                                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                await state.behaviorScoring.addIndicator(
                                    named: "ai_tool_boundary_violation",
                                    detail: "Wrote to \(filePath) outside \(session.projectDir)",
                                    forProcess: aiProc.pid, path: aiProc.executable
                                )
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
                                do {
                                    if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                                        await state.notifier.notify(alert: alert)
                                    }
                                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                await state.behaviorScoring.addIndicator(
                                    named: indicator, detail: detail,
                                    forProcess: aiProc.pid, path: aiProc.executable
                                )
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
                        do {
                            if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                                await state.notifier.notify(alert: alert)
                            }
                        } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        await state.behaviorScoring.addIndicator(
                            named: "fresh_package_install",
                            detail: "\(result.name) (\(result.registry.rawValue)) age: \(result.ageInDays.map { String(format: "%.1f", $0) } ?? "unknown") days",
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
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
                                do {
                                    if try await state.alertSink.submit(alert: blockAlert, event: enrichedEvent) {
                                        await state.notifier.notify(alert: blockAlert)
                                    }
                                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                                    do {
                                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                                            await state.notifier.notify(alert: alert)
                                        }
                                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    // Dedup on rule + destination (not the triggering process)
                    // so three different processes converging on the same
                    // github.com IP don't each produce a fresh alert when the
                    // correlator window re-evaluates.
                    let ruleId = "maccrab.correlator.network-convergence"
                    let dedupKey = net.destinationHostname ?? net.destinationIp
                    // v1.6.21 BLOCKER fix: atomic check+record closes a TOCTOU
                    // window where two concurrent network-convergence
                    // evaluations could both observe shouldSuppress == false
                    // and both emit duplicates.
                    if await state.deduplicator.shouldSuppressAndRecord(ruleId: ruleId, processPath: dedupKey) {
                        // Suppressed at the per-destination layer.
                    } else {
                        let alert = Alert(
                            ruleId: ruleId,
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
                        do {
                            if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                                await state.notifier.notify(alert: alert)
                            }
                        } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    }
                }
            }

            // === Process Tree ML: record transition and check for anomalies ===
            if enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                let parentName = enrichedEvent.process.ancestors.first?.name ?? "unknown"
                let childName = enrichedEvent.process.name
                let grandparentName = enrichedEvent.process.ancestors.count >= 2
                    ? enrichedEvent.process.ancestors[1].name : nil
                if let logProb = await state.processTreeAnalyzer.recordTransition(
                    parentName: parentName, childName: childName,
                    grandparentName: grandparentName
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

                // === Topology Anomaly Detection ===
                // Shape-based invariants complementary to the probabilistic
                // Markov tree above. Rare, near-categorical signals — each
                // finding translates to a BehaviorScoring indicator with a
                // high weight, so a single hit is enough to fire an alert.
                let parentPath = enrichedEvent.process.ancestors.first?.executable
                let parentPID = enrichedEvent.process.ancestors.first?.pid ?? 0
                let topologyFindings = await state.topologyAnomalyDetector.evaluate(
                    processPath: enrichedEvent.process.executable,
                    processPID: enrichedEvent.process.pid,
                    parentPath: parentPath,
                    parentPID: parentPID,
                    ancestryDepth: enrichedEvent.process.ancestors.count
                )
                for finding in topologyFindings {
                    await state.behaviorScoring.addIndicator(
                        named: finding.kind.rawValue,
                        detail: finding.detail,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
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
                do {
                    if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                await state.behaviorScoring.addIndicator(
                    named: "known_malicious_hash",
                    detail: "CDHash: \(cdhash)",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
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
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            if tlsAlert.severity >= .high { await state.notifier.notify(alert: alert) }
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            if gitEvent.severity >= .high { await state.notifier.notify(alert: alert) }
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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

            // v1.10.0 TraceGraph ingestion. Bridge handles category/action
            // mapping internally and returns nil-equivalent for events
            // that aren't in the causal graph schema. Anchor materialization
            // happens inside the bridge → rolling graph → materializer
            // path. Errors are logged inside the bridge and don't block
            // the rest of the event loop.
            //
            // v1.12.0: when the bridge materializes a Trace AND a graph
            // rule evaluator is loaded, walk the neighborhood around the
            // trace's root entity and run every graph rule against the
            // entities + edges. Matches become Alerts on the standard
            // sink — same flow as Sigma single-event matches above.
            //
            // v1.12.0 post-audit (B3): the per-trace neighborhood SQL
            // walk is detached into a fire-and-forget Task. Pre-fix,
            // a burst of anchor materializations (one `npm install` can
            // fire dozens) would serialize on the single causalStore
            // SQLite actor — same actor that handles every event/edge
            // insertion — and head-of-line-block the main event pump.
            // Detaching is safe because the graph evaluator's only
            // downstream consumer is the alert sink, which is itself
            // an actor with its own queue.
            if let bridge = state.causalGraphBridge {
                let materialized = await bridge.process(enrichedEvent)
                if !materialized.isEmpty,
                   let evaluator = state.graphEvaluator,
                   let store = state.causalStore {
                    let traceList = materialized
                    let anchorEventId = enrichedEvent.id.uuidString
                    let anchorProcPath = enrichedEvent.process.executable
                    let anchorProcName = enrichedEvent.process.name
                    let anchorEvent = enrichedEvent
                    let alertSink = state.alertSink
                    Task.detached(priority: .utility) {
                        for trace in traceList {
                            guard let rootId = trace.rootEntityId else { continue }
                            let window = TimeWindow(
                                start: trace.createdAt.addingTimeInterval(-300),
                                end: trace.createdAt.addingTimeInterval(300)
                            )
                            let subtree: GraphSubtree
                            do {
                                subtree = try await store.neighborhood(
                                    of: rootId,
                                    depth: 3,
                                    within: window
                                )
                            } catch {
                                continue
                            }
                            let matches = await evaluator.evaluate(
                                entities: subtree.entities,
                                edges: subtree.edges
                            )
                            for match in matches {
                                let alert = Alert(
                                    ruleId: match.ruleId,
                                    ruleTitle: match.ruleTitle,
                                    severity: Severity(rawValue: match.severity) ?? .medium,
                                    eventId: anchorEventId,
                                    processPath: anchorProcPath,
                                    processName: anchorProcName,
                                    description: "Multi-entity graph rule fired against trace \(trace.id). Bindings: \(match.bindings.map { "\($0.key)=\($0.value)" }.joined(separator: ", "))",
                                    mitreTactics: nil,
                                    mitreTechniques: match.attack.isEmpty ? nil : match.attack.joined(separator: ",")
                                )
                                do {
                                    _ = try await alertSink.submit(alert: alert, event: anchorEvent)
                                } catch {
                                    await StorageErrorTracker.shared.recordAlertError(error)
                                }
                            }
                        }
                    }
                }
            }

            // v1.12.0 — Bayesian intent posterior update. Each event
            // is mapped to zero-or-more Evidence values; the engine
            // accumulates per-process-tree posteriors and we emit an
            // alert only when the top non-benign goal crosses 0.85
            // with at least 3 distinct evidence types. Threshold +
            // evidence floor are deliberately strict — single-event
            // signals already fire through Sigma rules below.
            //
            // v1.12.0 RC3 (Int-HLoc1): the alert ruleTitle and
            // description strings emitted from this section
            // (`Intent posterior crossed threshold`, `Bayesian
            // belief network reports...`, `AI agent install:`,
            // `Counterfactual:`, `Forecast: likely next tactic...`)
            // ship as English-only literals — same shape as the
            // existing pre-v1.12 alert strings throughout EventLoop.
            // A workspace-wide alert-string localization sweep is
            // queued for v1.12.x; until then, non-English locale
            // users see English text in the alert table + OS
            // notifications. Matches the consistency rationale
            // already documented at V2IntelligenceWorkspace.swift
            // for the Supply chain section.
            let intentEvidence = IntentEvidenceClassifier.extract(enrichedEvent)
            var latestPosterior: BayesianIntentEngine.Posterior?
            let treeKey = IntentEvidenceClassifier.treeKey(for: enrichedEvent)
            if !intentEvidence.isEmpty {
                for evidence in intentEvidence {
                    latestPosterior = await state.bayesianIntent.observe(evidence, treeKey: treeKey)
                }
                if let posterior = latestPosterior,
                   posterior.topGoal != .benign,
                   posterior.topProbability >= state.intentPosteriorThreshold,
                   posterior.distinctEvidenceCount >= state.intentPosteriorMinDistinctEvidence {
                    let goalLabel = String(describing: posterior.topGoal)
                    let alert = Alert(
                        ruleId: "maccrab.intent.bayesian-posterior",
                        ruleTitle: "Intent posterior crossed threshold (\(goalLabel))",
                        severity: posterior.topProbability >= 0.95 ? .high : .medium,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: "Bayesian belief network reports p(\(goalLabel))=\(String(format: "%.2f", posterior.topProbability)) for process tree \(treeKey) after \(posterior.evidenceLog.count) observations (\(Set(posterior.evidenceLog).map { $0.rawValue }.sorted().joined(separator: ", ")))",
                        mitreTactics: nil,
                        mitreTechniques: nil
                    )
                    do {
                        _ = try await state.alertSink.submit(alert: alert, event: enrichedEvent)
                    } catch {
                        await StorageErrorTracker.shared.recordAlertError(error)
                    }
                }
            }

            // v1.12.0 — IntentClassifier verdict stamp. On a package-
            // manager install exec, build a BehaviorBrief from the
            // Bayesian engine's per-tree evidence log + the current
            // event's lineage / command-line, run the pure-local
            // heuristic classifier, and stamp IntentLabel +
            // IntentConfidence onto the event. The downstream Sigma
            // rule `llm_classifier_high_risk_intent.yml` predicates on
            // these enrichments to fire when the verdict is one of
            // {credentialHarvest, exfiltration, destructive,
            // lateralMovement}. LLM-backed verdicts remain available
            // via the `classify_package_intent` MCP tool — the hot-
            // path stays heuristic-only so the EventLoop never blocks
            // on a network LLM call.
            //
            // v1.12.0 RC3 fix (B-Int1): when the current event has no
            // new evidence (e.g., a plain `npm install` exec without
            // any credential-read in this same observation), we still
            // need the brief to see the tree's historical evidence
            // log. Otherwise the install event would build a brief
            // with empty credentialsRead → heuristic returns .benign
            // → the rule never fires for the credential-read-then-
            // install worm shape. Query the engine for the existing
            // posterior when `latestPosterior` is nil.
            // v1.12.0 RC6 fix (Perf-R6-N1): only pay the actor-hop
            // cost to fetch the posterior when this event is a
            // candidate for IntentBriefBuilder — i.e. a process-exec.
            // The brief builder rejects non-exec events at line 30-33
            // anyway, so for ~95% of events (file / network / non-exec
            // process) the prior code was burning an actor hop only to
            // discard the result. Gate up-front.
            let isInstallExecCandidate = enrichedEvent.eventCategory == .process
                && enrichedEvent.eventAction.caseInsensitiveCompare("exec") == .orderedSame
            let posteriorForBrief: BayesianIntentEngine.Posterior?
            if !isInstallExecCandidate {
                posteriorForBrief = nil
            } else if let latest = latestPosterior {
                posteriorForBrief = latest
            } else {
                posteriorForBrief = await state.bayesianIntent.posterior(treeKey: treeKey)
            }
            if let brief = IntentBriefBuilder.brief(for: enrichedEvent, posterior: posteriorForBrief) {
                let heuristicResult = IntentClassifier.heuristicClassifyPublic(brief)

                // v1.12.6 (wire-the-orphans Wave 3A): if a prior event
                // in the same process tree already triggered a
                // successful LLM classification, that refined verdict
                // wins for the current event — the LLM saw the brief
                // with full context and overrides the per-event
                // heuristic. The TTL on the cache keeps this in line
                // with the synchronous hot path: a stale refinement
                // (older than 10 min) is treated as missing.
                var stampedLabel = heuristicResult.label.rawValue
                var stampedConfidence = heuristicResult.confidence
                var stampedProvider = heuristicResult.provider
                if let refinement = await state.intentRefinementCache.refinement(for: treeKey) {
                    stampedLabel = refinement.label
                    stampedConfidence = refinement.confidence
                    stampedProvider = refinement.provider
                    enrichedEvent.enrichments["IntentRefinedBy"] = refinement.provider
                    if !refinement.reasons.isEmpty {
                        enrichedEvent.enrichments["IntentReasons"] = refinement.reasons.prefix(3).joined(separator: " | ")
                    }
                }
                enrichedEvent.enrichments["IntentLabel"] = stampedLabel
                enrichedEvent.enrichments["IntentConfidence"] = String(format: "%.2f", stampedConfidence)
                enrichedEvent.enrichments["IntentProvider"] = stampedProvider
                // v1.12.0 RC6 (Int-R6-N1) + RC7 fix (Int-R7-N1):
                // stamp a boolean high-confidence flag so the Sigma
                // rule can predicate on a numeric-equivalent threshold
                // via plain string equality.
                //
                // RC6 set the threshold at 0.7 — but the heuristic
                // classifier's max score per single-label-path is 4-5
                // (credentialHarvest=4, lateralMovement=5), divided by
                // 8 = confidence 0.5-0.625. So a 0.7 gate was
                // unreachable by the headline worm scenario (cat creds
                // → npm install). RC7 lowers the threshold to 0.5,
                // which the credentialHarvest path can clear exactly,
                // and which lateralMovement (creds + publish-endpoint)
                // clears with margin. The heuristic's design treats
                // 0.5 as the "moderate confidence" tier — same value
                // as `unknown` fallback's confidence, distinct from
                // `benign` (0.8). CHANGELOG updated to match.
                if stampedConfidence >= 0.5 {
                    enrichedEvent.enrichments["IntentHighConfidence"] = "true"
                }

                // v1.12.6 (wire-the-orphans Wave 3A): LLM-aware
                // tie-breaker. The synchronous heuristic above stays
                // the source of truth for the current event — we never
                // block the hot path waiting on the LLM. But for
                // AI-attributed installs where the heuristic was
                // ambiguous, we dispatch a detached classification so
                // the next event in the same tree sees a refined
                // verdict. Cost is bounded by:
                //
                //   1. AI attribution required — non-AI installs run
                //      heuristic only, matching prior behaviour.
                //   2. Heuristic must be < 0.7 confident — confident
                //      heuristic verdicts skip the LLM entirely. This
                //      is the standard "LLM is a tie-breaker, not a
                //      default classifier" pattern.
                //   3. IntentRefinementCache acts as a per-tree
                //      cooldown (10-min TTL) so a single tree can
                //      trigger at most one LLM call per window,
                //      regardless of how many events it generates.
                //   4. LLMService already enforces the global 5s min
                //      interval, 3-failure circuit breaker, and 50KB
                //      response cap.
                //
                // On LLM failure (circuit open / parse fail / nil)
                // we silently leave the heuristic verdict in place —
                // the synchronous stamp above already covered the
                // current event, and the next event will retry once
                // the TTL expires.
                let isAITriggered = enrichedEvent.enrichments["ai_tool"] != nil
                    || enrichedEvent.enrichments["agent_tool"] != nil
                    || enrichedEvent.enrichments["ai_tool_child"] == "true"
                if isAITriggered && heuristicResult.confidence < 0.7 {
                    let shouldDispatch = await state.intentRefinementCache.shouldClassify(treeKey: treeKey)
                    if shouldDispatch {
                        await state.intentRefinementCache.recordDispatch(treeKey: treeKey)
                        let classifier = state.intentClassifier
                        let cache = state.intentRefinementCache
                        let capturedBrief = brief
                        let capturedTreeKey = treeKey
                        Task.detached(priority: .utility) { @Sendable in
                            let llmResult = await classifier.classify(capturedBrief)
                            // Treat .unknown / heuristic-fallback as
                            // "no useful refinement" — they wouldn't
                            // improve the next event's verdict and
                            // would burn the TTL window.
                            guard llmResult.label != .unknown,
                                  llmResult.provider != "heuristic" else {
                                return
                            }
                            let refinement = IntentRefinementCache.Refinement(
                                label: llmResult.label.rawValue,
                                confidence: llmResult.confidence,
                                provider: llmResult.provider,
                                reasons: llmResult.reasons
                            )
                            await cache.recordResult(treeKey: capturedTreeKey, refinement: refinement)
                        }
                    }
                }

                // v1.12.0 post-audit (M-Int1): when the install was
                // initiated by an AI coding agent (claude / codex /
                // cursor / etc.), also run PromptIntentBridge.
                // It correlates the AI agent's recent context reads
                // with the package being installed and labels the
                // install user-initiated / autonomous / slopsquat /
                // injectionContext / vagueDestructive. The result
                // becomes a PromptIntentLabel enrichment which a
                // future rule can predicate on. Runs in a detached
                // Task because the bridge reads up to 32 context
                // files — too heavy for the hot path. The stamping
                // lands on the FOLLOWING events from the same tree
                // (PromptIntentLabel is a session attribute, not a
                // per-event verdict).
                // v1.12.0 RC3 fix (B-Int2): the enrichment key is
                // "ai_tool" (set by AIProcessTracker at lines 89/97
                // above) or "agent_tool" (set by TraceCorrelator's
                // EnrichmentKey.agentTool constant). Pre-fix we read
                // "AgentTool" which no writer produces, so the
                // PromptIntentBridge analyzeInstall path was dead
                // code in production. Accept either key now.
                let agentToolKey = enrichedEvent.enrichments["ai_tool"]
                    ?? enrichedEvent.enrichments["agent_tool"]
                if let agentTool = agentToolKey,
                   !agentTool.isEmpty {
                    // v1.12.0 RC4 fix (Int-R4-N3): pre-fix used
                    // `ancestors.last?.pid` which is launchd (pid 1),
                    // not the AI tool's pid. AgentLineageService keys
                    // its snapshot by the AI process's actual pid
                    // (the `claude` / `cursor` / etc. binary), so the
                    // bridge would always get nil and short-circuit.
                    // Match the lookup pattern already used at
                    // lines 183-186 for the lineage-record path:
                    // find the first ancestor that AIToolRegistry
                    // recognizes as an AI tool.
                    var aiPid = enrichedEvent.process.pid
                    for ancestor in enrichedEvent.process.ancestors {
                        if state.aiRegistry.isAITool(executablePath: ancestor.executable) != nil {
                            aiPid = ancestor.pid
                            break
                        }
                    }
                    let pkgName = brief.packageName
                    let bridge = state.promptIntentBridge
                    let alertSink = state.alertSink
                    let anchorEvent = enrichedEvent
                    let aiPidCaptured = aiPid
                    Task.detached(priority: .utility) {
                        let verdict = await bridge.analyzeInstall(
                            aiPid: aiPidCaptured,
                            packageName: pkgName
                        )
                        guard verdict.label != .unknown,
                              verdict.label != .userInitiated,
                              verdict.confidence >= 0.5 else { return }
                        let alert = Alert(
                            ruleId: "maccrab.prompt-intent.\(verdict.label.rawValue)",
                            ruleTitle: "AI agent install: \(verdict.label.rawValue) (\(pkgName))",
                            severity: verdict.label == .slopsquat || verdict.label == .vagueDestructive ? .high : .medium,
                            eventId: anchorEvent.id.uuidString,
                            processPath: anchorEvent.process.executable,
                            processName: anchorEvent.process.name,
                            description: "PromptIntentBridge classified install of \(pkgName) as \(verdict.label.rawValue) (confidence \(String(format: "%.2f", verdict.confidence))). Reasons: \(verdict.reasons.joined(separator: "; "))",
                            mitreTactics: nil,
                            mitreTechniques: nil
                        )
                        do {
                            _ = try await alertSink.submit(alert: alert, event: anchorEvent)
                        } catch {
                            await StorageErrorTracker.shared.recordAlertError(error)
                        }
                    }
                }
            }

            // === Detection: 3 layers ===

            // Layer 1: Single-event Sigma rules
            var matches = await state.ruleEngine.evaluate(enrichedEvent)

            // Layer 2: Temporal sequence rules (Phase 2)
            let sequenceMatches = await state.sequenceEngine.evaluate(enrichedEvent)
            matches.append(contentsOf: sequenceMatches)

            // v1.12.0 post-audit (M-Int2 + M-Int3): attach a
            // CounterfactualReasoner narrative AND a NextTechniquePredictor
            // forecast to HIGH/CRITICAL sequence matches. Pre-fix both
            // actors only fired in unit tests / MCP. This is a single-
            // step counterfactual built from the firing event because
            // SequenceEngine doesn't expose its internal `matchedSteps`
            // chain — a proper N-step counterfactual lives in v1.12.x
            // once SequenceEngine grows a `partialChain(for:)` accessor.
            // The single-step result still tells the analyst which
            // prevention capability could have blocked the impact
            // moment + the top-3 most-likely next tactics.
            if !sequenceMatches.isEmpty {
                for seqMatch in sequenceMatches where seqMatch.severity == .high || seqMatch.severity == .critical {
                    let matchCopy = seqMatch
                    let primitive = inferPreventionPrimitive(from: enrichedEvent)
                    let step = CounterfactualReasoner.ChainStep(
                        stepId: matchCopy.ruleId,
                        tactic: .impact,
                        timestamp: enrichedEvent.timestamp,
                        primitive: primitive
                    )
                    let reasoner = CounterfactualReasoner()
                    let predictor = NextTechniquePredictor()
                    let observedTactics = inferTacticsFromMatch(matchCopy)
                    let anchorEvent = enrichedEvent
                    let alertSink = state.alertSink
                    Task.detached(priority: .utility) {
                        // Counterfactual narrative
                        let result = await reasoner.analyze(chain: [step])
                        if result.earliestBlockable != nil {
                            let alert = Alert(
                                ruleId: "maccrab.counterfactual.\(matchCopy.ruleId)",
                                ruleTitle: "Counterfactual: \(matchCopy.ruleName)",
                                severity: .informational,
                                eventId: anchorEvent.id.uuidString,
                                processPath: anchorEvent.process.executable,
                                processName: anchorEvent.process.name,
                                description: result.narrative,
                                mitreTactics: nil,
                                mitreTechniques: nil
                            )
                            do {
                                _ = try await alertSink.submit(alert: alert, event: anchorEvent)
                            } catch {
                                await StorageErrorTracker.shared.recordAlertError(error)
                            }
                        }
                        // Next-tactic forecast
                        if !observedTactics.isEmpty {
                            let predictions = await predictor.predictNext(after: observedTactics, topN: 3)
                            if !predictions.isEmpty {
                                let summary = predictions.map { "\(String(describing: $0.tactic)) (\(String(format: "%.0f", $0.probability * 100))%)" }.joined(separator: ", ")
                                let alert = Alert(
                                    ruleId: "maccrab.predict.next-technique.\(matchCopy.ruleId)",
                                    ruleTitle: "Forecast: likely next tactic after \(matchCopy.ruleName)",
                                    severity: .informational,
                                    eventId: anchorEvent.id.uuidString,
                                    processPath: anchorEvent.process.executable,
                                    processName: anchorEvent.process.name,
                                    description: "Markov-1 prior over MITRE tactics suggests: \(summary). Watch the listed tactics over the next ~10 minutes.",
                                    mitreTactics: nil,
                                    mitreTechniques: nil
                                )
                                do {
                                    _ = try await alertSink.submit(alert: alert, event: anchorEvent)
                                } catch {
                                    await StorageErrorTracker.shared.recordAlertError(error)
                                }
                            }
                        }
                    }
                }
            }

            // LLM sequence analysis (non-blocking) — explains temporal attack chains
            if let llm = state.llmService, !sequenceMatches.isEmpty {
                for seqMatch in sequenceMatches {
                    let matchCopy = seqMatch
                    let procName = enrichedEvent.process.name
                    let procPath = enrichedEvent.process.executable
                    Task {
                        if let analysis = await llm.query(
                            systemPrompt: LLMPrompts.sequenceAnalysisSystem,
                            userPrompt: LLMPrompts.sequenceAnalysisUser(
                                ruleName: matchCopy.ruleName,
                                description: matchCopy.description,
                                processName: procName, processPath: procPath,
                                mitreTechniques: matchCopy.mitreTechniques,
                                tags: matchCopy.tags
                            ),
                            maxTokens: 512, temperature: 0.2
                        ) {
                            let analysisAlert = Alert(
                                ruleId: "maccrab.llm.sequence-analysis",
                                ruleTitle: "AI Sequence Analysis: \(matchCopy.ruleName)",
                                severity: .informational,
                                eventId: UUID().uuidString,
                                processPath: procPath, processName: procName,
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { _ = try await state.alertSink.submit(alert: analysisAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        }
                    }
                }
            }

            // Layer 3: Baseline anomaly detection (Phase 3)
            let baselineMatchResult = await state.baselineEngine.evaluate(enrichedEvent)
            if let baselineMatch = baselineMatchResult {
                matches.append(baselineMatch)

                // LLM baseline anomaly analysis (non-blocking)
                if let llm = state.llmService {
                    let parentName = enrichedEvent.process.ancestors.first?.name ?? "unknown"
                    let parentPath = enrichedEvent.process.ancestors.first?.executable ?? "unknown"
                    let childName = enrichedEvent.process.name
                    let childPath = enrichedEvent.process.executable
                    let pid = enrichedEvent.process.pid
                    let userName = enrichedEvent.process.userName
                    let edgeCount = await state.baselineEngine.edgeCount
                    Task {
                        if let analysis = await llm.query(
                            systemPrompt: LLMPrompts.baselineAnomalySystem,
                            userPrompt: LLMPrompts.baselineAnomalyUser(
                                parentName: parentName, childName: childName,
                                parentPath: parentPath, childPath: childPath,
                                pid: pid, userName: userName, edgeCount: edgeCount
                            ),
                            maxTokens: 512, temperature: 0.3
                        ) {
                            let analysisAlert = Alert(
                                ruleId: "maccrab.llm.baseline-analysis",
                                ruleTitle: "AI Anomaly Analysis: \(parentName) → \(childName)",
                                severity: .informational,
                                eventId: UUID().uuidString,
                                processPath: childPath, processName: childName,
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { _ = try await state.alertSink.submit(alert: analysisAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        }
                    }
                }
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

                    // LLM behavioral analysis (non-blocking) — explains what the
                    // indicator combination reveals about the attack pattern
                    if let llm = state.llmService {
                        let procName = enrichedEvent.process.name
                        let procPath = enrichedEvent.process.executable
                        let pid = enrichedEvent.process.pid
                        let score = scoringResult.totalScore
                        let indicators = scoringResult.indicators.map { ($0.name, $0.weight, $0.detail) }
                        Task {
                            if let analysis = await llm.query(
                                systemPrompt: LLMPrompts.behaviorAnalysisSystem,
                                userPrompt: LLMPrompts.behaviorAnalysisUser(
                                    processName: procName, processPath: procPath, pid: pid,
                                    totalScore: score, indicators: indicators
                                ),
                                maxTokens: 512, temperature: 0.2
                            ) {
                                let analysisAlert = Alert(
                                    ruleId: "maccrab.llm.behavior-analysis",
                                    ruleTitle: "AI Behavioral Analysis: \(procName)",
                                    severity: .informational,
                                    eventId: UUID().uuidString,
                                    processPath: procPath, processName: procName,
                                    description: analysis.response,
                                    mitreTactics: nil, mitreTechniques: nil,
                                    suppressed: false
                                )
                                do { _ = try await state.alertSink.submit(alert: analysisAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            }
                        }
                    }
                }
            }

            // v1.6.9: Apply shared noise filters AFTER all three
            // detection layers (Sigma / Sequence / Baseline +
            // Behavioral Composite) have appended their matches.
            //
            // Prior to v1.6.9 this ran AFTER Layer 1 only, which is
            // why /usr/libexec/networkserviceproxy kept firing the
            // credential_theft_exfil SEQUENCE rule despite every
            // rule-level filter we added (v1.6.5 filter_apple_daemons),
            // Gate 6 (v1.6.5), and Gate 7 (v1.6.8) — sequence matches
            // were appended to `matches` AFTER NoiseFilter.apply, so
            // they never saw any gate. Moving the call to here makes
            // every gate apply universally to every layer, which is
            // what every FP fix since v1.6.2 silently assumed.
            //
            // Also called from the FSEvents fallback in MonitorTasks
            // and the SIGHUP retroactive scan in SignalHandlers, so
            // behavior stays consistent across every rule-evaluation
            // entry point.
            NoiseFilter.apply(&matches, event: enrichedEvent, isWarmingUp: state.isWarmingUp)

            if !matches.isEmpty {
                // Batch-collect alerts from rule matches, then insert as a single
                // transaction to reduce SQLite I/O from O(n) transactions to O(1).
                var batchAlerts: [Alert] = []

                for match in matches {
                    // Suppression + deduplication checks
                    if await state.suppressionManager.isSuppressed(ruleId: match.ruleId, processPath: enrichedEvent.process.executable) {
                        continue
                    }
                    // v1.6.21 BLOCKER fix: atomic check+record closes a TOCTOU
                    // window where two concurrent rule-matches for the same
                    // (ruleId, processPath) tuple could both pass the
                    // shouldSuppress check and both emit duplicates.
                    if await state.deduplicator.shouldSuppressAndRecord(ruleId: match.ruleId, processPath: enrichedEvent.process.executable) {
                        continue
                    }

                    alertCount += 1

                    // Feedback-driven severity auto-tuning: rules the user
                    // repeatedly dismisses get downgraded one level (critical
                    // is never downgraded — the operator shouldn't be able to
                    // mute ransomware or SIP alerts by swiping them away).
                    let effectiveSeverity = await state.deduplicator.effectiveSeverity(
                        ruleId: match.ruleId, original: match.severity)

                    let alert = Alert(
                        id: UUID().uuidString,
                        timestamp: Date(),
                        ruleId: match.ruleId,
                        ruleTitle: match.ruleName,
                        severity: effectiveSeverity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: match.description,
                        mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                        mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                        suppressed: false
                    )

                    batchAlerts.append(alert)
                    // Only surface OS notifications for alerts that haven't
                    // been auto-downgraded below high — otherwise noisy rules
                    // keep popping banners after the user has indicated they
                    // don't care.
                    if effectiveSeverity >= .high {
                        await state.notifier.notify(alert: alert)
                    }
                    await state.responseEngine.execute(alert: alert, event: enrichedEvent)

                    // Send to external notification integrations (Slack, Teams, etc.)
                    await state.notificationIntegrations.sendAlert(
                        ruleTitle: alert.ruleTitle,
                        severity: effectiveSeverity.rawValue,
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
                    // v1.12.6 Wave 2C: surface MITRE technique tags, AI-tool
                    // attribution, and the process-tree depth so the campaign
                    // aggregates can be computed at persist time without a
                    // cross-DB join.
                    let techniqueTags = match.tags.filter { $0.contains("t1") }
                    let alertSummary = CampaignDetector.AlertSummary(
                        ruleId: alert.ruleId,
                        ruleTitle: alert.ruleTitle,
                        severity: match.severity,
                        processPath: alert.processPath,
                        pid: Int(enrichedEvent.process.pid),
                        userId: String(enrichedEvent.process.userId),
                        timestamp: alert.timestamp,
                        tactics: Set(tactics),
                        mitreTechniques: Set(techniqueTags),
                        aiTool: enrichedEvent.enrichments["ai_tool"],
                        processTreeDepth: enrichedEvent.process.ancestors.count
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
                            suppressed: false,
                            campaignId: campaign.id
                        )
                        do { _ = try await state.alertSink.submit(alert: campaignAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }

                        // Persist the campaign itself so dashboards and the
                        // analyst workflow survive daemon restarts. Failures
                        // are non-fatal — log and continue.
                        if let store = state.campaignStore {
                            // v1.12.6 Wave 2C: pass through the aggregate
                            // attribution computed by `CampaignDetector` over
                            // the contributing alerts. Empty sets surface as
                            // nil so the DB column stays NULL (idiomatic for
                            // "absent" rather than "[]").
                            let aggregatedUsers = campaign.affectedUsers.isEmpty
                                ? nil : Array(campaign.affectedUsers).sorted()
                            let aggregatedExecs = campaign.affectedExecutables.isEmpty
                                ? nil : Array(campaign.affectedExecutables).sorted()
                            let aggregatedTechniques = campaign.techniques.isEmpty
                                ? nil : Array(campaign.techniques).sorted()
                            let aggregatedAITools = campaign.aiTools.isEmpty
                                ? nil : Array(campaign.aiTools).sorted()
                            let record = CampaignStore.Record(
                                id: campaign.id,
                                type: campaign.type.rawValue,
                                severity: campaign.severity,
                                title: campaign.title,
                                description: campaign.description,
                                tactics: Array(campaign.tactics).sorted(),
                                timeSpanSeconds: campaign.timeSpanSeconds,
                                detectedAt: campaign.detectedAt,
                                alerts: campaign.alerts.map {
                                    CampaignStore.AlertRef(
                                        ruleId: $0.ruleId,
                                        ruleTitle: $0.ruleTitle,
                                        severity: $0.severity,
                                        processPath: $0.processPath,
                                        pid: $0.pid,
                                        userId: $0.userId,
                                        timestamp: $0.timestamp,
                                        tactics: Array($0.tactics).sorted()
                                    )
                                },
                                affectedUsers: aggregatedUsers,
                                affectedExecutables: aggregatedExecs,
                                firstSeen: campaign.firstSeen,
                                lastSeen: campaign.lastSeen,
                                processTreeDepth: campaign.processTreeDepth,
                                techniques: aggregatedTechniques,
                                aiTools: aggregatedAITools
                            )
                            do {
                                try await store.insert(record)
                            } catch {
                                await StorageErrorTracker.shared.recordAlertError(error)
                            }
                        }

                        await state.notifier.notify(alert: campaignAlert)

                        // Auto-generate a Sigma rule from the campaign. RuleGenerator
                        // writes the rule file and logs internally; the returned value
                        // is informational only.
                        let campaignAlerts = campaign.alerts.map { a in
                            (ruleId: a.ruleId, ruleTitle: a.ruleTitle, processPath: a.processPath, tactics: a.tactics, timestamp: a.timestamp)
                        }
                        if state.llmService != nil {
                            _ = await state.ruleGenerator.generateFromCampaignEnhanced(
                                campaignType: campaign.type.rawValue,
                                alerts: campaignAlerts
                            )
                        } else {
                            _ = await state.ruleGenerator.generateFromCampaign(
                                campaignType: campaign.type.rawValue,
                                alerts: campaignAlerts
                            )
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
                                // Investigation summary — use extended thinking for
                                // HIGH/CRITICAL campaigns with 3+ tactics. Falls back
                                // to regular query on non-Opus backends automatically.
                                let useDeepAnalysis = (campaignSeverity == .critical || campaignSeverity == .high)
                                    && campaignTactics.count >= 3
                                let investigationText: String?
                                if useDeepAnalysis {
                                    investigationText = await llm.deepAnalyzeCampaign(
                                        campaignType: campaignType,
                                        title: campaignTitle,
                                        severity: campaignSeverity.rawValue,
                                        tactics: campaignTactics,
                                        alerts: alertSummaries,
                                        thinkingBudgetTokens: 8000
                                    )
                                } else {
                                    investigationText = await llm.query(
                                        systemPrompt: LLMPrompts.investigationSystem,
                                        userPrompt: LLMPrompts.investigationUser(
                                            campaignType: campaignType, title: campaignTitle,
                                            severity: campaignSeverity.rawValue,
                                            tactics: campaignTactics,
                                            alerts: alertSummaries
                                        ),
                                        maxTokens: 1024, temperature: 0.3
                                    )?.response
                                }
                                if let text = investigationText {
                                    let label = useDeepAnalysis ? "Deep Analysis" : "Investigation Summary"
                                    let summaryAlert = Alert(
                                        ruleId: "maccrab.llm.investigation-summary",
                                        ruleTitle: "\(label): \(campaignTitle)",
                                        severity: .informational,
                                        eventId: campaignId,
                                        processPath: nil, processName: nil,
                                        description: text,
                                        mitreTactics: nil, mitreTechniques: nil,
                                        suppressed: false
                                    )
                                    do { _ = try await state.alertSink.submit(alert: summaryAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
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
                                        do { _ = try await state.alertSink.submit(alert: recAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                    }
                                }
                            }
                        }
                    }

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

                    // Phase 7 additional outputs (FileOutput, StreamOutput
                    // Splunk HEC / Elastic Bulk / Datadog). Fire-and-forget
                    // per sink — a slow or failing sink never blocks the
                    // detection pipeline.
                    for sink in state.additionalOutputs {
                        Task { await sink.send(alert: alert, event: enrichedEvent) }
                    }

                    // Phase 4 agentic triage — auto-invoke the LLM for
                    // HIGH and CRITICAL alerts when an LLMService is
                    // configured. Runs in a detached Task so the detection
                    // pipeline is never blocked by model latency. The
                    // result is persisted via AlertStore.updateInvestigation
                    // so the dashboard surfaces it on the next poll.
                    if alert.severity >= .high, let llm = state.llmService {
                        let capturedAlert = alert
                        let capturedEvent = enrichedEvent
                        let store = state.alertStore
                        Task.detached(priority: .background) {
                            if let investigation = await llm.investigate(
                                alert: capturedAlert, event: capturedEvent
                            ) {
                                do {
                                    try await store.updateInvestigation(
                                        alertId: capturedAlert.id,
                                        investigation: investigation
                                    )
                                } catch {
                                    await StorageErrorTracker.shared.recordAlertError(error)
                                }
                            }
                        }
                    }
                }

                // Batch insert all rule-match alerts. Routes through the
                // AlertSink chokepoint even though NoiseFilter + dedup were
                // already applied above — keeps the architectural invariant
                // (no direct AlertStore.insert outside AlertSink) intact.
                // v1.12.6 Wave 2B: pass enrichedEvent so AlertSink can
                // populate the schema-v5 attribution columns (user, CWD,
                // ai_tool, parent_exec, sha256, host_name) for every
                // alert in the batch — they all share the same triggering
                // event by construction.
                if !batchAlerts.isEmpty {
                    do { try await state.alertSink.insertEngineBatch(alerts: batchAlerts, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // LLM analysis for individual HIGH/CRITICAL alerts (non-blocking).
                // Only the first high/critical alert per event gets analysis to avoid
                // flooding the LLM when many rules fire on the same event.
                if let llm = state.llmService,
                   let topAlert = batchAlerts.first(where: { $0.severity == .critical || $0.severity == .high }),
                   // Skip campaign/LLM meta-alerts to avoid recursion
                   !topAlert.ruleId.hasPrefix("maccrab.campaign."),
                   !topAlert.ruleId.hasPrefix("maccrab.llm.") {
                    let alertCopy = topAlert
                    Task {
                        if let analysis = await llm.query(
                            systemPrompt: LLMPrompts.alertAnalysisSystem,
                            userPrompt: LLMPrompts.alertAnalysisUser(
                                ruleTitle: alertCopy.ruleTitle,
                                severity: alertCopy.severity.rawValue,
                                processName: alertCopy.processName,
                                processPath: alertCopy.processPath,
                                description: alertCopy.description,
                                mitreTechniques: alertCopy.mitreTechniques,
                                mitreTactics: alertCopy.mitreTactics
                            ),
                            maxTokens: 512, temperature: 0.2
                        ) {
                            let analysisAlert = Alert(
                                ruleId: "maccrab.llm.alert-analysis",
                                ruleTitle: "AI Analysis: \(alertCopy.ruleTitle)",
                                severity: .informational,
                                eventId: alertCopy.id,
                                processPath: alertCopy.processPath,
                                processName: alertCopy.processName,
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { _ = try await state.alertSink.submit(alert: analysisAlert, event: enrichedEvent) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        }
                    }
                }
            }

            // v1.10.2 (audit BLOCKER): the for-await body has many
            // Foundation calls (enricher, ruleEngine, JSONEncoder via
            // EventStore, ProcessInfo rebuild for sanitize) returning
            // autoreleased temporaries. `autoreleasepool {}` can't
            // wrap an async block; the next-best signal is a
            // cooperative yield, which Swift's async runtime treats as
            // a drain point for the current task's autorelease pool.
            // Without this, sustained 200-1000 events/s flow has been
            // observed accumulating autoreleased objects between
            // implicit drain points (mirror of v1.7.7-v1.7.9
            // eslogger/UnifiedLog/FileHasher fixes which used the same
            // pattern via the inner `autoreleasepool` over synchronous
            // chunks — that variant doesn't fit here because the body
            // is interleaved async).
            await Task.yield()
        }

        logger.info("Event stream ended. Daemon exiting.")
    }

    // NoiseFilter logic lives in MacCrabCore/Detection/NoiseFilter.swift
    // so the test target can exercise it directly. See FPRegressionTests.
}

/// v1.12.0 RC3 (Sec-H2): credential-path filter for AgentLineageService
/// records. The lineage snapshot is persisted to disk and read by the
/// dashboard / PromptIntentBridge / future MCP tooling — paths that
/// match credential shapes are dropped at record time so they never
/// leave the daemon's memory.
func isCredentialShapedPath(_ path: String) -> Bool {
    let lower = path.lowercased()
    return lower.contains("/.aws/credentials")
        || lower.contains("/.aws/config")
        // v1.12.0 RC5 (Sec-R5-N7): AWS SSO cache + Azure CLI +
        // Bitwarden + 1Password CLI paths added.
        || lower.contains("/.aws/sso/cache/")
        || lower.contains("/.azure/")
        || lower.contains("/.bw/data.json")
        || lower.contains("/.config/op/")
        // v1.12.0 RC6 (Sec-R6-N4): 1Password desktop (v7 and v8)
        // group-container vault paths, GnuPG keyrings.
        || lower.contains("/group containers/2bua8c4s2c.com.agilebits/")
        || lower.contains("/group containers/2bua8c4s2c.com.1password/")
        || lower.contains("/.gnupg/")
        || lower.contains("/.ssh/id_")
        || lower.contains("/.ssh/authorized_keys")
        || lower.hasSuffix("/.netrc")
        || lower.hasSuffix("/.npmrc")
        || lower.hasSuffix("/.pypirc")
        || lower.contains("/.docker/config.json")
        || lower.contains("/.kube/config")
        || lower.hasSuffix("/.gitconfig")
        || lower.contains("/.config/gh/hosts.yml")
        || lower.contains("/.cargo/credentials")
        || lower.contains("/library/keychains/")
        // v1.12.0 RC4 fix (Sec-R4-N7): expand browser profile coverage
        // beyond Chrome + Firefox. Safari uses /Library/Safari/ and
        // /Library/Containers/com.apple.Safari/; Arc, Brave, Edge,
        // Vivaldi, Opera all live under /Library/Application Support/.
        || lower.contains("/library/application support/google/chrome/")
        || lower.contains("/library/application support/firefox/")
        || lower.contains("/library/application support/bravesoftware/")
        || lower.contains("/library/application support/microsoft edge/")
        || lower.contains("/library/application support/arc/")
        || lower.contains("/library/application support/vivaldi/")
        || lower.contains("/library/application support/com.operasoftware.opera/")
        || lower.contains("/library/safari/")
        || lower.contains("/library/containers/com.apple.safari/")
        || lower.hasSuffix("/login data")
        || lower.hasSuffix("/cookies")
        || lower.hasSuffix("/cookies.binarycookies")
}
