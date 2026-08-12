import Foundation
import MacCrabCore
import os.log

/// The main event processing loop. Processes each event through
/// enrichment, AI guard, detection layers, and alert output.
enum EventLoop {
    /// v1.17: shared formatter for threat-intel IOC-match alerts.
    /// Builds a human description plus a machine-parseable remediation
    /// hint (type=/source=/family= prefixes) from the matched IOCRecord.
    /// Tolerates `record == nil` (a feed refresh can evict the entry
    /// between the isXMalicious check and this lookup) — falls back to
    /// the raw indicator value + type.
    static func iocMatchStrings(
        record: ThreatIntelFeed.IOCRecord?,
        value: String,
        type: String,
        hit: String
    ) -> (description: String, remediation: String) {
        guard let record else {
            return (
                "\(hit) \(value) matches a known-malicious \(type) from threat intelligence",
                "Threat-intel match (type=\(type)). Investigate the process and block the indicator."
            )
        }
        var desc = "\(hit) \(value) matches \(record.source) IOC"
        if let fam = record.malwareFamily, !fam.isEmpty { desc += ", family \(fam)" }
        if let first = record.firstSeen { desc += ", first seen \(iocDateFormatter.string(from: first))" }
        var hint = "Threat-intel match (type=\(type), source=\(record.source)"
        if let fam = record.malwareFamily, !fam.isEmpty { hint += ", family=\(fam)" }
        if !record.tags.isEmpty { hint += ", tags=\(record.tags.joined(separator: ","))" }
        hint += "). Investigate the process and block the indicator."
        return (desc, hint)
    }

    private static let iocDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.timeZone = TimeZone(identifier: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    /// v1.21.4 Phase-6 6A: direct agent-trace correlation for an event's
    /// OWN process identity, decoupled from the isAIChild lineage pass.
    ///
    /// A process launched with an inherited TRACEPARENT — the agent's own
    /// root process, or a helper the agent spawned that AIToolRegistry
    /// doesn't recognise — may never be tagged as an "AI child" by
    /// lineage, yet the ESCollector env-scan already bound its TRACEPARENT
    /// into the registry. This helper looks that binding up by exact
    /// `ProcessIdentity` so the event still gets `agent_trace_id`.
    ///
    /// It runs the TraceRegistry lookup only — NO AIToolRegistry lineage
    /// fallback (`aiToolForPath` returns nil). Pass `ancestors: []` for a
    /// direct-only lookup (the common call); a non-empty `ancestors` still
    /// only walks *bound* ancestors in the registry, never the shape-based
    /// lineage Pass-2, which stays in the isAIChild branch.
    static func correlateAgentTrace(
        identity: ProcessIdentity,
        ancestors: [ProcessAncestor],
        registry: TraceRegistry,
        telemetryGapActive: Bool = false
    ) async -> TraceCorrelation? {
        await TraceCorrelator.correlate(
            identity: identity,
            ancestors: ancestors,
            registry: registry,
            ancestorIdentityResolver: { ancestor in
                ProcessIdentity(
                    auditIdentity: AuditIdentity(
                        auid: 0, euid: 0, egid: 0, ruid: 0, rgid: 0,
                        pid: ancestor.pid, pidversion: 0, asid: 0
                    ),
                    pathHash: ProcessIdentity.fnv1a64(ancestor.executable),
                    pid: ancestor.pid,
                    startTime: 0
                )
            },
            aiToolForPath: { _ in nil },
            telemetryGapActive: telemetryGapActive
        )
    }

    /// Publish one complete tracker-owned view to the synchronous ES callback.
    /// Every project root here is the value ProjectBoundary accepted (including
    /// a live cwd resolved from an empty ES field), never the raw event field.
    private static func publishDynamicAIFileInterest(state: DaemonState) async {
        _ = await state.aiSessionLifecycleCoordinator.publishCurrent(
            tracker: state.aiTracker
        )
    }

    /// Only collectors backed by Endpoint Security process birth data may
    /// contribute an anti-recycle start identity. Other collectors synthesize
    /// ProcessInfo.startTime from observation time and must pass unknown.
    private static func reliableProcessStartIdentity(
        source: EventPipelineSource,
        startTime: Date
    ) -> UInt64? {
        switch source {
        case .endpointSecurity, .eslogger:
            return AIProcessTracker.processStartIdentity(startTime)
        case .kdebug, .unifiedLog, .tcc, .network:
            return nil
        }
    }

    /// Prefer immutable executable identity over path when learning a launch
    /// baseline. Hashes are strongest; the enriched signing tuple is a bounded
    /// fallback; path remains StatisticalAnomalyDetector's final fallback.
    /// This keeps an in-place binary replacement from inheriting the old
    /// executable's "normal" argument/entropy distribution.
    private static func statisticalBinaryIdentity(
        for process: MacCrabCore.ProcessInfo
    ) -> String? {
        if let cdhash = process.hashes?.cdhash, !cdhash.isEmpty {
            return "cdhash:" + String(cdhash.lowercased().prefix(128))
        }
        if let sha256 = process.hashes?.sha256, !sha256.isEmpty {
            return "sha256:" + String(sha256.lowercased().prefix(128))
        }
        if let signature = process.codeSignature {
            let team = String((signature.teamId ?? "-").prefix(64))
            let identifier = String((signature.signingId ?? "-").prefix(256))
            if team != "-" || identifier != "-" {
                return "sign:\(signature.signerType.rawValue):\(team):\(identifier)"
            }
        }
        return nil
    }

    /// Resolve an IP-only network event once, before any attribution, baseline,
    /// or cross-process consumer runs. The rebuilt value is the single hostname
    /// source for every later consumer; the enrichment key remains for storage
    /// compatibility and operator inspection.
    private static func backfillDNSHostname(
        state: DaemonState,
        event: inout Event
    ) async {
        guard let network = event.network,
              network.destinationHostname == nil,
              let domain = await state.dnsCollector.domainForIP(
                network.destinationIp
              ) else { return }
        let resolvedNetwork = NetworkInfo(
            sourceIp: network.sourceIp,
            sourcePort: network.sourcePort,
            destinationIp: network.destinationIp,
            destinationPort: network.destinationPort,
            destinationHostname: domain,
            direction: network.direction,
            transport: network.transport
        )
        event = Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: event.process,
            file: event.file,
            network: resolvedNetwork,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: event.severity,
            ruleMatches: event.ruleMatches
        )
        event.enrichments["dns.resolved_domain"] = domain
    }

    /// Ordered root registration shared by a directly-observed AI process and
    /// an AI ancestor discovered from a child event. ProjectBoundary owns cwd
    /// resolution and validation; tracker, lineage, durable session identity,
    /// and callback demand all consume that exact accepted value afterward.
    private static func registerAIRoot(
        state: DaemonState,
        pid: Int32,
        executable: String,
        type: AIToolType,
        reportedProjectDirectory: String,
        timestamp: Date,
        startTime: Date,
        processStartIdentity: UInt64?
    ) async -> AISessionLifecycleCoordinator.RootRegistration {
        await state.aiSessionLifecycleCoordinator.registerRoot(
            tracker: state.aiTracker,
            projectBoundary: state.projectBoundary,
            lineageService: state.agentLineageService,
            sessionRegistry: state.agentSessionRegistry,
            pid: pid,
            executable: executable,
            type: type,
            reportedProjectDirectory: reportedProjectDirectory,
            observedAt: timestamp,
            processStartTime: startTime,
            processStartIdentity: processStartIdentity
        )
    }

    /// One resolved identity for every filesystem guard, regardless of whether
    /// this event's subject is the AI root itself or a descendant. The root PID
    /// and project directory come from tracker/ProjectBoundary ownership, not a
    /// second executable-shape ancestry walk.
    private struct ResolvedAIAttribution {
        let rootPid: Int32
        let toolType: AIToolType
        let projectDirectory: String
    }

    private static let credentialFenceExemptBinaries: Set<String> = [
        "codesign", "security", "stapler", "productsign", "pkgbuild",
        "productbuild", "notarytool", "altool", "amfid", "xcodebuild",
        "maccrabctl", "maccrabd", "com.maccrab.agent",
        "sign_update", "generate_keys",
    ]

    /// Synchronous pre-detection preparation followed by bounded ownership.
    /// Detection continues on the original enriched Event; only the journal
    /// handle contains the credential-sanitized canonical value.
    private struct JournalBaseBoundary: Sendable {
        let admission: EventJournalAdmission?
        let sourceRetainedByteEstimate: Int
        let poisoned: Bool
    }

    private static func admitJournalBase(
        _ event: Event,
        lane: EventPipelineLane,
        sourceReservation: DeferredEnrichmentReservation,
        state: DaemonState
    ) async -> JournalBaseBoundary? {
        let preflight: EventJournalIngressPreflight
        do {
            preflight = try EventJournalAdmissionValidator.preflight(event)
        } catch {
            await state.eventWriter.recordRejectedBasePreparation(lane: lane)
            await StorageErrorTracker.shared.recordEventError(error)
            return nil
        }
        if !preflight.structurallyOverflowed {
            guard await state.deferredEnrichmentBuffer.resizeReservation(
                sourceReservation,
                to: preflight.sourceRetainedByteEstimate
            ) else {
                await state.eventWriter.recordRejectedBasePreparation(
                    lane: lane
                )
                return nil
            }
        }
        guard let outcome = await state.eventWriter.prepareAndEnqueueBase(
            event,
            lane: lane,
            precomputedPreflight: preflight
        ) else { return nil }
        return JournalBaseBoundary(
            admission: outcome.admission,
            sourceRetainedByteEstimate:
                outcome.sourceRetainedByteEstimate,
            poisoned: outcome.poisoned
        )
    }

    static func enqueueTerminalJournalRevision(
        _ event: Event,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?,
        unchangedFrom rawBase: Event? = nil,
        state: DaemonState
    ) async {
        if let rawBase, rawBase == event {
            _ = await state.eventWriter.completeUnchangedTerminalRevision(
                eventID: event.id,
                lane: lane,
                admission: admission
            )
            return
        }
        _ = await state.eventWriter.prepareAndEnqueueTerminalRevision(
            event,
            lane: lane,
            admission: admission
        )
    }

    /// Establish a digest-specific canonical terminal outcome before reviewed
    /// alerts or sparse projection promotion. Byte-identical completion needs
    /// no overlay; AlertSink still joins the immutable base receipt itself.
    static func settleTerminalJournalRevision(
        _ event: Event,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?,
        unchangedFrom rawBase: Event? = nil,
        state: DaemonState
    ) async -> EventJournalTerminalAdmission {
        if let rawBase, rawBase == event {
            let outcome = await state.eventWriter
                .completeUnchangedTerminalRevision(
                    eventID: event.id,
                    lane: lane,
                    admission: admission
                )
            return EventJournalTerminalAdmission(
                eventID: event.id,
                baseGeneration: admission?.generation ?? 0,
                baseCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalByteCount:
                    admission?.canonicalByteCount ?? 0,
                status: outcome == .unchanged
                    ? .verified : .mismatchedReceipt
            )
        }
        guard let rawBase else {
            return EventJournalTerminalAdmission(
                eventID: event.id,
                baseGeneration: admission?.generation ?? 0,
                baseCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalSHA256: nil,
                terminalCanonicalByteCount: 0,
                status: .mismatchedReceipt
            )
        }
        return await state.eventWriter.prepareAndSettleTerminalDelta(
            base: rawBase,
            terminal: event,
            lane: lane,
            admission: admission
        )
    }

    static func settleTerminalJournalDelta(
        _ delta: EventTerminalDelta?,
        eventID: UUID,
        lane: EventPipelineLane,
        admission: EventJournalAdmission?,
        state: DaemonState
    ) async -> EventJournalTerminalAdmission {
        guard let delta else {
            await state.eventWriter.recordRejectedTerminalPreparation(
                lane: lane
            )
            return EventJournalTerminalAdmission(
                eventID: eventID,
                baseGeneration: admission?.generation ?? 0,
                baseCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalSHA256: nil,
                terminalCanonicalByteCount: 0,
                status: .failed
            )
        }
        if delta.isEmpty {
            let outcome = await state.eventWriter
                .completeUnchangedTerminalRevision(
                    eventID: eventID,
                    lane: lane,
                    admission: admission
                )
            return EventJournalTerminalAdmission(
                eventID: eventID,
                baseGeneration: admission?.generation ?? 0,
                baseCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalSHA256: admission?.canonicalSHA256,
                terminalCanonicalByteCount:
                    admission?.canonicalByteCount ?? 0,
                status: outcome == .unchanged
                    ? .verified : .mismatchedReceipt
            )
        }
        return await state.eventWriter.prepareAndSettleTerminalDelta(
            delta,
            lane: lane,
            admission: admission
        )
    }

    /// Shared root/descendant enforcement. Keeping both direct controls here
    /// prevents the root branch from silently bypassing a guard that descendants
    /// receive, while preserving the credential-only honey/signing exclusions.
    private static func enforceAIFilesystemGuards(
        state: DaemonState,
        event: Event,
        attribution: ResolvedAIAttribution
    ) async {
        guard let filePath = event.file?.path else { return }
        let process = event.process
        let toolName = attribution.toolType.displayName
        let subject = (process.executable as NSString).lastPathComponent

        // Deployed credential-shaped honeyfiles have their own dedicated HIGH
        // detector. Signing/notarization tools legitimately use keychains under
        // AI-driven release builds; dedicated keychain-dump rules still cover
        // malicious CLI use. These exemptions apply only to CredentialFence,
        // never to project-boundary mutation enforcement.
        if event.enrichments["IsHoneyfile"] != "true",
           !credentialFenceExemptBinaries.contains(subject),
           let (credentialType, description) = state.credentialFence.checkAccessDetailed(
               filePath: filePath,
               aiToolName: toolName,
               aiToolType: attribution.toolType,
               accessingBinary: subject
           ) {
            let alert = Alert(
                ruleId: "maccrab.ai-guard.credential-access",
                ruleTitle: "🦀 AI Tool Accessed \(credentialType.rawValue)",
                severity: .medium,
                eventId: event.id.uuidString,
                processPath: process.executable,
                processName: process.name,
                description: description,
                mitreTactics: "attack.credential_access",
                mitreTechniques: "attack.t1552.001",
                suppressed: false
            )
            do {
                if try await state.alertSink.submit(alert: alert, event: event) {
                    await state.notifier.notify(alert: alert)
                }
            } catch {
                await StorageErrorTracker.shared.recordAlertError(error)
            }
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: "ai_tool_credential_access",
                detail: "\(credentialType.rawValue): \(filePath)",
                forProcess: process.pid,
                path: process.executable
            )
        }

        guard ProjectBoundary.mutationEventActions.contains(event.eventAction.lowercased()) else {
            return
        }
        if let violation = await state.projectBoundary.checkWrite(
            filePath: filePath,
            aiSessionPid: attribution.rootPid,
            aiToolName: toolName
        ) {
            let alert = Alert(
                ruleId: "maccrab.ai-guard.boundary-violation",
                ruleTitle: "🦀 AI Tool Wrote Outside Project Directory",
                severity: .medium,
                eventId: event.id.uuidString,
                processPath: process.executable,
                processName: process.name,
                description: violation.description,
                mitreTactics: "attack.defense_evasion",
                mitreTechniques: "attack.t1036",
                suppressed: false
            )
            do {
                if try await state.alertSink.submit(alert: alert, event: event) {
                    await state.notifier.notify(alert: alert)
                }
            } catch {
                await StorageErrorTracker.shared.recordAlertError(error)
            }
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: "ai_tool_boundary_violation",
                detail: "Wrote to \(filePath) outside \(attribution.projectDirectory)",
                forProcess: process.pid,
                path: process.executable
            )
        }
    }

    /// Alert-producing AI-child checks run only after the immutable journal
    /// base has captured every synchronous tool/session/lineage attribution.
    /// Keeping these checks out of the attribution branch makes the source
    /// ordering auditable: no BehaviorScore or AlertSink path can overtake the
    /// single base-admission boundary in `run`.
    private static func enforceAIChildBehaviorGuards(
        state: DaemonState,
        event: Event,
        aiType: AIToolType?
    ) async {
        let process = event.process

        // AI child spawning a shell -- track it
        let shellNames = ["/bash", "/zsh", "/sh", "/dash", "/fish"]
        if shellNames.contains(where: { process.executable.hasSuffix($0) }) {
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: "ai_tool_spawns_shell",
                detail: "\(aiType?.displayName ?? "AI tool") spawned \(process.name)",
                forProcess: process.pid,
                path: process.executable
            )
        }

        // AI child running sudo
        if process.executable.hasSuffix("/sudo")
            || process.commandLine.hasPrefix("sudo ") {
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: "ai_tool_runs_sudo",
                detail: "\(aiType?.displayName ?? "AI tool") child running sudo: \(process.commandLine.prefix(100))",
                forProcess: process.pid,
                path: process.executable
            )
        }

        // AI child installing packages
        let packageCommands = [
            "npm install", "npm i ", "pip install", "pip3 install",
            "cargo add", "brew install",
        ]
        if packageCommands.contains(where: {
            process.commandLine.lowercased().contains($0)
        }) {
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: "ai_tool_installs_unknown_pkg",
                detail: process.commandLine.prefix(200).description,
                forProcess: process.pid,
                path: process.executable
            )
        }

        // AI child downloading and executing
        let downloadCommands = ["curl", "wget"]
        let executionPipes = ["| sh", "| bash", "| zsh", "-o /tmp", "-O /tmp"]
        if downloadCommands.contains(where: { process.commandLine.contains($0) })
            && executionPipes.contains(where: { process.commandLine.contains($0) }) {
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: "ai_tool_downloads_and_exec",
                detail: process.commandLine.prefix(200).description,
                forProcess: process.pid,
                path: process.executable
            )
        }

        // AI child writing to persistence locations
        if let file = event.file {
            let persistencePaths = [
                "/LaunchAgents/", "/LaunchDaemons/", "/StartupItems/",
                ".zshrc", ".bashrc", ".bash_profile",
            ]
            if persistencePaths.contains(where: { file.path.contains($0) }) {
                await BehaviorScoreAlertEmitter.record(
                    state: state,
                    event: event,
                    named: "ai_tool_persistence_write",
                    detail: "AI tool writing to \(file.path)",
                    forProcess: process.pid,
                    path: process.executable
                )
            }
        }

        // Prompt injection scanning is alert-producing and therefore also
        // belongs on the post-admission side of the boundary.
        let textToScan = process.commandLine
        if !textToScan.isEmpty,
           textToScan.count > 20,
           let threat = await state.clipboardInjectionDetector.scan(textToScan) {
            let detail = threat.patterns.joined(separator: ", ")
            let isCompound = threat.patterns.count > 1
            let alert = Alert(
                ruleId: "maccrab.ai-guard.prompt-injection",
                ruleTitle: isCompound
                    ? "🦀 Compound Prompt Injection Detected in AI Tool Command"
                    : "🦀 Prompt Injection Detected in AI Tool Command",
                severity: threat.severity == .critical ? .critical : .high,
                eventId: event.id.uuidString,
                processPath: process.executable,
                processName: process.name,
                description: "Prompt injection detected in command executed by \(aiType?.displayName ?? "AI tool"). \(detail)",
                mitreTactics: "attack.initial_access",
                mitreTechniques: "attack.t1195.001",
                suppressed: false
            )
            do {
                if try await state.alertSink.submit(alert: alert, event: event) {
                    await state.notifier.notify(alert: alert)
                }
            } catch {
                await StorageErrorTracker.shared.recordAlertError(error)
            }
            await BehaviorScoreAlertEmitter.record(
                state: state,
                event: event,
                named: threat.severity == .critical
                    ? "prompt_injection_critical" : "prompt_injection",
                detail: detail,
                forProcess: process.pid,
                path: process.executable
            )
        }
    }

    static func run(
        state: DaemonState,
        lane: EventPipelineLane,
        eventStream: AsyncStream<EventPipelineEnvelope>,
        eventCount: LockedCounter
    ) async {
        for await envelope in eventStream {
            let event = envelope.event
            let eventProcessStartIdentity = reliableProcessStartIdentity(
                source: envelope.source,
                startTime: event.process.startTime
            )
            let processingStartedNanos = DispatchTime.now().uptimeNanoseconds
            state.eventPipelineTelemetry.recordDequeued(lane: lane)
            defer {
                let elapsed = DispatchTime.now().uptimeNanoseconds &- processingStartedNanos
                state.eventPipelineTelemetry.recordCompleted(
                    lane: lane,
                    elapsedNanos: elapsed
                )
            }
            eventCount.increment()

            // Source identity travels with the envelope through both bounded
            // lanes. Credit the collector that actually produced the event;
            // category heuristics miscredited mixed ES/UL/TCC/network traffic.
            await state.collectorRegistry.recordTick(name: envelope.source.key)

            // v1.10.0 perf: notify MCPAttributor of process exits so its
            // pid→server cache evicts proactively rather than waiting for
            // its 5K-entry LRU cap to overflow (audit P-W3.8). Cheap —
            // no-op for events that aren't NOTIFY_EXIT.
            if event.eventAction == "exit" {
                await state.mcpAttributor.processExited(pid: event.process.pid)
                _ = await state.aiSessionLifecycleCoordinator.processExited(
                    tracker: state.aiTracker,
                    projectBoundary: state.projectBoundary,
                    lineageService: state.agentLineageService,
                    sessionRegistry: state.agentSessionRegistry,
                    pid: event.process.pid,
                    expectedStartIdentity: eventProcessStartIdentity,
                    now: event.timestamp
                )
            }

            // Reserve before enrichment so a pending heavyweight result always
            // has bounded external ownership. Saturation back-pressures this
            // consumer; it never turns into an unreported event eviction.
            guard let heavyReservation = await state.deferredEnrichmentBuffer
                .reserveEventSlot() else {
                // Reservation admission seals only after ingestion has been
                // asked to stop. Do not begin unowned enrichment past that
                // terminal boundary.
                break
            }

            // Enrich the event (lineage, code signing)
            var enrichedEvent = await state.enricher.enrich(event)

            // YARA enrichment for file events (Phase 3)
            if enrichedEvent.eventCategory == .file {
                enrichedEvent = await state.yaraEnricher.enrich(enrichedEvent)
            }
            // Network consumers below must all see the same recovered hostname.
            // In particular MCPBaseline and CrossProcessCorrelator previously ran
            // before the later DNS enrichment and permanently learned nil/IP-only
            // observations even when DNSCollector already knew the domain.
            await backfillDNSHostname(state: state, event: &enrichedEvent)
            // === AI Tool Detection ===
            //
            let aiProc = enrichedEvent.process
            var resolvedAIAttribution: ResolvedAIAttribution?
            // Resolve genuine active ancestry BEFORE considering the subject's
            // executable as a new root. A nested Codex/Claude binary is still a
            // descendant of the already-active session; promoting it first
            // minted dozens of empty roots and evicted the useful timeline from
            // AgentLineageService's bounded LRU.
            let directAIType: AIToolType? = {
                guard enrichedEvent.eventAction != "fork",
                      enrichedEvent.eventAction != "exit" else { return nil }
                return state.aiRegistry.isAITool(executablePath: aiProc.executable)
            }()
            var childAttribution: (
                isChild: Bool,
                toolType: AIToolType?,
                projectDir: String?,
                rootPid: Int32?,
                attributionChanged: Bool
            ) = (false, nil, nil, nil, false)

            if enrichedEvent.eventAction != "exit",
               state.aiTracker.hasActiveSessionsHint {
                childAttribution = await state.aiTracker.isAIChild(
                    pid: aiProc.pid,
                    ancestors: aiProc.ancestors,
                    promoteUnregisteredAncestors: false,
                    processStartIdentity: eventProcessStartIdentity
                )
                if childAttribution.attributionChanged {
                    await publishDynamicAIFileInterest(state: state)
                }
            }

            // A daemon that starts after an agent may first observe one of its
            // children, not the root itself. Promote the nearest genuine AI
            // ancestor in owner order: boundary resolution first, then tracker
            // and lineage, then bind the child. Directly-recognised non-fork
            // subjects remain roots unless a currently-active ancestor already
            // claimed them above.
            if !childAttribution.isChild,
               directAIType == nil,
               enrichedEvent.eventAction != "exit",
               let ancestor = aiProc.ancestors.first(where: {
                   !AIProcessTracker.isApplePlatformPath($0.executable)
                       && state.aiRegistry.isAITool(executablePath: $0.executable) != nil
               }),
               let ancestorType = state.aiRegistry.isAITool(executablePath: ancestor.executable) {
                _ = await registerAIRoot(
                    state: state,
                    pid: ancestor.pid,
                    executable: ancestor.executable,
                    type: ancestorType,
                    reportedProjectDirectory: "",
                    timestamp: enrichedEvent.timestamp,
                    startTime: enrichedEvent.timestamp,
                    processStartIdentity: nil
                )
                childAttribution = await state.aiTracker.isAIChild(
                    pid: aiProc.pid,
                    ancestors: aiProc.ancestors,
                    promoteUnregisteredAncestors: false,
                    processStartIdentity: eventProcessStartIdentity
                )
                if childAttribution.attributionChanged {
                    await publishDynamicAIFileInterest(state: state)
                }
            }

            // AI-09: a NOTIFY_FORK event is built from `forkEvent.child`, and a
            // freshly-forked child still carries its PARENT's image until it
            // execs — so ES reports the forked pid as `claude` even when it is
            // about to become /bin/zsh. Minting an agent-lineage session on that
            // event created one bogus ROOT session per forked tool invocation:
            // runtime agent_lineage.json held 32 sessions of which 30 were
            // `events: []` ghosts, and the 32-session LRU cap then evicted the
            // only two sessions that held real timelines. Skip fork here. This
            // costs nothing: if the pid really is an AI-tool root, its NEXT
            // event (exec / file / network) mints the session, and in the
            // meantime the `else if` branch below attributes it correctly as an
            // AI CHILD. Gating on `== "exec"` instead would REGRESS — an agent
            // already running when the daemon starts never emits an exec we see,
            // so it would never get a session at all.
            if !childAttribution.isChild, let aiType = directAIType {
                let rootRegistration = await registerAIRoot(
                    state: state,
                    pid: aiProc.pid,
                    executable: aiProc.executable,
                    type: aiType,
                    reportedProjectDirectory: aiProc.workingDirectory,
                    timestamp: enrichedEvent.timestamp,
                    startTime: aiProc.startTime,
                    processStartIdentity: eventProcessStartIdentity
                )
                enrichedEvent.enrichments["ai_tool"] = aiType.rawValue
                enrichedEvent.enrichments["ai_tool_name"] = aiType.displayName
                enrichedEvent.enrichments["ai_root_pid"] = String(aiProc.pid)
                if !rootRegistration.projectDirectory.isEmpty {
                    enrichedEvent.enrichments["ai_project_dir"] = rootRegistration.projectDirectory
                }
                resolvedAIAttribution = ResolvedAIAttribution(
                    rootPid: aiProc.pid,
                    toolType: aiType,
                    projectDirectory: rootRegistration.projectDirectory
                )
                // v1.18 Wave-3 P1: stamp the durable session id minted/healed
                // by the ordered root registration above.
                if let sessionID = rootRegistration.sessionID {
                    enrichedEvent.enrichments["ai_tool_session_id"] = sessionID
                }
                // AI-13: `AgentEvent.Kind.llmCall` had ZERO producers anywhere
                // in the codebase — only the case definition and two consumers
                // in PromptIntentBridge. So `llmCallCount` was permanently 0 and
                // the `vagueDestructive` guard at PromptIntentBridge.swift:297
                // (`destructiveBlastRadius >= 3 && llmCallCount <= 2`) read as a
                // two-signal discriminator but was really one signal, firing on
                // any wide destructive change regardless of whether an LLM was
                // involved — precisely the discrimination it was written to add.
                //
                // The AGENT ROOT is the process that actually talks to the
                // model, and this branch is the root's branch (which previously
                // recorded no timeline data for its own traffic at all), so this
                // is where the producer belongs. Scoped to that tool's OWN known
                // provider endpoints so ordinary agent egress isn't miscounted.
                if let net = enrichedEvent.network,
                   let host = net.destinationHostname,
                   AIToolRegistry.isKnownEndpoint(hostname: host, toolType: aiType) {
                    await state.agentLineageService.record(
                        aiPid: aiProc.pid,
                        kind: .llmCall(provider: aiType.rawValue, endpoint: host,
                                       bytesUp: nil, bytesDown: nil),
                        timestamp: enrichedEvent.timestamp
                    )
                }
                // Root-owned file activity feeds the same bounded context as
                // child activity. Dynamic callback demand includes both root
                // and descendants, so omitting this producer would retain
                // README/source OPENs only to discard them before the timeline.
                if let file = enrichedEvent.file,
                   let kind = AgentLineageService.materializedFileEventKind(
                       path: file.path,
                       eventAction: enrichedEvent.eventAction
                   ) {
                    await state.agentLineageService.record(
                        aiPid: aiProc.pid,
                        kind: kind,
                        timestamp: enrichedEvent.timestamp
                    )
                }
            } else if childAttribution.isChild {
                    let aiType = childAttribution.toolType
                    let projectDir = childAttribution.projectDir
                    enrichedEvent.enrichments["ai_tool"] = aiType?.rawValue ?? "unknown"
                    enrichedEvent.enrichments["ai_tool_child"] = "true"
                    if let rootPid = childAttribution.rootPid {
                        enrichedEvent.enrichments["ai_root_pid"] = String(rootPid)
                        if let aiType {
                            resolvedAIAttribution = ResolvedAIAttribution(
                                rootPid: rootPid,
                                toolType: aiType,
                                projectDirectory: projectDir ?? ""
                            )
                        }
                    }
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
                        // v1.21.4 (P6 fix, part 3): use the REAL audit identity
                        // (carried on the enriched ProcessInfo) for the direct
                        // lookup — ProcessIdentity equality is the FULL
                        // AuditIdentity, so the old zeroed pidversion/asid here
                        // NEVER matched an ES-created binding (this branch's
                        // high-confidence traceparent path silently degraded to
                        // lineage on every AI-child event). Fall back to the
                        // best-effort zeroed shape only for non-ES sources
                        // (auditIdentity == nil), where a match isn't possible
                        // anyway. Ancestor identities still can't carry the audit
                        // token (ProcessAncestor is pid+path only), so the
                        // ancestor walk continues to rely on the lineage-by-path
                        // fallback below, not registry identity.
                        let lookupIdentity = ProcessIdentity(
                            auditIdentity: aiProc.auditIdentity ?? AuditIdentity(
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

                    // v1.6.7: record lineage events against the tracker-owned
                    // root. The nearest executable that merely *looks* like an
                    // AI tool may itself be a nested descendant; using it here
                    // split durable identity and timeline state across roots.
                    if let rootPid = childAttribution.rootPid {
                        let rootExecutable = aiProc.ancestors.first {
                            $0.pid == rootPid
                        }?.executable
                        // v1.18 Wave-3 P1: resolve this descendant's event to
                        // the root's durable session id (grace-aware, so a
                        // child that outlives the root still correlates) and
                        // stamp it for EventStore persistence.
                        if let sid = await state.agentSessionRegistry.sessionForRoot(
                            pid: rootPid,
                            pathHash: rootExecutable.map { ProcessIdentity.fnv1a64($0) },
                            now: enrichedEvent.timestamp
                        ) {
                            enrichedEvent.enrichments["ai_tool_session_id"] = sid
                        }
                        // One spawn row per actual EXEC. Pre-fix this was
                        // unconditional inside the AI-child branch, so every
                        // file callback emitted another identical processSpawn.
                        if enrichedEvent.eventCategory == .process,
                           enrichedEvent.eventAction == "exec" {
                            await state.agentLineageService.record(
                                aiPid: rootPid,
                                kind: .processSpawn(
                                    basename: aiProc.name,
                                    pid: aiProc.pid
                                ),
                                timestamp: enrichedEvent.timestamp
                            )
                        }
                        // Persist only the completed text context consumed by
                        // PromptIntentBridge. The canonical helper also owns the
                        // private-path denylist, so callback demand and lineage
                        // materialisation cannot drift.
                        if let file = enrichedEvent.file,
                           let kind = AgentLineageService.materializedFileEventKind(
                               path: file.path,
                               eventAction: enrichedEvent.eventAction
                           ) {
                            await state.agentLineageService.record(
                                aiPid: rootPid,
                                kind: kind,
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

            }

            // v1.21.4 Phase-6 6A: agent-trace correlation for the event's
            // OWN identity, decoupled from the isAIChild branch above.
            // That branch only runs for processes lineage recognises as
            // agent children — but a TRACEPARENT-bound process (the
            // agent's own root, or a helper AIToolRegistry doesn't know)
            // may never take it. If nothing above already stamped an
            // agent-trace attribution and the registry is live, try a
            // direct lookup on this pid's exact identity. No-op (registry
            // nil) when the feature master is off. Direct-only: the
            // ancestor walk / lineage Pass-2 stays in the isAIChild branch.
            // v1.21.4 (P6 fix): the direct lookup matches the TraceRegistry
            // binding on the FULL AuditIdentity (pidversion + asid + uids). Only
            // the ES path carries the process's real audit identity; without it
            // we CANNOT build a matching identity — a zeroed pidversion never
            // equals the binding's, so the pre-fix reconstruction here missed on
            // every event and agent_trace_id was never stamped. Use the real
            // identity when present; skip otherwise (non-ES sources don't feed
            // the env-scan binding anyway, so a lookup would be a guaranteed miss).
            // v1.21.4 (audit #259): short-circuit on the nonisolated
            // `hasBindingsHint` BEFORE the registry actor hop. With no agent
            // bound (the overwhelming common case) this direct lookup can only
            // miss, so the per-ES-event `await` into the registry actor was pure
            // overhead. The hint is a lock-guarded Bool mirror of the binding
            // set — reading it is free. It stays true when a telemetry gap is
            // active only if a binding exists, so the honest-degradation branch
            // below is still reachable whenever it can legitimately fire (an
            // empty registry has nothing to degrade from).
            let telemetryGapActive = enrichedEvent.process.session?.launchSource == .telemetryGap
            if let traceRegistry = state.traceRegistry,
               traceRegistry.hasBindingsHint,
               enrichedEvent.enrichments[TraceCorrelator.EnrichmentKey.confidence] == nil,
               let realAudit = enrichedEvent.process.auditIdentity {
                let p = enrichedEvent.process
                let ownIdentity = ProcessIdentity(
                    auditIdentity: realAudit,
                    pathHash: ProcessIdentity.fnv1a64(p.executable),
                    pid: p.pid,
                    startTime: UInt64(p.startTime.timeIntervalSince1970)
                )
                // v1.21.4 (audit #258): pass the active-gap signal so the
                // honest-degradation branch can distinguish a drop-induced
                // attribution loss from a benign orphan. Stamped by EventEnricher
                // from the TelemetryGapProbe over ESCollector.esGlobalDropped().
                if let correlation = await correlateAgentTrace(
                    identity: ownIdentity,
                    ancestors: [],
                    registry: traceRegistry,
                    telemetryGapActive: telemetryGapActive
                ) {
                    TraceCorrelator.apply(correlation, to: &enrichedEvent)
                }
            }

            // Finish every synchronous Event mutation before the immutable
            // base boundary. Direct detections below may alert immediately and
            // therefore must never observe a value whose canonical digest has
            // drifted from the receipt they inherit. Side effects (alerts,
            // behavior scoring, graph work, and advisory dispatch) remain in
            // their original source-order sections and consume these frozen
            // results without mutating the Event again.
            if enrichedEvent.eventCategory == .process,
               enrichedEvent.eventAction == "exec",
               let cached = await state.notarizationChecker.cachedResult(
                    binaryPath: enrichedEvent.process.executable
               ) {
                enrichedEvent.enrichments["notarization.status"] =
                    cached.status.rawValue
                if let source = cached.source {
                    enrichedEvent.enrichments["notarization.source"] = source
                }
            }

            let processTreeLogProbability: Double?
            if enrichedEvent.eventCategory == .process,
               enrichedEvent.eventAction == "exec" {
                let parentName = enrichedEvent.process.ancestors.first?.name
                    ?? "unknown"
                let childName = enrichedEvent.process.name
                let grandparentName = enrichedEvent.process.ancestors.count >= 2
                    ? enrichedEvent.process.ancestors[1].name : nil
                processTreeLogProbability = await state.processTreeAnalyzer
                    .recordTransition(
                        parentName: parentName,
                        childName: childName,
                        grandparentName: grandparentName
                    )
                if let logProbability = processTreeLogProbability,
                   logProbability < -8.0 {
                    enrichedEvent.enrichments["tree.anomaly_score"] = String(
                        format: "%.2f",
                        logProbability
                    )
                }
            } else {
                processTreeLogProbability = nil
            }

            if let filePath = enrichedEvent.file?.path {
                await state.quarantineEnricher.enrich(
                    &enrichedEvent.enrichments,
                    forFile: filePath,
                    userID: enrichedEvent.process.userId
                )
            }

            if enrichedEvent.eventCategory == .file,
               enrichedEvent.eventAction == "open",
               enrichedEvent.enrichments["ai_tool"] != nil
                    || enrichedEvent.enrichments["ai_tool_child"] != nil,
               let injectionPath = enrichedEvent.file?.path,
               await state.injectionEvidenceWeld.readsInjectedContent(
                    path: injectionPath
               ) {
                enrichedEvent.enrichments["untrusted_content"] = "true"
            }

            // Resolve and stamp deterministic intent fields before admission;
            // later alert/advisory work consumes these values but cannot alter
            // the canonical Event after the first security alert is possible.
            let intentEvidence = IntentEvidenceClassifier.extract(enrichedEvent)
            var latestIntentPosterior: BayesianIntentEngine.Posterior?
            let intentScopeKey = IntentEvidenceClassifier.scopeKey(
                for: enrichedEvent
            )
            for evidence in intentEvidence {
                latestIntentPosterior = await state.bayesianIntent.observe(
                    evidence,
                    treeKey: intentScopeKey,
                    observationToken: enrichedEvent.id.uuidString,
                    observedAt: enrichedEvent.timestamp
                )
            }
            let isInstallExecCandidate = enrichedEvent.eventCategory == .process
                && enrichedEvent.eventAction.caseInsensitiveCompare("exec")
                    == .orderedSame
            let posteriorForBrief: BayesianIntentEngine.Posterior?
            if !isInstallExecCandidate {
                posteriorForBrief = nil
            } else if let latestIntentPosterior {
                posteriorForBrief = latestIntentPosterior
            } else {
                posteriorForBrief = await state.bayesianIntent.posterior(
                    treeKey: intentScopeKey
                )
            }
            let intentBrief = IntentBriefBuilder.brief(
                for: enrichedEvent,
                posterior: posteriorForBrief
            )
            var intentHeuristicResult: IntentClassifier.ClassificationResult?
            var intentRefinementScope: IntentRefinementCache.Scope?
            var intentCachedRefinement: IntentRefinementCache.Refinement?
            if let intentBrief {
                let result = IntentClassifier.heuristicClassifyPublic(
                    intentBrief
                )
                intentHeuristicResult = result
                let refinementScope = IntentRefinementCache.scope(
                    sessionID:
                        enrichedEvent.enrichments["ai_tool_session_id"],
                    fallbackTreeKey: intentScopeKey,
                    brief: intentBrief
                )
                intentRefinementScope = refinementScope

                enrichedEvent.enrichments["IntentLabel"] =
                    result.label.rawValue
                enrichedEvent.enrichments["IntentConfidence"] = String(
                    format: "%.2f",
                    result.confidence
                )
                enrichedEvent.enrichments["IntentProvider"] = result.provider
                if let refinementScope,
                   let refinement = await state.intentRefinementCache
                    .refinement(for: refinementScope) {
                    intentCachedRefinement = refinement
                    enrichedEvent.enrichments["IntentModelLabel"] =
                        refinement.label
                    enrichedEvent.enrichments["IntentModelScore"] = String(
                        format: "%.2f",
                        refinement.confidence
                    )
                    enrichedEvent.enrichments["IntentModelProvider"] =
                        refinement.provider
                    enrichedEvent.enrichments["IntentModelDisagrees"] = String(
                        refinement.label != result.label.rawValue
                    )
                    if !refinement.reasons.isEmpty {
                        enrichedEvent.enrichments["IntentModelReasons"] =
                            refinement.reasons.prefix(3).joined(separator: " | ")
                    }
                }
                if result.confidence >= 0.5 {
                    enrichedEvent.enrichments["IntentHighConfidence"] = "true"
                }
            }

            // This is the latest common source-order boundary before any direct
            // AlertSink submission, BehaviorScore threshold emission, response
            // action, or derived detection task. It deliberately follows all
            // synchronous enrichment, DNS, AI tool/session/MCP attribution,
            // lineage materialization, and direct trace correlation so those
            // fields are immutable in the base rather than terminal overlays.
            let journalBaseEvent = enrichedEvent
            let journalBoundary = await admitJournalBase(
                journalBaseEvent,
                lane: lane,
                sourceReservation: heavyReservation,
                state: state
            )
            let journalAdmission = journalBoundary?.admission
            let retention = await state.deferredEnrichmentBuffer
                .retainWithOwnership(
                    enrichedEvent,
                    using: heavyReservation,
                    journalAdmission: journalAdmission,
                    sourceRetainedByteEstimate:
                        journalAdmission != nil
                            && journalBoundary?.poisoned == false
                        ? journalBoundary?.sourceRetainedByteEstimate ?? Int.max
                        : Int.max
                )
            let hasPendingHeavyEnrichment = retention
                .hasPendingHeavyEnrichment
            // The same ARC lease is also held by DeferredEnrichmentBuffer when
            // pending; no bytes are charged twice. Keep this reference through
            // the complete local detection scope while `enrichedEvent` is live.
            let eventLoopSourceLease = retention.eventLoopSourceLease

            // Detection always runs, including attacker-shaped overflow. A
            // pressure-rejected base binds an explicit nonverified status so
            // every resulting alert preserves its bounded trigger while the
            // gap remains qualification poison. A typed poisoned admission is
            // resolved by the normal identity-bound writer verifier.
            let forcedJournalStatus: EventJournalContextStatus? =
                journalAdmission == nil ? .dropped : nil
            await EventJournalAdmissionContext.$sourceMemoryLease.withValue(
                eventLoopSourceLease
            ) {
                await EventJournalAdmissionContext.$forcedNonverifiedStatus
                    .withValue(forcedJournalStatus) {
                    await EventJournalAdmissionContext.$current.withValue(
                        journalAdmission
                    ) {
                if childAttribution.isChild {
                    await enforceAIChildBehaviorGuards(
                        state: state,
                        event: enrichedEvent,
                        aiType: childAttribution.toolType
                    )
                }
                if let resolvedAIAttribution {
                    await enforceAIFilesystemGuards(
                        state: state,
                        event: enrichedEvent,
                        attribution: resolvedAIAttribution
                    )
                }

            // === Package freshness check for install commands ===
            // v1.19.1: the registry GET reveals the package name being installed,
            // so the freshness lookup is opt-in (off by default). Read the flag
            // live from state so a SIGHUP toggle takes effect on the next event.
            if state.packageFreshnessEnabled && enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                let packages = PackageFreshnessChecker.parseInstallCommand(enrichedEvent.process.commandLine)
                if !packages.isEmpty {
                    let packageChecker = state.packageChecker
                    let alertSink = state.alertSink
                    let notifier = state.notifier
                    let behaviorScoring = state.behaviorScoring
                    let responseEngine = state.responseEngine
                    let behaviorWarmingUp = state.isWarmingUp
                    let preventionEnabled = state.preventionEnabled
                    let supplyChainGate = state.supplyChainGate
                    let packageEvent = enrichedEvent
                    // Registry intelligence can produce a detection and an
                    // explicitly enabled prevention action, so it belongs to
                    // the protection lane (not the advisory/model lane). A
                    // rejected submission degrades protection truthfully but
                    // never stalls the event consumer on Internet latency.
                    state.detectionWorkLifecycle.submit(
                        label: "package-freshness"
                    ) {
                        let results = await packageChecker.checkPackages(packages)
                        for result in results where result.riskLevel >= .medium {
                            let severity: Severity = result.riskLevel == .critical ? .critical : result.riskLevel == .high ? .high : .medium
                            let alert = Alert(
                                ruleId: "maccrab.supply-chain.fresh-package",
                                ruleTitle: "Fresh Package Installed: \(result.name) (\(result.registry.rawValue))",
                                severity: severity,
                                eventId: packageEvent.id.uuidString,
                                processPath: packageEvent.process.executable,
                                processName: packageEvent.process.name,
                                description: result.description,
                                mitreTactics: "attack.initial_access",
                                mitreTechniques: "attack.t1195.002",
                                suppressed: false
                            )
                            do {
                                if try await alertSink.submit(
                                    alert: alert,
                                    event: packageEvent
                                ) {
                                    await notifier.notify(alert: alert)
                                }
                            } catch {
                                await StorageErrorTracker.shared
                                    .recordAlertError(error)
                            }
                            await BehaviorScoreAlertEmitter.record(
                                behaviorScoring: behaviorScoring,
                                alertSink: alertSink,
                                notifier: notifier,
                                responseEngine: responseEngine,
                                event: packageEvent,
                                isWarmingUp: behaviorWarmingUp,
                                named: "fresh_package_install",
                                detail: "\(result.name) (\(result.registry.rawValue)) age: \(result.ageInDays.map { String(format: "%.1f", $0) } ?? "unknown") days",
                                forProcess: packageEvent.process.pid,
                                path: packageEvent.process.executable
                            )
                            // === Supply Chain Gate: block critical-risk packages ===
                            if preventionEnabled && result.riskLevel >= .high {
                                if let blocked = await supplyChainGate.gate(
                                    packageName: result.name,
                                    registry: result.registry.rawValue,
                                    ageInDays: result.ageInDays,
                                    riskLevel: result.riskLevel.rawValue,
                                    installerPid: packageEvent.process.pid
                                ) {
                                    let blockAlert = Alert(
                                        ruleId: "maccrab.prevention.supply-chain-blocked",
                                        ruleTitle: "BLOCKED: Package Install Killed -- \(blocked.packageName)",
                                        severity: .critical,
                                        eventId: UUID().uuidString,
                                        processPath: packageEvent.process.executable,
                                        processName: packageEvent.process.name,
                                        description: "Supply chain gate killed installer (PID \(blocked.installerPid)): \(blocked.reason)",
                                        mitreTactics: "attack.initial_access",
                                        mitreTechniques: "attack.t1195.002",
                                        suppressed: false
                                    )
                                    do {
                                        if try await alertSink.submit(
                                            alert: blockAlert,
                                            event: packageEvent
                                        ) {
                                            await notifier.notify(alert: blockAlert)
                                        }
                                    } catch {
                                        await StorageErrorTracker.shared
                                            .recordAlertError(error)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // === ClickFix: a shell/Terminal exec carrying a recently-copied
            // delivery payload (curl|bash, etc.) — the dominant 2026 macOS
            // infostealer vector that sidesteps Gatekeeper (nothing is
            // downloaded-and-launched; the user pastes and runs). correlateExec
            // returns nil unless the exec's command line carries a payload the
            // clipboard monitor recorded as delivery-shaped, so this is cheap on
            // ordinary execs.
            if let clickFix = state.clickFix,
               enrichedEvent.eventCategory == .process, enrichedEvent.eventAction == "exec" {
                if let match = await clickFix.correlateExec(
                    commandLine: enrichedEvent.process.commandLine, at: enrichedEvent.timestamp
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.clickfix.paste-and-run",
                        ruleTitle: "ClickFix: pasted shell command executed",
                        severity: .high,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: "Shell exec carried a delivery-shaped payload copied to the clipboard \(String(format: "%.0f", match.ageSeconds))s earlier (ClickFix paste-and-run). Payload: \(match.clipboardPayload.prefix(200))",
                        mitreTactics: "attack.execution,attack.initial_access",
                        mitreTechniques: "attack.t1059.004,attack.t1204",
                        suppressed: false
                    )
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }
            }

            // v1.21.4: UEBA (per-user entity behaviour analytics). Feeds
            // process events into the per-user baseline; once a user is past
            // the cold-start window (100 obs), off-hours activity, first-seen
            // SSH source IPs, and novel tool executions surface as anomalies
            // routed to the standard alert sink. nil (the default — see
            // DaemonConfig.uebaEnabled) short-circuits before any actor hop.
            // observe() itself self-filters to exec/fork process events; the
            // category guard here just avoids the hop on the file firehose.
            if let ueba = state.uebaEngine,
               enrichedEvent.eventCategory == .process {
                let anomalies = await ueba.observe(event: enrichedEvent)
                for anomaly in anomalies {
                    let alert = Alert(
                        ruleId: anomaly.alertRuleId,
                        ruleTitle: anomaly.alertTitle,
                        severity: anomaly.severity,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: anomaly.detail,
                        mitreTactics: anomaly.mitreTactics,
                        mitreTechniques: anomaly.mitreTechniques
                    )
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }
            }

            // === Notarization check for executed binaries ===
            //
            // PERF (v1.17): spctl --assess is expensive (forks a process). It must
            // NEVER be awaited on the event pump. Cache-first inline: warm-cache execs
            // (and all system binaries) resolve synchronously with zero fork. On a cold
            // miss, the authoritative check — which warms the LRU cache for next time
            // and preserves the 5-concurrent rate limiter inside the actor — runs in a
            // bounded derived-work task off the hot path, where it also drives the behavior
            // indicator + sandbox prevention AND emits the revoked-cert alert on
            // first exec (see below). v1.17.2: the `notarization.status`
            // enrichment IS now read by detection — the RuleEngine
            // NotarizationStatus resolver prefers it (carries 'revoked'), and
            // Rules/defense_evasion/developer_cert_revoked.yml keys on it. On a
            // cold first-seen exec the enrichment is absent, so the YAML rule
            // can't fire yet; the detached check below covers that first exec
            // for the security-critical 'revoked' case specifically. Cached
            // values were already stamped before immutable base admission.
            if enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                // Capture only Sendable values — never the non-Sendable DaemonState.
                let execPath = enrichedEvent.process.executable
                let procPid = enrichedEvent.process.pid
                let procName = enrichedEvent.process.name
                let eventId = enrichedEvent.id.uuidString
                let isAppleSigned = enrichedEvent.process.codeSignature?.signerType == .apple
                let codeSignatureResolved = DeferredEventEnrichment.coverageState(
                    for: .codeSignature,
                    in: enrichedEvent
                ) == nil
                let preventionEnabled = state.preventionEnabled
                let notarizationChecker = state.notarizationChecker
                let behaviorScoring = state.behaviorScoring
                let sandboxAnalyzer = state.sandboxAnalyzer
                let alertSink = state.alertSink
                let notifier = state.notifier
                let responseEngine = state.responseEngine
                let behaviorWarmingUp = state.isWarmingUp
                let detachedEvent = enrichedEvent
                await state.detectionWorkLifecycle.submitOrRunInlineOnOverload(
                    label: "notarization-check"
                ) {
                    let notarResult = await notarizationChecker.check(binaryPath: execPath)

                    // v1.17.2: a REVOKED Developer-ID cert (spctl 'revoked') is
                    // near-certainly malicious (AMOS/Atomic Stealer post-takedown).
                    // The developer_cert_revoked YAML rule keys on the enriched
                    // notarization.status, but that enrichment is only present on
                    // the SYNCHRONOUS hot path once the spctl cache is warm — on a
                    // binary's FIRST execution (the moment that matters) the cache
                    // is cold and the rule can't fire. This detached check is the
                    // authoritative spctl assessment, so emit the critical alert
                    // here directly on first exec. Independent of preventionEnabled
                    // (it's detection, not prevention).
                    if notarResult.status == .revoked {
                        let alert = Alert(
                            ruleId: "maccrab.notarization.cert-revoked",
                            ruleTitle: "Execution of Binary With Revoked Developer Certificate",
                            severity: .critical,
                            eventId: eventId,
                            processPath: execPath,
                            processName: procName,
                            description: "\(execPath) is signed with a Developer ID certificate that Apple has REVOKED — it would not clear Gatekeeper on a fresh launch. Apple revokes Developer ID certs when the signed software is confirmed malicious.",
                            mitreTactics: "attack.defense_evasion",
                            mitreTechniques: "attack.t1553.001",
                            suppressed: false
                        )
                        do {
                            if try await alertSink.submit(alert: alert, event: detachedEvent) {
                                await notifier.notify(alert: alert)
                            }
                        } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                        return
                    }

                    // nil while heavyweight signing evidence is pending or
                    // unavailable is unknown, not "not Apple signed". Revocation
                    // above remains authoritative from spctl; the weaker
                    // not-notarized indicator and sandbox authority fail closed.
                    guard notarResult.status == .notNotarized,
                          codeSignatureResolved,
                          !isAppleSigned else { return }
                    await BehaviorScoreAlertEmitter.record(
                        behaviorScoring: behaviorScoring,
                        alertSink: alertSink,
                        notifier: notifier,
                        responseEngine: responseEngine,
                        event: detachedEvent,
                        isWarmingUp: behaviorWarmingUp,
                        named: "not_notarized",
                        detail: execPath,
                        forProcess: procPid,
                        path: execPath
                    )

                    // === Prevention: sandbox-analyze unnotarized binaries from Downloads/tmp ===
                    if preventionEnabled && SandboxAnalyzer.dynamicExecutionEnabled {
                        if execPath.contains("/Downloads/") || execPath.contains("/tmp/") || execPath.contains("/Users/Shared/") {
                            if let analysis = await sandboxAnalyzer.analyze(binaryPath: execPath) {
                                if analysis.isSuspicious {
                                    let alert = Alert(
                                        ruleId: "maccrab.prevention.sandbox-suspicious",
                                        ruleTitle: "Sandbox Analysis: Suspicious Behavior Detected",
                                        severity: .critical,
                                        eventId: eventId,
                                        processPath: execPath,
                                        processName: procName,
                                        description: "Unnotarized binary from \(execPath) attempted blocked operations in sandbox: \(analysis.blockedOperations.prefix(3).joined(separator: "; "))",
                                        mitreTactics: "attack.execution",
                                        mitreTechniques: "attack.t1204",
                                        suppressed: false
                                    )
                                    do {
                                        if try await alertSink.submit(alert: alert, event: detachedEvent) {
                                            await notifier.notify(alert: alert)
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
                // v1.18 (RC live-test fix): recover the domain for an IP-only
                // connection from the DNS reverse cache. AI tools resolve
                // api.anthropic.com / github.com via DNS (captured by DNSCollector)
                // and then connect by IP, so destinationHostname is usually nil at
                // the connection event. Without this the sandbox can't match the
                // domain allowlist and the wellKnownCloudPrefixes fallback misses
                // the AWS/Azure/Akamai ranges these APIs actually use — firing an
                // "unapproved IP" alert on every legit AI-API / GitHub call (~37/wk
                // of pure FP observed live). Recovering the domain lets the
                // allowlist match; a genuinely-unapproved host still fires (now
                // named, not a bare IP).
                var resolvedDomain = net.destinationHostname
                if resolvedDomain == nil {
                    resolvedDomain = await state.dnsCollector.domainForIP(net.destinationIp)
                }
                if let violation = await state.aiNetworkSandbox.checkConnection(
                    aiToolName: aiTool,
                    processPid: enrichedEvent.process.pid,
                    processPath: enrichedEvent.process.executable,
                    destinationIP: net.destinationIp,
                    destinationPort: net.destinationPort,
                    destinationDomain: resolvedDomain
                ) {
                    let alert = Alert(
                        ruleId: "maccrab.ai-guard.network-sandbox",
                        ruleTitle: "AI Tool Connected to Unapproved Destination",
                        // v1.18: .high → .medium. Recorded but should not banner
                        // at a High floor (AI subprocesses make routine outbound
                        // connections). Kept in sync with BuiltinRuleCatalog.
                        severity: .medium,
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
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: "ai_tool_unapproved_network",
                        detail: "\(violation.destinationDomain ?? violation.destinationIP):\(violation.destinationPort)",
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === Cross-process correlation ===
            // v1.21.4 perf: `recordFileEvent` drops ignored (system-noise) paths
            // as its first guard — inside the actor, after an await hop. Evaluate
            // the same pure predicate here, one frame earlier, so ignored paths
            // never pay the actor hop. Detection-identical: an ignored path
            // returned nil inside the actor without mutating correlator state, so
            // skipping the call yields the same nil and the same state.
            if let file = enrichedEvent.file,
               !CrossProcessCorrelator.shouldIgnoreFilePath(file.path) {
                let action = enrichedEvent.eventAction == "exec" ? "execute" : enrichedEvent.eventAction
                if let chain = await state.crossProcessCorrelator.recordFileEvent(
                    path: file.path, action: action,
                    pid: enrichedEvent.process.pid,
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    timestamp: enrichedEvent.timestamp
                ) {
                    // Dedup on the SHARED FILE (not the triggering executable) —
                    // mirror of the network path's dedup on destination below.
                    // A cross-process file chain is defined by the file every
                    // process converged on; keying dedup on the executable (the
                    // AlertSink default) leaves each converging process emitting a
                    // fresh alert as the correlator window re-evaluates — the
                    // residual the campaign wave's chainDominatedByShellUtilities
                    // widening missed (field: 1344 mostly-benign alerts). Pass
                    // that identity into AlertSink so reservation + commit stay
                    // transactional with the stored alert.
                    let ruleId = "maccrab.correlator.cross-process"
                    let dedupKey = file.path
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Cross-Process Attack Chain: \(chain.description.prefix(60))",
                        severity: chain.severity,
                        eventId: UUID().uuidString,
                        processPath: chain.events.last?.processPath,
                        processName: chain.events.last?.processName,
                        description: "Cross-process chain (\(chain.distinctPIDCount) distinct PIDs, \(chain.events.count) events, \(Int(chain.timeSpanSeconds))s): \(chain.description)",
                        mitreTactics: "attack.execution",
                        mitreTechniques: "attack.t1204",
                        suppressed: false
                    )
                    do {
                        if try await state.alertSink.submit(
                            alert: alert,
                            event: enrichedEvent,
                            dedupProcessPath: dedupKey
                        ) {
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
                        if try await state.alertSink.submit(
                            alert: alert,
                            event: enrichedEvent,
                            dedupProcessPath: dedupKey
                        ) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }
            }

            // === Process Tree ML: record transition and check for anomalies ===
            if enrichedEvent.eventCategory == .process && enrichedEvent.eventAction == "exec" {
                let parentName = enrichedEvent.process.ancestors.first?.name ?? "unknown"
                let childName = enrichedEvent.process.name
                if let logProb = processTreeLogProbability {
                    if logProb < -8.0 {
                        await BehaviorScoreAlertEmitter.record(
                            state: state,
                            event: enrichedEvent,
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
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: finding.kind.rawValue,
                        detail: finding.detail,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
            }

            // === DYLD injection detection ===
            let cmdline = enrichedEvent.process.commandLine.lowercased()
            let args = enrichedEvent.process.args.joined(separator: " ").lowercased()
            if cmdline.contains("dyld_insert_libraries") || args.contains("dyld_insert_libraries") {
                await BehaviorScoreAlertEmitter.record(
                    state: state,
                    event: enrichedEvent,
                    named: "library_injection",
                    detail: "DYLD_INSERT_LIBRARIES in command/env",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
            }

            // === Launch-shape statistical + entropy analysis ===
            // Argument shape and command-line entropy describe one process
            // launch, not every later file/network event emitted by that same
            // process. The old per-event path trained and scored the identical
            // command line thousands of times during file churn, wasting CPU
            // and teaching delivery mix as behavior. Evaluate exactly once on
            // exec and abstain from frequency inference while upstream loss or
            // sampling means launch timing is not known complete.
            let isProcessExec = enrichedEvent.eventCategory == .process
                && enrichedEvent.eventAction.caseInsensitiveCompare("exec") == .orderedSame
            if isProcessExec {
                let commandLineEntropy = EntropyAnalysis.shannonEntropy(
                    enrichedEvent.process.commandLine
                )
                let anomalies = await state.statisticalDetector.processEvent(
                    processPath: enrichedEvent.process.executable,
                    argCount: enrichedEvent.process.args.count,
                    commandLine: enrichedEvent.process.commandLine,
                    category: enrichedEvent.eventCategory.rawValue,
                    timestamp: enrichedEvent.timestamp,
                    commandLineEntropy: commandLineEntropy,
                    binaryIdentity: Self.statisticalBinaryIdentity(
                        for: enrichedEvent.process
                    ),
                    timingCoverageComplete: false
                )
                for anomaly in anomalies {
                    let indicator = anomaly.feature == "event_frequency"
                        ? "statistical_frequency_anomaly"
                        : "statistical_process_shape_anomaly"
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: indicator,
                        detail: "\(anomaly.feature) z=\(String(format: "%.1f", anomaly.zScore))",
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }

                if !enrichedEvent.process.commandLine.isEmpty {
                    let (entropy, suspicious, _) = EntropyAnalysis.analyzeCommandLine(
                        enrichedEvent.process.commandLine,
                        fullEntropy: commandLineEntropy
                    )
                    if suspicious {
                        await BehaviorScoreAlertEmitter.record(
                            state: state,
                            event: enrichedEvent,
                            named: "high_entropy_commandline",
                            detail: "entropy=\(String(format: "%.2f", entropy))",
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                }
            }

            // === Threat Intel + CT enrichment ===
            if let net = enrichedEvent.network {
                // Certificate Transparency check on destination domains
                if let host = net.destinationHostname {
                    // v1.19.1: the crt.sh GET reveals the destination domain, so
                    // it is opt-in (off by default). The local typosquat check
                    // below makes NO network request and runs regardless. The
                    // remote lookup is advisory and must never hold the event
                    // consumer behind Internet latency.
                    if state.certTransparencyEnabled {
                        let pid = enrichedEvent.process.pid
                        let processPath = enrichedEvent.process.executable
                        let ctMonitor = state.ctMonitor
                        let behaviorScoring = state.behaviorScoring
                        let alertSink = state.alertSink
                        let notifier = state.notifier
                        let responseEngine = state.responseEngine
                        let ctEvent = enrichedEvent
                        let behaviorWarmingUp = state.isWarmingUp
                        state.advisoryWorkLifecycle.submit(
                            label: "cert-transparency"
                        ) {
                            if let ctResult = await ctMonitor
                                .checkDomain(host), ctResult.isSuspicious {
                                await BehaviorScoreAlertEmitter.record(
                                    behaviorScoring: behaviorScoring,
                                    alertSink: alertSink,
                                    notifier: notifier,
                                    responseEngine: responseEngine,
                                    event: ctEvent,
                                    isWarmingUp: behaviorWarmingUp,
                                    named: "suspicious_certificate",
                                    detail: ctResult.reason ?? host,
                                    forProcess: pid,
                                    path: processPath
                                )
                            }
                        }
                    }
                    // Typosquatting check
                    let (isTypo, typoReason) = await state.ctMonitor.isTyposquat(host)
                    if isTypo {
                        await BehaviorScoreAlertEmitter.record(
                            state: state,
                            event: enrichedEvent,
                            named: "typosquat_domain",
                            detail: typoReason ?? host,
                            forProcess: enrichedEvent.process.pid,
                            path: enrichedEvent.process.executable
                        )
                    }
                }
            }

            // === App privacy audit: track network connections per process ===
            if let net = enrichedEvent.network {
                // FF-09: NO collector ever populates `destinationHostname` — the
                // only writer in the whole codebase is the event re-wrap further
                // down this same function — so passing it straight through handed
                // the auditor `domain: nil` on EVERY connection. That made
                // `trackingContact` structurally unreachable: it counts only
                // records with a non-nil domain against the 70+ entry
                // tracking-domain registry, so `maccrabctl privacy` could never
                // report a finding while reassuring the user "the auditor runs
                // hourly". Fall back to the DNS reverse-cache domain resolved a
                // few lines above — the same recovery the AI network sandbox
                // already does at its `resolvedDomain` site.
                await state.appPrivacyAuditor.recordConnection(
                    processName: enrichedEvent.process.name,
                    processPath: enrichedEvent.process.executable,
                    domain: net.destinationHostname ?? enrichedEvent.enrichments["dns.resolved_domain"],
                    ip: net.destinationIp,
                    port: net.destinationPort
                )
            }

            // Check process hash, network IPs, and domains against known-bad IOCs
            if let net = enrichedEvent.network {
                if await state.threatIntel.isIPMalicious(net.destinationIp) {
                    // v1.17: durable structured alert (was indicator-only).
                    let record = await state.threatIntel.recordForIP(net.destinationIp)
                    let (desc, hint) = iocMatchStrings(
                        record: record,
                        value: net.destinationIp,
                        type: "ip",
                        hit: "Outbound connection to"
                    )
                    let alert = Alert(
                        ruleId: "maccrab.threat-intel.ip-match",
                        ruleTitle: "Connection to Known Malicious IP",
                        severity: .critical,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: desc,
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1071",
                        suppressed: false,
                        remediationHint: hint
                    )
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: "known_malicious_ip",
                        detail: net.destinationIp,
                        forProcess: enrichedEvent.process.pid,
                        path: enrichedEvent.process.executable
                    )
                }
                if let host = net.destinationHostname, await state.threatIntel.isDomainMalicious(host) {
                    // v1.17: durable structured alert (was indicator-only).
                    let record = await state.threatIntel.recordForDomain(host)
                    let (desc, hint) = iocMatchStrings(
                        record: record,
                        value: host,
                        type: "domain",
                        hit: "Outbound connection to"
                    )
                    let alert = Alert(
                        ruleId: "maccrab.threat-intel.domain-match",
                        ruleTitle: "Connection to Known Malicious Domain",
                        severity: .critical,
                        eventId: enrichedEvent.id.uuidString,
                        processPath: enrichedEvent.process.executable,
                        processName: enrichedEvent.process.name,
                        description: desc,
                        mitreTactics: "attack.command_and_control",
                        mitreTechniques: "attack.t1071.001",
                        suppressed: false,
                        remediationHint: hint
                    )
                    do {
                        if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                            await state.notifier.notify(alert: alert)
                        }
                    } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
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
                // v1.17: carry the matched IOC's source/family/first-seen.
                let record = await state.threatIntel.recordForHash(cdhash)
                let (desc, hint) = iocMatchStrings(
                    record: record,
                    value: cdhash,
                    type: "hash",
                    hit: "Process binary CDHash"
                )
                let alert = Alert(
                    ruleId: "maccrab.threat-intel.hash-match",
                    ruleTitle: "Known Malicious Binary (CDHash Match)",
                    severity: .critical,
                    eventId: enrichedEvent.id.uuidString,
                    processPath: enrichedEvent.process.executable,
                    processName: enrichedEvent.process.name,
                    description: desc,
                    mitreTactics: "attack.execution",
                    mitreTechniques: "attack.t1204",
                    suppressed: false,
                    remediationHint: hint
                )
                do {
                    if try await state.alertSink.submit(alert: alert, event: enrichedEvent) {
                        await state.notifier.notify(alert: alert)
                    }
                } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                await BehaviorScoreAlertEmitter.record(
                    state: state,
                    event: enrichedEvent,
                    named: "known_malicious_hash",
                    detail: "CDHash: \(cdhash)",
                    forProcess: enrichedEvent.process.pid,
                    path: enrichedEvent.process.executable
                )
            }

            // === DYLD injection via environment variables (from eslogger) ===
            if let dyldEnv = enrichedEvent.enrichments["exec.dyld_env"] {
                await BehaviorScoreAlertEmitter.record(
                    state: state,
                    event: enrichedEvent,
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
                    destinationHostname: net.destinationHostname,
                    aiTool: enrichedEvent.enrichments["ai_tool"].flatMap(AIToolType.init(rawValue:)),
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
               let filePath = enrichedEvent.file?.path,
               FileInjectionScanner.isEligible(
                   path: filePath,
                   eventAction: enrichedEvent.eventAction
               ) {
                let scanner = state.fileInjectionScanner
                let alertSink = state.alertSink
                let notifier = state.notifier
                let scanEvent = enrichedEvent
                state.detectionWorkLifecycle.submit(
                    label: "file-injection-scan"
                ) {
                    if let scanResult = await scanner.scanFile(
                        path: filePath,
                        eventAction: scanEvent.eventAction
                    ) {
                        let alert = Alert(
                            ruleId: "maccrab.ai-guard.file-injection",
                            ruleTitle: "Prompt Injection in File: \((filePath as NSString).lastPathComponent)",
                            severity: scanResult.severity,
                            eventId: scanEvent.id.uuidString,
                            processPath: scanEvent.process.executable,
                            processName: scanEvent.process.name,
                            description: "Hidden prompt injection detected in \(filePath) (\(scanResult.confidence)% confidence). Threats: \(scanResult.threats.joined(separator: "; "))",
                            mitreTactics: "attack.initial_access",
                            mitreTechniques: "attack.t1195.002",
                            suppressed: false
                        )
                        do {
                            if try await alertSink.submit(
                                alert: alert,
                                event: scanEvent
                            ) {
                                await notifier.notify(alert: alert)
                            }
                        } catch {
                            await StorageErrorTracker.shared
                                .recordAlertError(error)
                        }
                    }
                }
            }

            // Phase-6 untrusted-content taint was resolved before immutable
            // base admission. The graph bridge below consumes that frozen bit;
            // no post-alert Event mutation is permitted here.

            // === Behavioral scoring: process-level indicators ===
            let proc = enrichedEvent.process
            let codeSignatureResolved = DeferredEventEnrichment.coverageState(
                for: .codeSignature,
                in: enrichedEvent
            ) == nil
            if codeSignatureResolved,
               proc.codeSignature == nil || proc.codeSignature?.signerType == .unsigned {
                // v1.19.1 (audit): legitimately-unsigned DEVELOPER tooling
                // (node_modules CLIs like esbuild, the Swift/Xcode toolchain,
                // Homebrew, AI agents) dominated the dev-endpoint false-positive
                // rate via "unsigned == suspicious". The unsigned-binary indicator
                // is for UNEXPECTED unsigned execs, not the dev toolchain — skip it
                // on dev-tooling paths. Genuinely-suspicious unsigned binaries
                // (in /tmp, downloads, random paths) are NOT dev-tooling paths and
                // still get the full indicator, plus the /tmp-exec / persistence
                // indicators below fire regardless, so real threats aren't blinded.
                // rc.9 review: rather than fully SKIP on dev paths, add a REDUCED
                // -weight variant (1.0 vs 3.0) so a malicious binary PLANTED in
                // node_modules / homebrew still accrues compound score.
                if CampaignDetector.isDevelopmentToolingPath(proc.executable) {
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: "unsigned_dev_tooling", detail: proc.executable,
                        forProcess: proc.pid, path: proc.executable
                    )
                } else {
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: "unsigned_binary", detail: proc.executable,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
            }
            if proc.executable.contains("/tmp/") || proc.executable.contains("/private/tmp/") {
                await BehaviorScoreAlertEmitter.record(
                    state: state,
                    event: enrichedEvent,
                    named: "executed_from_tmp", detail: proc.executable,
                    forProcess: proc.pid, path: proc.executable
                )
            }
            if let file = enrichedEvent.file {
                if file.path.contains("/LaunchAgents/") {
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: "writes_launch_agent", detail: file.path,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
                if file.path.contains("/LaunchDaemons/") {
                    await BehaviorScoreAlertEmitter.record(
                        state: state,
                        event: enrichedEvent,
                        named: "writes_launch_daemon", detail: file.path,
                        forProcess: proc.pid, path: proc.executable
                    )
                }
            }

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
            // walk runs in the bounded, joinable derived-work plane. Pre-fix,
            // a burst of anchor materializations (one `npm install` can
            // fire dozens) would serialize on the single causalStore
            // SQLite actor — same actor that handles every event/edge
            // insertion — and head-of-line-block the main event pump.
            // The work stays off the hot path, while daemon shutdown now owns
            // and joins every task before the alert sink is sealed.
            if let bridge = state.causalGraphBridge {
                let materialized = await bridge.process(enrichedEvent)
                if !materialized.isEmpty,
                   let evaluator = state.currentGraphEvaluator(),
                   let store = state.causalStore {
                    let traceList = materialized
                    let anchorEventId = enrichedEvent.id.uuidString
                    let anchorProcPath = enrichedEvent.process.executable
                    let anchorProcName = enrichedEvent.process.name
                    let anchorEvent = enrichedEvent
                    let alertSink = state.alertSink
                    await state.detectionWorkLifecycle.submitOrRunInlineOnOverload(
                        label: "graph-rule-evaluation"
                    ) {
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

                                // v1.21.4: record the graph-rule → trace hit in
                                // trace_rule_hits. Two payoffs: (1) durable
                                // provenance — which graph rule fired against which
                                // trace, with the full node bindings; (2) it gives
                                // `recordRuleHit` its first production caller, so the
                                // retention sweep's orphan-guard forward-proofing
                                // (SQLiteCausalGraphStore.{edge,entity}OrphanGuardSQL,
                                // STG-1/F5) — which already excludes rows referenced
                                // by matched_entity_id / matched_edge_id — now
                                // actually pins the primary entity/edge a surviving
                                // hit points at. Best-effort: a store-write failure
                                // must never disturb the detection path.
                                let ruleHitExplanation: String = {
                                    let obj: [String: Any] = [
                                        "bindings": match.bindings,
                                        "matched_edge_ids": match.matchedEdgeIds,
                                        "attack": match.attack,
                                    ]
                                    if let data = try? JSONSerialization.data(
                                        withJSONObject: obj, options: [.sortedKeys]
                                    ), let s = String(data: data, encoding: .utf8) {
                                        return s
                                    }
                                    return "{}"
                                }()
                                let ruleHit = TraceRuleHit(
                                    id: UUID().uuidString,
                                    traceId: trace.id,
                                    ruleId: match.ruleId,
                                    ruleTitle: match.ruleTitle,
                                    ruleVersion: trace.rulesetVersion,
                                    severity: match.severity,
                                    matchedEventId: anchorEventId,
                                    matchedEntityId: match.bindings.values.sorted().first,
                                    matchedEdgeId: match.matchedEdgeIds.sorted().first,
                                    matchedAt: trace.createdAt,
                                    explanationJson: ruleHitExplanation
                                )
                                try? await store.recordRuleHit(ruleHit)
                            }
                        }
                    }
                }
            }

            // v1.12.0 — Bayesian-style intent advisory update. Each event
            // is mapped to zero-or-more Evidence values; the engine
            // accumulates bounded per-process-tree evidence and we emit an
            // alert only when the top non-benign normalized score crosses 0.85
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
            if let posterior = latestIntentPosterior,
               posterior.observationAddedIndependentEvidence,
               posterior.topGoal != .benign,
               posterior.topProbability >= state.intentPosteriorThreshold,
               posterior.distinctEvidenceCount
                    >= state.intentPosteriorMinDistinctEvidence {
                let goalLabel = String(describing: posterior.topGoal)
                let alert = Alert(
                    ruleId: "maccrab.intent.bayesian-posterior",
                    ruleTitle: "Intent advisory score crossed threshold (\(goalLabel))",
                    severity: posterior.topProbability >= 0.95
                        ? .high : .medium,
                    eventId: enrichedEvent.id.uuidString,
                    processPath: enrichedEvent.process.executable,
                    processName: enrichedEvent.process.name,
                    description: "Uncalibrated normalized advisory score for \(goalLabel) is \(String(format: "%.2f", posterior.topProbability)) for intent scope \(posterior.treeKey), based on \(posterior.distinctEvidenceCount) independent evidence types (\(posterior.evidenceLog.map { $0.rawValue }.sorted().joined(separator: ", "))). This is a deterministic ranking signal, not an empirical probability.",
                    mitreTactics: nil,
                    mitreTechniques: nil
                )
                do {
                    _ = try await state.alertSink.submit(
                        alert: alert,
                        event: enrichedEvent
                    )
                } catch {
                    await StorageErrorTracker.shared.recordAlertError(error)
                }
            }

            // v1.12.0 — IntentClassifier verdict stamp. On a package-
            // manager install exec, build a BehaviorBrief from the
            // Bayesian engine's per-scope evidence log + the current
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
            // need the brief to see the intent scope's historical evidence
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
            if let brief = intentBrief,
               let heuristicResult = intentHeuristicResult {
                let refinementScope = intentRefinementScope
                if let refinement = intentCachedRefinement {
                    let advisoryLabels: Set<String> = [
                        IntentClassifier.IntentLabel.credentialHarvest.rawValue,
                        IntentClassifier.IntentLabel.exfiltration.rawValue,
                        IntentClassifier.IntentLabel.persistence.rawValue,
                        IntentClassifier.IntentLabel.destructive.rawValue,
                        IntentClassifier.IntentLabel.lateralMovement.rawValue,
                    ]
                    if advisoryLabels.contains(refinement.label),
                       refinement.confidence >= 0.5 {
                        let advisory = Alert(
                            ruleId: "maccrab.llm.intent-refinement.\(refinement.label)",
                            ruleTitle: "Model advisory: package intent requires review",
                            severity: .informational,
                            eventId: enrichedEvent.id.uuidString,
                            processPath: enrichedEvent.process.executable,
                            processName: enrichedEvent.process.name,
                            description: "Uncalibrated model score \(String(format: "%.2f", refinement.confidence)) labeled this bounded behavior brief \(refinement.label). Deterministic label remains \(heuristicResult.label.rawValue); the model result cannot authorize response or lower deterministic severity.",
                            mitreTactics: nil,
                            mitreTechniques: nil
                        )
                        let advisoryEvent = enrichedEvent
                        let alertSink = state.alertSink
                        state.advisoryWorkLifecycle.submit(
                            label: "intent-model-advisory"
                        ) {
                            do {
                                _ = try await alertSink.submit(
                                    alert: advisory,
                                    event: advisoryEvent
                                )
                            } catch {
                                await StorageErrorTracker.shared
                                    .recordAlertError(error)
                            }
                        }
                    }
                }
                // The rule-facing high-confidence bit and all other intent
                // fields were stamped before immutable base admission.

                // v1.12.6 (wire-the-orphans Wave 3A): LLM-aware
                // tie-breaker. The synchronous heuristic above stays
                // the source of truth for the current event — we never
                // block the hot path waiting on the LLM. But for
                // AI-attributed installs where the heuristic was
                // ambiguous, we dispatch a bounded background classification so
                // the next identical install observation in the same
                // AI session sees a refined verdict. Cost is bounded by:
                //
                //   1. AI attribution required — non-AI installs run
                //      heuristic only, matching prior behaviour.
                //   2. Heuristic must be < 0.7 confident — confident
                //      heuristic verdicts skip the LLM entirely. This
                //      is the standard "LLM is a tie-breaker, not a
                //      default classifier" pattern.
                //   3. IntentRefinementCache acts as a per-session +
                //      BehaviorBrief cooldown (10-min TTL). Distinct packages
                //      never share a verdict, while repeat observations of the
                //      same install reuse one classification.
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
                if isAITriggered,
                   heuristicResult.confidence < 0.7,
                   let refinementScope,
                   let generation = await state.intentRefinementCache.begin(scope: refinementScope) {
                    let classifier = state.intentClassifier
                    let cache = state.intentRefinementCache
                    let capturedBrief = brief
                    let capturedScope = refinementScope
                    let submitted = state.advisoryWorkLifecycle.submit(
                        label: "intent-refinement"
                    ) { @Sendable in
                        let llmResult = await classifier.classify(capturedBrief)
                        // Treat .unknown / heuristic-fallback as
                        // "no useful refinement" — they wouldn't
                        // improve the next event's verdict. The admitted
                        // generation still owns the cooldown until TTL expiry.
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
                        _ = await cache.recordResult(
                            scope: capturedScope,
                            token: generation,
                            refinement: refinement
                        )
                    }
                    if !submitted {
                        _ = await cache.cancelBeforeDispatch(
                            scope: capturedScope,
                            token: generation
                        )
                    }
                }

                // v1.12.0 post-audit (M-Int1): when the install was
                // initiated by an AI coding agent (claude / codex /
                // cursor / etc.), also run PromptIntentBridge.
                // It correlates the AI agent's recent context reads
                // with the package being installed and can produce a direct,
                // review-only slopsquat/context alert. It does not stamp a
                // durable session enrichment or claim to reconstruct the raw
                // prompt. Runs in the bounded advisory plane because the
                // bridge may read up to 32 context files.
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
                    // Consume the tracker-owned root stamped during AI
                    // attribution. Re-walking by executable shape selected a
                    // nested Codex/Claude descendant instead of the active root,
                    // so PromptIntentBridge queried a lineage session that did
                    // not exist.
                    let aiPid = enrichedEvent.enrichments["ai_root_pid"]
                        .flatMap { Int32($0) } ?? enrichedEvent.process.pid
                    let pkgName = brief.packageName
                    let bridge = state.promptIntentBridge
                    let alertSink = state.alertSink
                    let anchorEvent = enrichedEvent
                    let aiPidCaptured = aiPid
                    // Prompt/file-context correlation is advisory. It must not
                    // consume the security-decision lane or fall back inline
                    // to as many as 32 file reads when that lane is saturated.
                    // Advisory lifecycle telemetry makes overload shedding
                    // visible without delaying deterministic rule evaluation.
                    state.advisoryWorkLifecycle.submit(
                        label: "prompt-intent"
                    ) {
                        let verdict = await bridge.analyzeInstall(
                            aiPid: aiPidCaptured,
                            packageName: pkgName,
                            // A package-install observation is not itself a
                            // measured destructive action. Passing zero keeps
                            // injection/destructive labels abstained until a
                            // separate evidence source supplies real scope.
                            destructiveBlastRadius: 0
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
                            description: "PromptIntentBridge classified install of \(pkgName) as \(verdict.label.rawValue) (uncalibrated heuristic score \(String(format: "%.2f", verdict.confidence))). Reasons: \(verdict.reasons.joined(separator: "; "))",
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

            // Event-level boundary telemetry: exactly one reached mark before
            // RuleEngine starts and one completed mark after both stateless and
            // sequence rule actors return. These are not per-rule/per-match
            // counters and never contain event-derived labels.
            state.eventPipelineTelemetry.recordRuleEvaluationReached(
                lane: lane,
                category: enrichedEvent.eventCategory
            )

            // Layer 1: Single-event Sigma rules
            var primaryMatches = await state.ruleEngine.evaluate(enrichedEvent)

            // Layer 2: Temporal sequence rules (Phase 2)
            let sequenceMatches = await state.sequenceEngine.evaluate(enrichedEvent)
            primaryMatches.append(contentsOf: sequenceMatches)
            state.eventPipelineTelemetry.recordRuleEvaluationCompleted(
                lane: lane,
                category: enrichedEvent.eventCategory
            )

            // Layer 3: Baseline anomaly detection (Phase 3)
            // Gate the actor hop with the same shared predicate used inside
            // BaselineEngine. ES execs are `.start` + `"exec"`; checking only
            // `.creation` left the production baseline permanently empty while
            // fixture-shaped tests stayed green.
            let baselineMatchResult = BaselineEngine.isProcessCreationEvent(enrichedEvent)
                ? await state.baselineEngine.evaluate(enrichedEvent)
                : nil
            if let baselineMatch = baselineMatchResult {
                primaryMatches.append(baselineMatch)
            }

            let reviewedDispatch = prepareReviewedMatches(
                state: state,
                event: enrichedEvent,
                primaryMatches: primaryMatches,
                sequenceMatches: sequenceMatches
            )
            enrichedEvent = reviewedDispatch.event

            if !hasPendingHeavyEnrichment {
                let terminalAdmission = await settleTerminalJournalRevision(
                    enrichedEvent,
                    lane: lane,
                    admission: journalAdmission,
                    unchangedFrom: journalBaseEvent,
                    state: state
                )
                enrichedEvent = await EventJournalAdmissionContext
                    .$terminalRevision.withValue(terminalAdmission) {
                        await dispatchReviewedMatches(
                            state: state,
                            reviewed: reviewedDispatch
                        )
                    }
            }

            // Replay cannot overtake the initial evaluation. Publish the final
            // synchronous event revision now, apply any terminal patches that
            // won the two-lane race, then drain work completed during this event.
            if hasPendingHeavyEnrichment {
                await DeferredEnrichmentDispatcher.markReadyAndDispatch(
                    event: enrichedEvent,
                    initialPrimaryMatches:
                        reviewedDispatch.primaryMatches,
                    initialSequenceMatches:
                        reviewedDispatch.sequenceMatches,
                    state: state
                )
            }
            await DeferredEnrichmentDispatcher.drainAvailable(state: state)

            // Establish the lexical lifetime after every terminal/deferred path.
            // Merely assigning the lease above would allow ARC to release it at
            // its last optimizer-visible use before the raw Event dies.
            _ = eventLoopSourceLease?.bytes

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
                }
            }
        }

        logger.info("Event stream ended. Daemon exiting.")
    }

    struct ReviewedMatchDispatch: Sendable {
        let event: Event
        let primaryMatches: [RuleMatch]
        let sequenceMatches: [RuleMatch]
    }

    /// Deterministically apply NoiseFilter and fold reviewed matches into the
    /// terminal Event without causing alerts, promotion, behavior scoring, or
    /// any other externally visible effect. Callers must journal that exact
    /// returned Event before passing the value to `dispatchReviewedMatches`.
    static func prepareReviewedMatches(
        state: DaemonState,
        event sourceEvent: Event,
        primaryMatches initialPrimaryMatches: [RuleMatch],
        sequenceMatches: [RuleMatch]
    ) -> ReviewedMatchDispatch {
        var event = sourceEvent
        var primaryMatches = initialPrimaryMatches
        NoiseFilter.apply(
            &primaryMatches,
            event: event,
            isWarmingUp: state.isWarmingUp
        )
        primaryMatches = ReviewedRuleMatches.normalized(primaryMatches)
        let normalizedSequenceMatches = ReviewedRuleMatches.normalized(
            sequenceMatches
        )
        event.ruleMatches = ReviewedRuleMatches.merged(
            event.ruleMatches,
            primaryMatches
        )
        if let reviewedSeverity = event.ruleMatches.map(\.severity).max(),
           reviewedSeverity > event.severity {
            event.severity = reviewedSeverity
        }
        let survivingPrimaryMatches = Set(primaryMatches)
        return ReviewedMatchDispatch(
            event: event,
            primaryMatches: primaryMatches,
            sequenceMatches: normalizedSequenceMatches.filter {
                survivingPrimaryMatches.contains($0)
            }
        )
    }

    /// The one reviewed rule-match path for both first-pass and deferred
    /// dependency-filtered evaluation. Keeping suppression, behavior scoring,
    /// durable commit, response authority, notifications, integrations,
    /// campaigns, outputs, and advisory triage behind this one function prevents
    /// deferred evidence from acquiring a smaller or less-reviewed alert path.
    static func dispatchReviewedMatches(
        state: DaemonState,
        reviewed: ReviewedMatchDispatch
    ) async -> Event {
        let event = reviewed.event
        let primaryMatches = reviewed.primaryMatches
        let survivingSequenceMatches = reviewed.sequenceMatches
        if !event.ruleMatches.isEmpty,
           EventJournalAdmissionContext.terminalRevision?.status == .verified {
            _ = await state.eventWriter.promoteProjection(
                event: event,
                reviewedMatches: event.ruleMatches,
                admission: EventJournalAdmissionContext.current
            )
        }

        // Layer 4: Behavioral scoring -- escalate score on surviving rule
        // matches. Threshold delivery has its own durable token and is
        // acknowledged only after AlertSink commits or deliberately
        // filters/collapses the composite; it is no longer appended to the
        // primary batch where a failed commit silently spent the latch.
        for match in primaryMatches {
            await BehaviorScoreAlertEmitter.recordRuleMatch(
                state: state,
                event: event,
                match: match
            )
        }

        let matches = primaryMatches

        if !matches.isEmpty {
            // Batch-collect alerts from rule matches, then insert as a single
            // transaction to reduce SQLite I/O from O(n) transactions to O(1).
            var batchAlerts: [Alert] = []
            var batchContexts: [String: EngineAlertCandidateContext] = [:]
            var batchFanOut: [String: (Alert) async -> Void] = [:]

            for match in matches {
                // Suppression + deduplication checks. Match-aware: a broad
                // path/host/rule allowlist can't silence a must-fire critical
                // (active C2 / credential-theft) detection — only an explicit
                // rule+process entry can.
                if await state.suppressionManager.isSuppressed(match: match, processPath: event.process.executable) {
                    continue
                }
                // Per-rule dedup is reserved transactionally inside
                // AlertSink.insertEngineBatch. Recording it here poisoned the
                // suppression window when the later batch commit failed.

                // NOTE: the shared alerts-emitted counter is incremented
                // INSIDE AlertSink (the single chokepoint all ~60 emission
                // paths flow through) — see AlertSink.alertCounter. The
                // pre-fix increment here counted ONLY the single-event
                // rule-match path (~16x undercount); the batch insert below
                // (insertEngineBatch) now counts these alerts, so counting
                // here too would double-count.

                // Rule severity is part of the reviewed rule contract.
                // Suppressing a prior alert is not an explicit TP/FP label
                // and cannot silently weaken later notification/response.
                let effectiveSeverity = match.severity

                var alert = Alert(
                    id: UUID().uuidString,
                    timestamp: Date(),
                    ruleId: match.ruleId,
                    ruleTitle: match.ruleName,
                    severity: effectiveSeverity,
                    eventId: event.id.uuidString,
                    processPath: event.process.executable,
                    processName: event.process.name,
                    description: match.description,
                    mitreTactics: match.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                    mitreTechniques: match.tags.filter { $0.contains("t1") }.joined(separator: ","),
                    suppressed: false
                )

                // Phase-5 delivery-provenance weld: for the handful of
                // already-precise HIGH cred/exfil triggers, attach the
                // download-origin narrative (and a suspicious-delivery flag
                // when the FP conjunction holds) as ALERT CONTEXT. Pure
                // enrichment on `alert.description` — no new alert, no
                // severity change. Runs before the alert flows to responders
                // and outputs so the context travels with it everywhere.
                if state.deliveryProvenanceWeld.isTrigger(ruleId: alert.ruleId),
                   let weld = await state.deliveryProvenanceWeld.weld(alert: alert, event: event) {
                    alert.description = weld.appended(to: alert.description)
                }

                // Phase-5 injection-evidence weld: for the shipped agent-
                // attributed cred-read / read->egress triggers, retro-scan the
                // SAME agent session's prior agent-content reads (skills /
                // hooks / config) for the shipped injection-marker set. On a
                // hit, attach the poisoned file as context AND bump severity
                // one level. Session-scoped and additive — no new alert, no
                // auto-executed response. Awaited inline (like the delivery
                // weld) so the bumped severity + context travel with THIS
                // alert to responders, notifier, outputs, and the campaign
                // detector. Plaintext-marker matching only (see
                // InjectionEvidenceWeld header on obfuscation).
                if state.injectionEvidenceWeld.isTrigger(ruleId: alert.ruleId),
                   let evidence = await state.injectionEvidenceWeld.evidence(alert: alert, event: event) {
                    alert.description = evidence.appended(to: alert.description)
                    alert.severity = evidence.bumpedSeverity(from: alert.severity)
                }

                batchAlerts.append(alert)
                batchContexts[alert.id] = EngineAlertCandidateContext(
                    match: match,
                    isSequence: survivingSequenceMatches.contains(match)
                )
                // Capture the expensive/irreversible work, but do not run it
                // until AlertSink returns this exact alert id as a committed
                // survivor. The closure shadows the candidate with the
                // post-sink alert so severity recalibration and attribution
                // are identical to the stored row.
                batchFanOut[alert.id] = { persistedAlert in
                let alert = persistedAlert
                let effectiveSeverity = persistedAlert.severity
                // Surface OS notifications for committed high/critical
                // alerts. Suppression policy is applied explicitly before
                // insertion; severity is never learned from dismissals.
                if effectiveSeverity >= .high {
                    await state.notifier.notify(alert: alert)
                }
                await state.responseEngine.execute(alert: alert, event: event)

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
                    ruleTitle: alert.ruleTitle,
                    severity: effectiveSeverity,
                    processPath: alert.processPath
                        ?? event.process.executable,
                    parentPath: event.process.ancestors.first?.executable,
                    tactics: tactics
                )

                // Campaign detection: chain alerts into higher-level patterns
                // v1.12.6 Wave 2C: surface MITRE technique tags, AI-tool
                // attribution, and the process-tree depth so the campaign
                // aggregates can be computed at persist time without a
                // cross-DB join.
                let techniqueTags = match.tags.filter { $0.contains("t1") }
                // v1.19 (S1-T4): mark trusted-subject alerts so the campaign
                // detector can exclude LOW/MEDIUM trusted/agent activity from
                // tactic-counting (HIGH/CRITICAL still feed). Same trust
                // judgement NoiseFilter uses for the must-fire floor.
                let isTrustedSubject = NoiseFilter.isTrustedSigner(event: event)
                    || NoiseFilter.isAppleSystemBinary(event: event)
                let alertSummary = CampaignDetector.AlertSummary(
                    ruleId: alert.ruleId,
                    ruleTitle: alert.ruleTitle,
                    severity: effectiveSeverity,
                    processPath: alert.processPath,
                    pid: Int(event.process.pid),
                    userId: String(event.process.userId),
                    timestamp: alert.timestamp,
                    tactics: Set(tactics),
                    mitreTechniques: Set(techniqueTags),
                    aiTool: event.enrichments["ai_tool"],
                    processTreeDepth: event.process.ancestors.count,
                    isTrustedSubject: isTrustedSubject
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
                    let campaignPersisted: Bool
                    do {
                        campaignPersisted = try await state.alertSink.submit(
                            alert: campaignAlert,
                            event: event
                        )
                    } catch {
                        await StorageErrorTracker.shared.recordAlertError(error)
                        campaignPersisted = false
                    }
                    // AlertSink is authoritative here too: a collapsed or
                    // failed campaign row cannot authorize campaign-store
                    // persistence, notification, rule generation, or LLM
                    // summaries derived from a row the operator cannot see.
                    guard campaignPersisted else { continue }

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

                    // Produce a review-only Sigma candidate from the
                    // campaign. Stable semantic fingerprints and exclusive
                    // creation prevent restart growth/clobber. Model work is
                    // advisory and may never hold this post-commit security
                    // path behind network latency.
                    let campaignAlerts = campaign.alerts.map { a in
                        (ruleId: a.ruleId, ruleTitle: a.ruleTitle, processPath: a.processPath, tactics: a.tactics, timestamp: a.timestamp)
                    }
                    let ruleGenerator = state.ruleGenerator
                    let candidateCampaignType = campaign.type.rawValue
                    state.advisoryWorkLifecycle.submit(
                        label: "rule-candidate"
                    ) {
                        _ = await ruleGenerator.generateFromCampaignEnhanced(
                            campaignType: candidateCampaignType,
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

                        state.advisoryWorkLifecycle.submit(
                            label: "campaign-llm"
                        ) {
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
                                investigationText = await llm.commentary(
                                    systemPrompt: LLMPrompts.investigationSystem,
                                    userPrompt: LLMPrompts.investigationUser(
                                        campaignType: campaignType, title: campaignTitle,
                                        severity: campaignSeverity.rawValue,
                                        tactics: campaignTactics,
                                        alerts: alertSummaries
                                    ),
                                    maxTokens: 1024, temperature: 0.3,
                                    feature: .campaignInvestigation
                                )?.response
                            }
                            // Both branches apply the central persisted-advisory
                            // validator and semantic-operation ledger before any
                            // model-authored prose reaches AlertStore.
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
                                do { _ = try await state.alertSink.submit(alert: summaryAlert, event: event) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            }

                            // Active defense recommendation (high/critical only)
                            // NOTE: Advisory only — recommendations are stored as informational
                            // alerts for human review. Actions are NEVER auto-executed.
                            if campaignSeverity == .critical || campaignSeverity == .high {
                                let context = "Campaign: \(campaignType) — \(campaignTitle)\nSeverity: \(campaignSeverity.rawValue)\nAlerts: \(alertSummaries.map { "[\($0.severity)] \($0.title) (\($0.process ?? "?"))" }.joined(separator: "; "))"
                                if let rec = await llm.commentary(
                                    systemPrompt: LLMPrompts.activeDefenseSystem,
                                    userPrompt: LLMPrompts.activeDefenseUser(alertContext: context),
                                    maxTokens: 512, temperature: 0.1,
                                    feature: .activeDefense
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
                                    do { _ = try await state.alertSink.submit(alert: recAlert, event: event) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                                }
                            }
                        }
                    }
                }

                // v1.17.4: removed the always-on inline alerts.jsonl writer.
                // It dual-wrote the file (its own 50 MB/keep-5 rotation)
                // alongside the configurable FileOutput sink (100 MB rotation)
                // — two code paths, conflicting rotation, on the same default
                // path. No code reads alerts.jsonl; AlertStore (alerts.db) is
                // the canonical, queryable alert store. Operators who want a
                // local NDJSON tail configure a `file` output (daemon_config
                // `outputs`), which flows through `state.additionalOutputs`
                // below as the single writer.

                // Webhook output (Phase 3)
                if let webhook = state.webhookOutput {
                    state.outputWorkLifecycle.submit(label: "webhook") {
                        await webhook.send(alert: alert, event: event)
                    }
                }

                // Syslog output (Phase 3)
                if let syslog = state.syslogOutput {
                    state.outputWorkLifecycle.submit(label: "syslog") {
                        await syslog.send(alert: alert)
                    }
                }

                // Phase 7 additional outputs (FileOutput, StreamOutput
                // Splunk HEC / Elastic Bulk / Datadog). Fire-and-forget
                // per sink — a slow or failing sink never blocks the
                // detection pipeline.
                for sink in state.additionalOutputs {
                    state.outputWorkLifecycle.submit(
                        label: "additional-output"
                    ) {
                        await sink.send(alert: alert, event: event)
                    }
                }
                }

            }

            // Batch insert all rule-match alerts. Routes through the
            // AlertSink chokepoint even though NoiseFilter + dedup were
            // already applied above — keeps the architectural invariant
            // (no direct AlertStore.insert outside AlertSink) intact.
            // v1.12.6 Wave 2B: pass event so AlertSink can
            // populate the schema-v5 attribution columns (user, CWD,
            // ai_tool, parent_exec, sha256, host_name) for every
            // alert in the batch — they all share the same triggering
            // event by construction.
            var persistedAlerts: [Alert] = []
            if !batchAlerts.isEmpty {
                do {
                    persistedAlerts = try await state.alertSink.insertEngineBatch(
                        alerts: batchAlerts,
                        event: event
                    )
                } catch let partial as AlertBatchInsertFailure {
                    // AlertStore uses reserve-bounded transactions, so a
                    // later chunk can fail after an earlier prefix committed.
                    // AlertSink has already committed only that prefix's dedup
                    // reservations/counters. Preserve its exact rows here so
                    // notifications, response, integrations, campaigns and
                    // LLM triage still obey the real post-commit boundary.
                    persistedAlerts = partial.committedAlerts
                    await StorageErrorTracker.shared.recordAlertError(
                        partial.underlyingError
                    )
                } catch {
                    await StorageErrorTracker.shared.recordAlertError(error)
                }
            }

            let postCommitPlan = EngineAlertPostCommit.plan(
                persistedAlerts: persistedAlerts,
                contextsByAlertID: batchContexts
            )
            // Notifications, response actions, integrations, outputs, fleet,
            // incident grouping, and campaign mutation all live inside these
            // closures. Invoke only the closures whose exact alert ids were
            // returned by AlertSink after collapse and commit.
            for committed in postCommitPlan.survivors {
                if let fanOut = batchFanOut[committed.alert.id] {
                    await fanOut(committed.alert)
                }
            }

            // Counterfactual and next-tactic engines remain available for
            // explicit analyst workflows. They are intentionally not run
            // here: one synthetic step cannot establish an observed chain,
            // enabled-at-event prevention state, or an evaluated forecast.
            // Automatic derivative alerts would therefore fabricate more
            // certainty than the retained evidence supports.

            // Automatic LLM triage is post-commit and bounded to one
            // structured investigation per triggering event. Before this
            // boundary, every high/critical candidate launched up to two
            // parse attempts before AlertSink had persisted (or collapsed)
            // it, and an extra free-form analysis call duplicated the same
            // UI purpose. A failed insert or fully collapsed batch now makes
            // no model call; a successful N-alert batch makes at most two
            // backend calls (the investigator's one parse retry).
            if let llm = state.llmService,
               let triageAlert = postCommitPlan.triageAlert {
                let capturedEvent = event
                let store = state.alertStore
                state.advisoryWorkLifecycle.submit(label: "llm-triage") {
                    if let investigation = await llm.investigate(
                        alert: triageAlert,
                        event: capturedEvent
                    ) {
                        do {
                            try await store.updateInvestigation(
                                alertId: triageAlert.id,
                                investigation: investigation
                            )
                        } catch {
                            await StorageErrorTracker.shared.recordAlertError(error)
                        }
                    }
                }
            }
        }

        return event
    }

    // NoiseFilter logic lives in MacCrabCore/Detection/NoiseFilter.swift
    // so the test target can exercise it directly. See FPRegressionTests.
}
