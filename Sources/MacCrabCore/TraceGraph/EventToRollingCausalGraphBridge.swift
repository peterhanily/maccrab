// EventToRollingCausalGraphBridge.swift
// MacCrabCore
//
// v1.10 TraceGraph (production wiring) — translates v1.9 `Event`
// into `RollingCausalGraph.NormalizedEventInput` and pumps it through
// the rolling graph.
//
// # Where this gets wired
//
// Daemon-side, after `EventEnricher` has finished annotating an
// event but before `RuleEngine` evaluates it. In `MacCrabAgentKit`'s
// pipeline orchestration the call is one line:
//
//     await bridge.process(event)
//
// The bridge is constructed once at daemon startup with the
// production `RollingCausalGraph` instance.
//
// # Notes on processKey
//
// Per §10.1 of the v1.10.0 spec, `ProcessIdentity` (and hence
// `processKey`) requires the kernel-truth `audit_token` +
// `pidversion` for full anti-recycle correctness.
//
// Since the v1.21.4 P6 fix, ES-sourced events carry the normalized
// audit identity (`pidversion`/`asid`) on `ProcessInfo.auditIdentity`
// all the way through `EventEnricher` to this bridge. When present,
// `synthesizeProcessKey` folds `pidversion` (+ `asid`) into the key so
// a recycled pid running the same executable in the same wall-clock
// second maps to a DISTINCT graph node. For non-ES sources (eslogger /
// kdebug / FSEvents dev fallback) `auditIdentity` is nil and the bridge
// falls back to `(pid, startTime_epoch_seconds, executable_path)` —
// sufficient for the non-recycled common case. An
// `enrichments["process_key"]` value, if ever set upstream, still takes
// precedence over both.

import Foundation
import CryptoKit
import os.log

public actor EventToRollingCausalGraphBridge {

    private let rollingGraph: RollingCausalGraph
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "event-bridge")

    /// Optional override: if the daemon side starts annotating events
    /// with a real `enrichments["process_key"]` value (sourced from
    /// `ProcessIdentity` at exec time), set this key so the bridge
    /// prefers it over the fallback computation.
    public static let processKeyEnrichmentKey = "process_key"
    public static let parentProcessKeyEnrichmentKey = "parent_process_key"

    /// v1.17.4 (perf): the same pre-insert noise filter the EventStore path
    /// uses. Pre-fix the causal graph ingested EVERY event — unlike
    /// EventStore, which drops self-monitoring + dev-tool scratch at insert —
    /// so the graph churned on noise that carries no detection signal and
    /// dominated daemon CPU. Given its OWN instance (not shared with
    /// EventStore) so the insert-filter drop counter stays clean.
    private let insertFilter: EventInsertFilter?

    public init(rollingGraph: RollingCausalGraph, insertFilter: EventInsertFilter? = nil) {
        self.rollingGraph = rollingGraph
        self.insertFilter = insertFilter
    }

    /// Convert a v1.9 `Event` into a `NormalizedEventInput` and ingest.
    /// Returns the materialized traces (if any) for the daemon's
    /// downstream alert sink to surface.
    @discardableResult
    public func process(_ event: Event) async -> [Trace] {
        // v1.17.4 (perf): self-gate on the noise filter before doing any
        // graph work. The graph needs none of what defaultFilter drops
        // (self-monitoring, pty/null, SQLite scratch), and ingesting it was
        // the dominant per-event CPU cost.
        if insertFilter?.shouldDrop(event: event) == true {
            return []
        }
        guard let normalized = normalize(event) else {
            return []
        }
        do {
            return try await rollingGraph.ingest(normalized)
        } catch {
            logger.warning("rolling graph ingest failed: \(error.localizedDescription, privacy: .public)")
            return []
        }
    }

    // MARK: - Translation

    private func normalize(_ event: Event) -> RollingCausalGraph.NormalizedEventInput? {
        guard let category = mapCategory(event.eventCategory) else { return nil }
        guard let action = mapAction(event.eventAction) else { return nil }

        let processObservation = makeProcessObservation(from: event.process, enrichments: event.enrichments)

        let fileObservation: RollingCausalGraph.FileObservation? = {
            guard let file = event.file else { return nil }
            // FileInfo doesn't carry sha256 in v1.9 — that lives on
            // `ProcessInfo.hashes` for the executing process. The
            // bridge omits sha256 here; downstream enrichment can
            // attach it via a future `enrichments["file_sha256"]`.
            return RollingCausalGraph.FileObservation(
                path: file.path,
                pathHash: pathHash(file.path),
                sha256: nil,
                // v1.21.4 (Phase-6 6B, leg 2): EventLoop stamps this enrichment
                // when the Phase-5 InjectionMarkerScanner flagged plaintext
                // prompt-injection markers on this agent-attributed read.
                untrustedContent: event.enrichments["untrusted_content"] == "true"
            )
        }()

        let networkObservation: RollingCausalGraph.NetworkObservation? = {
            guard let net = event.network else { return nil }
            return RollingCausalGraph.NetworkObservation(
                host: net.destinationHostname,
                ip: net.destinationIp.isEmpty ? nil : net.destinationIp,
                port: Int(net.destinationPort),
                protocolName: net.transport,
                reputation: classifyReputation(host: net.destinationHostname, ip: net.destinationIp)
            )
        }()

        let agent = makeAgentEnrichment(from: event.enrichments)

        return RollingCausalGraph.NormalizedEventInput(
            eventId: event.id.uuidString,
            timestamp: event.timestamp,
            category: category,
            action: action,
            process: processObservation,
            parentProcess: nil,   // v1.9 Event already carries ancestors[]; the rolling graph derives the parent skeleton from the ProcessLineage actor at the daemon level
            file: fileObservation,
            network: networkObservation,
            agent: agent
        )
    }

    private func makeProcessObservation(
        from info: ProcessInfo,
        enrichments: [String: String]
    ) -> RollingCausalGraph.ProcessObservation {
        let processKey = enrichments[Self.processKeyEnrichmentKey]
            ?? synthesizeProcessKey(
                pid: info.pid,
                startTime: info.startTime,
                executable: info.executable,
                auditIdentity: info.auditIdentity
            )
        let parentProcessKey = enrichments[Self.parentProcessKeyEnrichmentKey]
        return RollingCausalGraph.ProcessObservation(
            processKey: processKey,
            pid: info.pid,
            ppid: info.ppid,
            executablePath: info.executable,
            executableHash: info.hashes?.sha256,
            isAppleSigned: info.codeSignature?.signerType == .apple,
            isNotarized: info.codeSignature?.isNotarized ?? false,
            signingTeamId: info.codeSignature?.teamId,
            signingIdentifier: info.codeSignature?.signingId,
            startTime: info.startTime,
            user: info.userName.isEmpty ? nil : info.userName,
            parentProcessKey: parentProcessKey
        )
    }

    private func makeAgentEnrichment(from enrichments: [String: String]) -> RollingCausalGraph.AgentEnrichment? {
        // v1.9 TraceCorrelator emits these enrichment keys.
        guard let traceId = enrichments[TraceCorrelator.EnrichmentKey.traceId] else { return nil }
        let confidenceRaw = enrichments[TraceCorrelator.EnrichmentKey.confidence] ?? ""
        let agentTool = enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        // confidence is a categorical string in v1.9 ("traceparent" / "lineage").
        // Map to the v1.10 numeric scale.
        let (confidence, method): (Double, AttributionMethod) = {
            switch confidenceRaw {
            case "traceparent":
                // A W3C TRACEPARENT is AI-specific ONLY when an AI tool was also
                // identified (agent_tool). A BARE traceparent — the ESCollector
                // self-stamp of a process that merely INHERITED the header in its
                // env, with no AI-tool match (TraceCorrelator.selfStampEnrichments
                // sets agentTool: nil) — could come from ANY OpenTelemetry-
                // instrumented producer (CI, a distributed-tracing app), not an AI
                // agent. So it must NOT be asserted as a high-confidence AI agent:
                // without an AI-tool signal, drop below the §11.3 assertion
                // threshold (0.85) so the AIAttributionRenderer renders it as
                // inferred, not fact.
                return agentTool != nil ? (0.95, .directTraceparent) : (0.5, .temporalProximity)
            case "lineage":     return (0.75, .processLineageMatch)
            default:            return (0.5, .temporalProximity)
            }
        }()
        let displayName = agentTool?.replacingOccurrences(of: "_", with: " ").capitalized
            ?? "Unknown AI agent"
        return RollingCausalGraph.AgentEnrichment(
            agentName: displayName,
            agentTool: agentTool,
            traceId: traceId,
            spanId: enrichments[TraceCorrelator.EnrichmentKey.spanId],
            confidence: confidence,
            attributionMethod: method
        )
    }

    // MARK: - Mapping helpers

    private func mapCategory(_ category: EventCategory) -> RollingCausalGraph.NormalizedEventInput.Category? {
        switch category {
        case .process:  return .process
        case .file:     return .file
        case .network:  return .network
        case .tcc:      return .tcc
        default:        return nil
        }
    }

    // nonisolated (pure string→enum switch, no actor state) + internal so
    // the v1.17.4 file-action mapping can be pinned directly by
    // EventToRollingCausalGraphBridgeTests (ES-OPEN-3).
    nonisolated func mapAction(_ action: String) -> RollingCausalGraph.NormalizedEventInput.Action? {
        switch action.lowercased() {
        case "exec":         return .exec
        case "exit":         return .exit
        case "create":       return .fileCreate
        case "write":        return .fileWrite
        // "open" is the credential-read action emitted by ESCollector /
        // KdebugCollector NOTIFY_OPEN (v1.17.4); "read" is a legacy alias
        // no collector emits but kept so a future one maps cleanly. Without
        // these the headline credential-READ leg never enters the causal
        // substrate. (ES-OPEN-3)
        case "open", "read": return .fileRead
        // A modified-close is a completed write session; map to .fileWrite
        // (not .fileRead) so it lands on the write side of the graph.
        case "close_modified": return .fileWrite
        case "rename":       return .fileRename
        case "unlink",
             "delete":       return .fileDelete
        case "connect":      return .netConnect
        case "tcc_grant":    return .tccGrant
        default:
            return nil
        }
    }

    private func synthesizeProcessKey(
        pid: Int32,
        startTime: Date,
        executable: String,
        auditIdentity: AuditIdentity?
    ) -> String {
        // v1.21.4 anti-recycle: when the event came from Endpoint Security, the
        // P6 fix carries the kernel-truth audit identity on `ProcessInfo`. Its
        // `pidversion` (the kernel's anti-recycle counter, bumped on every exec)
        // is the discriminator the old (pid, startTime-second, executable) tuple
        // lacked — a recycled pid running the same executable inside the same
        // wall-clock second gets a DIFFERENT pidversion, so folding it in keeps
        // the two distinct processes on distinct graph nodes. `asid` (audit
        // session id) further separates processes across login sessions. Both are
        // STABLE for a process's lifetime, so every observation of the SAME
        // process still yields the SAME key. `startTime` is deliberately EXCLUDED
        // from this branch for the same reason `ProcessIdentity.processKey` omits
        // it: collector timestamp jitter would otherwise split one logical
        // process across observations.
        if let audit = auditIdentity {
            let payload = "\(pid)|\(audit.pidversion)|\(audit.asid)|\(executable)"
            return SHA256.hash(data: Data(payload.utf8))
                .map { String(format: "%02x", $0) }.joined()
        }
        // Non-ES sources (eslogger / kdebug / FSEvents dev fallback) have no
        // audit_token → fall back to (pid, startTime epoch seconds, executable),
        // sufficient for the non-recycled common case.
        let payload = "\(pid)|\(Int(startTime.timeIntervalSince1970))|\(executable)"
        return SHA256.hash(data: Data(payload.utf8))
            .map { String(format: "%02x", $0) }.joined()
    }

    private func pathHash(_ path: String) -> String {
        SHA256.hash(data: Data(path.utf8))
            .map { String(format: "%02x", $0) }.joined()
    }

    /// Tiny reputation heuristic for the bridge's translation step.
    /// The daemon's full reputation pipeline (threat intel, allowlists,
    /// etc.) lives downstream — this is a conservative seed value
    /// that the rolling graph treats as "safe to default" but
    /// downstream enrichment may upgrade.
    private func classifyReputation(host: String?, ip: String) -> NetworkReputation {
        if !ip.isEmpty {
            if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("172.") {
                return .privateRange
            }
            if ip.hasPrefix("127.") || ip == "::1" {
                return .privateRange
            }
        }
        if let host = host?.lowercased() {
            if host == "localhost" || host.hasSuffix(".local") {
                return .privateRange
            }
        }
        return .unknown
    }
}
