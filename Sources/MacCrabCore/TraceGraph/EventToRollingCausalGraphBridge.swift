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
// pipeline orchestration the lane call is one nonisolated line:
//
//     bridge.offer(event)
//
// which hands the event to a bounded queue drained by one service task
// (`runIngestService`). Since v1.22.7 the lane never awaits the graph:
// measured on an installed host, the inline `await bridge.process(event)`
// joined in-flight store writes and recovery-barrier waits (348 waits,
// 462 s total, max 85.8 s) on the detection lane and evicted lineage
// events from the merged streams. Overflow of the queue is counted, never
// silent; a latched store sheds on a nonisolated fast path.
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
import os
import os.log

/// Outcome of one lane hand-off to the bounded TraceGraph ingest queue.
public enum TraceGraphIngestHandoff: Sendable, Equatable {
    /// The event has no causal-graph mapping (category or action); it was
    /// never a graph input and is counted as skipped, not lost.
    case skippedNonGraph
    /// The store is latched; the event was shed on the nonisolated fast path.
    case shedLatched
    case queued
    /// Queued, evicting the oldest waiting event (counted as dropped).
    case queuedEvictingOldest
    /// Offered after the queue was finished; counted as terminated.
    case terminated
}

/// Exact conservation counters for the bounded lane → TraceGraph hand-off.
///
/// At a locked snapshot:
///
///     handoffs = skippedNonGraph + latchedShed + offered
///     offered  = dropped + terminated + dequeued + backlog
///     dequeued = completed + inFlight
///
/// `dropped` is an eviction from the bounded queue while the ingest service is
/// stalled behind the store. Those events never reached the rolling writer, so
/// they are deliberately outside its input/committed/failed ledger, which
/// therefore keeps conserving exactly.
public struct TraceGraphIngestQueueTelemetry: Sendable, Equatable {
    public let capacity: Int
    public let handoffsTotal: UInt64
    public let skippedNonGraphTotal: UInt64
    public let latchedShedTotal: UInt64
    public let offeredTotal: UInt64
    public let droppedTotal: UInt64
    public let terminatedTotal: UInt64
    public let dequeuedTotal: UInt64
    public let completedTotal: UInt64
    /// Offers whose yield result is not yet published; the backlog estimate
    /// conservatively includes them.
    public let handoffsInFlight: UInt64
    public let backlog: Int
    public let inFlight: Int
    public let admissionLatched: Bool
    public let admissionProbesTotal: UInt64
    public let admissionLatchArmsTotal: UInt64

    public var conservesHandoffs: Bool {
        let (partial, overflow1) = skippedNonGraphTotal
            .addingReportingOverflow(latchedShedTotal)
        let (sum, overflow2) = partial.addingReportingOverflow(offeredTotal)
        return !overflow1 && !overflow2 && handoffsTotal == sum
    }

    public var conservesOffers: Bool {
        let removed = [droppedTotal, terminatedTotal, dequeuedTotal]
            .reduce(UInt64(0)) { $0.addingReportingOverflow($1).partialValue }
        return offeredTotal >= removed
            && offeredTotal - removed == UInt64(backlog)
    }
}

public actor EventToRollingCausalGraphBridge {

    public static let defaultIngestQueueCapacity = 8_192

    private struct IngestQueueCounters {
        var handoffs: UInt64 = 0
        var skippedNonGraph: UInt64 = 0
        var latchedShed: UInt64 = 0
        var offered: UInt64 = 0
        var dropped: UInt64 = 0
        var terminated: UInt64 = 0
        var dequeued: UInt64 = 0
        var completed: UInt64 = 0
        var handoffsInFlight: UInt64 = 0
    }

    private let rollingGraph: RollingCausalGraph
    /// Bounded lane hand-off. `.bufferingNewest` keeps the most recent events
    /// during a stall, so an anchor-bearing event is the one most likely to
    /// survive; every eviction is counted in `droppedTotal`.
    public nonisolated let ingestQueueCapacity: Int
    private nonisolated let ingestQueueContinuation: AsyncStream<Event>.Continuation
    private nonisolated let ingestQueueStream: OSAllocatedUnfairLock<AsyncStream<Event>?>
    private nonisolated let ingestQueueCounters = OSAllocatedUnfairLock(
        initialState: IngestQueueCounters()
    )
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

    public init(
        rollingGraph: RollingCausalGraph,
        insertFilter: EventInsertFilter? = nil,
        ingestQueueCapacity: Int = EventToRollingCausalGraphBridge.defaultIngestQueueCapacity
    ) {
        precondition(ingestQueueCapacity > 0)
        self.rollingGraph = rollingGraph
        self.insertFilter = insertFilter
        self.ingestQueueCapacity = ingestQueueCapacity
        let (stream, continuation) = AsyncStream.makeStream(
            of: Event.self,
            bufferingPolicy: .bufferingNewest(ingestQueueCapacity)
        )
        self.ingestQueueContinuation = continuation
        self.ingestQueueStream = OSAllocatedUnfairLock(initialState: stream)
    }

    // MARK: - Bounded lane hand-off

    /// Hand one enriched event to the ingest queue. Nonisolated and
    /// non-suspending: the lane pays a schema check, one latch read, and one
    /// bounded yield. It never joins an in-flight store write and never waits
    /// on storage admission or the recovery barrier.
    @discardableResult
    public nonisolated func offer(_ event: Event) -> TraceGraphIngestHandoff {
        guard mapCategory(event.eventCategory) != nil,
              mapAction(event.eventAction) != nil else {
            ingestQueueCounters.withLock { locked in
                Self.incrementSaturating(&locked.handoffs)
                Self.incrementSaturating(&locked.skippedNonGraph)
            }
            return .skippedNonGraph
        }
        if rollingGraph.admissionShedLatch.shouldShed() {
            ingestQueueCounters.withLock { locked in
                Self.incrementSaturating(&locked.handoffs)
                Self.incrementSaturating(&locked.latchedShed)
            }
            return .shedLatched
        }
        ingestQueueCounters.withLock { locked in
            Self.incrementSaturating(&locked.handoffs)
            Self.incrementSaturating(&locked.offered)
            Self.incrementSaturating(&locked.handoffsInFlight)
        }
        let result = ingestQueueContinuation.yield(event)
        return ingestQueueCounters.withLock { locked in
            if locked.handoffsInFlight > 0 { locked.handoffsInFlight -= 1 }
            switch result {
            case .enqueued:
                return .queued
            case .dropped:
                Self.incrementSaturating(&locked.dropped)
                return .queuedEvictingOldest
            case .terminated:
                Self.incrementSaturating(&locked.terminated)
                return .terminated
            @unknown default:
                Self.incrementSaturating(&locked.terminated)
                return .terminated
            }
        }
    }

    /// Drain the ingest queue until it is finished. Runs once, on its own
    /// task, for the daemon's lifetime; materialized traces are handed to
    /// `onMaterialized` off the detection lane.
    public nonisolated func runIngestService(
        onMaterialized: @escaping @Sendable ([Trace], Event) async -> Void
    ) async {
        let stream = ingestQueueStream.withLock { locked -> AsyncStream<Event>? in
            defer { locked = nil }
            return locked
        }
        guard let stream else { return }
        for await event in stream {
            ingestQueueCounters.withLock { Self.incrementSaturating(&$0.dequeued) }
            let traces = await process(event)
            if !traces.isEmpty {
                await onMaterialized(traces, event)
            }
            ingestQueueCounters.withLock { Self.incrementSaturating(&$0.completed) }
        }
    }

    /// Stop accepting hand-offs. The service drains what is already queued
    /// and returns; later offers are counted as terminated.
    public nonisolated func finishIngestQueue() {
        ingestQueueContinuation.finish()
    }

    public nonisolated func ingestQueueTelemetry() -> TraceGraphIngestQueueTelemetry {
        let latch = rollingGraph.admissionShedLatch.snapshot()
        return ingestQueueCounters.withLock { locked in
            let removed = [locked.dropped, locked.terminated, locked.dequeued]
                .reduce(UInt64(0)) { $0.addingReportingOverflow($1).partialValue }
            let backlog = locked.offered >= removed ? locked.offered - removed : 0
            let inFlight = locked.dequeued >= locked.completed
                ? locked.dequeued - locked.completed : 0
            return TraceGraphIngestQueueTelemetry(
                capacity: ingestQueueCapacity,
                handoffsTotal: locked.handoffs,
                skippedNonGraphTotal: locked.skippedNonGraph,
                latchedShedTotal: locked.latchedShed,
                offeredTotal: locked.offered,
                droppedTotal: locked.dropped,
                terminatedTotal: locked.terminated,
                dequeuedTotal: locked.dequeued,
                completedTotal: locked.completed,
                handoffsInFlight: locked.handoffsInFlight,
                backlog: Int(clamping: backlog),
                inFlight: Int(clamping: inFlight),
                admissionLatched: latch.armed,
                admissionProbesTotal: latch.probesTotal,
                admissionLatchArmsTotal: latch.armsTotal
            )
        }
    }

    @inline(__always)
    private static func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
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
        } catch is CausalGraphStorageAdmissionError {
            // Expected fail-closed shedding. SQLiteCausalGraphStore already
            // increments telemetry and logs only block/recovery transitions;
            // a warning here for every source event would defeat that design.
            return []
        } catch {
            logger.warning("rolling graph ingest failed: \(error.localizedDescription, privacy: .public)")
            return []
        }
    }

    /// Exact rolling-writer conservation counters for heartbeat/runtime probes.
    public func writeTelemetry() async -> CausalGraphIngestionWriteTelemetry {
        await rollingGraph.writeTelemetry()
    }

    /// Establish a stable persistence boundary for lifecycle owners/probes.
    public func flushPending() async throws {
        try await rollingGraph.flushPending()
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
        //
        // AI-02: `agent_trace_id` is stamped ONLY by the traceparent pass —
        // TraceCorrelator's Pass-2 lineage fallback returns `traceId: nil` — so
        // requiring it here meant the materializer emitted an `ai_agent` entity
        // and an `associated_with_agent` edge ONLY on hosts that had configured
        // the agent's OTLP/TRACEPARENT export. On an ordinary install
        // `trace_entities` held ZERO `ai_agent` rows, which makes every graph
        // rule that declares an `ai_agent` node structurally unsatisfiable —
        // including the v1.21.4 lethal-trifecta rule.
        //
        // Fall back to the DURABLE agent-session id (`ai_tool_session_id`,
        // minted by AgentSessionRegistry and stamped by EventLoop on BOTH the
        // AI-tool root and every attributed descendant) so the lineage tier is a
        // first-class agent producer. The synthesised id is namespaced
        // (`session:`) so it can never collide with a real 32-hex W3C trace id,
        // and it is pinned to the lineage confidence (0.75 / strong_inferred) —
        // below the §11.3 assertion threshold, so AIAttributionRenderer still
        // renders it as inferred rather than as fact.
        let traceId: String
        let confidenceRaw: String
        if let correlated = enrichments[TraceCorrelator.EnrichmentKey.traceId] {
            traceId = correlated
            confidenceRaw = enrichments[TraceCorrelator.EnrichmentKey.confidence] ?? ""
        } else if let sessionId = enrichments["ai_tool_session_id"], !sessionId.isEmpty {
            traceId = "session:\(sessionId)"
            confidenceRaw = AttributionEvidence.Confidence.lineage.rawValue
        } else {
            return nil
        }
        // `agent_tool` is stamped only by TraceCorrelator; on the session
        // fallback the tool identity lives in `ai_tool` (AIProcessTracker).
        let agentTool = enrichments[TraceCorrelator.EnrichmentKey.agentTool]
            ?? enrichments["ai_tool"]
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

    // nonisolated (pure enum switch) so the lane-side `offer` can reject
    // non-graph categories before touching the queue.
    nonisolated private func mapCategory(_ category: EventCategory) -> RollingCausalGraph.NormalizedEventInput.Category? {
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
        if let fileAction = TraceGraphFileObservationPolicy.callbackAction(eventAction: action) {
            switch fileAction {
            case .read: return .fileRead
            case .write: return .fileWrite
            case .create: return .fileCreate
            case .rename: return .fileRename
            case .delete: return .fileDelete
            }
        }
        switch action.lowercased() {
        case "exec":         return .exec
        case "exit":         return .exit
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
