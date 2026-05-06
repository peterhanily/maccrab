// TraceCorrelator.swift
// MacCrabCore
//
// v1.9 Agent Traces (PR-2) — attaches AttributionEvidence + flat enrichment
// fields to events. Two passes only in v1.9:
//
//   1. Direct hit on TraceRegistry — confidence: .traceparent
//   2. Lineage fallback to a known AI binary — confidence: .lineage
//
// Temporal correlation was deliberately cut from v1.9 per Plan v2 review.
// Runs after process enrichment, before rule evaluation.
//
// Resolution order for attribution conflicts (Plan v3 review #8):
//   1. Span-name prefix (set in PR-3 once we have a TraceStore; placeholder
//      hook today — span names are not yet observed pre-OTLP-receiver).
//   2. service.name exact match (deferred to PR-3 along with the receiver).
//   3. gen_ai.provider.name (deferred to PR-3).
//   4. gen_ai.system (legacy; deferred to PR-3).
//   5. Process lineage match against AIToolRegistry (this PR's responsibility).
//
// When step 1 disagrees with step 5 (the "agent lies in spans" case),
// PR-3b will increment `attribution_conflict` and prefer lineage. The
// counter hook is in TraceRegistry.metricsSnapshot already; the OTLP-side
// half lands when the receiver does.

import Foundation
import os.log

/// Correlation result. Holds the AttributionEvidence and the flat
/// enrichment dictionary that maps onto the v4-migration columns
/// (`agent_trace_id`, `agent_span_id`, `agent_tool`,
/// `machine_agent_confidence`, `agent_evidence_json`).
public struct TraceCorrelation: Sendable, Equatable {
    public let evidence: AttributionEvidence
    public let enrichments: [String: String]
}

public enum TraceCorrelator {

    /// Enrichment keys written into `Event.enrichments`. Mirror the column
    /// names so the storage write path can flatten without a separate
    /// translation table.
    public enum EnrichmentKey {
        public static let traceId = "agent_trace_id"
        public static let spanId = "agent_span_id"
        public static let agentTool = "agent_tool"
        public static let confidence = "machine_agent_confidence"
        public static let evidenceJson = "agent_evidence_json"
    }

    /// Correlate a single event.
    ///
    /// - Parameters:
    ///   - identity: ProcessIdentity for the event's process. Caller is
    ///     expected to construct this from the ES payload — at NOTIFY_EXEC
    ///     via `ProcessIdentity(from:executablePath:)`, at later events
    ///     via the cached identity associated with the firing pid.
    ///   - ancestors: ancestor chain (parent first → root last)
    ///   - registry: TraceRegistry instance (actor)
    ///   - ancestorIdentityResolver: closure returning a `ProcessIdentity`
    ///     for an ancestor, or nil if the registry-quality identity can't
    ///     be reconstructed cheaply for that hop. Returning nil causes the
    ///     hop to be skipped (preferred over fabricating an identity and
    ///     risking a false-positive recycle hit).
    ///   - aiToolForPath: closure mapping an executable path to an
    ///     AIToolType — typically `AIToolRegistry.isAITool`. Used only by
    ///     the lineage fallback.
    /// - Returns: a `TraceCorrelation` on a hit, or nil. Nil is the common
    ///   case (most processes are not under an AI agent).
    public static func correlate(
        identity: ProcessIdentity,
        ancestors: [ProcessAncestor],
        registry: TraceRegistry,
        ancestorIdentityResolver: (ProcessAncestor) -> ProcessIdentity?,
        aiToolForPath: (String) -> AIToolType?
    ) async -> TraceCorrelation? {
        // Pass 1: direct + lineage walk against TraceRegistry.
        if let lookup = await registry.lookup(
            forIdentity: identity,
            ancestors: ancestors,
            ancestorIdentity: ancestorIdentityResolver
        ) {
            let evidence = AttributionEvidence(
                source: .traceparentEnv,
                confidence: .traceparent,
                agentTool: lookup.binding.agentTool,
                traceId: lookup.binding.context.traceId,
                spanId: lookup.binding.context.parentSpanId,
                parentSpanId: lookup.binding.context.parentSpanId,
                matchedPid: identity.pid,
                matchedAncestorPid: lookup.hopCount == 0 ? nil : lookup.matchedPid,
                hopCount: lookup.hopCount == 0 ? nil : lookup.hopCount
            )
            return TraceCorrelation(
                evidence: evidence,
                enrichments: flatten(evidence)
            )
        }

        // Pass 2: lineage fallback. No TRACEPARENT inherited (Cursor,
        // Copilot CLI, an unconfigured Claude Code) but an ancestor binary
        // matches the AIToolRegistry. Lower confidence because we're
        // attributing on shape, not on a kernel-observed env propagation.
        for (hopIndex, ancestor) in ancestors.enumerated() {
            if hopIndex >= 8 { break } // same hard cap as TraceRegistry
            guard let tool = aiToolForPath(ancestor.executable),
                  tool != .unknown else { continue }
            let evidence = AttributionEvidence(
                source: .lineageRegistry,
                confidence: .lineage,
                agentTool: tool,
                traceId: nil,
                spanId: nil,
                parentSpanId: nil,
                matchedPid: identity.pid,
                matchedAncestorPid: ancestor.pid,
                hopCount: hopIndex + 1
            )
            return TraceCorrelation(
                evidence: evidence,
                enrichments: flatten(evidence)
            )
        }

        return nil
    }

    /// Flatten an AttributionEvidence into the indexable enrichment dict
    /// the EventStore v4 migration knows how to project into columns.
    public static func flatten(_ ev: AttributionEvidence) -> [String: String] {
        var out: [String: String] = [:]
        if let trace = ev.traceId { out[EnrichmentKey.traceId] = trace }
        if let span = ev.spanId { out[EnrichmentKey.spanId] = span }
        if let tool = ev.agentTool { out[EnrichmentKey.agentTool] = tool.rawValue }
        out[EnrichmentKey.confidence] = ev.confidence.rawValue
        if let json = ev.jsonString() {
            out[EnrichmentKey.evidenceJson] = json
        }
        return out
    }

    /// Apply a `TraceCorrelation` to a mutable event. Pure helper — no
    /// async, no actor hop. Caller is expected to hold `event` by value.
    public static func apply(_ correlation: TraceCorrelation, to event: inout Event) {
        for (k, v) in correlation.enrichments {
            event.enrichments[k] = v
        }
    }
}
