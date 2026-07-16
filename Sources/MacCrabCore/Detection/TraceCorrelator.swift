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
    ///   - telemetryGapActive: true when a kernel telemetry gap (ES per-client
    ///     queue backpressure) is active for this event's window. Default false
    ///     so existing callers are unchanged. Only consulted after both
    ///     attribution passes miss — see the honest-degradation branch below.
    /// - Returns: a `TraceCorrelation` on a hit, or nil. Nil is the common
    ///   case (most processes are not under an AI agent).
    public static func correlate(
        identity: ProcessIdentity,
        ancestors: [ProcessAncestor],
        registry: TraceRegistry,
        ancestorIdentityResolver: (ProcessAncestor) -> ProcessIdentity?,
        aiToolForPath: (String) -> AIToolType?,
        telemetryGapActive: Bool = false
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

        // Honest degradation: neither pass resolved an attribution AND the
        // ancestor chain is empty AND a kernel telemetry gap is active for this
        // window — emit a telemetry-gap evidence rather than a silent nil so a
        // drop-induced attribution loss is distinguishable from a benign
        // orphan. Gated on BOTH empty ancestry and the active-drop signal
        // (mirrors the EventEnricher session gate). This evidence asserts no
        // agent — confidence `.telemetryGap` must never drive a rule. Default-
        // off (`telemetryGapActive` defaults false), so existing callers are
        // unchanged and this only fires once the daemon wires the gap signal.
        if telemetryGapActive, ancestors.isEmpty {
            let evidence = AttributionEvidence(
                source: .telemetryGap,
                confidence: .telemetryGap,
                agentTool: nil,
                traceId: nil,
                spanId: nil,
                parentSpanId: nil,
                matchedPid: identity.pid
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

    /// Build the flat enrichment dictionary for SELF-STAMPING a process's
    /// own NOTIFY_EXEC event with the W3C TRACEPARENT it inherited in its
    /// exec env block.
    ///
    /// v1.21.4 (P6 fix): the async TraceRegistry bind created from the same
    /// exec's env-scan only ever helps DESCENDANTS — the exec event of the
    /// TRACEPARENT-carrying process itself flows through the pipeline and is
    /// direct-correlated BEFORE the detached bind Task lands, so the
    /// registry lookup misses and `agent_trace_id` was never stamped on the
    /// process's OWN event. Stamping the exec event directly here (high
    /// confidence, no registry round-trip, no race) closes that gap. The
    /// NOTIFY_EXEC event represents the post-exec target image — the same
    /// process whose env carried the header — so attributing it to that
    /// trace is correct.
    ///
    /// Reuses `flatten` so the keys match the registry-correlation path
    /// exactly (`agent_trace_id` / `agent_span_id` / `machine_agent_confidence`
    /// / `agent_evidence_json`). `agentTool` is nil: self-stamp is a pure
    /// env-provenance fact; the collector's best-effort tool tag is carried
    /// by the parallel `.bind` signal for descendant correlation, not here.
    public static func selfStampEnrichments(context: TraceContext, pid: pid_t) -> [String: String] {
        let evidence = AttributionEvidence(
            source: .traceparentEnv,
            confidence: .traceparent,
            agentTool: nil,
            traceId: context.traceId,
            spanId: context.parentSpanId,
            parentSpanId: context.parentSpanId,
            matchedPid: pid
        )
        return flatten(evidence)
    }

    /// Apply a `TraceCorrelation` to a mutable event. Pure helper — no
    /// async, no actor hop. Caller is expected to hold `event` by value.
    public static func apply(_ correlation: TraceCorrelation, to event: inout Event) {
        // v1.21.4 (P6 fix): never DOWNGRADE an already-`.traceparent`
        // attribution to a lower-confidence one. The exec self-stamp in
        // ESCollector writes machine_agent_confidence=traceparent directly
        // onto the TRACEPARENT-carrying process's OWN exec event. If that
        // same event is also recognised as an isAIChild and the registry
        // bind hasn't landed yet, the isAIChild correlate() can fall through
        // to the lineage pass, whose unconditional apply here would otherwise
        // overwrite the traceparent stamp with `.lineage`. Guard that single
        // direction only — an equal/higher-confidence re-apply (the same
        // binding resolving) stays idempotent.
        if event.enrichments[EnrichmentKey.confidence] == AttributionEvidence.Confidence.traceparent.rawValue,
           correlation.evidence.confidence != .traceparent {
            return
        }
        for (k, v) in correlation.enrichments {
            event.enrichments[k] = v
        }
    }
}
